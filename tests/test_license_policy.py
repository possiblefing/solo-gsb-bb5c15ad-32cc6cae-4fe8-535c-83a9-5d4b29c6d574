"""POST /license-policy 的端到端测试。

覆盖：先审计后判定的 409 短路（与 /audit-lock 的 issues 逐字节一致）、
原子与 AND/OR/括号表达式的三态判定、未提供 license 归为 unknown、
按包名排序、根包参与判定、菱形全部最短路径、环安全、marker 激活、
锁定版本取元数据、PEP 503 规范化、确定性排序，以及 422（非法 SPDX、
allow/deny 重叠或非法标识、非法快照/锁/根包/多余字段）与既有接口
对 allow/deny 字段的兼容性。
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

ENV = {
    "python_version": "3.11",
    "sys_platform": "linux",
    "platform_machine": "x86_64",
}
WIN_ENV = {
    "python_version": "3.11",
    "sys_platform": "win32",
    "platform_machine": "AMD64",
}

ALLOW = ["MIT", "Apache-2.0", "BSD-3-Clause"]
DENY = ["GPL-3.0-only", "AGPL-3.0-only"]


def c(version, deps=None, license_=..., **metadata):
    entry: dict = {"version": version, "dependencies": deps or []}
    if license_ is not ...:
        metadata["license"] = license_
    if metadata:
        entry["metadata"] = metadata
    return entry


def d(name, spec="", marker=""):
    return {"name": name, "specifier": spec, "marker": marker}


def policy(repo, lock, *, allow=None, deny=None, root="app", env=None, **overrides):
    body = {
        "repository": repo,
        "root": root,
        "target_environment": env or ENV,
        "current_lock": lock,
        "allow": ALLOW if allow is None else allow,
        "deny": DENY if deny is None else deny,
    }
    body.update(overrides)
    return client.post("/license-policy", json=body)


def report(repo, lock, **kw):
    r = policy(repo, lock, **kw)
    assert r.status_code == 200, r.text
    return r.json()


def names(body, key):
    return [e["name"] for e in body[key]]


# --------------------------------------------------------------------- #
# 1. 基础三态：允许 / 拒绝 / 未知 / 缺失元数据
# --------------------------------------------------------------------- #
def test_atom_allow_not_listed():
    repo = {"app": [c("1.0")], "lib": [c("1.0", license_="MIT")]}
    # app 依赖 lib，锁中两者均在。
    repo["app"][0]["dependencies"] = [d("lib")]
    body = report(repo, {"app": "1.0", "lib": "1.0"})
    assert body["status"] == "ok"
    assert body["root"] == "app"
    assert body["violations"] == []
    # app 未提供 license -> unknown；lib 允许，不出现。
    assert names(body, "unknowns") == ["app"]
    assert body["unknowns"][0] == {
        "name": "app",
        "license": None,
        "paths": [["app"]],
    }


def test_atom_deny_violation_with_paths():
    repo = {
        "app": [c("1.0", [d("gpl-lib")])],
        "gpl-lib": [c("1.0", license_="GPL-3.0-only")],
    }
    body = report(repo, {"app": "1.0", "gpl-lib": "1.0"})
    assert names(body, "violations") == ["gpl-lib"]
    entry = body["violations"][0]
    assert entry["license"] == "GPL-3.0-only"
    assert entry["paths"] == [["app", "gpl-lib"]]


def test_atom_unknown_identifier():
    repo = {
        "app": [c("1.0", [d("proprietary")])],
        "proprietary": [c("1.0", license_="Proprietary-Custom")],
    }
    body = report(repo, {"app": "1.0", "proprietary": "1.0"})
    assert body["violations"] == []
    assert names(body, "unknowns") == ["app", "proprietary"]


def test_empty_license_string_counts_as_missing():
    repo = {"app": [c("1.0", license_="   ")]}
    body = report(repo, {"app": "1.0"})
    assert names(body, "unknowns") == ["app"]
    assert body["unknowns"][0]["license"] is None


def test_results_sorted_by_package_name():
    deps = [d("zzz-gpl"), d("aaa-gpl"), d("mmm-unknown")]
    repo = {
        "app": [c("1.0", deps)],
        "zzz-gpl": [c("1.0", license_="GPL-3.0-only")],
        "aaa-gpl": [c("1.0", license_="AGPL-3.0-only")],
        "mmm-unknown": [c("1.0", license_="Custom-X")],
    }
    lock = {"app": "1.0", "zzz-gpl": "1.0", "aaa-gpl": "1.0",
            "mmm-unknown": "1.0"}
    body = report(repo, lock)
    assert names(body, "violations") == ["aaa-gpl", "zzz-gpl"]
    assert names(body, "unknowns") == ["app", "mmm-unknown"]


# --------------------------------------------------------------------- #
# 2. AND / OR / 括号三态真值表（端到端）
# --------------------------------------------------------------------- #
def test_and_all_allow_passes():
    repo = {"app": [c("1.0", [d("dual")])],
            "dual": [c("1.0", license_="MIT AND Apache-2.0")]}
    body = report(repo, {"app": "1.0", "dual": "1.0"})
    assert names(body, "violations") == []
    assert names(body, "unknowns") == ["app"]


def test_and_any_deny_violates_even_if_other_branch_allowed():
    repo = {"app": [c("1.0", [d("dual")])],
            "dual": [c("1.0", license_="MIT AND GPL-3.0-only")]}
    body = report(repo, {"app": "1.0", "dual": "1.0"})
    assert names(body, "violations") == ["dual"]


def test_and_mixed_unknown_without_deny_is_unknown():
    repo = {"app": [c("1.0", [d("dual")])],
            "dual": [c("1.0", license_="MIT AND Custom-X")]}
    body = report(repo, {"app": "1.0", "dual": "1.0"})
    assert body["violations"] == []
    assert [e["name"] for e in body["unknowns"] if e["name"] == "dual"] == ["dual"]


def test_or_any_allow_passes_even_with_denied_alternative():
    repo = {"app": [c("1.0", [d("dual")])],
            "dual": [c("1.0", license_="MIT OR GPL-3.0-only")]}
    body = report(repo, {"app": "1.0", "dual": "1.0"})
    assert names(body, "violations") == []
    assert names(body, "unknowns") == ["app"]


def test_or_all_deny_violates():
    repo = {"app": [c("1.0", [d("dual")])],
            "dual": [c("1.0", license_="GPL-3.0-only OR AGPL-3.0-only")]}
    body = report(repo, {"app": "1.0", "dual": "1.0"})
    assert names(body, "violations") == ["dual"]


def test_or_unknown_when_mixed_unknown_and_deny():
    repo = {"app": [c("1.0", [d("dual")])],
            "dual": [c("1.0", license_="GPL-3.0-only OR Custom-X")]}
    body = report(repo, {"app": "1.0", "dual": "1.0"})
    assert body["violations"] == []
    assert [e["name"] for e in body["unknowns"] if e["name"] == "dual"] == ["dual"]


def test_parenthesised_expression_changes_outcome():
    # (MIT OR GPL) AND Apache：括号组 allow，Apache allow -> allow。
    repo1 = {"app": [c("1.0", [d("x")])],
             "x": [c("1.0", license_="(MIT OR GPL-3.0-only) AND Apache-2.0")]}
    body1 = report(repo1, {"app": "1.0", "x": "1.0"})
    assert names(body1, "violations") == []

    # (MIT OR Apache) AND GPL -> deny。
    repo2 = {"app": [c("1.0", [d("x")])],
             "x": [c("1.0", license_="(MIT OR Apache-2.0) AND GPL-3.0-only")]}
    body2 = report(repo2, {"app": "1.0", "x": "1.0"})
    assert names(body2, "violations") == ["x"]


def test_keywords_case_insensitive_identifiers_literal():
    repo = {"app": [c("1.0", [d("x")])],
            "x": [c("1.0", license_="(mit oR GPL-3.0-only) and Apache-2.0")]}
    # mit 不是已知标识（大小写敏感）：括号 = unknown OR deny = unknown；
    # unknown AND allow = unknown。
    body = report(repo, {"app": "1.0", "x": "1.0"})
    assert body["violations"] == []
    assert [e["name"] for e in body["unknowns"] if e["name"] == "x"] == ["x"]


# --------------------------------------------------------------------- #
# 3. 路径：菱形全部最短路径、环安全、根包条目
# --------------------------------------------------------------------- #
def test_diamond_attaches_all_shortest_paths():
    repo = {
        "app": [c("1.0", [d("left"), d("right")])],
        "left": [c("1.0", [d("gpl-shared")])],
        "right": [c("1.0", [d("gpl-shared")])],
        "gpl-shared": [c("1.0", license_="GPL-3.0-only")],
    }
    lock = {"app": "1.0", "left": "1.0", "right": "1.0",
            "gpl-shared": "1.0"}
    body = report(repo, lock)
    entry = body["violations"][0]
    assert entry["name"] == "gpl-shared"
    assert entry["paths"] == [
        ["app", "left", "gpl-shared"],
        ["app", "right", "gpl-shared"],
    ]


def test_root_itself_judged_with_single_node_path():
    repo = {"app": [c("1.0", license_="GPL-3.0-only")]}
    body = report(repo, {"app": "1.0"})
    assert body["violations"] == [
        {"name": "app", "license": "GPL-3.0-only", "paths": [["app"]]}
    ]


def test_cycle_graph_is_safe():
    repo = {
        "app": [c("1.0", [d("cyc-a")])],
        "cyc-a": [c("1.0", [d("cyc-b")], license_="MIT")],
        "cyc-b": [c("1.0", [d("cyc-a"), d("gpl-deep")])],
        "gpl-deep": [c("1.0", license_="GPL-3.0-only")],
    }
    lock = {"app": "1.0", "cyc-a": "1.0", "cyc-b": "1.0", "gpl-deep": "1.0"}
    body = report(repo, lock)
    deep = next(e for e in body["violations"] if e["name"] == "gpl-deep")
    assert deep["paths"] == [["app", "cyc-a", "cyc-b", "gpl-deep"]]


# --------------------------------------------------------------------- #
# 4. 图按锁定版本、marker 激活构造
# --------------------------------------------------------------------- #
def test_metadata_taken_from_locked_version_only():
    repo = {
        "app": [c("1.0", [d("lib")])],
        "lib": [
            c("2.0", license_="GPL-3.0-only"),
            c("1.0", license_="MIT"),
        ],
    }
    # 锁在 1.0（MIT，允许）：2.0 的 GPL 元数据不得参与判定。
    body = report(repo, {"app": "1.0", "lib": "1.0"})
    assert names(body, "violations") == []
    assert [e["name"] for e in body["unknowns"]] == ["app"]


def test_inactive_marker_dependency_not_in_graph():
    repo = {
        "app": [c("1.0", [d("win-gpl", marker="sys_platform == 'win32'")])],
        "win-gpl": [c("1.0", license_="GPL-3.0-only")],
    }
    # linux：win-gpl 不激活，锁里没有它，审计有效 -> 不判定该包。
    body = report(repo, {"app": "1.0"}, env=ENV)
    assert names(body, "violations") == []
    # win32：锁中缺少激活的 win-gpl -> 审计失败 -> 409，不做判定。
    r = policy(repo, {"app": "1.0"}, env=WIN_ENV)
    assert r.status_code == 409
    assert r.json()["issues"][0]["type"] == "missing"
    assert "violations" not in r.json()


def test_pep503_normalization_everywhere():
    repo = {
        "App": [c("1.0", [d("Some_Lib")])],
        "some.lib": [c("1.0", license_="GPL-3.0-only")],
    }
    body = report(repo, {"APP": "1.0", "Some.Lib": "1.0"}, root="App")
    assert body["root"] == "app"
    assert names(body, "violations") == ["some-lib"]


def test_deterministic_across_input_ordering():
    deps = [d("zzz-gpl"), d("aaa-gpl"), d("mmm-gpl")]
    repo = {
        "app": [c("1.0", deps)],
        "zzz-gpl": [c("1.0", license_="GPL-3.0-only")],
        "aaa-gpl": [c("1.0", license_="AGPL-3.0-only")],
        "mmm-gpl": [c("1.0", license_="GPL-3.0-only")],
    }
    lock = {"app": "1.0", "zzz-gpl": "1.0", "aaa-gpl": "1.0",
            "mmm-gpl": "1.0"}
    body1 = report(repo, lock)
    body2 = report(
        dict(reversed(list(repo.items()))),
        dict(reversed(list(lock.items()))),
    )
    assert body1 == body2
    assert names(body1, "violations") == ["aaa-gpl", "mmm-gpl", "zzz-gpl"]


# --------------------------------------------------------------------- #
# 5. 409：锁无效，短路且 issues 与 /audit-lock 一致
# --------------------------------------------------------------------- #
def test_invalid_lock_returns_409_and_skips_judgement():
    repo = {
        "app": [c("1.0", [d("missing-lib"), d("old-lib", ">=2.0")])],
        "missing-lib": [c("1.0", license_="GPL-3.0-only")],
        "old-lib": [c("1.0"), c("2.0")],
    }
    r = policy(repo, {"app": "1.0", "old-lib": "1.0"})
    assert r.status_code == 409
    body = r.json()
    assert body["status"] == "invalid_lock"
    assert body["message"] == "锁定清单未通过审计，未执行许可证策略判定"
    assert [(i["type"], i["name"]) for i in body["issues"]] == [
        ("missing", "missing-lib"),
        ("constraint_mismatch", "old-lib"),
    ]
    assert "violations" not in body and "unknowns" not in body


def test_409_issues_match_audit_lock_endpoint():
    repo = {
        "app": [c("1.0", [d("lib")])],
        "lib": [c("1.0"), c("2.0")],
    }
    body = {
        "repository": repo, "root": "app", "target_environment": ENV,
        "current_lock": {"app": "1.0"},  # lib 可达却未锁定 -> missing
        "allow": ALLOW, "deny": DENY,
    }
    audit = client.post(
        "/audit-lock",
        json={k: v for k, v in body.items() if k not in ("allow", "deny")},
    ).json()
    r = client.post("/license-policy", json=body)
    assert r.status_code == 409
    assert r.json()["issues"] == audit["issues"]


# --------------------------------------------------------------------- #
# 6. 422：非法 SPDX、规则重叠、非法策略标识、非法快照/锁/根包/字段
# --------------------------------------------------------------------- #
def test_invalid_spdx_expression_422_locates_package():
    repo = {
        "app": [c("1.0", [d("bad")])],
        "bad": [c("1.0", license_="MIT AND")],
    }
    r = policy(repo, {"app": "1.0", "bad": "1.0"})
    assert r.status_code == 422
    body = r.json()
    assert body["status"] == "invalid_snapshot"
    assert "bad==1.0" in body["message"]
    assert "SPDX" in body["message"]


def test_with_expression_422():
    repo = {
        "app": [c("1.0", [d("bad")])],
        "bad": [c("1.0", license_="GPL-2.0-only WITH Classpath-exception-2.0")],
    }
    r = policy(repo, {"app": "1.0", "bad": "1.0"})
    assert r.status_code == 422
    assert "WITH" in r.json()["message"]


@pytest.mark.parametrize("license_text,operator", [
    ("MIT OR(Apache-2.0)", "OR"),         # 右侧缺少空白
    ("(MIT)AND(Apache-2.0)", "AND"),      # 两侧都缺少空白
    ("(MIT OR Apache-2.0) and(Apache-2.0)", "and"),
    ("GPL-3.0-only OR(BSD-3-Clause OR MIT)", "OR"),
])
def test_operator_missing_whitespace_returns_422(license_text, operator):
    """回归：AND/OR 任一侧缺少空白分隔时稳定 422，并定位包与违规运算符。"""
    repo = {
        "app": [c("1.0", [d("bad")])],
        "bad": [c("1.0", license_=license_text)],
    }
    r = policy(repo, {"app": "1.0", "bad": "1.0"})
    assert r.status_code == 422, r.text
    message = r.json()["message"]
    assert "bad==1.0" in message
    assert repr(operator) in message
    assert "空白" in message


def test_whitespace_separated_nested_expression_still_200():
    """合法形式（空白分隔、大小写混写、嵌套括号）不受影响，优先级不变。"""
    repo = {
        "app": [c("1.0", [d("ok1"), d("ok2"), d("no")])],
        "ok1": [c("1.0", license_="MIT OR (Apache-2.0)")],
        "ok2": [c("1.0", license_="(MIT) aNd (Apache-2.0)")],
        # (allow OR deny) AND allow -> allow：括号仍正确改变优先级
        "no": [c("1.0",
                 license_="(MIT OR GPL-3.0-only) AND Apache-2.0")],
    }
    lock = {"app": "1.0", "ok1": "1.0", "ok2": "1.0", "no": "1.0"}
    body = report(repo, lock)
    assert names(body, "violations") == []
    assert [e["name"] for e in body["unknowns"]] == ["app"]


def test_identifier_containing_operator_letters_still_judged():
    """ANDOR 这类含 AND/OR 字母片段的真实标识词仍按原子标识三态判定。"""
    repo = {
        "app": [c("1.0", [d("x")])],
        "x": [c("1.0", license_="ANDOR OR MIT")],
    }
    body = report(repo, {"app": "1.0", "x": "1.0"})
    assert names(body, "violations") == []
    assert [e["name"] for e in body["unknowns"]] == ["app"]


def test_policy_overlap_422():
    repo = {"app": [c("1.0", license_="MIT")]}
    r = policy(repo, {"app": "1.0"}, allow=["MIT"], deny=["MIT"])
    assert r.status_code == 422
    assert r.json()["status"] == "invalid_snapshot"
    assert "重叠" in r.json()["message"]


def test_policy_expression_identifier_422():
    repo = {"app": [c("1.0", license_="MIT")]}
    r = policy(repo, {"app": "1.0"}, allow=["MIT OR Apache-2.0"], deny=[])
    assert r.status_code == 422
    assert "allow" in r.json()["message"]


def test_policy_blank_identifier_422():
    repo = {"app": [c("1.0", license_="MIT")]}
    r = policy(repo, {"app": "1.0"}, deny=["  "])
    assert r.status_code == 422


def test_policy_reserved_word_identifier_422():
    repo = {"app": [c("1.0", license_="MIT")]}
    r = policy(repo, {"app": "1.0"}, allow=["WITH"])
    assert r.status_code == 422


def test_invalid_spdx_not_evaluated_when_lock_invalid_is_409():
    """锁审计优先：锁无效时即使存在非法 SPDX 表达式也只返回 409。"""
    repo = {
        "app": [c("1.0", [d("present")])],
        "present": [c("1.0", license_="MIT AND")],
    }
    r = policy(repo, {"app": "1.0"})  # present 缺失 -> missing
    assert r.status_code == 409


def test_bad_snapshot_422():
    r = policy({"app": [c("oops")]}, {"app": "1.0"})
    assert r.status_code == 422
    assert r.json()["status"] == "invalid_snapshot"


def test_bad_lock_version_422():
    r = policy({"app": [c("1.0")]}, {"app": "nope"})
    assert r.status_code == 422
    assert "PEP 440" in r.json()["message"]


def test_unknown_root_422():
    r = policy({"app": [c("1.0")]}, {"app": "1.0"}, root="missing")
    assert r.status_code == 422


def test_extra_field_forbidden_422():
    r = policy({"app": [c("1.0")]}, {"app": "1.0"}, unknown=1)
    assert r.status_code == 422


def test_allow_deny_default_to_empty_everything_unknown():
    repo = {"app": [c("1.0", license_="MIT")]}
    body = {
        "repository": repo, "root": "app", "target_environment": ENV,
        "current_lock": {"app": "1.0"},
    }
    r = client.post("/license-policy", json=body)
    assert r.status_code == 200, r.text
    assert names(r.json(), "unknowns") == ["app"]
    assert r.json()["violations"] == []


def test_existing_endpoints_reject_allow_deny_fields():
    """既有接口保持严格：allow/deny 只属于 /license-policy。"""
    for path in ("/audit-lock", "/sbom"):
        r = client.post(path, json={
            "repository": {"app": [c("1.0")]},
            "root": "app",
            "target_environment": ENV,
            "current_lock": {"app": "1.0"},
            "allow": ["MIT"],
        })
        assert r.status_code == 422, path
