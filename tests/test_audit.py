"""POST /audit-lock 的端到端测试。

覆盖：valid 判定、missing/unavailable/constraint_mismatch/extraneous 四类
问题、环中只展开一次但累计全部入边约束、菱形依赖、根约束与依赖约束、
PEP 503 规范化名与 PEP 440 版本等价性、marker 激活语义、预发布开关、
确定性排序，以及 422（非法快照/锁）映射。
"""

from __future__ import annotations

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


def c(version, deps=None):
    return {"version": version, "dependencies": deps or []}


def d(name, spec="", marker=""):
    return {"name": name, "specifier": spec, "marker": marker}


def audit(repo, lock, *, root="app", env=None, **overrides):
    body = {
        "repository": repo,
        "root": root,
        "target_environment": env or ENV,
        "current_lock": lock,
    }
    body.update(overrides)
    return client.post("/audit-lock", json=body)


def issues(repo, lock, **kw):
    r = audit(repo, lock, **kw)
    assert r.status_code == 200, r.text
    return r.json()["issues"]


# --------------------------------------------------------------------- #
# 1. valid
# --------------------------------------------------------------------- #
def test_valid_lock():
    repo = {
        "app": [c("1.0", [d("liba", ">=1.0"), d("libb", "<3")])],
        "liba": [c("1.0"), c("2.0")],
        "libb": [c("2.0")],
    }
    lock = {"app": "1.0", "liba": "2.0", "libb": "2.0"}
    r = audit(repo, lock)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "ok"
    assert body["valid"] is True
    assert body["issues"] == []


def test_pep440_version_equivalence_is_valid():
    """锁中 1.0 与快照 1.0.0 按 PEP 440 等价，约束 ==1.0 也满足。"""
    repo = {
        "app": [c("1.0", [d("libx", "==1.0")])],
        "libx": [c("1.0.0")],
    }
    body = issues(repo, {"app": "1.0", "libx": "1.0"})
    assert body == []


def test_pep503_name_normalization():
    repo = {
        "app": [c("1.0", [d("Some_Lib")])],
        "some-lib": [c("1.0")],
    }
    # 请求、快照键、锁键三种写法等价。
    body = issues(
        {"App": [c("1.0", [d("Some_Lib")])], "some.lib": [c("1.0")]},
        {"APP": "1.0", "Some.Lib": "1.0"},
    )
    assert body == []


# --------------------------------------------------------------------- #
# 2. missing：可达包未锁定
# --------------------------------------------------------------------- #
def test_missing_reachable_package():
    repo = {
        "app": [c("1.0", [d("liba", ">=1.0"), d("libb")])],
        "liba": [c("1.0")],
        "libb": [c("1.0")],
    }
    body = issues(repo, {"app": "1.0", "liba": "1.0"})
    assert [i["type"] for i in body] == ["missing"]
    issue = body[0]
    assert issue["name"] == "libb"
    assert issue["locked_version"] is None
    assert issue["available"] == ["1.0"]
    assert issue["constraints"] == [{"from": "app==1.0", "specifier": "*"}]


def test_missing_collects_all_incoming_constraints_diamond():
    """菱形：missing 包的两条入边约束都要累计。"""
    repo = {
        "app": [c("1.0", [d("left"), d("right")])],
        "left": [c("1.0", [d("shared", ">=1.0")])],
        "right": [c("1.0", [d("shared", "<2.0")])],
        "shared": [c("1.0"), c("2.0")],
    }
    lock = {"app": "1.0", "left": "1.0", "right": "1.0"}
    body = issues(repo, lock)
    assert len(body) == 1 and body[0]["type"] == "missing"
    assert body[0]["name"] == "shared"
    assert body[0]["constraints"] == [
        {"from": "left==1.0", "specifier": ">=1.0"},
        {"from": "right==1.0", "specifier": "<2.0"},
    ]


def test_unreachable_unlocked_package_is_not_missing():
    """未锁定包在锁定版本的依赖图上不可达时，不产生 missing。"""
    repo = {
        "app": [c("1.0", [d("liba")])],
        "liba": [c("1.0"), c("2.0", [d("new-dep")])],
        "new-dep": [c("1.0")],
    }
    body = issues(repo, {"app": "1.0", "liba": "1.0"})
    assert body == []


# --------------------------------------------------------------------- #
# 3. unavailable：锁定版本不在快照
# --------------------------------------------------------------------- #
def test_unavailable_locked_version_not_in_snapshot():
    repo = {
        "app": [c("1.0", [d("libx")])],
        "libx": [c("1.0"), c("2.0")],
    }
    body = issues(repo, {"app": "1.0", "libx": "3.0"})
    assert len(body) == 1
    issue = body[0]
    assert issue["type"] == "unavailable"
    assert issue["name"] == "libx"
    assert issue["locked_version"] == "3.0"
    assert issue["available"] == ["2.0", "1.0"]
    assert issue["constraints"] == [{"from": "app==1.0", "specifier": "*"}]


def test_unavailable_package_absent_from_snapshot():
    repo = {"app": [c("1.0", [d("ghost", ">=1")])]}
    body = issues(repo, {"app": "1.0", "ghost": "1.0"})
    assert len(body) == 1 and body[0]["type"] == "unavailable"
    assert body[0]["available"] == []
    assert body[0]["constraints"] == [{"from": "app==1.0", "specifier": ">=1"}]


def test_unavailable_blocks_traversal_but_still_reports_extraneous():
    """不可用版本的依赖声明未知：其下游锁中包判为 extraneous 而非可达。"""
    repo = {
        "app": [c("1.0", [d("libx")])],
        "libx": [c("1.0", [d("deep")])],
        "deep": [c("1.0")],
    }
    body = issues(repo, {"app": "1.0", "libx": "2.0", "deep": "1.0"})
    types = {(i["type"], i["name"]) for i in body}
    assert types == {("unavailable", "libx"), ("extraneous", "deep")}


# --------------------------------------------------------------------- #
# 4. constraint_mismatch：根约束与依赖约束
# --------------------------------------------------------------------- #
def test_root_specifier_mismatch():
    repo = {"app": [c("1.0"), c("2.0")]}
    body = issues(repo, {"app": "1.0"}, specifier=">=2.0")
    assert len(body) == 1
    issue = body[0]
    assert issue["type"] == "constraint_mismatch"
    assert issue["name"] == "app"
    assert issue["constraints"] == [
        {"from": "root", "specifier": ">=2.0", "satisfies": False}
    ]


def test_dependency_constraint_mismatch_lists_only_violated():
    repo = {
        "app": [c("1.0", [d("libx", ">=1.0,<2.0")])],
        "libx": [c("1.0"), c("2.0")],
    }
    body = issues(repo, {"app": "1.0", "libx": "2.0"})
    assert len(body) == 1
    issue = body[0]
    assert issue["type"] == "constraint_mismatch"
    assert issue["locked_version"] == "2.0"
    assert issue["constraints"] == [
        {"from": "app==1.0", "specifier": ">=1.0,<2.0", "satisfies": False}
    ]


def test_cycle_expanded_once_but_back_edge_constraint_accumulated():
    """环：cyc-a 只展开一次，但 cyc-b 回边的 ==2.0 必须累计并判 mismatch。"""
    repo = {
        "app": [c("1.0", [d("cyc-a")])],
        "cyc-a": [c("1.0", [d("cyc-b")]), c("2.0")],
        "cyc-b": [c("1.0", [d("cyc-a", "==2.0")])],
    }
    lock = {"app": "1.0", "cyc-a": "1.0", "cyc-b": "1.0"}
    body = issues(repo, lock)
    assert [(i["type"], i["name"]) for i in body] == [
        ("constraint_mismatch", "cyc-a")
    ]
    assert body[0]["constraints"] == [
        {"from": "cyc-b==1.0", "specifier": "==2.0", "satisfies": False}
    ]


def test_self_loop_does_not_duplicate_or_fail():
    repo = {
        "app": [c("1.0", [d("loopy")])],
        "loopy": [c("1.0", [d("loopy", ">=1.0")])],
    }
    body = issues(repo, {"app": "1.0", "loopy": "1.0"})
    assert body == []


def test_cycle_with_satisfying_back_edge_is_valid():
    repo = {
        "app": [c("1.0", [d("a")])],
        "a": [c("1.0", [d("b", ">=1")])],
        "b": [c("1.0", [d("a", "<2")])],
    }
    body = issues(repo, {"app": "1.0", "a": "1.0", "b": "1.0"})
    assert body == []


def test_constraint_mismatch_still_traverses_dependencies():
    """mismatch 的锁定版本仍在快照中：它的依赖继续参与遍历。"""
    repo = {
        "app": [c("1.0", [d("libx", "==2.0")])],
        "libx": [c("1.0", [d("child")]), c("2.0", [d("child")])],
        "child": [c("1.0")],
    }
    # libx 锁 1.0（与 ==2.0 冲突），但 1.0 的依赖 child 仍应被要求
    body = issues(repo, {"app": "1.0", "libx": "1.0"})
    assert {(i["type"], i["name"]) for i in body} == {
        ("constraint_mismatch", "libx"),
        ("missing", "child"),
    }


def test_duplicate_incoming_edges_are_deduplicated():
    """同一声明方、同一约束文本的多条入边只出现一次。"""
    repo = {
        "app": [c("1.0", [d("libx", ">=1"), d("libx", ">=1")])],
        "libx": [c("0.9"), c("1.0")],
    }
    body = issues(repo, {"app": "1.0", "libx": "0.9"})
    assert len(body) == 1
    assert body[0]["constraints"] == [
        {"from": "app==1.0", "specifier": ">=1", "satisfies": False}
    ]


def test_versions_from_different_origins_both_listed():
    """两个来源给出不同约束、锁版本只满足其一时，只列未满足的一条。"""
    repo = {
        "app": [c("1.0", [d("left"), d("right")])],
        "left": [c("1.0", [d("shared", ">=1.0")])],
        "right": [c("1.0", [d("shared", ">=2.0")])],
        "shared": [c("1.0"), c("2.0")],
    }
    lock = {"app": "1.0", "left": "1.0", "right": "1.0", "shared": "1.0"}
    body = issues(repo, lock)
    assert len(body) == 1 and body[0]["type"] == "constraint_mismatch"
    assert body[0]["constraints"] == [
        {"from": "right==1.0", "specifier": ">=2.0", "satisfies": False}
    ]


# --------------------------------------------------------------------- #
# 5. extraneous：锁中包不可达
# --------------------------------------------------------------------- #
def test_extraneous_locked_package_unreachable():
    repo = {"app": [c("1.0")]}
    r = audit(repo, {"app": "1.0", "stale": "1.0"})
    body = r.json()
    assert body["valid"] is False
    issue = body["issues"][0]
    assert issue == {
        "type": "extraneous",
        "name": "stale",
        "locked_version": "1.0",
        "available": [],
        "constraints": [],
    }


def test_extraneous_due_to_inactive_marker():
    """仅被未激活依赖要求的锁中包不可达 -> extraneous（不求解、不猜测）。"""
    repo = {
        "app": [c("1.0", [d("win-only", marker="sys_platform == 'win32'")])],
        "win-only": [c("1.0")],
    }
    body = issues(repo, {"app": "1.0", "win-only": "1.0"}, env=ENV)
    assert [(i["type"], i["name"]) for i in body] == [
        ("extraneous", "win-only")
    ]
    # 切到 win32 环境：依赖激活，锁有效。
    assert issues(repo, {"app": "1.0", "win-only": "1.0"}, env=WIN_ENV) == []


# --------------------------------------------------------------------- #
# 6. 组合与确定性排序
# --------------------------------------------------------------------- #
def test_all_four_issue_types_and_ordering():
    repo = {
        "app": [c("1.0", [
            d("needs-thing"),                       # missing
            d("old-lib", ">=2.0"),                  # 锁 1.0 -> mismatch
        ])],
        "old-lib": [c("1.0"), c("2.0")],
        "gone": [c("1.0")],
    }
    lock = {
        "app": "1.0",
        "old-lib": "1.0",
        "zz-gone": "1.0",      # extraneous（快照有但不可达）
        "zz-unavail": "9.0",   # extraneous 且版本不在快照；按 extraneous 报
    }
    body = issues(repo, lock)
    # 类型次序：missing -> unavailable -> constraint_mismatch -> extraneous
    assert [(i["type"], i["name"]) for i in body] == [
        ("missing", "needs-thing"),
        ("constraint_mismatch", "old-lib"),
        ("extraneous", "zz-gone"),
        ("extraneous", "zz-unavail"),
    ]


def test_ordering_within_type_is_by_name():
    repo = {
        "app": [c("1.0", [d("zeta"), d("alpha")])],
        "zeta": [c("1.0")],
        "alpha": [c("1.0")],
    }
    body = issues(repo, {"app": "1.0"})
    assert [i["name"] for i in body] == ["alpha", "zeta"]


def test_deterministic_across_repeated_calls_and_key_order():
    repo = {
        "app": [c("1.0", [d("libb"), d("liba")])],
        "liba": [c("1.0", [d("shared", "==1.0")])],
        "libb": [c("1.0", [d("shared", "==2.0")])],
        "shared": [c("1.0"), c("2.0")],
    }
    lock = {"app": "1.0", "liba": "1.0", "libb": "1.0", "shared": "1.0",
            "extra": "1.0"}
    body1 = audit(repo, lock).json()
    body2 = audit(dict(reversed(list(repo.items()))),
                  dict(reversed(list(lock.items())))).json()
    assert body1 == body2
    assert [(i["type"], i["name"]) for i in body1["issues"]] == [
        ("constraint_mismatch", "shared"),
        ("extraneous", "extra"),
    ]


# --------------------------------------------------------------------- #
# 7. marker 语义复用（与 /resolve 同一套已激活依赖）
# --------------------------------------------------------------------- #
def test_inactive_dependencies_are_ignored():
    repo = {
        "app": [c("1.0", [
            d("real", "==1.0"),
            d("win-thing", ">=42", marker="sys_platform == 'win32'"),
        ])],
        "real": [c("1.0")],
        "win-thing": [c("1.0")],
    }
    # linux 下 win-thing 未激活：即使锁里没有它也不 missing；
    # 它要求的 >=42 也不产生任何问题。
    assert issues(repo, {"app": "1.0", "real": "1.0"}, env=ENV) == []


def test_marker_activated_dependency_participates_in_audit():
    repo = {
        "app": [c("1.0", [d("linux-thing", "==1.0",
                            marker="sys_platform == 'linux'")])],
        "linux-thing": [c("1.0"), c("2.0")],
    }
    body = issues(repo, {"app": "1.0", "linux-thing": "2.0"}, env=ENV)
    assert [(i["type"], i["name"]) for i in body] == [
        ("constraint_mismatch", "linux-thing")
    ]
    # win32 下未激活：锁中的 linux-thing 反而 extraneous
    body_win = issues(repo, {"app": "1.0", "linux-thing": "2.0"}, env=WIN_ENV)
    assert [(i["type"], i["name"]) for i in body_win] == [
        ("extraneous", "linux-thing")
    ]


# --------------------------------------------------------------------- #
# 8. 预发布语义（与 /resolve 同一开关）
# --------------------------------------------------------------------- #
def test_prerelease_satisfaction_follows_pip_semantics():
    """预发布版本满足与否与求解器同一套 pip 跟随语义：

    * PEP 440 严格排序下 2.0rc1 < 2.0，默认不满足 >=2.0（候选选择时也会被
      排除）；allow_prereleases=true 放开后按纯 PEP 440 判断，仍不满足；
    * 约束显式钉住预发布（==2.0rc1）时谓词允许预发布，视为满足。
    """
    repo = {
        "app": [c("1.0", [d("libx", ">=2.0")])],
        "libx": [c("1.0"), c("2.0rc1"), c("2.0")],
    }
    body = issues(repo, {"app": "1.0", "libx": "2.0rc1"})
    assert [(i["type"], i["name"]) for i in body] == [
        ("constraint_mismatch", "libx")
    ]
    # 放开开关只影响预发布排除：rc1 仍然 < 2.0，故依旧 mismatch。
    body2 = issues(
        repo, {"app": "1.0", "libx": "2.0rc1"}, allow_prereleases=True
    )
    assert [(i["type"], i["name"]) for i in body2] == [
        ("constraint_mismatch", "libx")
    ]

    repo2 = {
        "app": [c("1.0", [d("libx", ">=2.0rc1")])],
        "libx": [c("2.0rc1"), c("2.0")],
    }
    assert issues(repo2, {"app": "1.0", "libx": "2.0rc1"}) == []


def test_explicit_prerelease_pin_satisfies_without_toggle():
    """约束显式钉住预发布版本时，pip 跟随语义下视为满足。"""
    repo = {
        "app": [c("1.0", [d("libx", "==2.0rc1")])],
        "libx": [c("2.0rc1")],
    }
    assert issues(repo, {"app": "1.0", "libx": "2.0rc1"}) == []


# --------------------------------------------------------------------- #
# 9. 422：非法快照 / current_lock / 根包
# --------------------------------------------------------------------- #
def test_invalid_lock_version_422():
    r = audit({"app": [c("1.0")]}, {"app": "not-a-version"})
    assert r.status_code == 422
    body = r.json()
    assert body["status"] == "invalid_snapshot"
    assert "PEP 440" in body["message"]


def test_conflicting_lock_versions_422():
    r = audit({"app": [c("1.0")]}, {"Lib_X": "1.0", "lib-x": "2.0"})
    assert r.status_code == 422
    assert r.json()["status"] == "invalid_snapshot"


def test_missing_current_lock_422():
    r = client.post("/audit-lock", json={
        "repository": {"app": [c("1.0")]},
        "root": "app",
        "target_environment": ENV,
    })
    assert r.status_code == 422


def test_extra_field_forbidden_422():
    r = audit({"app": [c("1.0")]}, {"app": "1.0"}, unknown_field=1)
    assert r.status_code == 422


def test_invalid_snapshot_version_422():
    r = audit({"app": [c("oops")]}, {"app": "1.0"})
    assert r.status_code == 422
    assert "PEP 440" in r.json()["message"]


def test_unknown_root_422():
    r = audit({"app": [c("1.0")]}, {}, root="missing")
    assert r.status_code == 422
    body = r.json()
    assert body["status"] == "invalid_snapshot"
    assert "missing" in body["message"]


def test_invalid_marker_422():
    repo = {"app": [c("1.0", [d("x", marker="os_name == 'posix'")])]}
    r = audit(repo, {"app": "1.0", "x": "1.0"})
    assert r.status_code == 422
    assert "os_name" in r.json()["message"]


def test_audit_does_not_require_target_field():
    """请求模型复用 /resolve + current_lock，禁止 /upgrade 的 target 字段。"""
    r = audit({"app": [c("1.0")]}, {"app": "1.0"}, target="app")
    assert r.status_code == 422


# --------------------------------------------------------------------- #
# 10. 不影响既有接口
# --------------------------------------------------------------------- #
def test_audit_does_not_change_resolve_behavior():
    repo = {
        "app": [c("1.0", [d("libx"), d("liby")])],
        "libx": [c("1.0"), c("2.0")],
        "liby": [c("1.0"), c("2.0")],
    }
    body = {
        "repository": repo, "root": "app", "target_environment": ENV,
    }
    before = client.post("/resolve", json=body).json()
    audit(repo, {"app": "1.0", "libx": "9.0"})
    after = client.post("/resolve", json=body).json()
    assert before == after
    assert before["locked"] == {"app": "1.0", "libx": "2.0", "liby": "2.0"}
