"""POST /dependency-paths 的端到端测试。

覆盖：先审计后查询的 409 短路、单节点根路径、不可达/不存在目标、
菱形等长路径保留、环安全不重复节点、自环、marker 激活、PEP 503
规范化名、路径与节点确定性排序，以及 422 与既有接口兼容性。
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


def query(repo, lock, target, *, root="app", env=None, **overrides):
    body = {
        "repository": repo,
        "root": root,
        "target_environment": env or ENV,
        "current_lock": lock,
        "target": target,
    }
    body.update(overrides)
    return client.post("/dependency-paths", json=body)


def paths(repo, lock, target, **kw):
    r = query(repo, lock, target, **kw)
    assert r.status_code == 200, r.text
    return r.json()["paths"]


# --------------------------------------------------------------------- #
# 1. 基础：线性链、根即目标、不可达
# --------------------------------------------------------------------- #
def test_linear_chain_shortest_path():
    repo = {
        "app": [c("1.0", [d("liba")])],
        "liba": [c("1.0", [d("libb")])],
        "libb": [c("1.0", [d("libc")])],
        "libc": [c("1.0")],
    }
    lock = {"app": "1.0", "liba": "1.0", "libb": "1.0", "libc": "1.0"}
    r = query(repo, lock, "libc")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "ok"
    assert body["root"] == "app"
    assert body["target"] == "libc"
    assert body["reachable"] is True
    assert body["paths"] == [["app", "liba", "libb", "libc"]]


def test_target_is_root_returns_single_node_path():
    repo = {"app": [c("1.0", [d("liba")])], "liba": [c("1.0")]}
    lock = {"app": "1.0", "liba": "1.0"}
    r = query(repo, lock, "app")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["reachable"] is True
    assert body["paths"] == [["app"]]


def test_target_not_in_lock_is_unreachable():
    repo = {
        "app": [c("1.0", [d("liba")])],
        "liba": [c("1.0")],
        "ghost": [c("1.0")],
    }
    lock = {"app": "1.0", "liba": "1.0"}
    r = query(repo, lock, "ghost")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["reachable"] is False
    assert body["paths"] == []


def test_unknown_target_name_still_422():
    """名称模式非法（如空串/非法字符）仍走请求校验 422。"""
    r = query({"app": [c("1.0")]}, {"app": "1.0"}, "not a name!")
    assert r.status_code == 422


# --------------------------------------------------------------------- #
# 2. 菱形：等长路径全部保留，不等长的丢弃
# --------------------------------------------------------------------- #
def test_diamond_keeps_all_equal_length_paths():
    repo = {
        "app": [c("1.0", [d("left"), d("right")])],
        "left": [c("1.0", [d("shared")])],
        "right": [c("1.0", [d("shared")])],
        "shared": [c("1.0")],
    }
    lock = {"app": "1.0", "left": "1.0", "right": "1.0", "shared": "1.0"}
    r = query(repo, lock, "shared")
    assert r.status_code == 200, r.text
    body = r.json()
    # 两条等长路径都保留，按字典序排序（left < right）。
    assert body["paths"] == [
        ["app", "left", "shared"],
        ["app", "right", "shared"],
    ]


def test_only_shortest_paths_when_diamond_has_unequal_arms():
    """汇合路径一长一短时只保留最短的；更长的等终点路径不出现。"""
    repo = {
        "app": [c("1.0", [d("short"), d("long-arm")])],
        "short": [c("1.0", [d("shared")])],
        "long-arm": [c("1.0", [d("long-mid")])],
        "long-mid": [c("1.0", [d("shared")])],
        "shared": [c("1.0")],
    }
    lock = {
        "app": "1.0", "short": "1.0", "long-arm": "1.0",
        "long-mid": "1.0", "shared": "1.0",
    }
    assert paths(repo, lock, "shared") == [["app", "short", "shared"]]


def test_multiple_diamonds_along_the_way_combine():
    """两层菱形：2 x 2 = 4 条等长路径，全部保留并排序。"""
    repo = {
        "app": [c("1.0", [d("a1"), d("a2")])],
        "a1": [c("1.0", [d("b1"), d("b2")])],
        "a2": [c("1.0", [d("b1"), d("b2")])],
        "b1": [c("1.0", [d("target")])],
        "b2": [c("1.0", [d("target")])],
        "target": [c("1.0")],
    }
    lock = {
        "app": "1.0", "a1": "1.0", "a2": "1.0",
        "b1": "1.0", "b2": "1.0", "target": "1.0",
    }
    assert paths(repo, lock, "target") == [
        ["app", "a1", "b1", "target"],
        ["app", "a1", "b2", "target"],
        ["app", "a2", "b1", "target"],
        ["app", "a2", "b2", "target"],
    ]


# --------------------------------------------------------------------- #
# 3. 环：不重复节点、不无限遍历，环可能产生等长最短路径
# --------------------------------------------------------------------- #
def test_cycle_does_not_duplicate_nodes_or_loop_forever():
    repo = {
        "app": [c("1.0", [d("cyc-a")])],
        "cyc-a": [c("1.0", [d("cyc-b")])],
        "cyc-b": [c("1.0", [d("cyc-a"), d("deep")])],
        "deep": [c("1.0")],
    }
    lock = {"app": "1.0", "cyc-a": "1.0", "cyc-b": "1.0", "deep": "1.0"}
    # cyc-a 沿环回走是更长路径，最短路径唯一；路径内节点不重复。
    assert paths(repo, lock, "cyc-a") == [["app", "cyc-a"]]
    result = paths(repo, lock, "deep")
    assert result == [["app", "cyc-a", "cyc-b", "deep"]]
    for path in result:
        assert len(path) == len(set(path))


def test_self_loop_is_safe():
    repo = {
        "app": [c("1.0", [d("loopy")])],
        "loopy": [c("1.0", [d("loopy", ">=1.0")])],
    }
    lock = {"app": "1.0", "loopy": "1.0"}
    assert paths(repo, lock, "loopy") == [["app", "loopy"]]


def test_cycle_can_produce_equal_length_shortest_paths():
    """环上两条等长路径到同一目标时都应保留（去环后形成菱形）。"""
    repo = {
        "app": [c("1.0", [d("a"), d("b")])],
        "a": [c("1.0", [d("c")])],
        "b": [c("1.0", [d("c")])],
        "c": [c("1.0", [d("a")])],  # 回边构成环，不增加更短路径
    }
    lock = {"app": "1.0", "a": "1.0", "b": "1.0", "c": "1.0"}
    assert paths(repo, lock, "c") == [
        ["app", "a", "c"],
        ["app", "b", "c"],
    ]


# --------------------------------------------------------------------- #
# 4. 图按锁定版本与已激活依赖构造
# --------------------------------------------------------------------- #
def test_graph_uses_locked_versions_not_latest():
    """liba 锁定 1.0（无下游）；2.0 的 new-dep 不得进入图。"""
    repo = {
        "app": [c("1.0", [d("liba")])],
        "liba": [c("1.0"), c("2.0", [d("new-dep")])],
        "new-dep": [c("1.0")],
    }
    lock = {"app": "1.0", "liba": "1.0"}
    r = query(repo, lock, "new-dep")
    assert r.status_code == 200, r.text
    assert r.json()["reachable"] is False
    assert paths(repo, lock, "liba") == [["app", "liba"]]


def test_marker_active_dependency_participates_in_graph():
    repo = {
        "app": [c("1.0", [d("linux-thing", marker="sys_platform == 'linux'")])],
        "linux-thing": [c("1.0")],
    }
    lock = {"app": "1.0", "linux-thing": "1.0"}
    assert paths(repo, lock, "linux-thing", env=ENV) == [
        ["app", "linux-thing"]
    ]
    # win32 下该依赖未激活 -> 锁审计 extraneous -> 409，不返回路径。
    r = query(repo, lock, "linux-thing", env=WIN_ENV)
    assert r.status_code == 409
    assert r.json()["issues"][0]["type"] == "extraneous"


def test_duplicate_dependency_declarations_yield_single_edge():
    repo = {
        "app": [c("1.0", [d("libx", ">=1.0"), d("libx", "<2.0")])],
        "libx": [c("1.0")],
    }
    lock = {"app": "1.0", "libx": "1.0"}
    assert paths(repo, lock, "libx") == [["app", "libx"]]


def test_pep503_normalization_in_request_target_and_lock():
    repo = {
        "App": [c("1.0", [d("Some_Lib")])],
        "some.lib": [c("1.0")],
    }
    lock = {"APP": "1.0", "Some.Lib": "1.0"}
    r = query(repo, lock, "SOME-LIB", root="App")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["root"] == "app"
    assert body["target"] == "some-lib"
    assert body["paths"] == [["app", "some-lib"]]


# --------------------------------------------------------------------- #
# 5. 确定性：与包键、依赖声明、锁键顺序无关
# --------------------------------------------------------------------- #
def test_deterministic_across_input_ordering():
    repo = {
        "app": [c("1.0", [d("zz-top"), d("aa-first"), d("mm-mid")])],
        "zz-top": [c("1.0", [d("target")])],
        "aa-first": [c("1.0", [d("target")])],
        "mm-mid": [c("1.0", [d("target")])],
        "target": [c("1.0")],
    }
    lock = {"app": "1.0", "zz-top": "1.0", "aa-first": "1.0",
            "mm-mid": "1.0", "target": "1.0"}
    body1 = query(repo, lock, "target").json()
    body2 = query(
        dict(reversed(list(repo.items()))),
        dict(reversed(list(lock.items()))),
        "TARGET",
    ).json()
    assert body1 == body2
    assert body1["paths"] == [
        ["app", "aa-first", "target"],
        ["app", "mm-mid", "target"],
        ["app", "zz-top", "target"],
    ]
    # 每条路径内部严格按访问次序，不做排序重排。
    assert all(p[0] == "app" and p[-1] == "target" for p in body1["paths"])


# --------------------------------------------------------------------- #
# 6. 锁无效：409，携带确定性排序的审计问题，不查询路径
# --------------------------------------------------------------------- #
def test_invalid_lock_returns_409_with_audit_issues_and_no_query():
    repo = {
        "app": [c("1.0", [
            d("needs-thing"),
            d("old-lib", ">=2.0"),
        ])],
        "old-lib": [c("1.0"), c("2.0")],
        "stale": [c("1.0")],
    }
    lock = {"app": "1.0", "old-lib": "1.0", "stale": "1.0"}
    r = query(repo, lock, "needs-thing")
    assert r.status_code == 409, r.text
    body = r.json()
    assert body["status"] == "invalid_lock"
    assert [(i["type"], i["name"]) for i in body["issues"]] == [
        ("missing", "needs-thing"),
        ("constraint_mismatch", "old-lib"),
        ("extraneous", "stale"),
    ]
    assert "paths" not in body and "reachable" not in body


def test_409_issues_match_audit_lock_endpoint():
    """同一请求体下，409 的 issues 必须与 /audit-lock 逐字节一致。"""
    repo = {
        "app": [c("1.0", [d("libx")])],
        "libx": [c("1.0"), c("2.0")],
    }
    lock = {"app": "1.0", "libx": "3.0"}
    body = {
        "repository": repo, "root": "app", "target_environment": ENV,
        "current_lock": lock,
    }
    audit_body = client.post("/audit-lock", json=body).json()
    path_body = query(repo, lock, "libx").json()
    assert path_body["issues"] == audit_body["issues"]


def test_missing_target_dependency_in_invalid_lock_still_just_409():
    """目标缺失本身就是 missing 审计问题：返回 409 而非 reachable=false。"""
    repo = {"app": [c("1.0", [d("wanted")])], "wanted": [c("1.0")]}
    r = query(repo, {"app": "1.0"}, "wanted")
    assert r.status_code == 409
    assert r.json()["issues"][0] == {
        "type": "missing",
        "name": "wanted",
        "locked_version": None,
        "available": ["1.0"],
        "constraints": [{"from": "app==1.0", "specifier": "*"}],
    }


# --------------------------------------------------------------------- #
# 7. 422：非法快照 / 锁 / 根包 / 字段
# --------------------------------------------------------------------- #
def test_bad_snapshot_422():
    r = query({"app": [c("oops")]}, {"app": "1.0"}, "app")
    assert r.status_code == 422
    assert r.json()["status"] == "invalid_snapshot"


def test_bad_lock_version_422():
    r = query({"app": [c("1.0")]}, {"app": "not-a-version"}, "app")
    assert r.status_code == 422
    assert "PEP 440" in r.json()["message"]


def test_unknown_root_422():
    r = query({"app": [c("1.0")]}, {"app": "1.0"}, "app", root="missing")
    assert r.status_code == 422
    assert "missing" in r.json()["message"]


def test_missing_target_field_422():
    body = {
        "repository": {"app": [c("1.0")]},
        "root": "app",
        "target_environment": ENV,
        "current_lock": {"app": "1.0"},
    }
    r = client.post("/dependency-paths", json=body)
    assert r.status_code == 422


def test_extra_field_forbidden_422():
    r = query({"app": [c("1.0")]}, {"app": "1.0"}, "app", unknown=1)
    assert r.status_code == 422


def test_audit_lock_still_rejects_target_field():
    """既有 /audit-lock 接口保持兼容：仍禁止 target 字段。"""
    r = client.post("/audit-lock", json={
        "repository": {"app": [c("1.0")]},
        "root": "app",
        "target_environment": ENV,
        "current_lock": {"app": "1.0"},
        "target": "app",
    })
    assert r.status_code == 422
