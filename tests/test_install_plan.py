"""POST /install-plan 的端到端测试。

覆盖：先审计后建图的 409 短路、线性链/菱形的最长路径分层（依赖批次不
晚于依赖它的包）、并行批内确定性排序、强连通分量压缩（多成员环、自环、
根包在环中、同层多环排序）、根包所在分量处于最后一批、marker 激活、
PEP 503 规范化、与输入顺序无关的确定性，以及 422 与既有接口兼容性。
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


def plan(repo, lock, *, root="app", env=None, **overrides):
    body = {
        "repository": repo,
        "root": root,
        "target_environment": env or ENV,
        "current_lock": lock,
    }
    body.update(overrides)
    return client.post("/install-plan", json=body)


def batches(repo, lock, **kw):
    r = plan(repo, lock, **kw)
    assert r.status_code == 200, r.text
    return r.json()["batches"]


def names_of(batch):
    """批内 item 的标识序列：单包取 name，循环分量取排序后的包元组。"""
    return [
        tuple(item["packages"]) if item["cyclic"] else item["name"]
        for item in batch
    ]


def levels(result):
    """全部批次的标识序列：每个批次一个列表。"""
    return [names_of(batch) for batch in result]


# --------------------------------------------------------------------- #
# 1. 基础：单包根、线性链、菱形并行分层
# --------------------------------------------------------------------- #
def test_single_root_is_one_batch():
    r = plan({"app": [c("1.0")]}, {"app": "1.0"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "ok"
    assert body["root"] == "app"
    assert body["batches"] == [[{"cyclic": False, "name": "app", "packages": None}]]


def test_linear_chain_batches_in_dependency_order():
    repo = {
        "app": [c("1.0", [d("liba")])],
        "liba": [c("1.0", [d("libb")])],
        "libb": [c("1.0", [d("libc")])],
        "libc": [c("1.0")],
    }
    lock = {"app": "1.0", "liba": "1.0", "libb": "1.0", "libc": "1.0"}
    result = batches(repo, lock)
    assert levels(result) == [["libc"], ["libb"], ["liba"], ["app"]]
    assert result[0][0] == {"cyclic": False, "name": "libc", "packages": None}


def test_diamond_dependencies_share_earliest_batch():
    # core 无依赖 -> 批次 0；left/right 只依赖 core -> 批次 1（并行）；
    # app 依赖两者 -> 批次 2（最后一批）。
    repo = {
        "app": [c("1.0", [d("left"), d("right")])],
        "left": [c("1.0", [d("core")])],
        "right": [c("1.0", [d("core")])],
        "core": [c("1.0")],
    }
    lock = {"app": "1.0", "left": "1.0", "right": "1.0", "core": "1.0"}
    result = batches(repo, lock)
    assert levels(result) == [["core"], ["left", "right"], ["app"]]


def test_independent_dependencies_are_parallel_in_first_batch():
    repo = {
        "app": [c("1.0", [d("zz-top"), d("aa-first"), d("mm-mid")])],
        "zz-top": [c("1.0")],
        "aa-first": [c("1.0")],
        "mm-mid": [c("1.0")],
    }
    lock = {"app": "1.0", "zz-top": "1.0", "aa-first": "1.0", "mm-mid": "1.0"}
    result = batches(repo, lock)
    # 三个无依赖包同批并行，批内按包名字典序；根包独占最后一批。
    assert levels(result) == [["aa-first", "mm-mid", "zz-top"], ["app"]]


def test_dependency_batch_never_later_than_dependent():
    """不变量：对每条 pkg -> dep 边（跨分量），dep 所在批次严格更早。"""
    repo = {
        "app": [c("1.0", [d("a"), d("x")])],
        "a": [c("1.0", [d("b"), d("y")])],
        "b": [c("1.0", [d("y")])],
        "x": [c("1.0", [d("y")])],
        "y": [c("1.0", [d("z")])],
        "z": [c("1.0")],
    }
    lock = {k: "1.0" for k in ("app", "a", "b", "x", "y", "z")}
    result = batches(repo, lock)
    level = {}
    for index, batch in enumerate(result):
        for item in batch:
            targets = item["packages"] if item["cyclic"] else [item["name"]]
            for name in targets:
                level[name] = index
    for name, deps in {
        "app": ("a", "x"), "a": ("b", "y"), "b": ("y",),
        "x": ("y",), "y": ("z",),
    }.items():
        for dep in deps:
            assert level[dep] < level[name], (name, dep, level)


# --------------------------------------------------------------------- #
# 2. 强连通分量：多成员环、自环、根包在环中、同层多环
# --------------------------------------------------------------------- #
def test_cyclic_component_is_one_batch_item_with_packages():
    repo = {
        "app": [c("1.0", [d("web-framework"), d("auth-lib")])],
        "web-framework": [c("1.0", [d("shared-util"), d("plugin-a")])],
        "auth-lib": [c("1.0", [d("shared-util")])],
        "shared-util": [c("1.0", [d("plugin-a")])],
        "plugin-a": [c("1.0", [d("shared-util")])],
    }
    lock = {
        "app": "1.0", "auth-lib": "1.0", "web-framework": "1.0",
        "shared-util": "1.0", "plugin-a": "1.0",
    }
    result = batches(repo, lock)
    assert levels(result) == [
        [("plugin-a", "shared-util")],
        ["auth-lib", "web-framework"],
        ["app"],
    ]
    cyclic_item = result[0][0]
    assert cyclic_item["cyclic"] is True
    assert cyclic_item["name"] is None
    assert cyclic_item["packages"] == ["plugin-a", "shared-util"]
    # 其余 item 为非循环单包项。
    for batch in result[1:]:
        for item in batch:
            assert item["cyclic"] is False
            assert item["packages"] is None
            assert item["name"]


def test_self_loop_is_a_cyclic_singleton_component():
    repo = {
        "app": [c("1.0", [d("loopy")])],
        "loopy": [c("1.0", [d("loopy", ">=1.0")])],
    }
    lock = {"app": "1.0", "loopy": "1.0"}
    result = batches(repo, lock)
    assert levels(result) == [[("loopy",)], ["app"]]
    item = result[0][0]
    assert item == {"cyclic": True, "name": None, "packages": ["loopy"]}


def test_root_in_cycle_lands_in_last_batch():
    """根包自身与下游成环：根循环分量必须处于最后一批。"""
    repo = {
        "app": [c("1.0", [d("rlib")])],
        "rlib": [c("1.0", [d("app")])],
    }
    result = batches(repo, {"app": "1.0", "rlib": "1.0"})
    assert levels(result) == [[("app", "rlib")]]
    assert result[-1][0]["packages"] == ["app", "rlib"]


def test_root_cycle_with_leaf_dependency():
    repo = {
        "app": [c("1.0", [d("rlib")])],
        "rlib": [c("1.0", [d("app"), d("leaf")])],
        "leaf": [c("1.0")],
    }
    result = batches(repo, {"app": "1.0", "rlib": "1.0", "leaf": "1.0"})
    assert levels(result) == [["leaf"], [("app", "rlib")]]


def test_multiple_cyclic_components_same_level_sorted_by_members():
    repo = {
        "app": [c("1.0", [d("p")])],
        "p": [c("1.0", [d("a1"), d("b1")])],
        "a1": [c("1.0", [d("a2")])],
        "a2": [c("1.0", [d("a1"), d("leaf")])],
        "b1": [c("1.0", [d("b2")])],
        "b2": [c("1.0", [d("b1"), d("leaf")])],
        "leaf": [c("1.0")],
    }
    lock = {k: "1.0" for k in ("app", "p", "a1", "a2", "b1", "b2", "leaf")}
    result = batches(repo, lock)
    assert levels(result) == [
        ["leaf"],
        [("a1", "a2"), ("b1", "b2")],
        ["p"],
        ["app"],
    ]


def test_package_outside_cycle_but_on_cycle_path_has_own_level():
    # core<->util 成环（批次 0）；gateway 依赖该环（批次 1）；
    # app 依赖 gateway（批次 2）。环外包不并入循环分量。
    repo = {
        "app": [c("1.0", [d("gateway")])],
        "gateway": [c("1.0", [d("core")])],
        "core": [c("1.0", [d("util")])],
        "util": [c("1.0", [d("core")])],
    }
    lock = {"app": "1.0", "gateway": "1.0", "core": "1.0", "util": "1.0"}
    result = batches(repo, lock)
    assert levels(result) == [
        [("core", "util")], ["gateway"], ["app"]
    ]


# --------------------------------------------------------------------- #
# 3. 图按锁定版本与已激活 marker 依赖构造
# --------------------------------------------------------------------- #
def test_graph_uses_locked_versions_not_latest():
    """liba 锁定 1.0（无下游）；2.0 的 new-dep 不得进入批次。"""
    repo = {
        "app": [c("1.0", [d("liba")])],
        "liba": [c("1.0"), c("2.0", [d("new-dep")])],
        "new-dep": [c("1.0")],
    }
    result = batches(repo, {"app": "1.0", "liba": "1.0"})
    flat = {
        name
        for batch in result
        for item in batch
        for name in (item["packages"] if item["cyclic"] else [item["name"]])
    }
    assert flat == {"app", "liba"}
    assert levels(result) == [["liba"], ["app"]]


def test_marker_inactive_dependency_excluded_and_invalid_lock_409():
    repo = {
        "app": [c("1.0", [d("linux-thing", marker="sys_platform == 'linux'")])],
        "linux-thing": [c("1.0")],
    }
    lock = {"app": "1.0", "linux-thing": "1.0"}
    # linux：依赖激活，linux-thing 先装。
    assert levels(batches(repo, lock, env=ENV)) == [["linux-thing"], ["app"]]
    # win32：依赖未激活，锁中多出不可达包 -> extraneous -> 409，不生成计划。
    r = plan(repo, lock, env=WIN_ENV)
    assert r.status_code == 409
    body = r.json()
    assert body["status"] == "invalid_lock"
    assert [(i["type"], i["name"]) for i in body["issues"]] == [
        ("extraneous", "linux-thing")
    ]
    assert "batches" not in body


def test_pep503_normalization_in_names_and_graph():
    repo = {
        "App": [c("1.0", [d("Some_Lib")])],
        "some.lib": [c("1.0")],
    }
    r = plan(repo, {"APP": "1.0", "Some.Lib": "1.0"}, root="App")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["root"] == "app"
    assert levels(body["batches"]) == [["some-lib"], ["app"]]


# --------------------------------------------------------------------- #
# 4. 确定性：与包键、依赖声明、锁键顺序无关
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
    b1 = plan(repo, lock).json()
    b2 = plan(
        dict(reversed(list(repo.items()))),
        dict(reversed(list(lock.items()))),
    ).json()
    assert b1 == b2
    assert levels(b1["batches"]) == [
        ["target"],
        ["aa-first", "mm-mid", "zz-top"],
        ["app"],
    ]


def test_cyclic_packages_listed_sorted_regardless_of_declaration_order():
    repo = {
        "app": [c("1.0", [d("cyc-c")])],
        "cyc-c": [c("1.0", [d("cyc-a")])],
        "cyc-a": [c("1.0", [d("cyc-b")])],
        "cyc-b": [c("1.0", [d("cyc-c")])],
    }
    lock = {"app": "1.0", "cyc-a": "1.0", "cyc-b": "1.0", "cyc-c": "1.0"}
    result = batches(
        dict(reversed(list(repo.items()))),
        dict(reversed(list(lock.items()))),
    )
    assert levels(result) == [[("cyc-a", "cyc-b", "cyc-c")], ["app"]]


# --------------------------------------------------------------------- #
# 5. 锁无效：409，携带与 /audit-lock 一致的问题，不生成计划
# --------------------------------------------------------------------- #
def test_invalid_lock_returns_409_with_audit_issues_and_no_batches():
    repo = {
        "app": [c("1.0", [d("needs-thing"), d("old-lib", ">=2.0")])],
        "old-lib": [c("1.0"), c("2.0")],
        "stale": [c("1.0")],
    }
    lock = {"app": "1.0", "old-lib": "1.0", "stale": "1.0"}
    r = plan(repo, lock)
    assert r.status_code == 409, r.text
    body = r.json()
    assert body["status"] == "invalid_lock"
    assert body["message"] == "锁定清单未通过审计，未生成安装计划"
    assert [(i["type"], i["name"]) for i in body["issues"]] == [
        ("missing", "needs-thing"),
        ("constraint_mismatch", "old-lib"),
        ("extraneous", "stale"),
    ]
    assert "batches" not in body


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
    plan_body = plan(repo, lock).json()
    assert plan_body["issues"] == audit_body["issues"]


def test_missing_dependency_in_lock_is_409_not_partial_plan():
    repo = {"app": [c("1.0", [d("wanted")])], "wanted": [c("1.0")]}
    r = plan(repo, {"app": "1.0"})
    assert r.status_code == 409
    assert r.json()["issues"][0]["type"] == "missing"


# --------------------------------------------------------------------- #
# 6. 422 与既有接口兼容性
# --------------------------------------------------------------------- #
def test_bad_snapshot_422():
    r = plan({"app": [c("oops")]}, {"app": "1.0"})
    assert r.status_code == 422
    assert r.json()["status"] == "invalid_snapshot"


def test_bad_lock_version_422():
    r = plan({"app": [c("1.0")]}, {"app": "not-a-version"})
    assert r.status_code == 422
    assert "PEP 440" in r.json()["message"]


def test_unknown_root_422():
    r = plan({"app": [c("1.0")]}, {"app": "1.0"}, root="missing")
    assert r.status_code == 422
    assert "missing" in r.json()["message"]


def test_missing_current_lock_field_422():
    r = client.post("/install-plan", json={
        "repository": {"app": [c("1.0")]},
        "root": "app",
        "target_environment": ENV,
    })
    assert r.status_code == 422


def test_extra_field_forbidden_422():
    r = plan({"app": [c("1.0")]}, {"app": "1.0"}, unknown=1)
    assert r.status_code == 422


def test_audit_lock_still_rejects_install_only_fields():
    """既有 /audit-lock 接口保持兼容：install-plan 未引入新字段，行为不变。"""
    r = client.post("/audit-lock", json={
        "repository": {"app": [c("1.0")]},
        "root": "app",
        "target_environment": ENV,
        "current_lock": {"app": "1.0"},
        "batches": [],
    })
    assert r.status_code == 422
