"""最短路径条数固定预算（1000 条）的回归测试。

分层菱形（每层两个分叉、逐层汇合再分叉）下，根到目标的最短路径条数
随层数指数增长（n 层 = 2**n 条），逐一构造路径列表会拖垮进程。修复后
BFS 建立最短前驱图，先按层做饱和计数：条数超过固定预算 1000 即饱和为
1001 并抛 PathCountLimit，不构造路径列表；/dependency-paths、
/license-policy、/lock-diff 任一查询超限均返回 409 status=limit
（含目标包、used=1001、limit=1000），多个目标按既有包名顺序稳定命中
首个超限项；未超限时仍返回全部最短路径且排序不变。
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.paths import PATH_COUNT_LIMIT, PathCountLimit, shortest_paths

client = TestClient(app)

ENV = {
    "python_version": "3.11",
    "sys_platform": "linux",
    "platform_machine": "x86_64",
}

assert PATH_COUNT_LIMIT == 1000  # 预算固定为 1000，不随配置变化


def c(version, deps=None, **metadata):
    entry: dict = {"version": version, "dependencies": deps or []}
    if metadata:
        entry["metadata"] = metadata
    return entry


def d(name, spec="", marker=""):
    return {"name": name, "specifier": spec, "marker": marker}


def layered_graph(layers):
    """layers 层 2 路菱形的邻接表：app -> l1a/l1b -> ... -> target。

    每层两个节点，第 i 层的两个节点都连向第 i+1 层的两个节点，最后一层
    都连向 target；根到 target 的最短路径恰为 2**layers 条。
    """
    graph = {"app": ["l1a", "l1b"]}
    for i in range(1, layers + 1):
        for s in ("a", "b"):
            node = f"l{i}{s}"
            graph[node] = [f"l{i + 1}a", f"l{i + 1}b"] if i < layers else ["target"]
    graph["target"] = []
    return graph


def wide_graph(width):
    """宽度菱形的邻接表：app -> w0..w{width-1} -> target，恰 width 条最短路径。"""
    graph = {"app": [f"w{i}" for i in range(width)]}
    for i in range(width):
        graph[f"w{i}"] = ["target"]
    graph["target"] = []
    return graph


def layered_repo_lock(layers, sinks, *, sink_metadata=None):
    """分层菱形仓库快照与有效锁：app -> l1a/l1b -> ... -> 各 sink。

    sinks 为最后一层两个节点共同指向的包名列表；根到每个 sink 的最短路径
    均为 2**layers 条。所有包默认携带 MIT 许可证（allow 判定通过、不产生
    路径查询），sink 可用 sink_metadata 覆盖（如 deny 的许可证）。
    """
    sink_metadata = sink_metadata or {}
    repo = {"app": [c("1.0", [d("l1a"), d("l1b")], license="MIT")]}
    lock = {"app": "1.0"}
    for i in range(1, layers + 1):
        for s in ("a", "b"):
            node = f"l{i}{s}"
            deps = [d(f"l{i + 1}a"), d(f"l{i + 1}b")] if i < layers else [
                d(sink) for sink in sinks
            ]
            repo[node] = [c("1.0", deps, license="MIT")]
            lock[node] = "1.0"
    for sink in sinks:
        repo[sink] = [c("1.0", **sink_metadata.get(sink, {"license": "MIT"}))]
        lock[sink] = "1.0"
    return repo, lock


def query_paths(repo, lock, target, *, root="app", **overrides):
    body = {
        "repository": repo,
        "root": root,
        "target_environment": ENV,
        "current_lock": lock,
        "target": target,
    }
    body.update(overrides)
    return client.post("/dependency-paths", json=body)


def query_policy(repo, lock, *, allow=None, deny=None, **overrides):
    body = {
        "repository": repo,
        "root": "app",
        "target_environment": ENV,
        "current_lock": lock,
        "allow": ["MIT"] if allow is None else allow,
        "deny": ["GPL-3.0-only"] if deny is None else deny,
    }
    body.update(overrides)
    return client.post("/license-policy", json=body)


def query_diff(repo, before, after, **overrides):
    body = {
        "repository": repo,
        "root": "app",
        "target_environment": ENV,
        "before_lock": before,
        "after_lock": after,
    }
    body.update(overrides)
    return client.post("/lock-diff", json=body)


# --------------------------------------------------------------------- #
# 1. paths 层：按层饱和计数，超限抛 PathCountLimit，不构造路径列表
# --------------------------------------------------------------------- #
def test_layered_diamond_over_budget_raises_with_saturated_used():
    # 10 层 = 1024 条 > 1000：超限，used 饱和为 1001（而非真实条数 1024）。
    with pytest.raises(PathCountLimit) as excinfo:
        shortest_paths(layered_graph(10), "app", "target")
    exc = excinfo.value
    assert exc.target == "target"
    assert exc.used == PATH_COUNT_LIMIT + 1 == 1001
    assert exc.limit == PATH_COUNT_LIMIT == 1000


def test_deep_layered_diamond_saturates_without_explosion():
    """20 层 = 1,048,576 条：计数饱和在 1001，进程不被指数级路径拖垮。"""
    with pytest.raises(PathCountLimit) as excinfo:
        shortest_paths(layered_graph(20), "app", "target")
    assert excinfo.value.used == 1001
    assert excinfo.value.limit == 1000


def test_exactly_at_budget_returns_all_paths():
    """恰 1000 条（预算边界）：不超限，全部路径照常返回且字典序排序。"""
    paths = shortest_paths(wide_graph(1000), "app", "target")
    assert len(paths) == 1000
    assert paths == sorted(paths)
    assert paths[0] == ["app", "w0", "target"]
    assert paths[-1] == ["app", "w999", "target"]


def test_one_over_budget_raises():
    """1001 条（预算 +1）：超限，used 恰为 1001。"""
    with pytest.raises(PathCountLimit) as excinfo:
        shortest_paths(wide_graph(1001), "app", "target")
    assert excinfo.value.used == 1001
    assert excinfo.value.limit == 1000


def test_far_over_budget_still_reports_saturated_1001():
    """5000 条：饱和计数与真实条数无关，used 恒为 1001（确定性）。"""
    with pytest.raises(PathCountLimit) as excinfo:
        shortest_paths(wide_graph(5000), "app", "target")
    assert excinfo.value.used == 1001


def test_under_budget_layered_diamond_unchanged():
    """9 层 = 512 条（未超限）：全部最短路径返回，排序与既有行为一致。"""
    paths = shortest_paths(layered_graph(9), "app", "target")
    assert len(paths) == 512
    assert paths == sorted(paths)
    assert paths[0] == ["app"] + ["l1a"] + [f"l{i}a" for i in range(2, 10)] + ["target"]
    assert all(len(p) == 11 for p in paths)


def test_unreachable_and_root_target_unaffected_by_budget():
    graph = layered_graph(10)
    assert shortest_paths(graph, "app", "ghost") == []
    assert shortest_paths(graph, "app", "app") == [["app"]]


# --------------------------------------------------------------------- #
# 2. POST /dependency-paths：超限 409 status=limit
# --------------------------------------------------------------------- #
def test_dependency_paths_over_budget_409_limit_payload():
    repo, lock = layered_repo_lock(10, ["target"])
    r = query_paths(repo, lock, "target")
    assert r.status_code == 409, r.text
    body = r.json()
    assert body["status"] == "limit"
    assert body["target"] == "target"
    assert body["used"] == 1001
    assert body["limit"] == 1000
    assert "message" in body
    # 超限时不构造路径列表：响应不含路径查询结果字段。
    assert "paths" not in body and "reachable" not in body


def test_dependency_paths_under_budget_still_returns_all_paths_sorted():
    repo, lock = layered_repo_lock(9, ["target"])
    r = query_paths(repo, lock, "target")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["reachable"] is True
    assert len(body["paths"]) == 512
    assert body["paths"] == sorted(body["paths"])
    assert body["paths"][0] == (
        ["app"] + [f"l{i}a" for i in range(1, 10)] + ["target"]
    )


def test_dependency_paths_limit_is_deterministic_across_input_ordering():
    """同一超限查询：包键/锁键重排后 409 响应逐字节一致。"""
    repo, lock = layered_repo_lock(10, ["target"])
    body1 = query_paths(repo, lock, "target").json()
    body2 = query_paths(
        dict(reversed(list(repo.items()))),
        dict(reversed(list(lock.items()))),
        "target",
    ).json()
    assert body1 == body2
    assert body1["used"] == 1001 and body1["limit"] == 1000


def test_dependency_paths_invalid_lock_still_invalid_lock_not_limit():
    """锁无效优先于路径预算：仍返回 409 invalid_lock，不执行路径查询。"""
    repo, lock = layered_repo_lock(10, ["target"])
    del lock["target"]  # target 可达但未锁定 -> missing
    r = query_paths(repo, lock, "target")
    assert r.status_code == 409
    body = r.json()
    assert body["status"] == "invalid_lock"
    assert body["issues"][0]["type"] == "missing"
    assert body["issues"][0]["name"] == "target"


# --------------------------------------------------------------------- #
# 3. POST /license-policy：命中包路径超限 409，按包名顺序命中首个
# --------------------------------------------------------------------- #
def test_license_policy_over_budget_409_limit_payload():
    repo, lock = layered_repo_lock(
        10, ["denied"], sink_metadata={"denied": {"license": "GPL-3.0-only"}}
    )
    r = query_policy(repo, lock)
    assert r.status_code == 409, r.text
    body = r.json()
    assert body["status"] == "limit"
    assert body["target"] == "denied"
    assert body["used"] == 1001
    assert body["limit"] == 1000
    assert "violations" not in body and "unknowns" not in body


def test_license_policy_first_exceeding_target_in_name_order():
    """多个命中包都超限时，按包名顺序稳定命中首个超限项。"""
    repo, lock = layered_repo_lock(
        10,
        ["denied-b", "denied-a"],
        sink_metadata={
            "denied-a": {"license": "GPL-3.0-only"},
            "denied-b": {"license": "GPL-3.0-only"},
        },
    )
    body = query_policy(repo, lock).json()
    assert body["status"] == "limit"
    assert body["target"] == "denied-a"  # denied-a < denied-b
    # 输入重排（声明顺序、锁键顺序）不改变命中的首个超限项。
    repo2, lock2 = layered_repo_lock(
        10,
        ["denied-a", "denied-b"],
        sink_metadata={
            "denied-a": {"license": "GPL-3.0-only"},
            "denied-b": {"license": "GPL-3.0-only"},
        },
    )
    body2 = query_policy(repo2, dict(reversed(list(lock2.items())))).json()
    assert body2 == body


def test_license_policy_unknown_license_over_budget_also_limit():
    """未提供许可证（unknown）的命中包同样受路径预算约束。"""
    repo, lock = layered_repo_lock(10, ["mystery"], sink_metadata={"mystery": {}})
    r = query_policy(repo, lock)
    assert r.status_code == 409
    body = r.json()
    assert body["status"] == "limit"
    assert body["target"] == "mystery"


def test_license_policy_under_budget_returns_all_paths():
    """未超限：命中包仍附全部最短路径，判定与排序不变。"""
    repo, lock = layered_repo_lock(
        9, ["denied"], sink_metadata={"denied": {"license": "GPL-3.0-only"}}
    )
    r = query_policy(repo, lock)
    assert r.status_code == 200, r.text
    body = r.json()
    assert [e["name"] for e in body["violations"]] == ["denied"]
    paths = body["violations"][0]["paths"]
    assert len(paths) == 512
    assert paths == sorted(paths)


# --------------------------------------------------------------------- #
# 4. POST /lock-diff：变化项路径超限 409，按既有包名顺序命中首个
# --------------------------------------------------------------------- #
def _diff_repo_and_locks(sinks):
    """before：app 1.0 -> helper；after：app 2.0 -> 10 层菱形 -> 各 sink。"""
    repo, after = layered_repo_lock(10, sinks)
    repo["app"] = [
        c("2.0", [d("l1a"), d("l1b")], license="MIT"),
        c("1.0", [d("helper")], license="MIT"),
    ]
    repo["helper"] = [c("1.0", license="MIT")]
    before = {"app": "1.0", "helper": "1.0"}
    after["app"] = "2.0"
    return repo, before, after


def test_lock_diff_added_package_over_budget_409():
    repo, before, after = _diff_repo_and_locks(["newpkg"])
    r = query_diff(repo, before, after)
    assert r.status_code == 409, r.text
    body = r.json()
    assert body["status"] == "limit"
    assert body["target"] == "newpkg"
    assert body["used"] == 1001
    assert body["limit"] == 1000
    assert "added" not in body and "removed" not in body


def test_lock_diff_first_exceeding_target_in_name_order():
    """多个变化项都超限时，按既有包名顺序稳定命中首个超限项。"""
    repo, before, after = _diff_repo_and_locks(["newpkg-b", "newpkg-a"])
    body = query_diff(repo, before, after).json()
    assert body["status"] == "limit"
    assert body["target"] == "newpkg-a"  # newpkg-a < newpkg-b


def test_lock_diff_upgraded_package_after_side_over_budget():
    """升降级项在 after 图中路径超限：before 侧正常、after 侧触发 409。"""
    repo, after = layered_repo_lock(10, ["shared"])
    repo["shared"] = [c("2.0", license="MIT"), c("1.0", license="MIT")]
    # before：app 1.0 直连 shared 1.0（单条路径）；after：app 2.0 经 10 层
    # 菱形到 shared 2.0（1024 条路径）。shared 两侧均可达且版本升高。
    repo["app"] = [
        c("2.0", [d("l1a"), d("l1b")], license="MIT"),
        c("1.0", [d("shared")], license="MIT"),
    ]
    before = {"app": "1.0", "shared": "1.0"}
    after["app"] = "2.0"
    after["shared"] = "2.0"
    r = query_diff(repo, before, after)
    assert r.status_code == 409, r.text
    body = r.json()
    assert body["status"] == "limit"
    assert body["target"] == "shared"


def test_lock_diff_under_budget_returns_all_paths():
    """未超限：变化项仍附前后图中的全部最短路径，分类与排序不变。"""
    repo, after = layered_repo_lock(9, ["newpkg"])
    repo["app"] = [
        c("2.0", [d("l1a"), d("l1b")], license="MIT"),
        c("1.0", [d("helper")], license="MIT"),
    ]
    repo["helper"] = [c("1.0", license="MIT")]
    before = {"app": "1.0", "helper": "1.0"}
    after["app"] = "2.0"
    r = query_diff(repo, before, after)
    assert r.status_code == 200, r.text
    body = r.json()
    added = {item["name"]: item for item in body["added"]}
    assert len(added["newpkg"]["after_paths"]) == 512
    assert added["newpkg"]["after_paths"] == sorted(added["newpkg"]["after_paths"])
    assert added["newpkg"]["before_paths"] == []
    assert [item["name"] for item in body["removed"]] == ["helper"]


def test_lock_diff_invalid_lock_still_invalid_lock_not_limit():
    """任一份锁无效优先于路径预算：仍返回 409 invalid_lock。"""
    repo, before, after = _diff_repo_and_locks(["newpkg"])
    del after["newpkg"]  # newpkg 可达但未锁定 -> missing
    r = query_diff(repo, before, after)
    assert r.status_code == 409
    body = r.json()
    assert body["status"] == "invalid_lock"
    assert body["after"]["valid"] is False
    assert body["after"]["issues"][0]["type"] == "missing"
