"""POST /lock-diff 的端到端测试。

覆盖：两份锁各自独立审计的 409 短路（before/after 分别标注、两份同时
无效时问题都返回）、added/removed/upgraded/downgraded 分类、PEP 440
版本方向（1.0 与 1.0.0 等价不产生变化）、每个变化项在前后图中的全部
最短根路径（菱形等长路径、不存在一侧为空数组）、根包自身升降级、
marker 激活语义、PEP 503 规范化名，以及与输入顺序无关的确定性和
422 校验。
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


def diff(repo, before, after, *, root="app", env=None, **overrides):
    body = {
        "repository": repo,
        "root": root,
        "target_environment": env or ENV,
        "before_lock": before,
        "after_lock": after,
    }
    body.update(overrides)
    return client.post("/lock-diff", json=body)


def diff_ok(repo, before, after, **kw):
    r = diff(repo, before, after, **kw)
    assert r.status_code == 200, r.text
    return r.json()


def names(items):
    return [item["name"] for item in items]


# --------------------------------------------------------------------- #
# 1. 基础：added / removed / upgraded / downgraded 分类与路径
# --------------------------------------------------------------------- #
def test_all_four_change_kinds_classified_with_paths():
    repo = {
        "app": [c("1.0", [d("web"), d("auth"), d("keep")])],
        "web": [
            c("2.0", [d("gone")]),
            c("1.0", [d("fresh")]),
        ],
        "auth": [
            c("2.0", [d("shared", ">=2.0")]),
            c("1.0", [d("shared", "<2.0")]),
        ],
        "keep": [c("2.0"), c("1.0")],
        "shared": [c("2.0"), c("1.0")],
        "gone": [c("1.0")],
        "fresh": [c("1.0")],
    }
    before = {
        "app": "1.0", "web": "2.0", "auth": "2.0", "keep": "2.0",
        "shared": "2.0", "gone": "1.0",
    }
    after = {
        "app": "1.0", "web": "1.0", "auth": "1.0", "keep": "1.0",
        "shared": "1.0", "fresh": "1.0",
    }
    body = diff_ok(repo, before, after)
    assert body["status"] == "ok"
    assert body["root"] == "app"

    assert names(body["added"]) == ["fresh"]
    added = body["added"][0]
    assert added["before_version"] is None
    assert added["after_version"] == "1.0"
    assert added["before_paths"] == []
    assert added["after_paths"] == [["app", "web", "fresh"]]

    assert names(body["removed"]) == ["gone"]
    removed = body["removed"][0]
    assert removed["before_version"] == "1.0"
    assert removed["after_version"] is None
    assert removed["before_paths"] == [["app", "web", "gone"]]
    assert removed["after_paths"] == []

    assert names(body["downgraded"]) == ["auth", "keep", "shared", "web"]
    assert body["upgraded"] == []

    shared_down = next(i for i in body["downgraded"] if i["name"] == "shared")
    assert (shared_down["before_version"], shared_down["after_version"]) == (
        "2.0", "1.0",
    )


def test_upgrade_direction_uses_pep440():
    repo = {
        "app": [c("1.0", [d("lib")])],
        "lib": [c("2.0"), c("1.0")],
    }
    body = diff_ok(repo, {"app": "1.0", "lib": "1.0"},
                   {"app": "1.0", "lib": "2.0"})
    assert names(body["upgraded"]) == ["lib"]
    assert body["downgraded"] == []
    entry = body["upgraded"][0]
    assert entry["before_paths"] == [["app", "lib"]]
    assert entry["after_paths"] == [["app", "lib"]]


def test_pep440_equivalent_versions_produce_no_change():
    """1.0 与 1.0.0 在 PEP 440 下等价：不产生变化项。"""
    repo = {
        "app": [c("1.0", [d("lib")])],
        "lib": [c("1.0.0")],
    }
    body = diff_ok(repo, {"app": "1.0", "lib": "1.0.0"},
                   {"app": "1.0", "lib": "1.0"})
    assert body["added"] == body["removed"] == []
    assert body["upgraded"] == body["downgraded"] == []


def test_root_package_itself_can_upgrade_and_downgrade():
    repo = {
        "app": [c("2.0"), c("1.0")],
    }
    up = diff_ok(repo, {"app": "1.0"}, {"app": "2.0"})
    assert names(up["upgraded"]) == ["app"]
    assert up["upgraded"][0]["before_paths"] == [["app"]]
    assert up["upgraded"][0]["after_paths"] == [["app"]]

    down = diff_ok(repo, {"app": "2.0"}, {"app": "1.0"})
    assert names(down["downgraded"]) == ["app"]


def test_identical_locks_have_no_changes():
    repo = {
        "app": [c("1.0", [d("a"), d("b")])],
        "a": [c("1.0")],
        "b": [c("1.0", [d("a")])],
    }
    lock = {"app": "1.0", "a": "1.0", "b": "1.0"}
    body = diff_ok(repo, lock, dict(lock))
    assert body == {
        "status": "ok", "root": "app",
        "added": [], "removed": [], "upgraded": [], "downgraded": [],
    }


# --------------------------------------------------------------------- #
# 2. 路径：菱形等长路径在两侧分别给出，按字典序排序
# --------------------------------------------------------------------- #
def test_diamond_shortest_paths_on_both_sides():
    repo = {
        "app": [c("1.0", [d("left"), d("right")])],
        "left": [
            c("2.0", [d("shared")]),
            c("1.0", [d("shared")]),
        ],
        "right": [c("1.0", [d("shared")])],
        "shared": [c("2.0"), c("1.0")],
    }
    before = {"app": "1.0", "left": "1.0", "right": "1.0", "shared": "1.0"}
    after = {"app": "1.0", "left": "2.0", "right": "1.0", "shared": "2.0"}
    body = diff_ok(repo, before, after)
    assert names(body["upgraded"]) == ["left", "shared"]
    shared = next(i for i in body["upgraded"] if i["name"] == "shared")
    expected = [
        ["app", "left", "shared"],
        ["app", "right", "shared"],
    ]
    assert shared["before_paths"] == expected
    assert shared["after_paths"] == expected


def test_path_shape_changes_between_sides():
    """同一包两侧都在，但它在两张图中的最短路径形态可以不同。"""
    repo = {
        "app": [
            c("1.0", [d("direct"), d("mid")]),
        ],
        "direct": [
            c("2.0"),
            c("1.0", [d("target")]),
        ],
        "mid": [c("1.0", [d("target")])],
        "target": [c("1.0")],
    }
    # before: target 仅经 mid 到达（direct 1.0 也依赖它，构成菱形）
    before = {
        "app": "1.0", "direct": "1.0", "mid": "1.0", "target": "1.0",
    }
    # after: direct 升到 2.0 后不再依赖 target，只剩 app -> mid -> target
    after = {
        "app": "1.0", "direct": "2.0", "mid": "1.0", "target": "1.0",
    }
    body = diff_ok(repo, before, after)
    all_entries = (
        body["added"] + body["removed"]
        + body["upgraded"] + body["downgraded"]
    )
    # target 两侧均在且版本未变：路径形态变化（菱形 → 单路径）不产生变化项。
    assert all(i["name"] != "target" for i in all_entries)
    direct = next(i for i in body["upgraded"] if i["name"] == "direct")
    assert direct["before_paths"] == [["app", "direct"]]
    assert direct["after_paths"] == [["app", "direct"]]


# --------------------------------------------------------------------- #
# 3. 409：两份锁各自独立审计，before/after 分别标注
# --------------------------------------------------------------------- #
def test_invalid_before_lock_returns_409_labelled():
    repo = {
        "app": [c("1.0", [d("req")])],
        "req": [c("1.0")],
        "extra": [c("1.0")],
    }
    valid = {"app": "1.0", "req": "1.0"}
    invalid_before = {"app": "1.0", "req": "1.0", "extra": "1.0"}
    r = diff(repo, invalid_before, valid)
    assert r.status_code == 409, r.text
    body = r.json()
    assert body["status"] == "invalid_lock"
    assert "before_lock" in body["message"]
    assert body["before"]["valid"] is False
    assert [(i["type"], i["name"]) for i in body["before"]["issues"]] == [
        ("extraneous", "extra"),
    ]
    assert body["after"] == {"valid": True, "issues": []}
    # 409 不返回任何比较结果。
    assert "added" not in body and "upgraded" not in body


def test_invalid_after_lock_returns_409_labelled():
    repo = {
        "app": [c("1.0", [d("req", ">=2.0")])],
        "req": [c("2.0"), c("1.0")],
    }
    valid = {"app": "1.0", "req": "2.0"}
    invalid_after = {"app": "1.0", "req": "1.0"}
    r = diff(repo, valid, invalid_after)
    assert r.status_code == 409
    body = r.json()
    assert "after_lock" in body["message"]
    assert body["before"] == {"valid": True, "issues": []}
    assert body["after"]["valid"] is False
    assert body["after"]["issues"][0]["type"] == "constraint_mismatch"
    assert body["after"]["issues"][0]["name"] == "req"


def test_both_locks_invalid_reports_both_sides():
    repo = {
        "app": [c("1.0", [d("need")])],
        "need": [c("1.0")],
    }
    # before: need 缺失（missing）；after: 锁了快照中没有的 ghost（extraneous）
    before = {"app": "1.0"}
    after = {"app": "1.0", "ghost": "1.0"}
    r = diff(repo, before, after)
    assert r.status_code == 409
    body = r.json()
    assert "before_lock" in body["message"] and "after_lock" in body["message"]
    assert [(i["type"], i["name"]) for i in body["before"]["issues"]] == [
        ("missing", "need"),
    ]
    assert [(i["type"], i["name"]) for i in body["after"]["issues"]] == [
        ("missing", "need"),
        ("extraneous", "ghost"),
    ]


def test_409_issues_match_audit_lock_endpoint_for_each_side():
    """各侧 409 的 issues 必须与 /audit-lock 逐字节一致。"""
    repo = {
        "app": [c("1.0", [d("libx")])],
        "libx": [c("1.0"), c("2.0")],
    }
    valid = {"app": "1.0", "libx": "1.0"}
    invalid = {"app": "1.0", "libx": "3.0"}
    body = diff(repo, invalid, valid).json()

    audit = client.post("/audit-lock", json={
        "repository": repo, "root": "app", "target_environment": ENV,
        "current_lock": invalid,
    }).json()
    assert body["before"]["issues"] == audit["issues"]


# --------------------------------------------------------------------- #
# 4. marker：同一目标环境对两份锁同时生效
# --------------------------------------------------------------------- #
def test_marker_active_dependency_counts_as_reachable():
    repo = {
        "app": [c("1.0", [d("linux-thing", marker="sys_platform == 'linux'")])],
        "linux-thing": [c("2.0"), c("1.0")],
    }
    before = {"app": "1.0", "linux-thing": "1.0"}
    after = {"app": "1.0", "linux-thing": "2.0"}
    body = diff_ok(repo, before, after, env=ENV)
    assert names(body["upgraded"]) == ["linux-thing"]

    # win32 下该依赖未激活：两份锁都把 linux-thing 判为 extraneous -> 409。
    r = diff(repo, before, after, env=WIN_ENV)
    assert r.status_code == 409
    sides = r.json()
    assert all(
        (i["type"], i["name"]) == ("extraneous", "linux-thing")
        for i in sides["before"]["issues"] + sides["after"]["issues"]
    )


# --------------------------------------------------------------------- #
# 5. 规范化与确定性
# --------------------------------------------------------------------- #
def test_pep503_name_normalization_in_locks_and_root():
    repo = {
        "App": [c("1.0", [d("Some_Lib")])],
        "some.lib": [c("2.0"), c("1.0")],
    }
    before = {"APP": "1.0", "Some.Lib": "1.0"}
    after = {"app": "1.0", "some-lib": "2.0"}
    body = diff_ok(repo, before, after, root="App")
    assert body["root"] == "app"
    up = body["upgraded"][0]
    assert up["name"] == "some-lib"
    assert up["before_paths"] == [["app", "some-lib"]]
    assert up["after_paths"] == [["app", "some-lib"]]


def test_result_independent_of_input_ordering():
    repo = {
        "app": [c("1.0", [d("zz"), d("aa")])],
        "zz": [c("2.0"), c("1.0")],
        "aa": [c("2.0"), c("1.0")],
    }
    before = {"zz": "1.0", "app": "1.0", "aa": "1.0"}
    after = {"aa": "2.0", "zz": "2.0", "app": "1.0"}
    body1 = diff_ok(repo, before, after)
    body2 = diff_ok(
        dict(reversed(list(repo.items()))),
        dict(reversed(list(before.items()))),
        dict(reversed(list(after.items()))),
        root="app",
    )
    assert body1 == body2
    assert names(body1["upgraded"]) == ["aa", "zz"]
    # 调换 before/after 提交顺序：upgraded 与 downgraded 互换、结果对称。
    swapped = diff_ok(repo, after, before)
    assert names(swapped["downgraded"]) == ["aa", "zz"]
    assert swapped["upgraded"] == []


# --------------------------------------------------------------------- #
# 6. 422：非法快照 / 锁 / 根包 / 字段
# --------------------------------------------------------------------- #
def test_bad_snapshot_422():
    r = diff({"app": [c("oops")]}, {"app": "1.0"}, {"app": "1.0"})
    assert r.status_code == 422
    assert r.json()["status"] == "invalid_snapshot"


def test_bad_before_lock_version_422():
    r = diff({"app": [c("1.0")]}, {"app": "nope"}, {"app": "1.0"})
    assert r.status_code == 422
    assert "before_lock" in r.json()["message"]
    assert "PEP 440" in r.json()["message"]


def test_bad_after_lock_version_422():
    r = diff({"app": [c("1.0")]}, {"app": "1.0"}, {"app": "nope"})
    assert r.status_code == 422
    assert "after_lock" in r.json()["message"]
    assert "PEP 440" in r.json()["message"]


def test_unknown_root_422():
    r = diff({"app": [c("1.0")]}, {"app": "1.0"}, {"app": "1.0"}, root="missing")
    assert r.status_code == 422
    assert "missing" in r.json()["message"]


def test_missing_lock_field_422():
    body = {
        "repository": {"app": [c("1.0")]},
        "root": "app",
        "target_environment": ENV,
        "before_lock": {"app": "1.0"},
    }
    assert client.post("/lock-diff", json=body).status_code == 422
    body["after_lock"] = {"app": "1.0"}
    del body["before_lock"]
    assert client.post("/lock-diff", json=body).status_code == 422


def test_extra_field_forbidden_422():
    r = diff(
        {"app": [c("1.0")]}, {"app": "1.0"}, {"app": "1.0"}, unknown=1,
    )
    assert r.status_code == 422


def test_existing_endpoints_still_reject_lock_diff_fields():
    """既有接口保持兼容：/audit-lock 不接受 before_lock/after_lock。"""
    r = client.post("/audit-lock", json={
        "repository": {"app": [c("1.0")]},
        "root": "app",
        "target_environment": ENV,
        "before_lock": {"app": "1.0"},
        "after_lock": {"app": "1.0"},
    })
    assert r.status_code == 422
