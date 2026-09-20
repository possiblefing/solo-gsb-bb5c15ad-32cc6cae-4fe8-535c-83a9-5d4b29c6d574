"""POST /lock-groups 路由层测试。"""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app
from app.lock_groups import CandidateLock, lock_group_id, select_lock_groups

client = TestClient(app)

LINUX_X64 = {
    "id": "linux-x64",
    "python_version": "3.11",
    "sys_platform": "linux",
    "platform_machine": "x86_64",
}
WIN_AMD64 = {
    "id": "win-amd64",
    "python_version": "3.11",
    "sys_platform": "win32",
    "platform_machine": "AMD64",
}
MAC_ARM64 = {
    "id": "mac-arm64",
    "python_version": "3.11",
    "sys_platform": "darwin",
    "platform_machine": "arm64",
}


def groups_payload(environments, *, repository=None, **overrides):
    base = {
        "repository": repository
        or {
            "app": [
                {"version": "1.0",
                 "dependencies": [
                     {"name": "shared-lib", "specifier": ">=1.0"},
                     {"name": "linux-only",
                      "marker": "sys_platform == 'linux'"},
                     {"name": "win-only",
                      "marker": "sys_platform == 'win32'"},
                 ]}
            ],
            "shared-lib": [{"version": "1.5"}, {"version": "1.0"}],
            "linux-only": [{"version": "1.0"}],
            "win-only": [{"version": "1.0"}],
        },
        "root": "app",
        "specifier": "",
        "allow_prereleases": False,
        "target_environments": environments,
    }
    base.update(overrides)
    return base


def test_lock_groups_distinct_environment_specific_locks():
    r = client.post("/lock-groups", json=groups_payload([LINUX_X64, WIN_AMD64]))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "ok"
    assert body["root"] == "app"

    by_env: dict[str, dict] = {}
    assert len(body["groups"]) == 2
    for group in body["groups"]:
        assert set(group) == {"id", "environments", "locked"}
        assert group["id"].startswith("lg-")
        assert len(group["id"]) == len("lg-") + 12
        for env_id in group["environments"]:
            by_env[env_id] = group["locked"]

    # 平台专属锁互不为对方环境审计通过（包集不同 -> missing/extraneous），
    # 因此每个锁只覆盖自己的来源环境。
    assert by_env["linux-x64"] == {
        "app": "1.0", "linux-only": "1.0", "shared-lib": "1.5"
    }
    assert by_env["win-amd64"] == {
        "app": "1.0", "shared-lib": "1.5", "win-only": "1.0"
    }

    # groups 按稳定组 id 排序
    ids = [g["id"] for g in body["groups"]]
    assert ids == sorted(ids)
    # 每组 locked 按包名排序
    for group in body["groups"]:
        names = list(group["locked"])
        assert names == sorted(names)


def test_lock_groups_shared_lock_covers_multiple_environments():
    """非 linux 平台锁内容相同：去重后一份锁同时覆盖 win 与 mac。"""
    repo = {
        "app": [
            {"version": "2.0.0", "dependencies": [
                {"name": "std-kit", "specifier": ""},
                {"name": "posix-plugin",
                 "marker": "sys_platform != 'linux'"},
                {"name": "unix-plugin", "specifier": ">=2.0",
                 "marker": "sys_platform == 'linux'"},
            ]}
        ],
        "std-kit": [{"version": "1.0.0"}],
        "posix-plugin": [{"version": "1.0.0"}],
        "unix-plugin": [{"version": "2.1.0"}, {"version": "2.0.0"}],
    }
    r = client.post("/lock-groups", json=groups_payload(
        [LINUX_X64, WIN_AMD64, MAC_ARM64], repository=repo))
    assert r.status_code == 200, r.text
    groups = r.json()["groups"]

    # 最少锁文件：posix-plugin 锁一份覆盖 win+mac，unix-plugin 锁覆盖 linux。
    assert len(groups) == 2
    coverage = {tuple(g["environments"]): g["locked"] for g in groups}
    assert ("linux-x64",) in coverage
    assert ("mac-arm64", "win-amd64") in coverage
    assert coverage[("linux-x64",)] == {
        "app": "2.0.0", "std-kit": "1.0.0", "unix-plugin": "2.1.0"
    }
    assert coverage[("mac-arm64", "win-amd64")] == {
        "app": "2.0.0", "posix-plugin": "1.0.0", "std-kit": "1.0.0"
    }
    # 每组 environments 按 id 排序
    for group in groups:
        assert group["environments"] == sorted(group["environments"])


def test_lock_groups_lower_lock_covers_unconstrained_environment():
    """低版本锁在无约束环境同样通过审计时，单份锁即可覆盖全部环境。"""
    repo = {
        "app": [{"version": "1.0", "dependencies": [
            {"name": "core", "specifier": ""},
            {"name": "core", "specifier": "<2",
             "marker": "sys_platform == 'linux'"},
            {"name": "core", "specifier": "<2",
             "marker": "sys_platform == 'win32'"},
        ]}],
        "core": [{"version": "2.0"}, {"version": "1.0"}],
    }
    r = client.post("/lock-groups", json=groups_payload(
        [MAC_ARM64, LINUX_X64, WIN_AMD64], repository=repo))
    assert r.status_code == 200, r.text
    groups = r.json()["groups"]
    # core==1.0 锁在三个环境均无审计问题，最小覆盖只需 1 份锁文件。
    assert len(groups) == 1
    assert groups[0]["environments"] == [
        "linux-x64", "mac-arm64", "win-amd64"
    ]
    assert groups[0]["locked"] == {"app": "1.0", "core": "1.0"}


def test_lock_groups_deterministic_under_input_reordering():
    """环境提交顺序变化不改变响应（组 id 与组序均由内容决定）。"""
    payload_fwd = groups_payload([LINUX_X64, WIN_AMD64])
    payload_rev = groups_payload([WIN_AMD64, LINUX_X64])
    body_fwd = client.post("/lock-groups", json=payload_fwd).json()
    body_rev = client.post("/lock-groups", json=payload_rev).json()
    assert body_fwd == body_rev


def test_lock_groups_group_id_is_content_fingerprint():
    r = client.post("/lock-groups", json=groups_payload([LINUX_X64, WIN_AMD64]))
    groups = r.json()["groups"]
    # 组 id 只取决于锁内容：与对同一份锁单独计算的内容指纹一致。
    for group in groups:
        assert group["id"] == lock_group_id(group["locked"])
    # 锁字典输入顺序不影响指纹
    lock = {"app": "1.0", "shared-lib": "1.5"}
    assert lock_group_id(lock) == lock_group_id(
        dict(reversed(list(lock.items())))
    )


def test_lock_groups_409_conflict_keeps_source_chains():
    repo = {
        "app": [{"version": "1.0", "dependencies": [
            {"name": "left", "specifier": ""},
            {"name": "right", "specifier": "",
             "marker": "sys_platform == 'win32'"},
        ]}],
        "left": [{"version": "1.0",
                  "dependencies": [{"name": "core", "specifier": "==1.0"}]}],
        "right": [{"version": "1.0",
                   "dependencies": [{"name": "core", "specifier": "==2.0"}]}],
        "core": [{"version": "1.0"}, {"version": "2.0"}],
    }
    r = client.post("/lock-groups", json=groups_payload(
        [LINUX_X64, WIN_AMD64], repository=repo))
    assert r.status_code == 409, r.text
    body = r.json()
    assert body["status"] == "conflict"
    assert "win-amd64" in body["message"]
    assert len(body["failures"]) == 1
    failure = body["failures"][0]
    assert failure["id"] == "win-amd64"
    assert failure["status"] == "conflict"
    # 保留该环境的冲突来源链（与 /resolve 409 同形）
    conflict = failure["conflicts"][0]
    assert conflict["subject"] == "core"
    assert conflict["kind"] == "incompatible"
    assert len(conflict["constraints"]) == 2
    assert "groups" not in body


def test_lock_groups_409_all_failing_environments_sorted():
    repo = {
        "app": [{"version": "1.0", "dependencies": [
            {"name": "core", "specifier": ">=99"},
        ]}],
        "core": [{"version": "1.0"}],
    }
    r = client.post("/lock-groups", json=groups_payload(
        [WIN_AMD64, LINUX_X64, MAC_ARM64], repository=repo))
    assert r.status_code == 409
    assert [f["id"] for f in r.json()["failures"]] == [
        "linux-x64", "mac-arm64", "win-amd64"
    ]


def test_lock_groups_too_few_environments_422():
    r = client.post("/lock-groups", json=groups_payload([LINUX_X64]))
    assert r.status_code == 422


def test_lock_groups_too_many_environments_422():
    envs = [{**LINUX_X64, "id": f"env-{i}"} for i in range(9)]
    r = client.post("/lock-groups", json=groups_payload(envs))
    assert r.status_code == 422


def test_lock_groups_duplicate_id_422():
    r = client.post("/lock-groups", json=groups_payload(
        [LINUX_X64, {**WIN_AMD64, "id": "linux-x64"}]))
    assert r.status_code == 422
    body = r.json()
    assert body["status"] == "invalid_snapshot"
    assert "linux-x64" in body["message"]


def test_lock_groups_invalid_snapshot_422():
    repo = {"app": [{"version": "oops"}]}
    r = client.post("/lock-groups", json=groups_payload(
        [LINUX_X64, WIN_AMD64], repository=repo))
    assert r.status_code == 422
    assert "PEP 440" in r.json()["message"]


def test_lock_groups_unknown_root_422():
    r = client.post("/lock-groups",
                    json=groups_payload([LINUX_X64, WIN_AMD64], root="ghost"))
    assert r.status_code == 422
    assert r.json()["status"] == "invalid_snapshot"


def test_lock_groups_extra_field_forbidden_422():
    r = client.post("/lock-groups", json=groups_payload(
        [LINUX_X64, WIN_AMD64], surprise=1))
    assert r.status_code == 422


# --------------------------------------------------------------------- #
# select_lock_groups：精确最小集合覆盖与稳定裁决（直接单元测试）
# --------------------------------------------------------------------- #
def _cand(locked: dict[str, str], *covers: str) -> CandidateLock:
    return CandidateLock(locked=locked, covers=frozenset(covers))


def test_select_minimum_set_cover():
    a = _cand({"p": "1"}, "e1", "e2")
    b = _cand({"p": "2"}, "e2", "e3")
    c = _cand({"p": "3"}, "e3")
    picked = select_lock_groups([a, b, c], ["e1", "e2", "e3"])
    assert picked == [a, b]


def test_select_prefers_fewer_locks_over_more():
    a = _cand({"p": "1"}, "e1")
    b = _cand({"p": "2"}, "e2")
    big = _cand({"p": "9"}, "e1", "e2")
    picked = select_lock_groups([a, b, big], ["e1", "e2"])
    assert picked == [big]


def test_select_tie_break_by_lock_content_and_env_id_stable_order():
    """两份锁都能单独覆盖全部环境：并列时按锁内容稳定序取内容较小者。"""
    lower = _cand({"pkg": "1.0"}, "e1", "e2")
    higher = _cand({"pkg": "2.0"}, "e1", "e2")
    assert select_lock_groups([higher, lower], ["e1", "e2"]) == [lower]
    assert select_lock_groups([lower, higher], ["e2", "e1"]) == [lower]

    # 内容序比较是逐 (包名, 版本) 对的字典序：包名次序优先于版本。
    a_lock = _cand({"a": "9", "z": "1"}, "e1")
    z_lock = _cand({"a": "1", "z": "1"}, "e2")
    combo = _cand({"a": "1", "z": "1", "extra": "1"}, "e1", "e2")
    # 两锁方案 {a_lock, z_lock} 与单锁 combo 都是 2 份/1 份——单锁更少
    assert select_lock_groups(
        [a_lock, z_lock, combo], ["e1", "e2"]
    ) == [combo]


def test_select_tie_break_env_assignment_order():
    """同尺寸并列：按每个环境（id 升序）由内容序最靠前的可覆盖锁负责裁决。

    每个环境恰有两份互不可覆盖对方的候选锁（内容序 l1 < l2 < r1 < r2），
    任一左锁 + 任一右锁都构成 2 份锁的并列最优覆盖；e1 列恒取最靠前的 l1，
    e2 列在 l1 选定后取最靠前的 r1，故结果为 {l1, r1}。
    """
    l1 = _cand({"l": "1"}, "e1")
    l2 = _cand({"l": "2"}, "e1")
    r1 = _cand({"r": "1"}, "e2")
    r2 = _cand({"r": "2"}, "e2")
    expected = [l1, r1]
    assert select_lock_groups([r2, l2, r1, l1], ["e1", "e2"]) == expected
    # 与输入顺序、环境 id 排列无关
    assert select_lock_groups([l2, r2, l1, r1], ["e2", "e1"]) == expected


def test_select_input_order_independent():
    a = _cand({"p": "1"}, "e1", "e2")
    b = _cand({"p": "2"}, "e2", "e3")
    c = _cand({"p": "3"}, "e3")
    first = select_lock_groups([c, a, b], ["e3", "e1", "e2"])
    second = select_lock_groups([b, c, a], ["e1", "e2", "e3"])
    assert first == second == [a, b]
