"""POST /resolve-matrix 路由层测试。"""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

LINUX_X64_PY311 = {
    "id": "linux-x64",
    "python_version": "3.11",
    "sys_platform": "linux",
    "platform_machine": "x86_64",
}
WIN_AMD64_PY39 = {
    "id": "win-amd64",
    "python_version": "3.9",
    "sys_platform": "win32",
    "platform_machine": "AMD64",
}
LINUX_ARM64_PY311 = {
    "id": "linux-arm64",
    "python_version": "3.11",
    "sys_platform": "linux",
    "platform_machine": "aarch64",
}


def matrix_payload(environments, **overrides):
    base = {
        "repository": {
            "app": [
                {"version": "1.0",
                 "dependencies": [
                     {"name": "shared-lib", "specifier": ">=1.0"},
                     {"name": "linux-only", "specifier": "",
                      "marker": "sys_platform == 'linux'"},
                     {"name": "win-only", "specifier": "",
                      "marker": "sys_platform == 'win32'"},
                 ]}
            ],
            "shared-lib": [
                {"version": "1.5"},
                {"version": "1.0"},
                {"version": "2.0rc1"},
            ],
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


def test_matrix_ok_shared_and_divergent_rows():
    r = client.post("/resolve-matrix", json=matrix_payload(
        [LINUX_X64_PY311, WIN_AMD64_PY39]))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "ok"
    assert body["root"] == "app"
    assert "root_version" not in body  # 根版本在每个 result 内（环境间可能不同）

    # results 按 id 排序：linux-x64 在 win-amd64 之前
    assert [e["id"] for e in body["results"]] == ["linux-x64", "win-amd64"]
    assert body["results"][0]["root_version"] == "1.0"
    assert body["results"][1]["root_version"] == "1.0"
    assert body["results"][0]["locked"] == {
        "app": "1.0", "linux-only": "1.0", "shared-lib": "1.5"
    }
    assert body["results"][1]["locked"] == {
        "app": "1.0", "shared-lib": "1.5", "win-only": "1.0"
    }

    rows = {row["name"]: row for row in body["matrix"]}
    # matrix 按包名排序
    assert [row["name"] for row in body["matrix"]] == sorted(rows)

    assert rows["app"] == {
        "name": "app",
        "versions": {"linux-x64": "1.0", "win-amd64": "1.0"},
        "state": "shared",
    }
    assert rows["shared-lib"] == {
        "name": "shared-lib",
        "versions": {"linux-x64": "1.5", "win-amd64": "1.5"},
        "state": "shared",
    }
    # 平台专属包：缺失环境为 null，状态 divergent
    assert rows["linux-only"]["versions"] == {
        "linux-x64": "1.0", "win-amd64": None
    }
    assert rows["linux-only"]["state"] == "divergent"
    assert rows["win-only"]["versions"] == {
        "linux-x64": None, "win-amd64": "1.0"
    }
    assert rows["win-only"]["state"] == "divergent"


def test_matrix_state_divergent_on_version_difference():
    """同包在两环境都存在但版本不同 -> divergent（非 null 版本差异）。"""
    repo = {
        "app": [
            {"version": "2.0",
             "dependencies": [
                 {"name": "modern", "marker": "python_version >= '3.10'",
                  "specifier": ""},
                 {"name": "modern", "marker": "python_version < '3.10'",
                  "specifier": "<3"},
             ]}
        ],
        "modern": [{"version": "3.0"}, {"version": "2.9"}],
    }
    r = client.post("/resolve-matrix", json=matrix_payload(
        [LINUX_X64_PY311, WIN_AMD64_PY39], repository=repo))
    assert r.status_code == 200, r.text
    rows = {row["name"]: row for row in r.json()["matrix"]}
    assert rows["modern"]["versions"] == {
        "linux-x64": "3.0", "win-amd64": "2.9"
    }
    assert rows["modern"]["state"] == "divergent"
    assert rows["app"]["state"] == "shared"


def test_matrix_results_sorted_by_id_independent_of_input_order():
    body_rev = client.post("/resolve-matrix", json=matrix_payload(
        [WIN_AMD64_PY39, LINUX_X64_PY311])).json()
    body_fwd = client.post("/resolve-matrix", json=matrix_payload(
        [LINUX_X64_PY311, WIN_AMD64_PY39])).json()
    assert [e["id"] for e in body_rev["results"]] == ["linux-x64", "win-amd64"]
    assert body_rev == body_fwd


def test_matrix_409_any_environment_conflict_lists_failure():
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
    r = client.post("/resolve-matrix", json=matrix_payload(
        [LINUX_X64_PY311, WIN_AMD64_PY39], repository=repo))
    assert r.status_code == 409, r.text
    body = r.json()
    assert body["status"] == "conflict"
    assert "win-amd64" in body["message"]
    assert len(body["failures"]) == 1
    failure = body["failures"][0]
    assert failure["id"] == "win-amd64"
    # 失败内容是该环境的原冲突结果（与 /resolve 的 409 同形）
    assert failure["status"] == "conflict"
    assert failure["conflicts"][0]["subject"] == "core"
    assert failure["conflicts"][0]["kind"] == "incompatible"
    # 成功环境的锁定清单不随 409 返回
    assert "results" not in body


def test_matrix_409_all_failing_environments_listed_sorted():
    """两个环境都无解时 failures 列出两者并按 id 排序。"""
    repo = {
        "app": [{"version": "1.0", "dependencies": [
            {"name": "core", "specifier": ">=99"},
        ]}],
        "core": [{"version": "1.0"}],
    }
    r = client.post("/resolve-matrix", json=matrix_payload(
        [WIN_AMD64_PY39, LINUX_X64_PY311, LINUX_ARM64_PY311], repository=repo))
    assert r.status_code == 409
    body = r.json()
    assert [f["id"] for f in body["failures"]] == [
        "linux-arm64", "linux-x64", "win-amd64"
    ]
    assert all(f["status"] == "conflict" for f in body["failures"])
    assert all(
        f["conflicts"][0]["subject"] == "core" for f in body["failures"]
    )


def test_matrix_three_environments_share_versions_matrix():
    r = client.post("/resolve-matrix", json=matrix_payload(
        [LINUX_X64_PY311, LINUX_ARM64_PY311, WIN_AMD64_PY39]))
    assert r.status_code == 200, r.text
    body = r.json()
    assert [e["id"] for e in body["results"]] == [
        "linux-arm64", "linux-x64", "win-amd64"
    ]
    # 两个 linux 环境的锁一致；win 不同
    linux_locks = {
        e["id"]: e["locked"]
        for e in body["results"] if e["id"].startswith("linux")
    }
    assert linux_locks["linux-arm64"] == linux_locks["linux-x64"]
    rows = {row["name"]: row for row in body["matrix"]}
    assert rows["shared-lib"]["versions"] == {
        "linux-arm64": "1.5", "linux-x64": "1.5", "win-amd64": "1.5"
    }
    assert rows["shared-lib"]["state"] == "shared"
    assert set(rows["linux-only"]["versions"]) == {
        "linux-arm64", "linux-x64", "win-amd64"
    }
    assert rows["linux-only"]["state"] == "divergent"


def test_matrix_too_few_environments_422():
    r = client.post("/resolve-matrix", json=matrix_payload([LINUX_X64_PY311]))
    assert r.status_code == 422


def test_matrix_too_many_environments_422():
    envs = [
        {**LINUX_X64_PY311, "id": f"env-{i}"} for i in range(9)
    ]
    r = client.post("/resolve-matrix", json=matrix_payload(envs))
    assert r.status_code == 422


def test_matrix_duplicate_id_422():
    r = client.post("/resolve-matrix", json=matrix_payload(
        [LINUX_X64_PY311, {**LINUX_ARM64_PY311, "id": "linux-x64"}]))
    assert r.status_code == 422
    assert r.json()["status"] == "invalid_snapshot"
    assert "linux-x64" in r.json()["message"]


def test_matrix_invalid_id_pattern_422():
    bad = {**LINUX_X64_PY311, "id": "bad id!"}
    r = client.post("/resolve-matrix", json=matrix_payload(
        [bad, WIN_AMD64_PY39]))
    assert r.status_code == 422


def test_matrix_empty_id_422():
    bad = {**LINUX_X64_PY311, "id": ""}
    r = client.post("/resolve-matrix", json=matrix_payload(
        [bad, WIN_AMD64_PY39]))
    assert r.status_code == 422


def test_matrix_unknown_root_422():
    r = client.post("/resolve-matrix",
                    json=matrix_payload([LINUX_X64_PY311, WIN_AMD64_PY39],
                                        root="missing"))
    assert r.status_code == 422
    assert r.json()["status"] == "invalid_snapshot"


def test_matrix_bad_snapshot_422():
    repo = {"app": [{"version": "oops", "dependencies": []}]}
    r = client.post("/resolve-matrix", json=matrix_payload(
        [LINUX_X64_PY311, WIN_AMD64_PY39], repository=repo))
    assert r.status_code == 422
    assert "PEP 440" in r.json()["message"]


def test_matrix_bad_environment_value_422():
    bad = {**LINUX_X64_PY311, "python_version": "not-a-version"}
    r = client.post("/resolve-matrix", json=matrix_payload(
        [bad, WIN_AMD64_PY39]))
    assert r.status_code == 422
    assert "python_version" in r.json()["message"]


def test_matrix_extra_field_forbidden_422():
    r = client.post("/resolve-matrix", json=matrix_payload(
        [LINUX_X64_PY311, WIN_AMD64_PY39], unknown_field=1))
    assert r.status_code == 422


def test_matrix_allow_prereleases_applies_per_resolution():
    r1 = client.post("/resolve-matrix", json=matrix_payload(
        [LINUX_X64_PY311, WIN_AMD64_PY39]))
    assert all(
        "2.0rc1" not in e["locked"].values() for e in r1.json()["results"]
    )
    r2 = client.post("/resolve-matrix", json=matrix_payload(
        [LINUX_X64_PY311, WIN_AMD64_PY39], allow_prereleases=True))
    assert all(
        e["locked"]["shared-lib"] == "2.0rc1" for e in r2.json()["results"]
    )


def test_matrix_each_environment_uses_own_marker_activation():
    """环境值只影响自己的求解：linux-only/win-only 按各自环境出现。"""
    body = client.post("/resolve-matrix", json=matrix_payload(
        [LINUX_X64_PY311, WIN_AMD64_PY39])).json()
    locked = {e["id"]: e["locked"] for e in body["results"]}
    assert "linux-only" in locked["linux-x64"]
    assert "linux-only" not in locked["win-amd64"]
    assert "win-only" in locked["win-amd64"]
    assert "win-only" not in locked["linux-x64"]


def test_matrix_root_version_can_diverge_per_environment():
    """环境相关回溯可能让根版本不同：各自 root_version 不同，matrix 标 divergent。"""
    repo = {
        "app": [
            {"version": "2.0", "dependencies": [
                {"name": "win-bad", "specifier": "==99",
                 "marker": "sys_platform == 'win32'"}]},
            {"version": "1.0", "dependencies": []},
        ],
        "win-bad": [{"version": "1.0"}],
    }
    r = client.post("/resolve-matrix", json=matrix_payload(
        [LINUX_X64_PY311, WIN_AMD64_PY39], repository=repo))
    assert r.status_code == 200, r.text
    body = r.json()
    root_versions = {e["id"]: e["root_version"] for e in body["results"]}
    assert root_versions == {"linux-x64": "2.0", "win-amd64": "1.0"}
    app_row = next(row for row in body["matrix"] if row["name"] == "app")
    assert app_row["versions"] == {
        "linux-x64": "2.0", "win-amd64": "1.0"
    }
    assert app_row["state"] == "divergent"
    # win-bad 只在 win 环境（随 app 1.0 未激活而缺失）：两环境都没有它
    assert all("win-bad" not in e["locked"] for e in body["results"])
