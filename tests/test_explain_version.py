"""POST /explain-version 的端到端测试。

覆盖：基准锁求解、目标包不可达 422、反事实可行时的 added/removed/changed、
反事实无解时 409 复用约束来源链、包名规范化、marker、预发布与排序/确定性
语义，以及 /resolve 行为不变。
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


def c(version, deps=None):
    return {"version": version, "dependencies": deps or []}


def d(name, spec="", marker=""):
    return {"name": name, "specifier": spec, "marker": marker}


def explain(repo, target_package, target_version, *, env=None, **overrides):
    body = {
        "repository": repo,
        "root": "app",
        "target_environment": env or ENV,
        "target_package": target_package,
        "target_version": target_version,
    }
    body.update(overrides)
    return client.post("/explain-version", json=body)


# 与 examples/lock-diff.json 相同的快照：基准锁含 telemetry-lib，
# 强制 web-framework==2.4.0 后改拉 legacy-helper。
def diamond_repo():
    return {
        "app": [c("1.0.0", [d("web-framework", ">=2.0"), d("auth-lib")])],
        "web-framework": [
            c("3.2.0", [d("shared-util", ">=1.0,<3.0"), d("telemetry-lib")]),
            c("2.4.0", [d("shared-util", ">=1.0,<2.0"), d("legacy-helper")]),
        ],
        "auth-lib": [
            c("1.1.0", [d("shared-util", ">=1.5"), d("json-tool", "<2.0")]),
            c("0.9.0", [d("shared-util", "<2.0")]),
        ],
        "shared-util": [c("2.0.0"), c("1.5.0"), c("1.4.0")],
        "telemetry-lib": [c("1.0.0")],
        "legacy-helper": [c("0.5.0")],
        "json-tool": [c("2.0.0"), c("1.0.0")],
    }


# --------------------------------------------------------------------- #
# 1. 基本反事实求解：基准锁 + added/removed/changed
# --------------------------------------------------------------------- #
def test_explain_basic_downgrade_with_add_remove_change():
    r = explain(diamond_repo(), "web-framework", "2.4.0")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "ok"
    assert body["root"] == "app"
    assert body["root_version"] == "1.0.0"
    assert body["target_package"] == "web-framework"
    assert body["target_version"] == "2.4.0"
    # 基准锁与 /resolve 在同一快照下的输出一致
    baseline = {
        "app": "1.0.0",
        "auth-lib": "1.1.0",
        "json-tool": "1.0.0",
        "shared-util": "2.0.0",
        "telemetry-lib": "1.0.0",
        "web-framework": "3.2.0",
    }
    assert body["baseline_locked"] == baseline
    r_resolve = client.post("/resolve", json={
        "repository": diamond_repo(), "root": "app", "target_environment": ENV,
    })
    assert r_resolve.json()["locked"] == baseline
    # 反事实锁：web-framework 降到 2.4.0，shared-util 随之降到 1.5.0，
    # telemetry-lib 被移除，legacy-helper 被引入
    assert body["locked"] == {
        "app": "1.0.0",
        "auth-lib": "1.1.0",
        "json-tool": "1.0.0",
        "legacy-helper": "0.5.0",
        "shared-util": "1.5.0",
        "web-framework": "2.4.0",
    }
    assert body["added"] == [{"name": "legacy-helper", "version": "0.5.0"}]
    assert body["removed"] == [{"name": "telemetry-lib", "version": "1.0.0"}]
    assert body["changed"] == [
        {"name": "shared-util", "from": "2.0.0", "to": "1.5.0"},
        {"name": "web-framework", "from": "3.2.0", "to": "2.4.0"},
    ]


def test_explain_force_higher_version_than_baseline():
    """反事实目标可以高于基准版本：基准为保 aaa-lib 2.0 把 libx 降到 1.0
    （MRV 平局按名称展开，aaa-lib 先选高版本），强制 libx==2.0 后
    aaa-lib 回退到 1.0，整体仍然可行。"""
    repo = {
        "app": [c("1.0", [d("libx"), d("aaa-lib")])],
        "libx": [c("1.0"), c("2.0", [d("aaa-lib", "<2.0")])],
        "aaa-lib": [c("1.0"), c("2.0")],
    }
    r = explain(repo, "libx", "2.0")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["baseline_locked"] == {"app": "1.0", "aaa-lib": "2.0", "libx": "1.0"}
    assert body["locked"] == {"app": "1.0", "aaa-lib": "1.0", "libx": "2.0"}
    assert body["added"] == []
    assert body["removed"] == []
    assert body["changed"] == [
        {"name": "aaa-lib", "from": "2.0", "to": "1.0"},
        {"name": "libx", "from": "1.0", "to": "2.0"},
    ]


def test_explain_force_baseline_version_produces_empty_diff():
    """强制版本与基准锁一致时：反事实锁不变，三类差异全为空。"""
    r = explain(diamond_repo(), "shared-util", "2.0.0")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["locked"] == body["baseline_locked"]
    assert body["added"] == []
    assert body["removed"] == []
    assert body["changed"] == []


def test_explain_version_equivalence_produces_no_change():
    """PEP 440 等价版本（1.0 与 1.0.0）不产生 changed 项。"""
    repo = {
        "app": [c("1.0", [d("libx")])],
        "libx": [c("1.0.0")],
    }
    r = explain(repo, "libx", "1.0")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["target_version"] == "1.0"
    assert body["locked"] == {"app": "1.0", "libx": "1.0.0"}
    assert body["changed"] == []


def test_explain_root_package_as_target():
    """目标包可以是根包本身：强制根版本后整体重解。"""
    repo = {
        "app": [c("1.0"), c("2.0", [d("liba")])],
        "liba": [c("1.0")],
    }
    r = explain(repo, "app", "1.0")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["baseline_locked"] == {"app": "2.0", "liba": "1.0"}
    assert body["locked"] == {"app": "1.0"}
    assert body["root_version"] == "1.0"
    assert body["added"] == []
    assert body["removed"] == [{"name": "liba", "version": "1.0"}]
    assert body["changed"] == [{"name": "app", "from": "2.0", "to": "1.0"}]


def test_explain_target_version_normalized_in_output():
    """target_version 输出为 PEP 440 规范化形式，与输入拼写无关。"""
    repo = {
        "app": [c("1.0", [d("libx")])],
        "libx": [c("1.0"), c("2.0")],
    }
    r = explain(repo, "libx", " 1.0 ")
    assert r.status_code == 200, r.text
    assert r.json()["target_version"] == "1.0"


# --------------------------------------------------------------------- #
# 2. 422：目标包不可达、非法版本、缺字段、多余字段、未知根包
# --------------------------------------------------------------------- #
def test_explain_target_not_in_baseline_lock_422():
    """目标包存在于快照但不被根包可达：基准锁中没有它，返回 422。"""
    repo = {
        "app": [c("1.0", [d("libx")])],
        "libx": [c("1.0")],
        "ghost": [c("1.0")],
    }
    r = explain(repo, "ghost", "1.0")
    assert r.status_code == 422
    body = r.json()
    assert body["status"] == "invalid_snapshot"
    assert "ghost" in body["message"]
    assert "基准锁" in body["message"]


def test_explain_target_absent_from_repository_422():
    """目标包根本不在快照中：同样不可达，返回 422。"""
    repo = {"app": [c("1.0")]}
    r = explain(repo, "ghost", "1.0")
    assert r.status_code == 422
    assert r.json()["status"] == "invalid_snapshot"


def test_explain_invalid_target_version_422():
    repo = {"app": [c("1.0")]}
    r = explain(repo, "app", "not-a-version")
    assert r.status_code == 422
    body = r.json()
    assert body["status"] == "invalid_snapshot"
    assert "PEP 440" in body["message"]


def test_explain_unknown_root_422():
    repo = {"app": [c("1.0")]}
    r = explain(repo, "app", "1.0", root="missing")
    assert r.status_code == 422
    assert r.json()["status"] == "invalid_snapshot"


def test_explain_missing_target_fields_422():
    body = {
        "repository": {"app": [c("1.0")]},
        "root": "app",
        "target_environment": ENV,
    }
    assert client.post("/explain-version", json=body).status_code == 422


def test_explain_extra_field_forbidden_422():
    repo = {"app": [c("1.0")]}
    r = explain(repo, "app", "1.0", unknown_field=1)
    assert r.status_code == 422


# --------------------------------------------------------------------- #
# 3. 409：基准锁无解 / 反事实无解（复用约束来源链）
# --------------------------------------------------------------------- #
def test_explain_baseline_unresolvable_409():
    """基准锁本身无解：返回与 /resolve 一致的 409 冲突结果。"""
    repo = {
        "app": [c("1.0", [d("left"), d("right")])],
        "left": [c("1.0", [d("core", "==1.0")])],
        "right": [c("1.0", [d("core", "==2.0")])],
        "core": [c("1.0"), c("2.0")],
    }
    r = explain(repo, "core", "1.0")
    assert r.status_code == 409
    body = r.json()
    assert body["status"] == "conflict"
    assert body["conflicts"][0]["subject"] == "core"


def test_explain_forced_version_infeasible_409_with_chains():
    """强制 shared-util==2.0.0 与 auth-lib 的 <2.0 冲突：409 附来源链。"""
    repo = {
        "app": [c("1.0.0", [d("web-framework", ">=2.0"), d("auth-lib")])],
        "web-framework": [
            c("3.1.0", [d("shared-util", "==2.0.0")]),
            c("2.4.0", [d("shared-util", ">=1.0,<2.0")]),
        ],
        "auth-lib": [c("0.9.0", [d("shared-util", "<2.0")])],
        "shared-util": [c("2.0.0"), c("1.5.0"), c("1.4.0")],
    }
    r = explain(repo, "shared-util", "2.0.0")
    assert r.status_code == 409
    body = r.json()
    assert body["status"] == "conflict"
    assert "shared-util" in body["message"]
    assert "2.0.0" in body["message"]
    conflict = body["conflicts"][0]
    assert conflict["subject"] == "shared-util"
    chains = [entry["chain"] for entry in conflict["constraints"]]
    # 钉版本约束本身作为一条根级来源链出现
    assert [{"package": None, "version": None, "requires": "==2.0.0"}] in chains
    # 阻塞方：auth-lib 的 <2.0 约束链（根需求 -> app -> auth-lib）
    assert any(
        link["package"] == "auth-lib" and link["requires"] == "<2.0"
        for chain in chains
        for link in chain
    )


def test_explain_forced_version_not_in_snapshot_409():
    """强制版本不在快照中：反事实无解，409 的 no_candidates 说明阻塞。"""
    repo = {
        "app": [c("1.0", [d("libx")])],
        "libx": [c("1.0"), c("2.0")],
    }
    r = explain(repo, "libx", "9.9")
    assert r.status_code == 409
    body = r.json()
    assert body["status"] == "conflict"
    conflict = body["conflicts"][0]
    assert conflict["subject"] == "libx"
    assert conflict["kind"] == "no_candidates"
    assert "9.9" in conflict["message"]


# --------------------------------------------------------------------- #
# 4. 包名规范化 / marker / 预发布语义与 /resolve 一致
# --------------------------------------------------------------------- #
def test_explain_target_package_canonicalized():
    """target_package 按 PEP 503 规范化匹配，输出为规范化名。"""
    repo = {
        "app": [c("1.0", [d("Lib_X")])],
        "lib-x": [c("1.0"), c("2.0")],
    }
    r = explain(repo, "LIB_X", "1.0")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["target_package"] == "lib-x"
    assert body["locked"]["lib-x"] == "1.0"
    assert body["changed"] == [{"name": "lib-x", "from": "2.0", "to": "1.0"}]


def test_explain_respects_target_environment_markers():
    """基准锁与反事实求解都按目标环境求值 marker：强制回退 libx==1.0 后，
    被移除的平台依赖随环境不同而不同。"""
    repo = {
        "app": [c("1.0", [d("libx")])],
        "libx": [
            c("1.0"),
            c("2.0", [
                d("win-lib", marker="sys_platform == 'win32'"),
                d("posix-lib", marker="sys_platform == 'linux'"),
            ]),
        ],
        "win-lib": [c("1.0")],
        "posix-lib": [c("1.0")],
    }
    r = explain(repo, "libx", "1.0")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["baseline_locked"] == {"app": "1.0", "libx": "2.0", "posix-lib": "1.0"}
    assert body["locked"] == {"app": "1.0", "libx": "1.0"}
    assert body["removed"] == [{"name": "posix-lib", "version": "1.0"}]

    win_env = {"python_version": "3.11", "sys_platform": "win32",
               "platform_machine": "AMD64"}
    r2 = explain(repo, "libx", "1.0", env=win_env)
    body2 = r2.json()
    assert body2["baseline_locked"] == {"app": "1.0", "libx": "2.0", "win-lib": "1.0"}
    assert body2["locked"] == {"app": "1.0", "libx": "1.0"}
    assert body2["removed"] == [{"name": "win-lib", "version": "1.0"}]


def test_explain_invalid_marker_still_422():
    repo = {
        "app": [c("1.0", [d("libx")])],
        "libx": [c("1.0"), c("2.0", [d("x", marker="os_name == 'posix'")])],
    }
    r = explain(repo, "libx", "2.0")
    assert r.status_code == 422
    assert "os_name" in r.json()["message"]


def test_explain_prerelease_pin_explicitly_allowed():
    """显式 ==预发布 钉版本遵循 pip 跟随语义：即使 allow_prereleases=false
    也接受被钉的预发布版本；其余包的预发布候选仍被排除。"""
    repo = {
        "app": [c("1.0", [d("libx")])],
        "libx": [
            c("1.0"),
            c("2.0rc1", [d("liby")]),
        ],
        "liby": [c("1.0"), c("2.0a1")],
    }
    r = explain(repo, "libx", "2.0rc1")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["locked"]["libx"] == "2.0rc1"
    # liby 的预发布候选不因目标钉版本而放开
    assert body["locked"]["liby"] == "1.0"


def test_explain_prerelease_baseline_follows_toggle():
    """基准锁与反事实求解都遵循 allow_prereleases 开关。"""
    repo = {
        "app": [c("1.0", [d("libx")])],
        "libx": [c("1.0"), c("2.0rc1")],
    }
    r = explain(repo, "libx", "1.0")
    assert r.status_code == 200, r.text
    assert r.json()["baseline_locked"]["libx"] == "1.0"

    r2 = explain(repo, "libx", "2.0rc1", allow_prereleases=True)
    assert r2.status_code == 200, r2.text
    body = r2.json()
    assert body["baseline_locked"]["libx"] == "2.0rc1"
    assert body["locked"]["libx"] == "2.0rc1"
    assert body["changed"] == []


# --------------------------------------------------------------------- #
# 5. 确定性与 /resolve 行为不变
# --------------------------------------------------------------------- #
def test_explain_deterministic_across_repeated_calls():
    body1 = explain(diamond_repo(), "web-framework", "2.4.0").json()
    body2 = explain(diamond_repo(), "web-framework", "2.4.0").json()
    assert body1 == body2


def test_explain_does_not_change_resolve_behavior():
    """同一快照上 /resolve 的输出不受 /explain-version 影响（无共享状态）。"""
    repo = diamond_repo()
    resolve_body = {
        "repository": repo, "root": "app", "target_environment": ENV,
    }
    before = client.post("/resolve", json=resolve_body).json()
    explain(repo, "web-framework", "2.4.0")
    after = client.post("/resolve", json=resolve_body).json()
    assert before == after
    assert before["locked"]["web-framework"] == "3.2.0"
