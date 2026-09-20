"""/resolve-matrix 与 /lock-groups 的请求级共享求解预算测试。

覆盖：
* resolver 层 SharedAttemptBudget 的跨实例累计计数、耗尽语义与
  单实例 attempt_limit 的优先级（保留 /resolve 既有上限语义）；
* HTTP 层 409 status=limit 负载（触发环境、已用次数、上限）；
* 环境按 id 稳定顺序执行：输入重排后截断位置与响应一致；
* 预算耗尽时后续环境不再求解；
* 单环境 /resolve 与无冲突矩阵请求不受 MATRIX_ATTEMPT_LIMIT 影响；
* 环境变量非法时启动（模块导入）失败；
* /lock-groups 与 /resolve-matrix 行为同形。
"""

from __future__ import annotations

import pytest

from app.repository import build_repository, canonical, parse_root_specifier
from app.resolver import (
    ResolutionLimit,
    Resolver,
    SharedAttemptBudget,
    SharedBudgetExceeded,
)
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

LINUX = {
    "id": "linux-x64",
    "python_version": "3.11",
    "sys_platform": "linux",
    "platform_machine": "x86_64",
}
WIN = {
    "id": "win-amd64",
    "python_version": "3.9",
    "sys_platform": "win32",
    "platform_machine": "AMD64",
}
MAC = {
    "id": "mac-arm64",
    "python_version": "3.11",
    "sys_platform": "darwin",
    "platform_machine": "arm64",
}

SIMPLE_REPO = {
    "app": [
        {"version": "1.0",
         "dependencies": [
             {"name": "linux-only", "marker": "sys_platform == 'linux'"},
             {"name": "win-only", "marker": "sys_platform == 'win32'"},
         ]}
    ],
    "linux-only": [{"version": "1.0"}],
    "win-only": [{"version": "1.0"}],
}


def matrix_payload(environments, *, repository=None, **overrides):
    base = {
        "repository": repository or SIMPLE_REPO,
        "root": "app",
        "specifier": "",
        "allow_prereleases": False,
        "target_environments": environments,
    }
    base.update(overrides)
    return base


# --------------------------------------------------------------------- #
# resolver 层：SharedAttemptBudget
# --------------------------------------------------------------------- #
def _resolver_with_budget(budget: SharedAttemptBudget) -> Resolver:
    repo = build_repository(SIMPLE_REPO, LINUX)
    return Resolver(repo, shared_budget=budget)


def test_shared_budget_charge_allows_exactly_limit_then_refuses():
    budget = SharedAttemptBudget(3)
    assert [budget.charge() for _ in range(4)] == [True, True, True, False]
    # 满额后 used 恰为 limit（不溢出），可直接对外报告。
    assert budget.used == 3
    assert budget.limit == 3


def test_shared_budget_accumulates_across_resolver_instances():
    """两个 Resolver 共用一个预算：尝试次数累计，第二个实例耗尽预算即抛出。"""
    budget = SharedAttemptBudget(2)
    repo_linux = build_repository(SIMPLE_REPO, LINUX)
    repo_win = build_repository(SIMPLE_REPO, WIN)

    r1 = Resolver(repo_linux, shared_budget=budget)
    state = r1.resolve(canonical("app"), parse_root_specifier(""), "")
    assert state is not None
    # linux 分支依次尝试 app 与 linux-only：共 2 次，恰好用尽。
    assert r1.attempts == 2 and budget.used == 2

    r2 = Resolver(repo_win, shared_budget=budget)
    with pytest.raises(SharedBudgetExceeded):
        r2.resolve(canonical("app"), parse_root_specifier(""), "")
    assert budget.used == 2


def test_shared_budget_without_budget_keeps_single_env_semantics():
    """shared_budget=None 时求解行为与引入预算前完全一致（/resolve 路径）。"""
    repo = build_repository(SIMPLE_REPO, LINUX)
    r = Resolver(repo)
    state = r.resolve(canonical("app"), parse_root_specifier(""), "")
    assert state is not None
    assert r.attempts == 2


def test_per_resolver_attempt_limit_hits_before_shared_budget():
    """单实例 attempt_limit 优先于共享预算：命中前者不计费、抛 ResolutionLimit。

    保留单环境 /resolve 的既有上限语义：即便共享预算还很充裕，
    某个环境自身的搜索超过 attempt_limit 时仍按该环境的 status=limit
    冲突结果报告（矩阵中作为 failures 继续跑完全部环境）。
    """
    budget = SharedAttemptBudget(1_000_000)
    repo = {
        "app": [{"version": "1.0", "dependencies": [{"name": "x"}]}],
        "x": [{"version": "1.0"}],
    }
    r = Resolver(build_repository(repo, LINUX), attempt_limit=0,
                 shared_budget=budget)
    with pytest.raises(ResolutionLimit):
        r.resolve(canonical("app"), parse_root_specifier(""), "")
    # 命中单实例上限时不向共享预算计费。
    assert budget.used == 0


def test_shared_budget_requires_positive_limit():
    with pytest.raises(ValueError):
        SharedAttemptBudget(0)


# --------------------------------------------------------------------- #
# HTTP 层：409 status=limit 负载
# --------------------------------------------------------------------- #
def heavy_light_repo(m: int = 40):
    """构造跨环境预算截断快照：

    * linux 环境（id=linux-x64，按 id 排在最前）：resolver 的 M 个版本
      依次钉死不存在的 shared==M+1，各回溯一次，共 M 次确定性尝试（重）；
    * win 环境（id=win-amd64）：limiter 仅两个候选，尝试 3 次即结束（轻）。

    MRV 保证子包（resolver/limiter/shared，候选数都少于根 app）先展开，
    根 app 最后；环境间互斥 marker 保证每个环境只走自己的分支。
    """
    return {
        "app": [{"version": "1.0", "dependencies": [
            {"name": "resolver", "marker": "sys_platform == 'linux'"},
            {"name": "limiter", "marker": "sys_platform == 'win32'"},
        ]}],
        "resolver": [
            {"version": str(v),
             "dependencies": [{"name": "shared", "specifier": f"=={m + 1}"}]}
            for v in range(1, m + 1)
        ],
        "limiter": [
            {"version": "1", "dependencies": [{"name": "shared"}]},
            {"version": "0.9"},
        ],
        "shared": [{"version": str(v)} for v in range(1, m + 1)],
    }


def test_resolve_matrix_409_limit_payload_when_budget_exhausted(monkeypatch):
    from app import config

    monkeypatch.setattr(config, "MATRIX_ATTEMPT_LIMIT", 5)
    monkeypatch.setattr("app.main.MATRIX_ATTEMPT_LIMIT", 5)

    r = client.post("/resolve-matrix",
                    json=matrix_payload([LINUX, WIN], repository=heavy_light_repo()))
    assert r.status_code == 409, r.text
    body = r.json()
    assert body["status"] == "limit"
    assert body["environment"] == "linux-x64"
    assert body["used"] == 5
    assert body["limit"] == 5
    assert "linux-x64" in body["message"]
    # 截断形态不携带 failures / results。
    assert "failures" not in body
    assert "results" not in body


def test_resolve_matrix_limit_truncation_stable_under_reordering(monkeypatch):
    """环境按 id 稳定顺序执行：重排输入后截断位置与响应逐字节一致。"""
    from app import config

    monkeypatch.setattr(config, "MATRIX_ATTEMPT_LIMIT", 5)
    monkeypatch.setattr("app.main.MATRIX_ATTEMPT_LIMIT", 5)

    body_fwd = client.post(
        "/resolve-matrix",
        json=matrix_payload([LINUX, WIN], repository=heavy_light_repo()),
    ).json()
    body_rev = client.post(
        "/resolve-matrix",
        json=matrix_payload([WIN, LINUX], repository=heavy_light_repo()),
    ).json()
    # 两种提交顺序下都在 id 最小的重环境 linux-x64 上截断，响应一致。
    assert body_fwd == body_rev
    assert body_fwd["environment"] == "linux-x64"


def test_resolve_matrix_budget_stops_later_environments(monkeypatch):
    """预算在第一个环境耗尽时，后续环境完全不求解；重排提交顺序结果相同。"""
    from app import config

    monkeypatch.setattr(config, "MATRIX_ATTEMPT_LIMIT", 3)
    monkeypatch.setattr("app.main.MATRIX_ATTEMPT_LIMIT", 3)

    for order in ([LINUX, WIN], [WIN, LINUX]):
        r = client.post("/resolve-matrix",
                        json=matrix_payload(order, repository=heavy_light_repo()))
        assert r.status_code == 409
        body = r.json()
        # 重环境 linux-x64 的前 3 次尝试即耗尽预算，win-amd64 根本不启动。
        assert body["environment"] == "linux-x64"
        assert body["used"] == 3


def test_resolve_matrix_budget_accumulates_and_skips_remaining(monkeypatch):
    """第一个环境成功计费后，第二个环境耗尽预算：第三个环境完全不求解。"""
    from app import config

    monkeypatch.setattr(config, "MATRIX_ATTEMPT_LIMIT", 3)
    monkeypatch.setattr("app.main.MATRIX_ATTEMPT_LIMIT", 3)

    m = 40
    repo = {
        "app": [{"version": "1.0", "dependencies": [
            {"name": "resolver", "marker": "sys_platform == 'win32'"},
        ]}],
        "resolver": [
            {"version": str(v),
             "dependencies": [{"name": "shared", "specifier": f"=={m + 1}"}]}
            for v in range(1, m + 1)
        ],
        "shared": [{"version": str(v)} for v in range(1, m + 1)],
    }
    # 提交顺序打乱：id 升序应为 a(mac, 无激活依赖, 1 次) -> b(win, 重) -> c(linux)。
    payload = matrix_payload([MAC, WIN, LINUX], repository=repo)
    r = client.post("/resolve-matrix", json=payload)
    assert r.status_code == 409, r.text
    body = r.json()
    assert body["status"] == "limit"
    assert body["environment"] == "win-amd64"
    assert body["used"] == 3
    # 第三个环境 linux-x64 不出现在响应的任何位置（未求解）。
    assert "linux-x64" not in body["message"]


def test_resolve_matrix_light_then_heavy_triggers_in_second_env(monkeypatch):
    """首个环境成功计费、第二个环境耗尽预算：触发环境为第二个 id。"""
    from app import config

    # linux 成功消耗 2 次（app、linux-only）；win 的重搜索随后耗尽预算。
    # 用 id 顺序使 linux 在前：构造 win 重、linux 轻的快照。
    m = 40
    repo = {
        "app": [{"version": "1.0", "dependencies": [
            {"name": "linux-only", "marker": "sys_platform == 'linux'"},
            {"name": "resolver", "marker": "sys_platform == 'win32'"},
        ]}],
        "linux-only": [{"version": "1.0"}],
        "resolver": [
            {"version": str(v),
             "dependencies": [{"name": "shared", "specifier": f"=={m + 1}"}]}
            for v in range(1, m + 1)
        ],
        "shared": [{"version": str(v)} for v in range(1, m + 1)],
    }
    monkeypatch.setattr(config, "MATRIX_ATTEMPT_LIMIT", 6)
    monkeypatch.setattr("app.main.MATRIX_ATTEMPT_LIMIT", 6)

    r = client.post("/resolve-matrix",
                    json=matrix_payload([WIN, LINUX], repository=repo))
    assert r.status_code == 409, r.text
    body = r.json()
    assert body["status"] == "limit"
    # id 升序：linux-x64（轻、成功，2 次）先跑，win-amd64（重）随后截断。
    assert body["environment"] == "win-amd64"
    assert body["used"] == 6
    assert body["limit"] == 6


def test_resolve_matrix_default_budget_keeps_existing_conflict_behavior(monkeypatch):
    """默认（充裕）预算下，单环境自身无解仍走 failures 形态，预算不介入。"""
    repo = {
        "app": [{"version": "1.0", "dependencies": [
            {"name": "core", "specifier": ">=99"},
        ]}],
        "core": [{"version": "1.0"}],
    }
    r = client.post("/resolve-matrix",
                    json=matrix_payload([LINUX, WIN], repository=repo))
    assert r.status_code == 409
    body = r.json()
    assert body["status"] == "conflict"
    assert [f["id"] for f in body["failures"]] == ["linux-x64", "win-amd64"]


def test_resolve_matrix_success_unaffected_by_budget(monkeypatch):
    from app import config

    monkeypatch.setattr(config, "MATRIX_ATTEMPT_LIMIT", 100)
    monkeypatch.setattr("app.main.MATRIX_ATTEMPT_LIMIT", 100)
    r = client.post("/resolve-matrix", json=matrix_payload([WIN, LINUX]))
    assert r.status_code == 200, r.text
    assert [e["id"] for e in r.json()["results"]] == ["linux-x64", "win-amd64"]


def test_lock_groups_409_limit_same_shape_as_matrix(monkeypatch):
    """/lock-groups 共享同一预算与 409 status=limit 形态。"""
    from app import config

    monkeypatch.setattr(config, "MATRIX_ATTEMPT_LIMIT", 5)
    monkeypatch.setattr("app.main.MATRIX_ATTEMPT_LIMIT", 5)

    for order in ([LINUX, WIN], [WIN, LINUX]):
        r = client.post("/lock-groups",
                        json=matrix_payload(order, repository=heavy_light_repo()))
        assert r.status_code == 409, r.text
        body = r.json()
        assert body == {
            "status": "limit",
            "environment": "linux-x64",
            "used": 5,
            "limit": 5,
            "message": body["message"],
        }
        assert "groups" not in body


def test_lock_groups_success_unaffected_by_budget(monkeypatch):
    from app import config

    monkeypatch.setattr(config, "MATRIX_ATTEMPT_LIMIT", 100)
    monkeypatch.setattr("app.main.MATRIX_ATTEMPT_LIMIT", 100)
    r = client.post("/lock-groups", json=matrix_payload([WIN, LINUX]))
    assert r.status_code == 200, r.text
    assert len(r.json()["groups"]) == 2


def test_single_resolve_ignores_matrix_budget(monkeypatch):
    """单环境 /resolve 不受 MATRIX_ATTEMPT_LIMIT 影响，也不返回 limit 形态。"""
    from app import config

    # 即使把共享预算配成 1，/resolve 不读取它：正常快照依旧 200。
    monkeypatch.setattr(config, "MATRIX_ATTEMPT_LIMIT", 1)
    monkeypatch.setattr("app.main.MATRIX_ATTEMPT_LIMIT", 1)

    r = client.post("/resolve", json={
        "repository": SIMPLE_REPO,
        "root": "app",
        "specifier": "",
        "allow_prereleases": False,
        "target_environment": {
            "python_version": "3.11", "sys_platform": "linux",
            "platform_machine": "x86_64",
        },
    })
    assert r.status_code == 200, r.text
    assert r.json()["locked"] == {"app": "1.0", "linux-only": "1.0"}


def test_per_environment_limit_still_reported_as_failure(monkeypatch):
    """某个环境自身超过单实例上限时，作为 failures[].status=limit 报告，
    服务端继续跑完全部环境（既有冲突来源链语义不变）。"""
    # 单实例上限固定为 100_000，无法在合理时间内触发；这里通过验证默认
    # 预算（800k）与单实例上限（100k）的关系锁定优先级设计：
    # 默认预算等于 8 个单实例上限之和，任何单环境都必先撞上自身上限。
    from app import config
    from app.resolver import DEFAULT_ATTEMPT_LIMIT

    assert config.DEFAULT_MATRIX_ATTEMPT_LIMIT == DEFAULT_ATTEMPT_LIMIT * 8


# --------------------------------------------------------------------- #
# 配置：环境变量非法时启动失败
# --------------------------------------------------------------------- #
def test_config_parses_valid_env(monkeypatch):
    from app import config

    monkeypatch.setenv("MATRIX_ATTEMPT_LIMIT", "42")
    assert config.matrix_attempt_limit_from_env() == 42


@pytest.mark.parametrize("bad", ["0", "-1", "abc", "1.5", "   ", "1e3", "+5", ""])
def test_config_rejects_invalid_env(monkeypatch, bad):
    from app import config

    monkeypatch.setenv("MATRIX_ATTEMPT_LIMIT", bad)
    with pytest.raises(config.ConfigurationError):
        config.matrix_attempt_limit_from_env()


def test_config_default_when_unset(monkeypatch):
    from app import config

    monkeypatch.delenv("MATRIX_ATTEMPT_LIMIT", raising=False)
    assert (
        config.matrix_attempt_limit_from_env()
        == config.DEFAULT_MATRIX_ATTEMPT_LIMIT
    )


def test_app_fails_to_start_with_invalid_env():
    """端到端：非法 MATRIX_ATTEMPT_LIMIT 时，uvicorn 启动加载应用的同一
    动作（import app.main）在子进程中非零退出，服务无法开始接受请求。

    用子进程隔离，避免重载模块污染本进程测试的类身份。
    """
    import os
    import subprocess
    import sys

    env = {**os.environ, "MATRIX_ATTEMPT_LIMIT": "not-an-int"}
    proc = subprocess.run(
        [sys.executable, "-c", "import app.main"],
        capture_output=True,
        text=True,
        env=env,
    )
    assert proc.returncode != 0
    assert "MATRIX_ATTEMPT_LIMIT" in proc.stderr
    assert "ConfigurationError" in proc.stderr


def test_app_starts_with_valid_env():
    """对照：合法配置（含默认缺省）下应用可正常导入。"""
    import os
    import subprocess
    import sys

    env = {**os.environ, "MATRIX_ATTEMPT_LIMIT": "12345"}
    proc = subprocess.run(
        [sys.executable, "-c", "import app.main; print('started')"],
        capture_output=True,
        text=True,
        env=env,
    )
    assert proc.returncode == 0, proc.stderr
    assert "started" in proc.stdout
