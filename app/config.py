"""进程级配置：全部来自环境变量，启动时一次性校验。

非法配置（缺失时使用内置默认值，不算非法）直接抛出
``ConfigurationError``，由 FastAPI 的启动过程在服务开始接受请求前终止
进程（容器编排会按重启策略拉起并持续失败，从而暴露配置错误）。

当前仅包含多环境接口（``/resolve-matrix``、``/lock-groups``）共用的
**请求级求解预算**：同一次请求内各目标环境的候选尝试次数累计计数，
达到上限立即停止后续环境的求解（见 resolver.SharedAttemptBudget）。
单环境 ``/resolve`` 不读取此项，仍沿用每个求解器实例的固定上限。
"""

from __future__ import annotations

import os

from .resolver import DEFAULT_ATTEMPT_LIMIT

# 多环境请求的共享预算默认值：2～8 个环境，各环境单实例上限为
# DEFAULT_ATTEMPT_LIMIT，默认取上限之和，使默认配置下两个多环境接口的
# 行为与引入共享预算前完全一致（只有显式调小预算才会产生请求级截断）。
DEFAULT_MATRIX_ATTEMPT_LIMIT = DEFAULT_ATTEMPT_LIMIT * 8

# 环境变量名：/resolve-matrix 与 /lock-groups 的请求级共享尝试预算。
MATRIX_ATTEMPT_LIMIT_ENV = "MATRIX_ATTEMPT_LIMIT"


class ConfigurationError(RuntimeError):
    """环境变量配置非法：在启动时抛出，阻止服务接受请求。"""


def _parse_positive_int(raw: str, *, env_name: str) -> int:
    """把环境变量值解析为正整数；任何非法形式（含空白、正负号、小数）都拒绝。"""
    text = raw.strip()
    if not text.isdigit() or int(text) <= 0:
        raise ConfigurationError(
            f"环境变量 {env_name}={raw!r} 非法：必须是不小于 1 的十进制正整数"
            f"（缺省时默认 {DEFAULT_MATRIX_ATTEMPT_LIMIT}）"
        )
    return int(text)


def matrix_attempt_limit_from_env() -> int:
    """从环境变量读取多环境请求的共享求解预算；变量未设置时取内置默认值。

    变量被显式设置为空串/纯空白也视为非法（启动失败），避免“配了但
    没配上”的静默回退。
    """
    raw = os.environ.get(MATRIX_ATTEMPT_LIMIT_ENV)
    if raw is None:
        return DEFAULT_MATRIX_ATTEMPT_LIMIT
    return _parse_positive_int(raw, env_name=MATRIX_ATTEMPT_LIMIT_ENV)


# 模块导入即解析（FastAPI/uvicorn 加载 app.main 时发生）：
# 非法配置在启动阶段失败，而不是拖到第一个请求才报错。
MATRIX_ATTEMPT_LIMIT = matrix_attempt_limit_from_env()
