"""PEP 508 环境标记（marker）解析与求值。

本服务只允许 marker 引用三个由请求显式给出的变量：
``python_version``、``sys_platform``、``platform_machine``。
标记环境完全由请求体的 ``target_environment`` 构造，**绝不读取宿主机**的
``sys`` / ``platform`` 信息（不使用 ``Marker.evaluate``，因为它会合并
``default_environment()``，而该函数探测当前进程）；改为把打包后的环境
直接交给 packaging 的底层求值函数。
"""

from __future__ import annotations

from collections.abc import Mapping

from packaging.markers import (
    InvalidMarker,
    Marker,
    UndefinedComparison,
    UndefinedEnvironmentName,
    _evaluate_markers,
)
from packaging.version import InvalidVersion, Version

# marker 允许引用的全部变量；引用任何其它名称都越界（422）。
ALLOWED_MARKER_VARS: frozenset[str] = frozenset(
    {"python_version", "sys_platform", "platform_machine"}
)

MARKER_VARS_TEXT = "、".join(sorted(ALLOWED_MARKER_VARS))


class MarkerError(ValueError):
    """marker 非法：语法错误、引用越界变量或无法求值。"""


def _collect_variable_names(markers: object) -> set[str]:
    """遍历 packaging 的 marker AST，收集引用的变量名。

    AST 节点形如 ``[(Variable, Op, Value), 'and', [(...), 'or', ...]]``。
    节点类型在不同 packaging 版本里来自不同模块，按类名字面量判定。
    """
    names: set[str] = set()

    def walk(node: object) -> None:
        if isinstance(node, list):
            for child in node:
                walk(child)
        elif isinstance(node, tuple):
            lhs, _op, rhs = node
            for side in (lhs, rhs):
                if type(side).__name__ == "Variable":
                    names.add(side.value)
                # 另一侧为 Value（字面量），无需处理。

    walk(markers)
    return names


def parse_marker(text: str, *, location: str) -> Marker | None:
    """解析并校验一条依赖的 marker；空串视为无条件（返回 None）。

    ``location`` 为出错时定位用的“包==版本 / 依赖”描述。
    """
    raw = (text or "").strip()
    if not raw:
        return None
    try:
        marker = Marker(raw)
    except InvalidMarker as exc:
        raise MarkerError(
            f"{location} 的 marker {raw!r} 不是合法的 PEP 508 标记: {exc}"
        ) from exc

    referenced = _collect_variable_names(marker._markers)
    illegal = sorted(referenced - ALLOWED_MARKER_VARS)
    if illegal:
        raise MarkerError(
            f"{location} 的 marker {raw!r} 引用了不允许的变量 "
            f"{', '.join(illegal)!r}；仅允许引用：{MARKER_VARS_TEXT}"
        )
    return marker


def build_environment(
    raw: Mapping[str, str], *, location: str = "target_environment"
) -> dict[str, str]:
    """把请求里的 target_environment 打包为 marker 求值环境。

    ``python_version`` 必须是合法的 PEP 440 版本（与该变量的 PEP 508
    语义一致）；另两个字段只做非空字符串比较，不做格式限制。
    """
    python_version = str(raw["python_version"]).strip()
    sys_platform = str(raw["sys_platform"]).strip()
    platform_machine = str(raw["platform_machine"]).strip()
    if not python_version or not sys_platform or not platform_machine:
        raise MarkerError(
            "target_environment 的 python_version / sys_platform / "
            "platform_machine 均不能为空字符串"
        )
    try:
        Version(python_version)
    except InvalidVersion as exc:
        raise MarkerError(
            f"{location}.python_version {python_version!r} 不是合法的 PEP 440 版本"
        ) from exc
    return {
        "python_version": python_version,
        "sys_platform": sys_platform,
        "platform_machine": platform_machine,
    }


def marker_active(marker: Marker | None, environment: Mapping[str, str]) -> bool:
    """在给定环境下求值；marker 为 None（未声明）时恒激活。

    求值环境仅含请求提供的三个变量，不探测宿主机。
    """
    if marker is None:
        return True
    try:
        return bool(_evaluate_markers(marker._markers, dict(environment)))
    except UndefinedEnvironmentName as exc:
        # 越界变量已在 parse_marker 拦截；兜底仍按非法 marker 报 422。
        raise MarkerError(f"marker 引用了未提供的变量: {exc}") from exc
    except UndefinedComparison as exc:
        raise MarkerError(f"marker 无法在给定环境下求值: {exc}") from exc
