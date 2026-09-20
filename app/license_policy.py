"""许可证策略判定（POST /license-policy）。

调用本模块前，请求的 ``current_lock`` 已由 :func:`app.audit.audit_lock`
判定为**有效**（无 missing / unavailable / constraint_mismatch /
extraneous）。因此与 :mod:`app.sbom` 一样，这里不做任何版本选择与约束
核对，只沿**已激活依赖图**（与 /dependency-paths 同一张图：按锁定版本、
目标环境下 marker 求值后激活的依赖）逐包判定许可证策略，并复用
:func:`app.paths.shortest_paths` 为每个命中的包附上根包到它的全部最短
包路径。

对每个可达包取其**锁定版本**候选携带的 ``metadata.license``：

* 未提供（``null`` / 空串）：整包判定为 ``unknown``（无法按表达式求值，
  但不阻断请求）；
* 提供文本：按 SPDX AND/OR/括号表达式解析（非法表达式抛
  LicenseExpressionError，API 层映射为 422），再用 allow/deny 两个标识
  集合做三态判定——拒绝进入 ``violations``，未知进入 ``unknowns``，
  允许不出现在结果中。

两个输出列表各自只取决于快照、目标环境、锁定清单与策略集合，均按
规范化包名排序；每条附 ``paths``（根包到该包的全部最短路径，字典序
排序，语义与 /dependency-paths 一致）。命中包按包名顺序逐个查询路径，
某条查询的最短路径条数超过固定预算（app.paths.PATH_COUNT_LIMIT）时
抛 :exc:`app.paths.PathCountLimit`（命中首个超限项），由路由层映射为
409 ``status=limit``，不构造任何路径列表。
"""

from __future__ import annotations

from collections.abc import Collection

from packaging.version import Version

from .audit import _find_candidate
from .paths import shortest_paths
from .repository import Repository
from .spdx import (
    DENY,
    UNKNOWN,
    LicenseExpressionError,
    evaluate_spdx_expression,
    parse_spdx_expression,
)


def evaluate_license_policy(
    repo: Repository,
    *,
    root_name: str,
    current_lock: dict[str, Version],
    graph: dict[str, list[str]],
    allow: Collection[str],
    deny: Collection[str],
) -> dict:
    """沿已激活依赖图对每个可达包做许可证三态判定。

    ``graph`` 为 :func:`app.paths.build_locked_graph` 产出的根可达子图
    （节点集恰为锁中全部包）。返回
    ``{"violations": [...], "unknowns": [...]}``，两项均按包名排序；
    包的 SPDX 表达式非法时抛 LicenseExpressionError（定位到包与版本）。
    命中包按包名顺序逐个查询最短路径，某条查询超过固定条数预算时抛
    :exc:`app.paths.PathCountLimit`（首个超限项），不构造路径列表。
    """
    violations: list[dict] = []
    unknowns: list[dict] = []

    for name in sorted(graph):
        locked = current_lock[name]
        cand = _find_candidate(repo, name, locked)  # 有效锁：锁定版本必在快照
        assert cand is not None
        license_text = cand.metadata.license

        decision = UNKNOWN
        if license_text is not None:
            try:
                node = parse_spdx_expression(license_text)
            except LicenseExpressionError as exc:
                raise LicenseExpressionError(
                    f"包 {name}=={locked} 的许可证表达式 {license_text!r}"
                    f" 不是合法的 SPDX 表达式: {exc}"
                ) from exc
            decision = evaluate_spdx_expression(node, allow, deny)

        if decision == DENY:
            violations.append(_entry(name, graph, root_name, license_text))
        elif decision == UNKNOWN:
            unknowns.append(_entry(name, graph, root_name, license_text))

    return {"violations": violations, "unknowns": unknowns}


def _entry(
    name: str,
    graph: dict[str, list[str]],
    root_name: str,
    license_text: str | None,
) -> dict:
    """构造一个命中包的输出条目：名称、许可证文本与全部最短根路径。"""
    return {
        "name": name,
        "license": license_text,
        "paths": shortest_paths(graph, root_name, name),
    }
