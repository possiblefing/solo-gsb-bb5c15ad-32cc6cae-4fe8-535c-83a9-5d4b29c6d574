"""锁定依赖图上的最短包路径（POST /dependency-paths）。

调用本模块前，请求的 ``current_lock`` 已由 :func:`app.audit.audit_lock`
判定为**有效**（无 missing / unavailable / constraint_mismatch /
extraneous）。因此这里不做任何版本选择与约束核对，只按**锁定版本**在目标
环境下已激活的依赖建图：

* 图节点为 PEP 503 规范化包名；边 ``pkg -> dep`` 表示 ``pkg`` 的锁定版本
  声明了该依赖（marker 已在构造快照时求值，未激活依赖不在快照内）；
* 同一对包之间的多条声明（不同约束文本）只产生一条边——路径解释的是
  “包为何出现”，与约束文本无关；邻接表按包名排序，保证遍历确定性；
* 依赖环（含自环）天然安全：建图每个包只展开一次，路径搜索用 BFS
  前驱表，不递归、不重复节点、不可能无限遍历。

从根包到目标包返回**所有最短路径**（边数最少）；菱形依赖产生的等长路径
全部保留。输出路径整体按字典序排序，路径内节点即访问次序。

分层菱形（每层两个分叉、逐层汇合再分叉）下最短路径条数随层数**指数
增长**，逐一构造路径列表会拖垮进程。因此 BFS 建立最短前驱图后先**按层
做饱和计数**（只累加条数、不构造路径），条数超过固定预算
:data:`PATH_COUNT_LIMIT` 时抛 :exc:`PathCountLimit`，由路由层映射为
409 ``status=limit``；未超限才重建并返回全部最短路径。
"""

from __future__ import annotations

from collections import deque

from packaging.version import Version

from .audit import _find_candidate
from .repository import Repository

# 单次最短路径查询的路径条数预算（固定值，不随配置变化）：分层菱形下
# 路径条数指数增长，饱和计数超过预算即放弃构造路径列表（409 status=limit）。
PATH_COUNT_LIMIT = 1_000


class PathCountLimit(RuntimeError):
    """最短路径条数超过固定预算 :data:`PATH_COUNT_LIMIT`。

    携带触发查询的目标包、饱和计数（恒为 ``limit + 1``）与预算上限，
    由路由层映射为 409 ``status=limit`` 响应；抛出时不构造任何路径列表。
    """

    def __init__(self, target: str, *, used: int, limit: int):
        super().__init__(
            f"根包到目标包 {target!r} 的最短路径条数超过预算："
            f"饱和计数 {used}，上限 {limit}"
        )
        self.target = target
        self.used = used
        self.limit = limit


def build_locked_graph(
    repo: Repository,
    *,
    root_name: str,
    current_lock: dict[str, Version],
) -> dict[str, list[str]]:
    """按锁定版本展开已激活依赖，构造根包可达子图。

    前置条件：``current_lock`` 已通过审计——每个可达包都在锁中、锁定版本
    都在快照中（无遍历断点），且锁中没有不可达包，故可达子图的节点集恰为
    锁中全部包。每个包只展开一次，环不会造成重复或无限遍历。
    """
    graph: dict[str, list[str]] = {}
    seen: set[str] = {root_name}
    queue: deque[str] = deque([root_name])

    while queue:
        name = queue.popleft()
        locked = current_lock[name]  # 有效锁：根可达包必有锁定版本
        cand = _find_candidate(repo, name, locked)  # 有效锁：锁定版本必在快照
        neighbours = sorted({dep.name for dep in cand.deps})
        graph[name] = neighbours
        for dep_name in neighbours:
            if dep_name not in seen:
                seen.add(dep_name)
                queue.append(dep_name)

    return graph


def shortest_paths(
    graph: dict[str, list[str]], root: str, target: str
) -> list[list[str]]:
    """根包到目标包的所有最短路径；不可达（或目标不在图中）时返回空列表。

    无权 BFS 记录每个节点在最短距离上的全部前驱（菱形的等长路径由此全部
    保留；环上回边距离更长，不会进入前驱表）。随后**先按层做饱和计数**：
    分层菱形下最短路径条数随层数指数增长，条数超过固定预算
    :data:`PATH_COUNT_LIMIT` 时抛 :exc:`PathCountLimit`，不构造任何路径
    列表；未超限时才按深度自顶向下重建路径，避免深链上的递归。最终路径
    按字典序排序，与输入顺序无关。
    """
    if target not in graph:
        return []
    if target == root:
        # 目标即根包：唯一的最短路径是单节点路径。
        return [[root]]

    parents: dict[str, list[str]] = {root: []}
    distance: dict[str, int] = {root: 0}
    queue: deque[str] = deque([root])

    found_distance: int | None = None
    while queue:
        name = queue.popleft()
        if found_distance is not None and distance[name] >= found_distance:
            continue
        for nxt in graph[name]:
            if nxt not in distance:
                distance[nxt] = distance[name] + 1
                parents[nxt] = [name]
                if nxt == target:
                    found_distance = distance[nxt]
                else:
                    queue.append(nxt)
            elif distance[nxt] == distance[name] + 1:
                # 等长的另一条最短路径（菱形汇合），同样记录。
                parents[nxt].append(name)

    if target not in parents:
        return []

    # 按层饱和计数：count[node] 为根到 node 的最短路径条数（父节点距离
    # 恰小一层，逐层推进即可累加）。条数一旦超过预算即饱和为 limit+1
    # 并停止累加，因此超限目标的计数恒为 limit+1，与真实条数无关。
    count: dict[str, int] = {root: 1}
    by_depth: dict[int, list[str]] = {}
    for node, dist in distance.items():
        by_depth.setdefault(dist, []).append(node)
    for depth in range(1, distance[target] + 1):
        for node in by_depth.get(depth, []):
            total = 0
            for parent in parents[node]:
                total += count[parent]
                if total > PATH_COUNT_LIMIT:
                    total = PATH_COUNT_LIMIT + 1
                    break
            count[node] = total

    if count[target] > PATH_COUNT_LIMIT:
        # 超限：只报告饱和计数（恒为 limit+1），不构造任何路径列表。
        raise PathCountLimit(
            target, used=count[target], limit=PATH_COUNT_LIMIT
        )

    # 按层重建：suffixes[d] 为距目标 d 层上的全部后缀。
    suffixes: dict[int, list[list[str]]] = {0: [[target]]}
    for depth in range(1, distance[target] + 1):
        current: list[list[str]] = []
        for suffix in suffixes[depth - 1]:
            node = suffix[0]
            for parent in parents[node]:
                current.append([parent, *suffix])
        suffixes[depth] = current

    paths = suffixes[distance[target]]
    return sorted(paths)
