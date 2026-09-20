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
"""

from __future__ import annotations

from collections import deque

from packaging.version import Version

from .audit import _find_candidate
from .repository import Repository


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
    保留；环上回边距离更长，不会进入前驱表），再按深度自顶向下重建路径，
    避免深链上的递归。最终路径按字典序排序，与输入顺序无关。
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
