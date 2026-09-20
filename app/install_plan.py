"""有效锁定清单上的并行安装计划（POST /install-plan）。

调用本模块前，请求的 ``current_lock`` 已由 :func:`app.audit.audit_lock`
判定为**有效**（无 missing / unavailable / constraint_mismatch /
extraneous）。因此这里不做任何版本选择与约束核对，只在与
/dependency-paths、/sbom **同一张已激活依赖图**上（按锁定版本、目标
环境下 marker 求值后激活的依赖，节点集恰为根可达包）做两件事：

1. **强连通分量压缩**：用 Kosaraju 算法求有向图的强连通分量（SCC），
   把每个分量收缩成一个节点，分量之间的依赖边去重后构成 **DAG**——
   环上的互相依赖无法以任何先后顺序安装，因此同一分量必须作为一个
   batch item 原子安装；
2. **依赖优先的并行分层**：在 DAG 上以“任一依赖所在批次不得晚于依赖
   它的包”为约束做**最长路径分层**（每个分量的批次号 = 其各依赖分量
   批次号最大值 + 1，无依赖者为 0）：同一批内的分量互不依赖、可并行
   安装，且批次数最少。

输出确定性保证：

* 批次按批次号升序（批次 0 无任何依赖，先安装）；
* 同一批内的 item 按键排序：单包 item 以 ``(包名,)``、循环分量以其
  内部包名排序后的元组为键，按元组字典序排列；
* 循环分量 ``packages`` 内的包名按规范化名排序；
* 结果只取决于快照、目标环境与锁定清单，与包键 / 候选列表 / 依赖声明 /
  锁键的输入顺序无关。

根包可达图中根包可达每个节点，DAG 上根分量沿依赖边可到达任一分量，
故根分量的最长路径层号恒为最大值——**根包所在分量必然处于最后一批**。
"""

from __future__ import annotations

from packaging.version import Version

from .repository import Repository


def _strongly_connected_components(
    graph: dict[str, list[str]],
) -> list[list[str]]:
    """Kosaraju 算法求 SCC（两次 DFS 均为迭代实现，不递归）。

    邻接表按包名排序遍历；分量成员各自排序，分量整体顺序无关（调用方
    会再按成员元组排序），算法结果与输入顺序无关。
    """
    nodes = sorted(graph)

    # 第一次 DFS（原图）：按完成顺序记录节点。
    visited: set[str] = set()
    finish_order: list[str] = []
    for start in nodes:
        if start in visited:
            continue
        visited.add(start)
        stack: list[tuple[str, int]] = [(start, 0)]
        while stack:
            name, index = stack[-1]
            neighbours = graph[name]
            if index < len(neighbours):
                nxt = neighbours[index]
                stack[-1] = (name, index + 1)
                if nxt not in visited:
                    visited.add(nxt)
                    stack.append((nxt, 0))
            else:
                finish_order.append(name)
                stack.pop()

    # 反图：边 pkg -> dep 反转为 dep -> pkg。
    reverse: dict[str, list[str]] = {name: [] for name in nodes}
    for name in nodes:
        for dep in graph[name]:
            reverse[dep].append(name)

    # 第二次 DFS（反图）：按第一次完成顺序的逆序展开，每次展开即一个 SCC。
    assigned: set[str] = set()
    components: list[list[str]] = []
    for start in reversed(finish_order):
        if start in assigned:
            continue
        members: list[str] = []
        stack = [start]
        assigned.add(start)
        while stack:
            name = stack.pop()
            members.append(name)
            for nxt in reverse[name]:
                if nxt not in assigned:
                    assigned.add(nxt)
                    stack.append(nxt)
        components.append(sorted(members))

    return components


def build_install_plan(
    repo: Repository,
    *,
    root_name: str,
    current_lock: dict[str, Version],
    graph: dict[str, list[str]],
) -> dict:
    """把已激活依赖图压缩为 DAG 并输出依赖优先的并行安装批次。

    ``graph`` 为 :func:`app.paths.build_locked_graph` 产出的根可达子图
    （邻接已按名称排序去重）。``repo`` / ``current_lock`` 仅用于与其他
    锁后模块保持同一调用形态——有效锁上图已自洽，本函数不读取版本。
    返回 ``{"batches": [[item, ...], ...]}``：item 形如
    ``{"cyclic": false, "name": 包名}`` 或
    ``{"cyclic": true, "packages": [包名, ...]}``。
    """
    del repo, current_lock  # 与 /sbom 等模块同形；建图只需 graph

    # 分量成员排序后按成员元组确定分量编号，保证后续顺序与算法遍历无关。
    components = sorted(
        _strongly_connected_components(graph), key=lambda members: tuple(members)
    )
    component_of = {
        name: index
        for index, members in enumerate(components)
        for name in members
    }

    # 多成员分量必有环；单成员分量仅在存在自环时是循环分量。
    cyclic = [
        len(members) > 1 or members[0] in graph[members[0]]
        for members in components
    ]

    # 压缩为 DAG：边 component(pkg) -> component(dep)，分量内部的边丢弃。
    count = len(components)
    dag: list[set[int]] = [set() for _ in range(count)]
    for name, deps in graph.items():
        owner = component_of[name]
        for dep in deps:
            dependency = component_of[dep]
            if dependency != owner:
                dag[owner].add(dependency)

    # 最长路径分层（DAG 上的迭代后序遍历）：
    # level[c] = 0（无跨分量依赖）或 max(level[d] + 1 for d in dag[c])。
    level: dict[int, int] = {}
    for start in range(count):
        if start in level:
            continue
        stack: list[tuple[int, int]] = [(start, 0)]
        while stack:
            component, index = stack[-1]
            successors = sorted(dag[component])
            if index < len(successors):
                nxt = successors[index]
                stack[-1] = (component, index + 1)
                if nxt not in level:
                    stack.append((nxt, 0))
            else:
                level[component] = (
                    0
                    if not dag[component]
                    else max(level[d] + 1 for d in dag[component])
                )
                stack.pop()

    # 最长路径层号从 0 起连续（层 k 的分量沿递推边必有层 k-1 的后继）。
    max_level = max(level.values(), default=0)
    batches: list[list[dict]] = [[] for _ in range(max_level + 1)]
    for index, members in enumerate(components):  # 编号即批内字典序
        if cyclic[index]:
            item = {"cyclic": True, "packages": members}
        else:
            item = {"cyclic": False, "name": members[0]}
        batches[level[index]].append(item)

    # 不变量：根包可达图中每个节点都从根可达，根分量沿 DAG 边可到达任一
    # 分量，其层号必为最大值，即根包所在分量处于最后一批。
    root_component = component_of[root_name]
    assert level[root_component] == max_level

    return {"batches": batches}
