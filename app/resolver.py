"""确定性回溯依赖求解器。

规则：
* 同一个包（PEP 503 规范化名）全局只能选定一个版本；
* 候选版本严格按 PEP 440 从高到低尝试；
* 对每个包，沿所有传递路径收集到的全部约束必须同时满足；
* 新约束与已选版本冲突、或交集下没有候选时，沿选择点回溯尝试更低版本；
* 已选定的包再次被要求（含依赖环、菱形依赖）时不重复展开，只校验约束；
* 结果与冲突报告均按名称/版本排序，不依赖输入字典顺序。

冲突报告通过 chosen_for（每个包由哪一条需求首次触发展开）重建
“根需求 → …… → 冲突包”的约束来源链。

升级模式（POST /upgrade 使用，见 upgrade()）：
* 逐一枚举严格高于当前版本的目标候选（降序），钉住 ``==版本`` 后整体求解，
  第一个存在可行解的候选即为升级目标版本；
* 预发布候选默认遵循 allow_prereleases 开关；目标包即根包时，用户提交的
  根约束按 PEP 440 跟随语义放行其显式提到的预发布版本（升级器内部生成的
  ``==候选版本`` 钉选不参与该判定）；
* 对确定的钉版本，求解器不再返回首个解，而是按既定确定性顺序枚举全部解，
  保留“非目标包相对 current_lock 的新增/删除/版本变化数量”最少的解；
  数量相同时，枚举顺序保证先遇到的（即普通模式会选中的）解胜出；
* 枚举按分支定界剪枝：已选包中已与 current_lock 不同的数量是最终成本的
  下界（选择集沿分支只增不减），下界不优于当前最优即剪枝；
* 普通 /resolve 路径不进入优化模式，行为与性能特征完全不变。

反事实模式（POST /explain-version 使用，见 resolve_forced()）：
* 以与根需求并列的根级 ``==版本`` 约束钉住目标包后整体求解，其余规则
  （MRV、高版本优先、回溯、预发布跟随语义、尝试上限）与普通 /resolve
  完全一致；不进入升级优化模式，返回确定性顺序下的首个解。

请求级共享预算（POST /resolve-matrix、/lock-groups 使用）：
* 同一次请求内为每个目标环境新建的 Resolver 传入同一个
  SharedAttemptBudget：候选尝试先受本实例 attempt_limit 约束（单环境
  /resolve 的既有上限语义不变），再向共享预算计费；
* 共享预算用尽时本次尝试被拒绝，_solve 立即上抛 _BUDGET_SENTINEL，
  resolve() 转抛 SharedBudgetExceeded，由路由层停止后续环境的求解。
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field

from packaging.specifiers import SpecifierSet
from packaging.version import Version

from .repository import Candidate, Repository, canonical, version_satisfies

# 尝试候选版本的总次数上限，防止恶意快照造成指数级搜索。
DEFAULT_ATTEMPT_LIMIT = 100_000

# 依赖链深度护栏：超过该深度视为快照异常，返回 409 而非崩溃。
DEFAULT_DEPTH_LIMIT = 5_000

# 求解器是递归下降的（每展开一个未决包下沉一层），把解释器栈抬高，
# 让 DEFAULT_DEPTH_LIMIT 以内的链都能处理。
sys.setrecursionlimit(max(sys.getrecursionlimit(), DEFAULT_DEPTH_LIMIT + 1_000))

_ROOT = "root"  # 根请求在来源链 / 依赖边中的虚拟声明方


class ResolutionLimit(RuntimeError):
    """搜索超过尝试次数上限。"""


class SharedBudgetExceeded(RuntimeError):
    """请求级共享求解预算耗尽（多个 Resolver 累计的候选尝试次数超限）。"""


# _solve 的返回哨兵：
# None=约束冲突（正常回溯失败）；
# _LIMIT_SENTINEL=超过本求解器实例的尝试/深度上限；
# _BUDGET_SENTINEL=超过请求级共享预算（立即停止整个请求的后续求解）。
_LIMIT_SENTINEL: object = object()
_BUDGET_SENTINEL: object = object()


class SharedAttemptBudget:
    """多个 Resolver 实例共享、跨环境累计的候选尝试预算。

    用于 /resolve-matrix 与 /lock-groups：同一次请求内各环境的候选
    尝试次数累加到 ``used``，``charge`` 在累计值超过 ``limit`` 时返回
    False（调用方立即放弃该次尝试并沿递归上抛 _BUDGET_SENTINEL）。
    预算只统计真正进入候选循环的尝试，与单实例 attempts 计数同源。
    """

    __slots__ = ("limit", "used")

    def __init__(self, limit: int):
        if limit <= 0:
            raise ValueError("共享尝试预算必须为正整数")
        self.limit = limit
        self.used = 0

    def charge(self, count: int = 1) -> bool:
        """登记 count 次尝试并返回该次尝试是否被允许。

        预算已满（``used`` 恒不超过 ``limit``）时拒绝，由调用方中止求解；
        恰好用尽预算（used==limit）的那次尝试仍允许执行，下一次才被拒绝，
        因此超限时 ``used`` 恰等于 ``limit``，可直接用于对外报告。
        """
        if self.used >= self.limit:
            return False
        self.used = min(self.limit, self.used + count)
        return True


@dataclass(frozen=True)
class Requirement:
    """一条施加在 subject 上的约束及其来源边。"""

    subject: str
    spec: SpecifierSet
    raw_spec: str
    # 来源：(声明方包名, 声明方版本)；根需求为 None。
    origin: tuple[str, str] | None
    # 声明方依赖列表中的序号（稳定排序用）。
    order: int


@dataclass
class State:
    """一次分支中的求解状态；回溯通过对每次尝试拷贝状态实现。

    clone() 采用浅拷贝：可变容器（dict / 各约束列表 / 边集合）只在
    本层真正修改时才复制（写时复制），使深依赖链下的回溯保持线性成本。
    """

    # 已折叠（已选定）包的全部需求，按折叠顺序排列。
    constraints: dict[str, list[Requirement]] = field(default_factory=dict)
    selection: dict[str, Version] = field(default_factory=dict)
    # 每个包是被哪一条需求首次触发展开的（来源链回溯用）。
    chosen_for: dict[str, Requirement] = field(default_factory=dict)
    # 依赖边：(声明方包, 声明方版本, 被依赖包, 原始约束)
    edges: set[tuple[str, str, str, str]] = field(default_factory=set)

    def clone(self) -> State:
        # 浅拷贝即可：本层只会 (a) 给 dict 增加新键，或
        # (b) 通过 _replace_constraints / 复制后的 edges 集合修改既有值。
        return State(
            constraints=dict(self.constraints),
            selection=dict(self.selection),
            chosen_for=dict(self.chosen_for),
            edges=self.edges,  # 占位；首次 add 前必须先 copy（见 add_edge）
        )

    def add_edge(self, edge: tuple[str, str, str, str]) -> None:
        # 写时复制：与父分支共享的 set 在首次写入时复制。
        self.edges = self.edges | {edge}

    def append_constraint(self, subject: str, reqs: list[Requirement]) -> None:
        """折叠（覆盖）某包的约束列表（新列表，不影响共享的旧列表）。"""
        self.constraints[subject] = reqs


@dataclass(frozen=True)
class ChainLink:
    """来源链上的一跳。"""

    package: str | None  # None 表示根请求
    version: str | None
    requires: str  # 该跳施加的原始约束文本


@dataclass(frozen=True)
class ConflictReport:
    subject: str
    kind: str  # "incompatible" | "no_candidates"
    message: str
    chains: tuple[tuple[ChainLink, ...], ...]
    partial_selection: dict[str, str]


def _combined_spec(reqs: list[Requirement]) -> SpecifierSet:
    spec = SpecifierSet()
    for r in reqs:
        spec &= r.spec
    return spec


def _req_sort_key(r: Requirement) -> tuple:
    # 根需求恒在最前；其后按声明方、版本、声明序号、约束文本排序。
    if r.origin is None:
        return (0, "", "", -1, r.raw_spec)
    return (1, r.origin[0], r.origin[1], r.order, r.raw_spec)


def _chain_for(req: Requirement | None, state: State) -> tuple[ChainLink, ...]:
    """沿 chosen_for 重建一条需求的来源链：根请求 → …… → 该需求。"""
    links: list[ChainLink] = []
    seen: set[str] = set()
    cur: Requirement | None = req
    while cur is not None:
        if cur.subject in seen:  # 环保护（来源链本应是树）
            break
        seen.add(cur.subject)
        if cur.origin is None:
            links.append(ChainLink(None, None, cur.raw_spec))
            cur = None
        else:
            links.append(ChainLink(cur.origin[0], cur.origin[1], cur.raw_spec))
            cur = state.chosen_for.get(cur.origin[0])
    links.reverse()
    return tuple(links)


def _chain_key(chain: tuple[ChainLink, ...]) -> tuple:
    return tuple(
        (link.package or "", link.version or "", link.requires) for link in chain
    )


class Resolver:
    def __init__(
        self,
        repository: Repository,
        *,
        allow_prereleases: bool = False,
        attempt_limit: int = DEFAULT_ATTEMPT_LIMIT,
        depth_limit: int = DEFAULT_DEPTH_LIMIT,
        shared_budget: SharedAttemptBudget | None = None,
    ):
        self.repo = repository
        self.allow_prereleases = allow_prereleases
        self.attempt_limit = attempt_limit
        self.depth_limit = depth_limit
        # 可选的请求级共享预算：/resolve-matrix、/lock-groups 为同一次请求
        # 内的每个环境传入同一个实例累计计数；None 表示单环境接口，
        # 只受 attempt_limit / depth_limit 约束，语义不变。
        self.shared_budget = shared_budget
        self.attempts = 0
        self.max_depth = 0
        # subject -> 跨失败分支累积的去重来源链。
        self._collected: dict[str, set[tuple[ChainLink, ...]]] = {}
        self._kind: dict[str, str] = {}
        self._message: dict[str, str] = {}
        self._snapshot: dict[str, str] = {}
        # 升级优化模式：_opt_reference 非 None 时枚举全部解，
        # 保留相对 reference（current_lock）变化最少的解（见 resolve_optimal）。
        self._opt_reference: dict[str, Version] | None = None
        self._opt_target: str | None = None
        self._best_state: State | None = None
        self._best_cost: float = float("inf")

    # ------------------------------------------------------------------ #
    # 版本匹配
    # ------------------------------------------------------------------ #
    def _version_satisfies(self, version: Version, spec: SpecifierSet) -> bool:
        return version_satisfies(
            version, spec, allow_prereleases=self.allow_prereleases
        )

    def _eligible(self, subject: str, spec: SpecifierSet) -> list[Candidate]:
        # 仓库候选已按版本降序排列，过滤后顺序不变。
        return [
            cand
            for cand in self.repo.candidates(subject)
            if self._version_satisfies(cand.version, spec)
        ]

    # ------------------------------------------------------------------ #
    # 冲突记录
    # ------------------------------------------------------------------ #
    def _record(
        self,
        subject: str,
        kind: str,
        message: str,
        reqs: list[Requirement],
        state: State,
    ) -> None:
        bucket = self._collected.setdefault(subject, set())
        bucket.update(_chain_for(r, state) for r in reqs)
        self._kind[subject] = kind
        self._message[subject] = message
        if not self._snapshot:
            self._snapshot = {
                pkg: str(ver) for pkg, ver in sorted(state.selection.items())
            }

    def _no_candidate_message(
        self, subject: str, combined: SpecifierSet
    ) -> str:
        spec_text = str(combined) or "（无约束）"
        if not self.repo.known(subject):
            return f"包 {subject} 不在仓库快照中，但约束要求 {spec_text}"
        available = ", ".join(str(c.version) for c in self.repo.candidates(subject))
        return (
            f"包 {subject} 在约束交集 {spec_text} 下没有可满足的版本；"
            f"快照中的版本（降序）：{available or '无'}"
        )

    # ------------------------------------------------------------------ #
    # 入口
    # ------------------------------------------------------------------ #
    def resolve(
        self,
        root_name: str,
        root_spec: SpecifierSet,
        root_raw: str,
        extra_requirements: list[Requirement] | None = None,
    ) -> State | None:
        """成功返回最终 State；约束无解返回 None；超上限抛 ResolutionLimit。

        ``extra_requirements`` 是与根需求并列的额外根级约束（升级模式用来
        钉住目标包版本）；普通 /resolve 不传，行为不变。优化模式下返回的
        是相对 reference 变化最少的解（见 resolve_optimal）。
        """
        root_name = canonical(root_name)
        root_req = Requirement(root_name, root_spec, root_raw.strip() or "*", None, 0)
        state = State()
        result = self._solve(state, [root_req, *(extra_requirements or ())], depth=0)
        if result is _BUDGET_SENTINEL:
            # 请求级共享预算耗尽：触发环境与对外消息由路由层拼装。
            assert self.shared_budget is not None
            raise SharedBudgetExceeded(
                f"请求级共享求解预算耗尽：已尝试 {self.shared_budget.used} 个候选版本"
            )
        if result is _LIMIT_SENTINEL:
            if self.max_depth > self.depth_limit:
                raise ResolutionLimit(
                    f"依赖链深度超过上限（{self.depth_limit}）"
                )
            raise ResolutionLimit("搜索超过尝试次数上限")
        if self._opt_reference is not None:
            # 优化模式下 _solve 枚举全部解后恒返回 None，最优解在 _best_state。
            return self._best_state
        return result  # type: ignore[return-value]

    # ------------------------------------------------------------------ #
    # 升级（POST /upgrade）
    # ------------------------------------------------------------------ #
    def higher_candidates(
        self,
        target: str,
        current_version: Version,
        *,
        root_name: str | None = None,
        root_spec: SpecifierSet | None = None,
    ) -> list[Candidate]:
        """严格高于 current_version 的候选（遵循预发布开关），按版本降序。

        预发布候选在 ``allow_prereleases=False`` 时默认排除；唯一例外：
        目标包即根包（PEP 503 规范化后同名），且用户提交的根约束按
        PEP 440 跟随语义显式放行预发布（如 ``==2.0rc1`` / ``>=2.0a1``，
        谓词 ``prereleases=True``）——此时满足根约束的预发布候选照常
        参与枚举，与 /resolve 对根包的约束处理一致。判定只依据用户提交
        的根约束：升级器内部为逐候选求解生成的 ``==候选版本`` 钉选不参与
        （否则每个预发布候选都会被自己的钉选放行，默认排除形同虚设）。
        """
        target_is_root = root_name is not None and canonical(root_name) == target
        higher = []
        for cand in self.repo.candidates(target):
            if cand.version <= current_version:
                continue
            if not self.allow_prereleases and (
                cand.version.is_prerelease or cand.version.is_devrelease
            ):
                follows_user_spec = (
                    target_is_root
                    and root_spec is not None
                    and version_satisfies(
                        cand.version, root_spec, allow_prereleases=False
                    )
                )
                if not follows_user_spec:
                    continue
            higher.append(cand)
        return higher

    def upgrade(
        self,
        root_name: str,
        root_spec: SpecifierSet,
        root_raw: str,
        *,
        target: str,
        current_version: Version,
        reference: dict[str, Version],
    ) -> State | None:
        """在整体可解析的前提下把 target 升到尽可能高的版本。

        仅考虑严格高于 current_version 的候选（降序尝试）；对每个候选以
        根级 ``==版本`` 约束钉住后整体求解，第一个存在可行解的候选即为
        目标版本。对该版本枚举全部解，返回非目标包相对 reference
        （current_lock）变化最少的解；数量相同按既定确定性顺序取先遇到者。
        所有更高候选均无解时返回 None；超上限抛 ResolutionLimit。

        预发布候选默认遵循 ``allow_prereleases`` 开关；target 与根包
        规范化后同名时，用户提交的根约束按 PEP 440 跟随语义放行其显式
        提到的预发布版本（见 higher_candidates）。
        """
        target = canonical(target)
        for cand in self.higher_candidates(
            target,
            current_version,
            root_name=root_name,
            root_spec=root_spec,
        ):
            pin = Requirement(
                target,
                SpecifierSet(f"=={cand.version}"),
                f"=={cand.version}",
                None,
                0,
            )
            state = self.resolve_optimal(
                root_name,
                root_spec,
                root_raw,
                pin=pin,
                reference=reference,
                target=target,
            )
            if state is not None:
                return state
        return None

    def resolve_optimal(
        self,
        root_name: str,
        root_spec: SpecifierSet,
        root_raw: str,
        *,
        pin: Requirement,
        reference: dict[str, Version],
        target: str,
    ) -> State | None:
        """在 pin 约束下枚举全部解，返回相对 reference 变化最少的状态。"""
        self._opt_reference = reference
        self._opt_target = canonical(target)
        self._best_state = None
        self._best_cost = float("inf")
        try:
            return self.resolve(
                root_name, root_spec, root_raw, extra_requirements=[pin]
            )
        finally:
            self._opt_reference = None
            self._opt_target = None
            self._best_state = None
            self._best_cost = float("inf")

    # ------------------------------------------------------------------ #
    # 反事实求解（POST /explain-version）
    # ------------------------------------------------------------------ #
    def resolve_forced(
        self,
        root_name: str,
        root_spec: SpecifierSet,
        root_raw: str,
        *,
        target: str,
        target_version: Version,
    ) -> State | None:
        """把 target 钉在指定版本做反事实整体求解。

        以与根需求并列的根级 ``==版本`` 约束钉住目标包（与升级模式的钉版本
        机制相同），除此之外的一切规则——MRV、高版本优先、回溯、预发布
        跟随语义（显式 ``==预发布`` 约束仍接受该预发布）、尝试上限——与
        普通 /resolve 完全一致；不进入优化模式，返回确定性顺序下的首个解。
        无解返回 None，超上限抛 ResolutionLimit。
        """
        target = canonical(target)
        pin = Requirement(
            target,
            SpecifierSet(f"=={target_version}"),
            f"=={target_version}",
            None,
            0,
        )
        return self.resolve(
            root_name, root_spec, root_raw, extra_requirements=[pin]
        )

    # ------------------------------------------------------------------ #
    # 升级成本（非目标包相对 current_lock 的变化数）
    # ------------------------------------------------------------------ #
    def _lower_bound(self, state: State) -> int:
        """已选包中已与 reference 不同的数量（最终成本的单调下界）。"""
        assert self._opt_reference is not None
        ref = self._opt_reference
        target = self._opt_target
        return sum(
            1
            for pkg, ver in state.selection.items()
            if pkg != target and ref.get(pkg) != ver
        )

    def _change_cost(self, state: State) -> int:
        """完整解的成本：新增 + 删除 + 版本变化的非目标包数量。"""
        assert self._opt_reference is not None
        ref = self._opt_reference
        target = self._opt_target
        cost = self._lower_bound(state)  # 新增或版本变化的已选包
        cost += sum(
            1
            for pkg in ref
            if pkg != target and pkg not in state.selection  # 被删除的包
        )
        return cost

    # ------------------------------------------------------------------ #
    # 递归主体
    # ------------------------------------------------------------------ #
    def _solve(
        self, in_state: State, pending: list[Requirement], *, depth: int
    ) -> State | object:
        # 先克隆：本层的约束折叠 / 选边都发生在私有状态上，
        # 这样候选分支全部失败时不会污染父分支（回溯正确性）。
        state = in_state.clone()
        self.max_depth = max(self.max_depth, depth)
        if depth > self.depth_limit:
            return _LIMIT_SENTINEL

        # --- 第一步：把待处理需求按包归组 ------------------------------
        groups: dict[str, list[Requirement]] = {}
        for r in sorted(pending, key=_req_sort_key):
            groups.setdefault(r.subject, []).append(r)

        # --- 第二步：已选定的包（依赖环 / 菱形）只校验，绝不重新展开 ----
        for subject in sorted(groups):
            if subject not in state.selection:
                continue
            new_reqs = groups.pop(subject)
            reqs = state.constraints[subject] + new_reqs
            combined = _combined_spec(reqs)
            selected = state.selection[subject]
            for r in new_reqs:
                if r.origin is not None:
                    state.add_edge(
                        (r.origin[0], r.origin[1], subject, r.raw_spec)
                    )
            if not self._version_satisfies(selected, combined):
                self._record(
                    subject,
                    "incompatible",
                    f"已选 {subject}=={selected} 与约束交集 {combined or '（无约束）'} 不兼容",
                    reqs,
                    state,
                )
                return None
            state.append_constraint(subject, reqs)

        if not groups:
            if self._opt_reference is None:
                return state  # 所有需求都已落在已选包上且全部满足
            # 优化模式：记录最优解后返回 None，让父层继续枚举其余分支。
            cost = self._change_cost(state)
            if cost < self._best_cost:
                self._best_cost = cost
                self._best_state = state
            return None

        # --- 第三步：MRV——可满足候选最少的包先展开（名称次序兜底） -----
        def mrv_key(name: str) -> tuple[int, str]:
            combined = _combined_spec(groups[name])
            return (len(self._eligible(name, combined)), name)

        chosen = min(groups, key=mrv_key)
        chosen_reqs = sorted(groups.pop(chosen), key=_req_sort_key)
        combined = _combined_spec(chosen_reqs)
        eligible = self._eligible(chosen, combined)

        # 折叠约束、来源边与触发需求。
        state.append_constraint(chosen, chosen_reqs)
        for r in chosen_reqs:
            if r.origin is not None:
                state.add_edge(
                    (r.origin[0], r.origin[1], chosen, r.raw_spec)
                )
        state.chosen_for[chosen] = min(
            chosen_reqs, key=lambda r: (len(_chain_for(r, state)), _chain_key(_chain_for(r, state)))
        )

        if not eligible:
            self._record(
                chosen,
                "no_candidates",
                self._no_candidate_message(chosen, combined),
                chosen_reqs,
                state,
            )
            return None

        # 其余未决需求原样带入每个候选分支。
        rest = [r for reqs in groups.values() for r in reqs]

        # --- 第四步：候选版本从高到低，逐版本克隆分支尝试 --------------
        for cand in eligible:
            self.attempts += 1
            # 单实例上限优先（与 /resolve 的既有上限语义一致）：命中即按本
            # 环境 limit 处理，不再占用请求级共享预算。
            if self.attempts > self.attempt_limit:
                return _LIMIT_SENTINEL
            # 请求级共享预算：预算已被本请求前序尝试用完时立即中止，
            # 沿递归上抛以停止本次请求后续环境的求解。
            if self.shared_budget is not None and not self.shared_budget.charge():
                return _BUDGET_SENTINEL

            branch = state.clone()
            branch.selection[chosen] = cand.version

            # 优化模式剪枝：选择集沿分支只增不减，下界不劣于当前最优即跳过。
            if (
                self._opt_reference is not None
                and self._lower_bound(branch) >= self._best_cost
            ):
                continue

            introduced = [
                Requirement(
                    dep.name,
                    dep.spec,
                    dep.raw_spec,
                    (chosen, str(cand.version)),
                    order,
                )
                for order, dep in enumerate(cand.deps)
            ]
            result = self._solve(branch, introduced + rest, depth=depth + 1)
            if result is _BUDGET_SENTINEL:
                return _BUDGET_SENTINEL
            if result is _LIMIT_SENTINEL:
                return _LIMIT_SENTINEL
            if result is not None:
                return result
        return None

    # ------------------------------------------------------------------ #
    # 输出
    # ------------------------------------------------------------------ #
    def build_output(self, state: State, root_name: str) -> dict:
        root_name = canonical(root_name)
        locked = {pkg: str(ver) for pkg, ver in sorted(state.selection.items())}

        edge_out = [
            {"from": f"{pkg}=={ver}", "to": dep, "specifier": raw}
            for pkg, ver, dep, raw in sorted(state.edges)
        ]
        # 根请求 -> 根包的边放在最前。
        root_spec = state.constraints[root_name][0].raw_spec
        edge_out = [{"from": _ROOT, "to": root_name, "specifier": root_spec}] + edge_out

        return {
            "status": "ok",
            "root": root_name,
            "root_version": str(state.selection[root_name]),
            "locked": locked,
            "edges": edge_out,
        }

    def build_conflicts(self, *, limit: bool = False) -> dict:
        conflicts = [
            ConflictReport(
                subject=subject,
                kind=self._kind[subject],
                message=self._message[subject],
                chains=tuple(sorted(self._collected[subject], key=_chain_key)),
                partial_selection=dict(self._snapshot),
            )
            for subject in sorted(self._collected)
        ]
        if limit:
            status = "limit"
            message = (
                f"解析在尝试 {self.attempts} 个候选版本后超过上限；"
                "以下为搜索过程中记录的冲突点"
            )
        else:
            status = "conflict"
            subjects = "、".join(c.subject for c in conflicts) or "未知"
            message = f"依赖约束无解，冲突包：{subjects}"
        return {"status": status, "message": message, "_conflicts": conflicts}
