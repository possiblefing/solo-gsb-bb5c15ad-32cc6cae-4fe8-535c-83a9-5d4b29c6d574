"""FastAPI 入口：全部数据随请求在本地内存中处理。

* POST /resolve     提交仓库快照 + 根包 + 版本约束 + 目标环境（PEP 508 marker
  在请求环境下求值），返回锁定清单或冲突来源链
* POST /resolve-matrix
  同一份快照 + 根约束 + 2～8 个带唯一 id 的目标环境：按 id 稳定顺序逐
  环境复用 /resolve 规则求解，全部成功时返回按 id 排序的各环境 locked
  与按包名排序的跨环境版本矩阵（shared/divergent）；任一环境无解则整体
  409，列出各失败环境的原冲突结果。同请求各环境的候选尝试次数累计到
  请求级共享预算（环境变量 MATRIX_ATTEMPT_LIMIT），耗尽即立即停止后续
  求解并返回 409 status=limit（触发环境、已用次数与上限）
* POST /lock-groups
  请求同 /resolve-matrix：先按 id 稳定顺序逐环境复用 /resolve 规则各求
  一份候选锁（共享同一请求级求解预算，预算耗尽同样立即返回 409
  status=limit），任一环境无解则整体 409 并保留该环境的冲突来源链；全部
  有解后把去重后的每份候选锁在所有环境上按 /audit-lock 规则交叉校验，
  精确选择“覆盖全部环境的锁文件数量最少”的锁组，并列最优按锁内容及
  环境 id 的稳定序裁决；响应按稳定组 id 排列，每组给出覆盖环境与锁内容，
  同一输入结果确定
* POST /upgrade     在 /resolve 语义基础上附加 current_lock 与单个升级目标：
  仅考虑严格高于当前版本的候选，取能完成整体解析的最高版本，并在该版本
  的所有有效解中最小化非目标包相对 current_lock 的变化数量
* POST /audit-lock  只审计不求解：按 current_lock 的锁定版本从根包遍历
  已激活依赖，报告 missing/unavailable/constraint_mismatch/extraneous
* POST /dependency-paths
  先按 /audit-lock 规则校验 current_lock；无效返回 409 审计问题，
  有效则按锁定版本与目标环境已激活依赖建图，返回根包到目标包的
  全部最短包路径（菱形保留等长路径，环安全、确定性排序）；最短路径
  条数超过固定预算 1000 时返回 409 status=limit（饱和计数 1001），
  不构造路径列表
* POST /install-plan
  先按 /audit-lock 规则校验 current_lock；无效返回 409 审计问题，
  有效则只对根可达包按已激活依赖建图，把强连通分量压缩为 DAG，
  输出依赖优先的并行安装 batches：同一循环分量作为一个 batch item，
  标记 cyclic 并列出内部包；批次/分量/包名确定性排序，依赖先于
  依赖它的包，根包所在分量处于最后一批
* POST /sbom
  先按 /audit-lock 规则校验 current_lock；无效返回 409 审计问题，
  有效则沿已激活依赖图生成确定性 JSON 清单：每包含规范化名称、版本、
  PURL、依赖名称与候选版本携带的 source_url/sha256/license 元数据；
  缺失元数据只形成 warnings，不阻断导出；结果按包名排序
* POST /license-policy
  先按 /audit-lock 规则校验 current_lock；无效返回 409 审计问题，
  有效则解析各可达包锁定版本 metadata.license 的 SPDX AND/OR/括号
  表达式，按请求的 allow/deny 标识集合做三态判定，返回按包名排序的
  violations 与 unknowns（各附根包到该包的全部最短路径；某命中包
  路径条数超过固定预算 1000 时整体返回 409 status=limit，按包名
  顺序命中首个超限项）；
  非法 SPDX 表达式或 allow/deny 规则重叠返回 422
* POST /lock-diff
  同一份仓库快照与目标环境下提交 before_lock、after_lock 两份锁定清单：
  各自独立复用 /audit-lock 规则校验，任一无效即整体 409 并分别标注
  before/after 的审计问题；均有效时只比较两份锁的根可达包，按规范化
  包名输出 added/removed/upgraded/downgraded（版本方向按 PEP 440），
  每个变化项附其在前后依赖图中的全部最短根路径（不存在的一侧为空数组）；
  某变化项路径条数超过固定预算 1000 时整体返回 409 status=limit
  （按既有包名顺序命中首个超限项）
* POST /explain-version
  沿用 /resolve 的仓库、根约束与目标环境，先按原规则求出基准锁定清单
  （目标包不在其中即不可达，返回 422），再把 target_package 钉在
  target_version 上做反事实整体求解：可行时返回新锁与相对基准锁的
  added/removed/changed；不可行时返回 409，复用约束来源链说明阻塞原因
* GET  /healthz     健康检查
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from packaging.version import Version

from .audit import audit_lock
from .config import MATRIX_ATTEMPT_LIMIT
from .install_plan import build_install_plan
from .license_policy import evaluate_license_policy
from .lock_diff import diff_locks
from .lock_groups import (
    CandidateLock,
    lock_content_key,
    lock_group_id,
    select_lock_groups,
)
from .paths import PathCountLimit, build_locked_graph, shortest_paths
from .repository import (
    Repository,
    SnapshotError,
    build_repository,
    canonical,
    parse_current_lock,
    parse_root_specifier,
    parse_target_version,
)
from .resolver import (
    ResolutionLimit,
    Resolver,
    SharedAttemptBudget,
    SharedBudgetExceeded,
)
from .sbom import build_sbom
from .schemas import (
    AuditLockRequest,
    AuditLockResponse,
    DependencyPathsRequest,
    DependencyPathsResponse,
    ExplainVersionRequest,
    ExplainVersionResponse,
    InstallPlanRequest,
    InstallPlanResponse,
    InvalidLockResponse,
    InvalidSnapshotResponse,
    LicensePolicyRequest,
    LicensePolicyResponse,
    LockDiffInvalidResponse,
    LockDiffRequest,
    LockDiffResponse,
    LockGroupsRequest,
    LockGroupsResponse,
    ResolveMatrixRequest,
    ResolveMatrixResponse,
    MatrixLimitResponse,
    MatrixUnresolvedResponse,
    PathLimitResponse,
    ResolveRequest,
    ResolveResponse,
    SbomRequest,
    SbomResponse,
    UnresolvedResponse,
    UpgradeRequest,
    UpgradeResponse,
)
from .spdx import LicenseExpressionError, parse_policy_sets

app = FastAPI(
    title="本地依赖解析 API",
    description=(
        "基于 Python packaging（PEP 440/503/508）与回溯搜索的依赖求解器。"
        "所有仓库数据与目标环境随请求提交，本地解析，不访问任何远程索引、"
        "不读取宿主机平台信息。"
    ),
    version="1.10.0",
)


def _conflict_payload(raw: dict) -> dict:
    """把 Resolver.build_conflicts() 的内部结构转为对外 JSON。"""
    return {
        "status": raw["status"],
        "message": raw["message"],
        "conflicts": [
            {
                "subject": c.subject,
                "kind": c.kind,
                "message": c.message,
                "constraints": [
                    {
                        "chain": [
                            {
                                "package": link.package,
                                "version": link.version,
                                "requires": link.requires,
                            }
                            for link in chain
                        ]
                    }
                    for chain in c.chains
                ],
                "partial_selection": c.partial_selection,
            }
            for c in raw["_conflicts"]
        ],
    }


@app.get("/healthz", summary="健康检查")
def healthz() -> dict:
    return {"status": "ok"}


def _resolve_once(
    *,
    repository_payload: dict,
    target_environment: dict,
    root_canonical: str,
    specifier: str,
    allow_prereleases: bool,
    shared_budget: SharedAttemptBudget | None = None,
) -> tuple[dict | None, dict | None]:
    """按 /resolve 的既有规则对单个目标环境求解一次。

    返回 ``(ok_payload, conflict_payload)``，二者恰有一个非 None：

    * 成功：``ok_payload`` 为 build_output 的 200 响应体；
    * 无解或超单环境上限：``conflict_payload`` 为 _conflict_payload 的 409 响应体。

    ``shared_budget`` 非 None 时（/resolve-matrix、/lock-groups），候选
    尝试还会计入请求级共享预算；预算耗尽抛出 SharedBudgetExceeded，由
    调用方停止后续环境的求解。快照/约束构造期的 SnapshotError 不在此
    捕获，由调用方映射为 422。
    """
    repo = build_repository(repository_payload, target_environment)
    root_spec = parse_root_specifier(specifier)

    resolver = Resolver(
        repo,
        allow_prereleases=allow_prereleases,
        shared_budget=shared_budget,
    )
    try:
        state = resolver.resolve(root_canonical, root_spec, specifier)
    except ResolutionLimit:
        return None, _conflict_payload(resolver.build_conflicts(limit=True))

    if state is not None:
        return resolver.build_output(state, root_canonical), None
    return None, _conflict_payload(resolver.build_conflicts())


def _ordered_matrix_environments(payload: dict) -> list[dict]:
    """请求环境按 id 的稳定顺序排列。

    两个多环境接口必须按 id 升序逐环境求解：使请求级共享预算的截断位置
    （在哪个环境耗尽预算）只取决于环境集合、与提交顺序无关，从而输入
    重排后 409 截断响应也逐字节一致。
    """
    return sorted(payload["target_environments"], key=lambda env: env["id"])


def _matrix_limit_payload(
    *, env_id: str, budget: SharedAttemptBudget
) -> dict:
    """请求级共享预算耗尽的 409 响应体。"""
    return {
        "status": "limit",
        "message": (
            f"请求级共享求解预算在环境 {env_id!r} 的求解中耗尽："
            f"各目标环境累计已尝试 {budget.used} 个候选版本，"
            f"达到上限 {budget.limit}；后续环境已停止求解"
        ),
        "environment": env_id,
        "used": budget.used,
        "limit": budget.limit,
    }


def _path_limit_payload(exc: PathCountLimit) -> dict:
    """最短路径条数超限的 409 响应体（三个路径查询接口同形）。

    ``used`` 为饱和计数（恒为 limit+1）：分层菱形下真实条数随层数指数
    增长，计数到 limit+1 即饱和停止，不构造任何路径列表。
    """
    return {
        "status": "limit",
        "message": (
            f"根包到目标包 {exc.target!r} 的最短路径条数超过预算："
            f"饱和计数 {exc.used}，超过上限 {exc.limit}；"
            "未构造路径列表"
        ),
        "target": exc.target,
        "used": exc.used,
        "limit": exc.limit,
    }


@app.post(
    "/resolve",
    summary="解析依赖并生成确定性锁定清单",
    response_model=ResolveResponse,
    responses={
        409: {"model": UnresolvedResponse, "description": "约束无解或超过搜索上限"},
        422: {"model": InvalidSnapshotResponse, "description": "快照或请求非法"},
    },
)
def resolve(request: ResolveRequest):
    root_canonical = canonical(request.root)
    payload = request.model_dump()

    try:
        repo = build_repository(payload["repository"], payload["target_environment"])
        root_spec = parse_root_specifier(request.specifier)
    except SnapshotError as exc:
        return JSONResponse(
            status_code=422,
            content={"status": "invalid_snapshot", "message": str(exc)},
        )

    if not repo.known(root_canonical):
        return JSONResponse(
            status_code=422,
            content={
                "status": "invalid_snapshot",
                "message": f"根包 {root_canonical!r} 不存在于仓库快照中",
            },
        )

    resolver = Resolver(repo, allow_prereleases=request.allow_prereleases)
    try:
        state = resolver.resolve(root_canonical, root_spec, request.specifier)
    except ResolutionLimit:
        return JSONResponse(
            status_code=409,
            content=_conflict_payload(resolver.build_conflicts(limit=True)),
        )

    if state is not None:
        return resolver.build_output(state, root_canonical)

    return JSONResponse(
        status_code=409,
        content=_conflict_payload(resolver.build_conflicts()),
    )


@app.post(
    "/resolve-matrix",
    summary="同一份快照在 2～8 个目标环境下分别求解并给出跨环境版本矩阵",
    response_model=ResolveMatrixResponse,
    responses={
        409: {
            "model": MatrixUnresolvedResponse | MatrixLimitResponse,
            "description": (
                "任一目标环境无解：列出各失败环境的原冲突结果（status=conflict）；"
                "或请求级共享求解预算耗尽（status=limit，立即停止后续环境求解）"
            ),
        },
        422: {"model": InvalidSnapshotResponse, "description": "快照或请求非法（含重复 id）"},
    },
)
def resolve_matrix(request: ResolveMatrixRequest):
    root_canonical = canonical(request.root)
    payload = request.model_dump()

    # 环境必须按 id 稳定顺序执行：请求级共享预算的截断位置、成功/失败
    # 集合与响应均只取决于环境集合，与提交顺序无关。
    ordered_environments = _ordered_matrix_environments(payload)

    # id 唯一性在路由层校验：Pydantic 的 pattern/min_length 负责格式，
    # 重复值在此返回 422，不进入任何求解。
    seen: set[str] = set()
    for env in request.target_environments:
        if env.id in seen:
            return JSONResponse(
                status_code=422,
                content={
                    "status": "invalid_snapshot",
                    "message": f"target_environments 的 id {env.id!r} 重复，必须唯一",
                },
            )
        seen.add(env.id)

    # marker 解析/求值与根约束非法属于 422；根包只查一次（与环境无关）。
    try:
        repo_known = build_repository(
            payload["repository"], ordered_environments[0]
        )
        parse_root_specifier(request.specifier)
    except SnapshotError as exc:
        return JSONResponse(
            status_code=422,
            content={"status": "invalid_snapshot", "message": str(exc)},
        )

    if not repo_known.known(root_canonical):
        return JSONResponse(
            status_code=422,
            content={
                "status": "invalid_snapshot",
                "message": f"根包 {root_canonical!r} 不存在于仓库快照中",
            },
        )

    # 逐环境独立求解：每个环境一个全新 Resolver，冲突收集互不干扰；
    # 但候选尝试次数累计到请求级共享预算。即使某环境已无解也继续跑完
    # 其余环境，以便 409 列出所有失败环境；仅共享预算耗尽时立即停止
    # 后续求解（返回 status=limit）。
    budget = SharedAttemptBudget(MATRIX_ATTEMPT_LIMIT)
    successes: dict[str, dict] = {}
    failures: list[dict] = []
    for env in ordered_environments:
        env_id = env["id"]
        try:
            ok, conflict = _resolve_once(
                repository_payload=payload["repository"],
                target_environment=env,
                root_canonical=root_canonical,
                specifier=request.specifier,
                allow_prereleases=request.allow_prereleases,
                shared_budget=budget,
            )
        except SnapshotError as exc:
            return JSONResponse(
                status_code=422,
                content={"status": "invalid_snapshot", "message": str(exc)},
            )
        except SharedBudgetExceeded:
            return JSONResponse(
                status_code=409,
                content=_matrix_limit_payload(env_id=env_id, budget=budget),
            )
        if ok is not None:
            successes[env_id] = ok
        else:
            assert conflict is not None
            failures.append({"id": env_id, **conflict})

    if failures:
        failures.sort(key=lambda f: f["id"])
        ids = "、".join(f["id"] for f in failures)
        return JSONResponse(
            status_code=409,
            content={
                "status": "conflict",
                "message": (
                    f"{len(failures)} 个目标环境无解（共 "
                    f"{len(request.target_environments)} 个）：{ids}"
                ),
                "failures": failures,
            },
        )

    # 全部成功：results 按 id 排序；matrix 按包名排序，逐包收集各环境版本。
    ordered_ids = sorted(successes)
    results = [
        {
            "id": env_id,
            "root_version": successes[env_id]["root_version"],
            "locked": successes[env_id]["locked"],
        }
        for env_id in ordered_ids
    ]
    all_packages = sorted(
        {pkg for ok in successes.values() for pkg in ok["locked"]}
    )
    matrix = []
    for pkg in all_packages:
        versions = {
            env_id: successes[env_id]["locked"].get(pkg) for env_id in ordered_ids
        }
        resolved = [v for v in versions.values() if v is not None]
        state = (
            "shared"
            if len(resolved) == len(ordered_ids)
            and len(set(resolved)) == 1
            else "divergent"
        )
        matrix.append({"name": pkg, "versions": versions, "state": state})

    return {
        "status": "ok",
        "root": root_canonical,
        "results": results,
        "matrix": matrix,
    }


@app.post(
    "/lock-groups",
    summary="用最少的锁文件覆盖全部目标环境：逐环境求解 + 跨环境审计 + 精确集合覆盖",
    response_model=LockGroupsResponse,
    responses={
        409: {
            "model": MatrixUnresolvedResponse | MatrixLimitResponse,
            "description": (
                "任一目标环境无解：列出各失败环境的原冲突结果（status=conflict）；"
                "或请求级共享求解预算耗尽（status=limit，立即停止后续环境求解）"
            ),
        },
        422: {"model": InvalidSnapshotResponse, "description": "快照或请求非法（含重复 id）"},
    },
)
def lock_groups(request: LockGroupsRequest):
    root_canonical = canonical(request.root)
    payload = request.model_dump()

    # 环境按 id 稳定顺序执行（与 /resolve-matrix 一致），保证共享预算
    # 截断位置与环境提交顺序无关。
    ordered_environments = _ordered_matrix_environments(payload)

    # id 唯一性在路由层校验（与 /resolve-matrix 完全一致）：重复值返回 422，
    # 不进入任何求解。
    seen: set[str] = set()
    for env in request.target_environments:
        if env.id in seen:
            return JSONResponse(
                status_code=422,
                content={
                    "status": "invalid_snapshot",
                    "message": f"target_environments 的 id {env.id!r} 重复，必须唯一",
                },
            )
        seen.add(env.id)

    # marker 解析/求值与根约束非法属于 422；根包只查一次（与环境无关）。
    try:
        repo_known = build_repository(
            payload["repository"], ordered_environments[0]
        )
        root_spec = parse_root_specifier(request.specifier)
    except SnapshotError as exc:
        return JSONResponse(
            status_code=422,
            content={"status": "invalid_snapshot", "message": str(exc)},
        )

    if not repo_known.known(root_canonical):
        return JSONResponse(
            status_code=422,
            content={
                "status": "invalid_snapshot",
                "message": f"根包 {root_canonical!r} 不存在于仓库快照中",
            },
        )

    # 第一步：逐环境独立复用 /resolve 规则求解；即使某环境已无解也继续跑完
    # 全部环境，以便 409 一次性列出所有失败环境（与 /resolve-matrix 同形）。
    # 各环境候选尝试累计到请求级共享预算，预算耗尽立即停止后续求解。
    budget = SharedAttemptBudget(MATRIX_ATTEMPT_LIMIT)
    env_locks: dict[str, dict[str, str]] = {}
    failures: list[dict] = []
    for env in ordered_environments:
        env_id = env["id"]
        try:
            ok, conflict = _resolve_once(
                repository_payload=payload["repository"],
                target_environment=env,
                root_canonical=root_canonical,
                specifier=request.specifier,
                allow_prereleases=request.allow_prereleases,
                shared_budget=budget,
            )
        except SnapshotError as exc:
            return JSONResponse(
                status_code=422,
                content={"status": "invalid_snapshot", "message": str(exc)},
            )
        except SharedBudgetExceeded:
            return JSONResponse(
                status_code=409,
                content=_matrix_limit_payload(env_id=env_id, budget=budget),
            )
        if ok is not None:
            env_locks[env_id] = ok["locked"]
        else:
            assert conflict is not None
            failures.append({"id": env_id, **conflict})

    if failures:
        failures.sort(key=lambda f: f["id"])
        ids = "、".join(f["id"] for f in failures)
        return JSONResponse(
            status_code=409,
            content={
                "status": "conflict",
                "message": (
                    f"{len(failures)} 个目标环境无解（共 "
                    f"{len(request.target_environments)} 个）：{ids}"
                ),
                "failures": failures,
            },
        )

    # 第二步：候选锁按内容去重（来自不同环境但锁内容相同的解只保留一份）。
    unique: dict[tuple[tuple[str, str], ...], dict[str, str]] = {}
    for env_id in sorted(env_locks):
        unique.setdefault(lock_content_key(env_locks[env_id]), env_locks[env_id])

    # 第三步：每份候选锁在每个环境上按 /audit-lock 的同一套规则交叉审计：
    # 无任何审计问题时该锁才可覆盖该环境（marker 按被审计环境求值）。
    # 每个环境的快照只构造一次，供全部候选锁复用。
    env_repos: dict[str, Repository] = {}
    for env in ordered_environments:
        try:
            env_repos[env["id"]] = build_repository(payload["repository"], env)
        except SnapshotError as exc:
            return JSONResponse(
                status_code=422,
                content={"status": "invalid_snapshot", "message": str(exc)},
            )

    candidates: list[CandidateLock] = []
    for locked in unique.values():
        try:
            current_lock = parse_current_lock(locked)
        except SnapshotError as exc:
            return JSONResponse(
                status_code=422,
                content={"status": "invalid_snapshot", "message": str(exc)},
            )
        covered: set[str] = set()
        for env_id, repo in env_repos.items():
            result = audit_lock(
                repo,
                root_name=root_canonical,
                root_spec=root_spec,
                root_raw=request.specifier,
                current_lock=current_lock,
                allow_prereleases=request.allow_prereleases,
            )
            if result["valid"]:
                covered.add(env_id)
        # 不变量：每个环境自己求出的候选锁在自身环境下必然通过审计。
        assert covered, "候选锁至少应通过其来源环境的审计"
        candidates.append(CandidateLock(locked=locked, covers=frozenset(covered)))

    # 第四步：精确选择覆盖全部环境的最少锁组（候选锁 ≤ 8，直接枚举子集），
    # 并列最优按锁内容及环境 id 的稳定序裁决。
    selected = select_lock_groups(
        candidates, [env["id"] for env in ordered_environments]
    )
    groups = [
        {
            "id": lock_group_id(cand.locked),
            "environments": sorted(cand.covers),
            "locked": {name: cand.locked[name] for name in sorted(cand.locked)},
        }
        for cand in selected
    ]
    # 响应按稳定组 id（锁内容指纹）排列；指纹前缀极小概率相同时按锁内容兜底。
    groups.sort(key=lambda group: (group["id"], lock_content_key(group["locked"])))

    return {"status": "ok", "root": root_canonical, "groups": groups}


def _lock_changes(
    current: dict[str, Version], locked: dict[str, str]
) -> list[dict]:
    """current_lock 与新锁定清单的逐项差异，按包名排序。

    版本按 PEP 440 比较（如 1.0 与 1.0.0 视为相同，不产生变化项）；
    新增包 from 为 None，被删除的包 to 为 None。
    """
    changes = []
    for name in sorted(set(current) | set(locked)):
        old = current.get(name)
        new = locked.get(name)
        if old is not None and new is not None and old == Version(new):
            continue
        changes.append(
            {
                "name": name,
                "from": str(old) if old is not None else None,
                "to": new,
            }
        )
    return changes


@app.post(
    "/upgrade",
    summary="在现有锁定清单上升级单个目标包",
    response_model=UpgradeResponse,
    responses={
        409: {"model": UnresolvedResponse, "description": "无可行升级或超过搜索上限"},
        422: {"model": InvalidSnapshotResponse, "description": "快照、current_lock 或请求非法"},
    },
)
def upgrade(request: UpgradeRequest):
    root_canonical = canonical(request.root)
    target_canonical = canonical(request.target)
    payload = request.model_dump()

    try:
        repo = build_repository(payload["repository"], payload["target_environment"])
        root_spec = parse_root_specifier(request.specifier)
        current_lock = parse_current_lock(payload["current_lock"])
    except SnapshotError as exc:
        return JSONResponse(
            status_code=422,
            content={"status": "invalid_snapshot", "message": str(exc)},
        )

    if not repo.known(root_canonical):
        return JSONResponse(
            status_code=422,
            content={
                "status": "invalid_snapshot",
                "message": f"根包 {root_canonical!r} 不存在于仓库快照中",
            },
        )

    if target_canonical not in current_lock:
        return JSONResponse(
            status_code=422,
            content={
                "status": "invalid_snapshot",
                "message": f"目标包 {target_canonical!r} 不存在于 current_lock 中",
            },
        )

    resolver = Resolver(repo, allow_prereleases=request.allow_prereleases)
    try:
        state = resolver.upgrade(
            root_canonical,
            root_spec,
            request.specifier,
            target=target_canonical,
            current_version=current_lock[target_canonical],
            reference=current_lock,
        )
    except ResolutionLimit:
        return JSONResponse(
            status_code=409,
            content=_conflict_payload(resolver.build_conflicts(limit=True)),
        )

    if state is None:
        content = _conflict_payload(resolver.build_conflicts())
        content["message"] = (
            f"目标包 {target_canonical!r} 没有可行的升级："
            "不存在严格高于当前版本且能完成整体解析的候选版本"
        )
        return JSONResponse(status_code=409, content=content)

    locked = {pkg: str(ver) for pkg, ver in sorted(state.selection.items())}
    return {
        "status": "ok",
        "root": root_canonical,
        "root_version": str(state.selection[root_canonical]),
        "locked": locked,
        "changes": _lock_changes(current_lock, locked),
    }


@app.post(
    "/audit-lock",
    summary="审计现有锁定清单而不重新求解",
    response_model=AuditLockResponse,
    responses={
        422: {"model": InvalidSnapshotResponse, "description": "快照或 current_lock 非法"},
    },
)
def audit_lock_endpoint(request: AuditLockRequest):
    root_canonical = canonical(request.root)
    payload = request.model_dump()

    try:
        repo = build_repository(payload["repository"], payload["target_environment"])
        root_spec = parse_root_specifier(request.specifier)
        current_lock = parse_current_lock(payload["current_lock"])
    except SnapshotError as exc:
        return JSONResponse(
            status_code=422,
            content={"status": "invalid_snapshot", "message": str(exc)},
        )

    if not repo.known(root_canonical):
        return JSONResponse(
            status_code=422,
            content={
                "status": "invalid_snapshot",
                "message": f"根包 {root_canonical!r} 不存在于仓库快照中",
            },
        )

    result = audit_lock(
        repo,
        root_name=root_canonical,
        root_spec=root_spec,
        root_raw=request.specifier,
        current_lock=current_lock,
        allow_prereleases=request.allow_prereleases,
    )
    return {"status": "ok", **result}


@app.post(
    "/dependency-paths",
    summary="解释目标包为何出现在锁定清单中：根包到目标包的全部最短路径",
    response_model=DependencyPathsResponse,
    responses={
        409: {
            "model": InvalidLockResponse | PathLimitResponse,
            "description": (
                "锁定清单未通过审计（status=invalid_lock）；"
                "或最短路径条数超过固定预算（status=limit，未构造路径列表）"
            ),
        },
        422: {"model": InvalidSnapshotResponse, "description": "快照或 current_lock 非法"},
    },
)
def dependency_paths_endpoint(request: DependencyPathsRequest):
    root_canonical = canonical(request.root)
    target_canonical = canonical(request.target)
    payload = request.model_dump()

    try:
        repo = build_repository(payload["repository"], payload["target_environment"])
        root_spec = parse_root_specifier(request.specifier)
        current_lock = parse_current_lock(payload["current_lock"])
    except SnapshotError as exc:
        return JSONResponse(
            status_code=422,
            content={"status": "invalid_snapshot", "message": str(exc)},
        )

    if not repo.known(root_canonical):
        return JSONResponse(
            status_code=422,
            content={
                "status": "invalid_snapshot",
                "message": f"根包 {root_canonical!r} 不存在于仓库快照中",
            },
        )

    # 先按现有审计规则校验锁定清单；无效则带确定性排序的问题返回 409，
    # 不执行任何路径查询。
    result = audit_lock(
        repo,
        root_name=root_canonical,
        root_spec=root_spec,
        root_raw=request.specifier,
        current_lock=current_lock,
        allow_prereleases=request.allow_prereleases,
    )
    if not result["valid"]:
        return JSONResponse(
            status_code=409,
            content={
                "status": "invalid_lock",
                "message": "锁定清单未通过审计，未执行路径查询",
                "issues": result["issues"],
            },
        )

    # 有效锁：按锁定版本与目标环境激活的依赖建图（无版本选择）。
    graph = build_locked_graph(
        repo, root_name=root_canonical, current_lock=current_lock
    )
    try:
        paths = shortest_paths(graph, root_canonical, target_canonical)
    except PathCountLimit as exc:
        # 最短路径条数超过固定预算：409 status=limit，未构造路径列表。
        return JSONResponse(status_code=409, content=_path_limit_payload(exc))
    return {
        "status": "ok",
        "root": root_canonical,
        "target": target_canonical,
        "reachable": bool(paths),
        "paths": paths,
    }


@app.post(
    "/install-plan",
    summary="在有效锁定清单上输出依赖优先的并行安装批次（SCC 压缩为 DAG）",
    response_model=InstallPlanResponse,
    responses={
        409: {"model": InvalidLockResponse, "description": "锁定清单未通过审计"},
        422: {"model": InvalidSnapshotResponse, "description": "快照或 current_lock 非法"},
    },
)
def install_plan_endpoint(request: InstallPlanRequest):
    root_canonical = canonical(request.root)
    payload = request.model_dump()

    try:
        repo = build_repository(payload["repository"], payload["target_environment"])
        root_spec = parse_root_specifier(request.specifier)
        current_lock = parse_current_lock(payload["current_lock"])
    except SnapshotError as exc:
        return JSONResponse(
            status_code=422,
            content={"status": "invalid_snapshot", "message": str(exc)},
        )

    if not repo.known(root_canonical):
        return JSONResponse(
            status_code=422,
            content={
                "status": "invalid_snapshot",
                "message": f"根包 {root_canonical!r} 不存在于仓库快照中",
            },
        )

    # 先按现有审计规则校验锁定清单；无效则带确定性排序的问题返回 409，
    # 不生成任何安装批次。
    result = audit_lock(
        repo,
        root_name=root_canonical,
        root_spec=root_spec,
        root_raw=request.specifier,
        current_lock=current_lock,
        allow_prereleases=request.allow_prereleases,
    )
    if not result["valid"]:
        return JSONResponse(
            status_code=409,
            content={
                "status": "invalid_lock",
                "message": "锁定清单未通过审计，未生成安装计划",
                "issues": result["issues"],
            },
        )

    # 有效锁：按锁定版本与目标环境激活的依赖建图（无版本选择，节点集恰为
    # 根可达包），SCC 压缩为 DAG 后最长路径分层输出并行安装批次。
    graph = build_locked_graph(
        repo, root_name=root_canonical, current_lock=current_lock
    )
    document = build_install_plan(
        repo,
        root_name=root_canonical,
        current_lock=current_lock,
        graph=graph,
    )
    return {"status": "ok", "root": root_canonical, **document}


@app.post(
    "/sbom",
    summary="沿有效锁定清单的已激活依赖图导出确定性 JSON SBOM",
    response_model=SbomResponse,
    responses={
        409: {"model": InvalidLockResponse, "description": "锁定清单未通过审计"},
        422: {"model": InvalidSnapshotResponse, "description": "快照或 current_lock 非法"},
    },
)
def sbom_endpoint(request: SbomRequest):
    root_canonical = canonical(request.root)
    payload = request.model_dump()

    try:
        repo = build_repository(payload["repository"], payload["target_environment"])
        root_spec = parse_root_specifier(request.specifier)
        current_lock = parse_current_lock(payload["current_lock"])
    except SnapshotError as exc:
        return JSONResponse(
            status_code=422,
            content={"status": "invalid_snapshot", "message": str(exc)},
        )

    if not repo.known(root_canonical):
        return JSONResponse(
            status_code=422,
            content={
                "status": "invalid_snapshot",
                "message": f"根包 {root_canonical!r} 不存在于仓库快照中",
            },
        )

    # 先按现有审计规则校验锁定清单；无效则带确定性排序的问题返回 409，
    # 不导出任何清单。
    result = audit_lock(
        repo,
        root_name=root_canonical,
        root_spec=root_spec,
        root_raw=request.specifier,
        current_lock=current_lock,
        allow_prereleases=request.allow_prereleases,
    )
    if not result["valid"]:
        return JSONResponse(
            status_code=409,
            content={
                "status": "invalid_lock",
                "message": "锁定清单未通过审计，未导出 SBOM",
                "issues": result["issues"],
            },
        )

    # 有效锁：按锁定版本与目标环境激活的依赖建图（无版本选择），再导出。
    graph = build_locked_graph(
        repo, root_name=root_canonical, current_lock=current_lock
    )
    document = build_sbom(
        repo,
        root_name=root_canonical,
        current_lock=current_lock,
        graph=graph,
    )
    return {"status": "ok", "root": root_canonical, **document}


@app.post(
    "/license-policy",
    summary="在有效锁定清单上按 allow/deny 判定各可达包的 SPDX 许可证表达式",
    response_model=LicensePolicyResponse,
    responses={
        409: {
            "model": InvalidLockResponse | PathLimitResponse,
            "description": (
                "锁定清单未通过审计（status=invalid_lock）；"
                "或某命中包的最短路径条数超过固定预算（status=limit，"
                "按包名顺序命中首个超限项，未构造路径列表）"
            ),
        },
        422: {
            "model": InvalidSnapshotResponse,
            "description": "快照/current_lock 非法、SPDX 表达式非法或 allow/deny 规则重叠",
        },
    },
)
def license_policy_endpoint(request: LicensePolicyRequest):
    root_canonical = canonical(request.root)
    payload = request.model_dump()

    try:
        repo = build_repository(payload["repository"], payload["target_environment"])
        root_spec = parse_root_specifier(request.specifier)
        current_lock = parse_current_lock(payload["current_lock"])
    except SnapshotError as exc:
        return JSONResponse(
            status_code=422,
            content={"status": "invalid_snapshot", "message": str(exc)},
        )

    if not repo.known(root_canonical):
        return JSONResponse(
            status_code=422,
            content={
                "status": "invalid_snapshot",
                "message": f"根包 {root_canonical!r} 不存在于仓库快照中",
            },
        )

    # 先按现有审计规则校验锁定清单；无效则带确定性排序的问题返回 409，
    # 不解析任何许可证表达式。
    result = audit_lock(
        repo,
        root_name=root_canonical,
        root_spec=root_spec,
        root_raw=request.specifier,
        current_lock=current_lock,
        allow_prereleases=request.allow_prereleases,
    )
    if not result["valid"]:
        return JSONResponse(
            status_code=409,
            content={
                "status": "invalid_lock",
                "message": "锁定清单未通过审计，未执行许可证策略判定",
                "issues": result["issues"],
            },
        )

    # 规则集合（标识合法性、allow/deny 重叠）与许可证表达式均属于请求
    # 语义校验：非法返回 422，输出不做任何判定。命中包的最短路径条数超过
    # 固定预算时整体 409（status=limit）：判定按包名顺序逐包进行，命中的
    # 是首个超限目标，未构造任何路径列表。
    try:
        allow_set, deny_set = parse_policy_sets(request.allow, request.deny)
        graph = build_locked_graph(
            repo, root_name=root_canonical, current_lock=current_lock
        )
        document = evaluate_license_policy(
            repo,
            root_name=root_canonical,
            current_lock=current_lock,
            graph=graph,
            allow=allow_set,
            deny=deny_set,
        )
    except (SnapshotError, LicenseExpressionError) as exc:
        return JSONResponse(
            status_code=422,
            content={"status": "invalid_snapshot", "message": str(exc)},
        )
    except PathCountLimit as exc:
        return JSONResponse(status_code=409, content=_path_limit_payload(exc))

    return {"status": "ok", "root": root_canonical, **document}


@app.post(
    "/lock-diff",
    summary="同一快照与目标环境下比较两份有效锁的根可达包差异",
    response_model=LockDiffResponse,
    responses={
        409: {
            "model": LockDiffInvalidResponse | PathLimitResponse,
            "description": (
                "before_lock/after_lock 任一未通过审计（status=invalid_lock，"
                "两侧问题分别标注）；或某变化项的最短路径条数超过固定预算"
                "（status=limit，按既有包名顺序命中首个超限项，未构造路径列表）"
            ),
        },
        422: {"model": InvalidSnapshotResponse, "description": "快照或任一锁非法"},
    },
)
def lock_diff_endpoint(request: LockDiffRequest):
    root_canonical = canonical(request.root)
    payload = request.model_dump()

    try:
        repo = build_repository(payload["repository"], payload["target_environment"])
        root_spec = parse_root_specifier(request.specifier)
        before_lock = parse_current_lock(
            payload["before_lock"], label="before_lock"
        )
        after_lock = parse_current_lock(payload["after_lock"], label="after_lock")
    except SnapshotError as exc:
        return JSONResponse(
            status_code=422,
            content={"status": "invalid_snapshot", "message": str(exc)},
        )

    if not repo.known(root_canonical):
        return JSONResponse(
            status_code=422,
            content={
                "status": "invalid_snapshot",
                "message": f"根包 {root_canonical!r} 不存在于仓库快照中",
            },
        )

    # 两份锁各自独立复用 /audit-lock 的同一套规则校验：即使某一份已无效，
    # 另一份仍照常审计，以便 409 一次性标注 before/after 的全部问题。
    before_result = audit_lock(
        repo,
        root_name=root_canonical,
        root_spec=root_spec,
        root_raw=request.specifier,
        current_lock=before_lock,
        allow_prereleases=request.allow_prereleases,
    )
    after_result = audit_lock(
        repo,
        root_name=root_canonical,
        root_spec=root_spec,
        root_raw=request.specifier,
        current_lock=after_lock,
        allow_prereleases=request.allow_prereleases,
    )
    if not before_result["valid"] or not after_result["valid"]:
        invalid_sides = [
            side
            for side, result in (
                ("before_lock", before_result),
                ("after_lock", after_result),
            )
            if not result["valid"]
        ]
        return JSONResponse(
            status_code=409,
            content={
                "status": "invalid_lock",
                "message": (
                    "锁定清单未通过审计，未执行差异比较："
                    + "、".join(invalid_sides)
                    + " 无效"
                ),
                "before": {
                    "valid": before_result["valid"],
                    "issues": before_result["issues"],
                },
                "after": {
                    "valid": after_result["valid"],
                    "issues": after_result["issues"],
                },
            },
        )

    # 两份锁均有效：只比较根可达包，版本方向按 PEP 440；每个变化项附
    # 前后依赖图中的全部最短根路径（不存在的一侧为空数组）。某条路径
    # 查询超过固定条数预算时整体 409（status=limit）：变化项按既有
    # 包名顺序逐个处理，命中的是首个超限目标，未构造任何路径列表。
    try:
        document = diff_locks(
            repo,
            root_name=root_canonical,
            before_lock=before_lock,
            after_lock=after_lock,
        )
    except PathCountLimit as exc:
        return JSONResponse(status_code=409, content=_path_limit_payload(exc))
    return {"status": "ok", "root": root_canonical, **document}


def _baseline_diff(
    baseline: dict[str, Version], locked: dict[str, Version]
) -> tuple[list[dict], list[dict], list[dict]]:
    """基准锁与反事实锁的版本集差异：added / removed / changed。

    三个列表各自按规范化包名排序；版本按 PEP 440 比较（1.0 与 1.0.0
    相等，不产生 changed 项）。
    """
    added = [
        {"name": name, "version": str(locked[name])}
        for name in sorted(set(locked) - set(baseline))
    ]
    removed = [
        {"name": name, "version": str(baseline[name])}
        for name in sorted(set(baseline) - set(locked))
    ]
    changed = [
        {"name": name, "from": str(baseline[name]), "to": str(locked[name])}
        for name in sorted(set(baseline) & set(locked))
        if baseline[name] != locked[name]
    ]
    return added, removed, changed


@app.post(
    "/explain-version",
    summary="反事实解释：强制目标包为指定版本后的锁定清单与相对基准锁的差异",
    response_model=ExplainVersionResponse,
    responses={
        409: {
            "model": UnresolvedResponse,
            "description": "基准锁无解，或强制目标版本后无解 / 超过搜索上限",
        },
        422: {
            "model": InvalidSnapshotResponse,
            "description": "快照或请求非法，或目标包不在基准锁定清单中",
        },
    },
)
def explain_version(request: ExplainVersionRequest):
    root_canonical = canonical(request.root)
    target_canonical = canonical(request.target_package)
    payload = request.model_dump()

    try:
        repo = build_repository(payload["repository"], payload["target_environment"])
        root_spec = parse_root_specifier(request.specifier)
        target_version = parse_target_version(request.target_version)
    except SnapshotError as exc:
        return JSONResponse(
            status_code=422,
            content={"status": "invalid_snapshot", "message": str(exc)},
        )

    if not repo.known(root_canonical):
        return JSONResponse(
            status_code=422,
            content={
                "status": "invalid_snapshot",
                "message": f"根包 {root_canonical!r} 不存在于仓库快照中",
            },
        )

    # 第一步：按 /resolve 原规则求基准锁（独立 Resolver，与 /resolve 单次
    # 调用完全同形）；基准本身无解时直接返回该冲突/超限结果。
    baseline_resolver = Resolver(repo, allow_prereleases=request.allow_prereleases)
    try:
        baseline_state = baseline_resolver.resolve(
            root_canonical, root_spec, request.specifier
        )
    except ResolutionLimit:
        return JSONResponse(
            status_code=409,
            content=_conflict_payload(baseline_resolver.build_conflicts(limit=True)),
        )
    if baseline_state is None:
        return JSONResponse(
            status_code=409,
            content=_conflict_payload(baseline_resolver.build_conflicts()),
        )

    # 目标包必须出现在基准锁中（即从根包可达），否则没有可解释的基准。
    if target_canonical not in baseline_state.selection:
        return JSONResponse(
            status_code=422,
            content={
                "status": "invalid_snapshot",
                "message": (
                    f"目标包 {target_canonical!r} 不在基准锁定清单中"
                    "（从根包不可达），无法做版本解释"
                ),
            },
        )

    # 第二步：其余规则不变，仅以根级 ==版本 约束钉住目标包做反事实求解
    # （全新 Resolver：冲突收集与尝试计数与基准求解互不干扰）。
    forced_resolver = Resolver(repo, allow_prereleases=request.allow_prereleases)
    try:
        state = forced_resolver.resolve_forced(
            root_canonical,
            root_spec,
            request.specifier,
            target=target_canonical,
            target_version=target_version,
        )
    except ResolutionLimit:
        return JSONResponse(
            status_code=409,
            content=_conflict_payload(forced_resolver.build_conflicts(limit=True)),
        )

    if state is None:
        content = _conflict_payload(forced_resolver.build_conflicts())
        content["message"] = (
            f"无法将目标包 {target_canonical!r} 强制为 {target_version}："
            "该版本下依赖约束无解"
        )
        return JSONResponse(status_code=409, content=content)

    baseline_locked = {
        pkg: str(ver) for pkg, ver in sorted(baseline_state.selection.items())
    }
    locked = {pkg: str(ver) for pkg, ver in sorted(state.selection.items())}
    added, removed, changed = _baseline_diff(
        baseline_state.selection, state.selection
    )
    return {
        "status": "ok",
        "root": root_canonical,
        "root_version": str(state.selection[root_canonical]),
        "target_package": target_canonical,
        "target_version": str(target_version),
        "baseline_locked": baseline_locked,
        "locked": locked,
        "added": added,
        "removed": removed,
        "changed": changed,
    }
