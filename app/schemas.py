"""HTTP 请求 / 响应的 Pydantic 模型。

所有数据随请求传入，服务端不读取任何远程索引、不做磁盘缓存。
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

# PEP 503 允许的发行包名：字母数字点/连字符/下划线，首尾为字母或数字
# （单字符包名也合法）。
NAME_PATTERN = r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$"


class DependencyIn(BaseModel):
    """一条声明式依赖（requires_dist 风格，支持 PEP 440 约束 + PEP 508 marker）。"""

    model_config = {"extra": "forbid"}

    name: str = Field(
        ...,
        min_length=1,
        pattern=NAME_PATTERN,
        description="被依赖的发行包名（按 PEP 503 规范化后匹配）。",
    )
    specifier: str = Field(
        "",
        description="PEP 440 版本约束，如 '>=1.0,<2.0'；空字符串表示不约束。",
    )
    marker: str = Field(
        "",
        description=(
            "PEP 508 环境标记表达式（不含分号），如 \"sys_platform == 'linux'\"；"
            "仅允许引用 python_version / sys_platform / platform_machine，"
            "空字符串表示无条件激活。"
        ),
    )


class TargetEnvironmentIn(BaseModel):
    """marker 求值所用的目标环境；三项必填且全部取自请求（不读宿主机）。"""

    model_config = {"extra": "forbid"}

    python_version: str = Field(
        ...,
        min_length=1,
        description="目标解释器版本（PEP 440），如 '3.11'、'3.12.4'。",
    )
    sys_platform: str = Field(
        ...,
        min_length=1,
        description="目标操作系统，对应 sys_platform，如 'linux'、'win32'、'darwin'。",
    )
    platform_machine: str = Field(
        ...,
        min_length=1,
        description="目标 CPU 架构，对应 platform.machine()，如 'x86_64'、'aarch64'、'AMD64'。",
    )


class CandidateMetadataIn(BaseModel):
    """候选版本随快照携带的 SBOM 元数据；三项全部可选。

    字段缺失或为空字符串表示“未提供”（/sbom 导出时只形成 warnings，
    不阻断）；提供非空值时由 repository 层做格式校验（非法返回 422）。
    """

    model_config = {"extra": "forbid"}

    source_url: str | None = Field(
        None,
        description="该版本源码/分发包的 http(s) URL；未提供时为 null。",
    )
    sha256: str | None = Field(
        None,
        description="该版本分发包的 SHA-256 摘要（64 位十六进制字符）；未提供时为 null。",
    )
    license: str | None = Field(
        None,
        description="该版本声明的许可证（SPDX 标识或许可证文本）；未提供时为 null。",
    )


class CandidateIn(BaseModel):
    """仓库快照中的一个候选版本。"""

    model_config = {"extra": "forbid"}

    version: str = Field(..., min_length=1, description="PEP 440 版本号。")
    dependencies: list[DependencyIn] = Field(
        default_factory=list,
        description="该版本声明的依赖（输出会做确定性排序，与声明顺序无关）。",
    )
    metadata: CandidateMetadataIn | None = Field(
        None,
        description=(
            "该版本的可选 SBOM 元数据（source_url / sha256 / license）；"
            "仅 POST /sbom 使用，缺字段不阻断其他端点。"
        ),
    )


class _ResolveInputs(BaseModel):
    """各求解端点（/resolve、/resolve-matrix 等）共用的请求输入。

    只含与具体目标环境无关的字段；单环境端点再附加 ``target_environment``，
    多环境矩阵端点附加 ``target_environments``。
    """

    model_config = {"extra": "forbid"}

    repository: dict[str, list[CandidateIn]] = Field(
        ...,
        description=(
            "仓库快照：键为包名（按 PEP 503 规范化匹配，大小写/下划线/点/连字符等价），"
            "值为候选版本列表；列表顺序无关，内部按 PEP 440 版本降序排列。"
        ),
    )
    root: str = Field(
        ...,
        min_length=1,
        pattern=NAME_PATTERN,
        description="根包名称；必须存在于 repository 中。",
    )
    specifier: str = Field(
        "",
        description="对根包的 PEP 440 版本约束，默认取最高版本。",
    )
    allow_prereleases: bool = Field(
        False,
        description="是否允许预发布版本（dev/a/b/rc）。默认关闭。",
    )


class ResolveRequest(_ResolveInputs):
    """POST /resolve 的请求体。"""

    model_config = {"extra": "forbid"}

    target_environment: TargetEnvironmentIn = Field(
        ...,
        description=(
            "必填的目标环境，用于求解决策与每条依赖的 PEP 508 marker；"
            "值完全取自请求，服务端不读取宿主机信息。"
        ),
    )


class MatrixTargetEnvironmentIn(TargetEnvironmentIn):
    """/resolve-matrix 的目标环境：在三项环境值上附加调用方给定的唯一 id。"""

    model_config = {"extra": "forbid"}

    id: str = Field(
        ...,
        min_length=1,
        pattern=NAME_PATTERN,
        description=(
            "环境标识，用于在结果中对应各环境锁定清单与矩阵列；"
            "同一次请求内必须唯一（重复返回 422）。"
        ),
    )


class ResolveMatrixRequest(_ResolveInputs):
    """POST /resolve-matrix 的请求体：同一份快照在 2～8 个目标环境下分别求解。"""

    model_config = {"extra": "forbid"}

    target_environments: list[MatrixTargetEnvironmentIn] = Field(
        ...,
        min_length=2,
        max_length=8,
        description=(
            "2～8 个目标环境，每个带调用方给定的唯一 id；"
            "各环境独立复用 /resolve 的全部求解规则（marker 激活、回溯、预发布开关）。"
        ),
    )


class LockGroupsRequest(ResolveMatrixRequest):
    """POST /lock-groups 的请求体：字段与 /resolve-matrix 完全一致。

    同一份仓库快照、根约束与 2～8 个带唯一 id 的目标环境；服务端逐环境
    复用 /resolve 规则求出候选锁，再把去重后的每份候选锁在全部环境上按
    /audit-lock 规则交叉审计，选择覆盖全部环境所需数量最少的锁组。
    """

    model_config = {"extra": "forbid"}


class UpgradeRequest(ResolveRequest):
    """POST /upgrade 的请求体：在 /resolve 全部字段上附加当前锁定清单与升级目标。"""

    model_config = {"extra": "forbid"}

    current_lock: dict[str, str] = Field(
        ...,
        description=(
            "当前锁定清单：包名（PEP 503 规范化匹配）-> PEP 440 版本；"
            "作为最小化变更的参照，不参与约束求解。"
        ),
    )
    target: str = Field(
        ...,
        min_length=1,
        pattern=NAME_PATTERN,
        description="要升级的包名；必须存在于 current_lock 中，否则返回 422。",
    )


class AuditLockRequest(ResolveRequest):
    """POST /audit-lock 的请求体：在 /resolve 全部字段上附加被审计的锁定清单。

    审计不重新求解：current_lock 中的版本就是被检查的对象，而不是参照。
    """

    model_config = {"extra": "forbid"}

    current_lock: dict[str, str] = Field(
        ...,
        description=(
            "被审计的锁定清单：包名（PEP 503 规范化匹配）-> PEP 440 版本；"
            "审计从根包按这些锁定版本遍历已激活依赖，不做任何版本选择。"
        ),
    )


class DependencyPathsRequest(AuditLockRequest):
    """POST /dependency-paths 的请求体：在锁定审计字段上附加目标包。

    先按 /audit-lock 的同一套规则校验 current_lock；仅当锁有效时才按
    锁定版本建图，查询从根包到 target 的所有最短包路径。
    """

    model_config = {"extra": "forbid"}

    target: str = Field(
        ...,
        min_length=1,
        pattern=NAME_PATTERN,
        description="要解释的目标包名（PEP 503 规范化匹配）；不可达时返回 reachable=false。",
    )


class SbomRequest(AuditLockRequest):
    """POST /sbom 的请求体：沿用 /audit-lock 全部字段（/resolve 字段 + current_lock）。

    先按 /audit-lock 的同一套规则校验 current_lock；锁有效时沿已激活
    依赖图导出确定性 JSON 清单。候选版本可携带的 source_url / sha256 /
    license 元数据定义在 repository 的候选条目上。
    """

    model_config = {"extra": "forbid"}


class InstallPlanRequest(AuditLockRequest):
    """POST /install-plan 的请求体：沿用 /audit-lock 全部字段，无额外字段。

    先按 /audit-lock 的同一套规则校验 current_lock；锁有效时只对根可达
    包按已激活依赖建图，强连通分量压缩为 DAG 后输出依赖优先的并行
    安装批次。
    """

    model_config = {"extra": "forbid"}


class LicensePolicyRequest(AuditLockRequest):
    """POST /license-policy 的请求体：在 /audit-lock 字段上附加 allow/deny。

    先按 /audit-lock 的同一套规则校验 current_lock；锁有效时解析各可达包
    锁定版本 metadata.license 的 SPDX AND/OR/括号表达式，按 allow/deny
    两个标识集合做三态判定。两个集合均为单个 SPDX 标识词（不接受
    AND/OR 表达式），同一标识不得同时出现在两个集合中（规则重叠返回 422）。
    """

    model_config = {"extra": "forbid"}

    allow: list[str] = Field(
        default_factory=list,
        description=(
            "允许的 SPDX 许可证标识集合（单个标识词，大小写敏感），"
            "如 [\"MIT\", \"Apache-2.0\"]；缺省为空列表。"
        ),
    )
    deny: list[str] = Field(
        default_factory=list,
        description=(
            "拒绝的 SPDX 许可证标识集合（单个标识词，大小写敏感），"
            "如 [\"GPL-3.0-only\"]；缺省为空列表。不得与 allow 重叠。"
        ),
    )


class LockDiffRequest(_ResolveInputs):
    """POST /lock-diff 的请求体：同一快照与目标环境下比较两份锁。

    在 /resolve 的快照/根/约束字段（不含单环境之外的字段）上附加单个
    target_environment 与 before_lock / after_lock 两份锁定清单；两份锁
    各自先独立复用 /audit-lock 的同一套规则校验，再做根可达包比较。
    """

    model_config = {"extra": "forbid"}

    target_environment: TargetEnvironmentIn = Field(
        ...,
        description=(
            "必填的目标环境：两份锁在**同一个目标环境**下审计与建图"
            "（marker 激活、约束核对语义与 /resolve 完全一致）。"
        ),
    )
    before_lock: dict[str, str] = Field(
        ...,
        description=(
            "比较基准锁定清单：包名（PEP 503 规范化匹配）-> PEP 440 版本；"
            "先独立复用 /audit-lock 规则校验，无效时整体返回 409。"
        ),
    )
    after_lock: dict[str, str] = Field(
        ...,
        description=(
            "比较目标锁定清单：格式同 before_lock；与 before_lock 各自独立"
            "审计，任一无效即整体返回 409 并标注 before/after 对应问题。"
        ),
    )


class ExplainVersionRequest(ResolveRequest):
    """POST /explain-version 的请求体：在 /resolve 全部字段上指定反事实目标。

    先按 /resolve 原规则求出基准锁定清单（目标包必须出现在其中，否则
    返回 422），再把 target_package 钉在 target_version 上做反事实整体
    求解：可行返回新锁与相对基准锁的差异，无解返回 409 约束来源链。
    """

    model_config = {"extra": "forbid"}

    target_package: str = Field(
        ...,
        min_length=1,
        pattern=NAME_PATTERN,
        description=(
            "要解释的目标包名（PEP 503 规范化匹配）；"
            "必须出现在基准锁定清单中（从根包可达），否则返回 422。"
        ),
    )
    target_version: str = Field(
        ...,
        min_length=1,
        description=(
            "强制目标包使用的 PEP 440 版本（输出为规范化形式）；"
            "非法版本返回 422，该版本下整体无解返回 409。"
        ),
    )


# --------------------------------------------------------------------- #
# 响应模型
# --------------------------------------------------------------------- #
class EdgeOut(BaseModel):
    model_config = {"extra": "forbid"}

    from_: str = Field(..., alias="from", description="声明方，'root' 表示根请求。")
    to: str = Field(..., description="被依赖方（规范化包名）。")
    specifier: str = Field(..., description="声明的原始约束；空约束显示为 '*'。")


class ResolveResponse(BaseModel):
    model_config = {"extra": "forbid", "populate_by_name": True}

    status: Literal["ok"]
    root: str
    root_version: str
    locked: dict[str, str] = Field(
        ..., description="确定性锁定清单：规范化包名 -> 版本。"
    )
    edges: list[EdgeOut] = Field(..., description="依赖边（已排序）。")


class ChangeOut(BaseModel):
    """单个包相对 current_lock 的变化。"""

    model_config = {"extra": "forbid", "populate_by_name": True}

    name: str = Field(..., description="规范化包名。")
    from_: str | None = Field(
        ..., alias="from", description="current_lock 中的版本；新增包为 null。"
    )
    to: str | None = Field(
        ..., description="升级后锁定清单中的版本；被删除的包为 null。"
    )


class UpgradeResponse(BaseModel):
    model_config = {"extra": "forbid", "populate_by_name": True}

    status: Literal["ok"]
    root: str
    root_version: str
    locked: dict[str, str] = Field(
        ..., description="升级后的完整确定性锁定清单：规范化包名 -> 版本。"
    )
    changes: list[ChangeOut] = Field(
        ...,
        description=(
            "相对 current_lock 的全部变化（含目标包），按包名排序；"
            "from 为 null 表示新增，to 为 null 表示删除。"
        ),
    )


class ChainLinkOut(BaseModel):
    """来源链中的一跳。"""

    model_config = {"extra": "forbid"}

    package: str | None = Field(
        ..., description="提出约束的包名；null 表示请求本身（根需求）。"
    )
    version: str | None = Field(
        ..., description="提出约束的已选版本；根需求时为 null。"
    )
    requires: str = Field(..., description="该跳施加的原始约束文本。")


class ConstraintChainOut(BaseModel):
    model_config = {"extra": "forbid"}

    chain: list[ChainLinkOut] = Field(
        ..., description="根需求 -> ... -> 冲突包的一条约束来源链。"
    )


class ConflictOut(BaseModel):
    model_config = {"extra": "forbid"}

    subject: str = Field(..., description="冲突所针对的包名（规范化）。")
    kind: Literal["incompatible", "no_candidates"]
    message: str
    constraints: list[ConstraintChainOut] = Field(
        ..., description="对该包所有互不兼容的约束及其来源链。"
    )
    partial_selection: dict[str, str] = Field(
        ..., description="冲突点上已确定的选择快照（规范化名 -> 版本）。"
    )


class UnresolvedResponse(BaseModel):
    model_config = {"extra": "forbid"}

    status: Literal["conflict", "limit"]
    message: str
    conflicts: list[ConflictOut]


class InvalidSnapshotResponse(BaseModel):
    model_config = {"extra": "forbid"}

    status: Literal["invalid_snapshot"]
    message: str


# --------------------------------------------------------------------- #
# POST /resolve-matrix 响应
# --------------------------------------------------------------------- #
class MatrixEnvironmentOut(BaseModel):
    """单个目标环境的求解结果；results 按 id 排序。"""

    model_config = {"extra": "forbid"}

    id: str = Field(..., description="与请求 target_environments[].id 对应。")
    root_version: str = Field(
        ...,
        description=(
            "该环境锁定的根包版本；根版本也可能因环境相关回溯而不同，"
            "差异同样体现在 matrix 的根包行上。"
        ),
    )
    locked: dict[str, str] = Field(
        ..., description="该环境下的确定性锁定清单：规范化包名 -> 版本。"
    )


class MatrixPackageOut(BaseModel):
    """matrix 中的一行：一个包在各环境的版本及跨环境一致标记。"""

    model_config = {"extra": "forbid"}

    name: str = Field(..., description="规范化包名（PEP 503）。")
    versions: dict[str, str | None] = Field(
        ...,
        description=(
            "环境 id -> 该环境锁定的版本；该包未出现在某环境的锁定清单中时为 null。"
        ),
    )
    state: Literal["shared", "divergent"] = Field(
        ...,
        description=(
            "shared=每个环境都锁定且版本完全相同；"
            "divergent=版本不同，或该包只出现在部分环境（对应 versions 中为 null）。"
        ),
    )


class ResolveMatrixResponse(BaseModel):
    model_config = {"extra": "forbid"}

    status: Literal["ok"]
    root: str
    results: list[MatrixEnvironmentOut] = Field(
        ..., description="各目标环境的锁定清单，按 id 排序（含各自的 root_version）。"
    )
    matrix: list[MatrixPackageOut] = Field(
        ..., description="跨环境版本矩阵，按包名排序（根包同样是其中一行）。"
    )


class MatrixFailureOut(BaseModel):
    """409 时一个失败环境的原冲突结果（与 /resolve 的 409 内容一致）。"""

    model_config = {"extra": "forbid"}

    id: str
    status: Literal["conflict", "limit"]
    message: str
    conflicts: list[ConflictOut]


class MatrixUnresolvedResponse(BaseModel):
    """任一目标环境无解：整体 409，列出各失败环境的原冲突结果（按 id 排序）。"""

    model_config = {"extra": "forbid"}

    status: Literal["conflict"]
    message: str
    failures: list[MatrixFailureOut]


class MatrixLimitResponse(BaseModel):
    """请求级共享求解预算耗尽：整体 409，立即停止后续环境求解。

    与 MatrixUnresolvedResponse 互斥：单个环境自身的尝试上限仍以
    ``failures`` 中该环境 ``status:"limit"`` 的冲突结果报告（继续跑完全部
    环境）；只有同请求内跨环境累计计数达到共享预算上限时才返回本形态。
    """

    model_config = {"extra": "forbid"}

    status: Literal["limit"]
    message: str
    environment: str = Field(
        ...,
        description=(
            "触发预算耗尽的环境 id：各环境按 id 稳定顺序执行，"
            "该值只取决于环境集合，与请求中的提交顺序无关。"
        ),
    )
    used: int = Field(
        ..., description="停止时同请求内各环境累计已尝试的候选版本次数（恰等于 limit）。"
    )
    limit: int = Field(
        ..., description="请求级共享求解预算上限（环境变量 MATRIX_ATTEMPT_LIMIT 配置）。"
    )


# --------------------------------------------------------------------- #
# POST /lock-groups 响应
# --------------------------------------------------------------------- #
class LockGroupOut(BaseModel):
    """一个锁组：一份锁文件及其在交叉审计下可覆盖的目标环境。"""

    model_config = {"extra": "forbid"}

    id: str = Field(
        ...,
        description=(
            "由锁内容派生的稳定组 id（'lg-' + 锁内容 SHA-256 的 12 位十六进制"
            "前缀）；同内容的锁恒为同一 id，与请求顺序无关。"
        ),
    )
    environments: list[str] = Field(
        ...,
        description=(
            "该锁通过 /audit-lock 交叉审计、可覆盖的全部环境 id，按 id 排序；"
            "各组覆盖集的并集为全部目标环境。"
        ),
    )
    locked: dict[str, str] = Field(
        ...,
        description=(
            "锁内容：规范化包名 -> PEP 440 版本（按包名排序），"
            "即对应环境按 /resolve 规则求出的候选锁。"
        ),
    )


class LockGroupsResponse(BaseModel):
    """覆盖全部环境的最少锁组选择结果。"""

    model_config = {"extra": "forbid"}

    status: Literal["ok"]
    root: str
    groups: list[LockGroupOut] = Field(
        ...,
        description=(
            "锁组列表，按组 id（锁内容指纹）稳定排序；并列最优时已按锁内容"
            "及环境 id 的稳定序裁决，同一请求结果确定。"
        ),
    )


# --------------------------------------------------------------------- #
# POST /audit-lock 响应
# --------------------------------------------------------------------- #
class AuditConstraintOut(BaseModel):
    """一条累计到被审计包上的入边约束及其来源。"""

    model_config = {"extra": "forbid", "populate_by_name": True}

    from_: str = Field(
        ..., alias="from", description="声明方，'root' 表示根请求；否则为 'pkg==version'。"
    )
    specifier: str = Field(..., description="声明的原始约束；空约束显示为 '*'。")


class AuditConstraintViolationOut(AuditConstraintOut):
    """constraint_mismatch 中一条未被锁定版本满足的约束。"""

    model_config = {"extra": "forbid", "populate_by_name": True}

    satisfies: bool = Field(
        ...,
        description=(
            "锁定版本是否满足该约束（PEP 440）；该列表中恒为 false。"
            "missing/unavailable/extraneous 的约束不携带此字段。"
        ),
    )


class AuditIssueOut(BaseModel):
    """一条审计问题；每个包的每种类型至多一条。"""

    model_config = {"extra": "forbid", "populate_by_name": True}

    type: Literal["missing", "unavailable", "constraint_mismatch", "extraneous"] = (
        Field(..., description=(
            "missing=可达包未锁定；unavailable=锁定版本不在快照；"
            "constraint_mismatch=锁定版本不满足根或依赖约束；"
            "extraneous=锁中包不可达。"
        ))
    )
    name: str = Field(..., description="问题所针对的包名（PEP 503 规范化）。")
    locked_version: str | None = Field(
        ..., description="锁定清单中的版本；missing 时为 null。"
    )
    available: list[str] = Field(
        ...,
        description=(
            "快照中该包的全部可用版本（PEP 440 降序）；"
            "包不在快照中时为空列表。"
        ),
    )
    constraints: list[AuditConstraintViolationOut | AuditConstraintOut] = Field(
        ...,
        description=(
            "累计到该包的全部入边约束（含根约束，已去重并按来源排序）；"
            "constraint_mismatch 仅列出未满足的约束（逐条带 satisfies=false）；"
            "extraneous 恒为空。"
        ),
    )


class AuditLockResponse(BaseModel):
    model_config = {"extra": "forbid"}

    status: Literal["ok"]
    valid: bool = Field(..., description="issues 为空时为 true。")
    issues: list[AuditIssueOut] = Field(
        ...,
        description=(
            "审计问题，确定性排序：先按类型"
            "（missing、unavailable、constraint_mismatch、extraneous），"
            "再按规范化包名。"
        ),
    )


# --------------------------------------------------------------------- #
# POST /dependency-paths 响应
# --------------------------------------------------------------------- #
class DependencyPathsResponse(BaseModel):
    """锁有效时的路径查询结果。"""

    model_config = {"extra": "forbid"}

    status: Literal["ok"]
    root: str = Field(..., description="规范化根包名。")
    target: str = Field(..., description="规范化目标包名。")
    reachable: bool = Field(
        ...,
        description=(
            "目标是否出现在锁定清单并从根包可达；为 false 时 paths 恒为空。"
        ),
    )
    paths: list[list[str]] = Field(
        ...,
        description=(
            "根包到目标包的所有最短包路径（每条为规范化包名序列，含首尾）；"
            "菱形依赖的等长路径全部保留；路径整体按字典序确定性排序。"
        ),
    )


class InvalidLockResponse(BaseModel):
    """锁定清单未通过审计：409，不执行路径查询。"""

    model_config = {"extra": "forbid"}

    status: Literal["invalid_lock"]
    message: str
    issues: list[AuditIssueOut] = Field(
        ...,
        description=(
            "与 /audit-lock 完全一致的审计问题，确定性排序：先按类型"
            "（missing、unavailable、constraint_mismatch、extraneous），"
            "再按规范化包名。"
        ),
    )


class PathLimitResponse(BaseModel):
    """最短路径条数超过固定预算（1000 条）：409，未构造路径列表。

    /dependency-paths、/license-policy、/lock-diff 三个路径查询接口共用；
    一次查询涉及多个目标时按既有包名顺序命中首个超限项。
    """

    model_config = {"extra": "forbid"}

    status: Literal["limit"]
    message: str
    target: str = Field(
        ..., description="触发超限的目标包名（PEP 503 规范化）。"
    )
    used: int = Field(
        ...,
        description=(
            "停止时的饱和路径计数：条数超过预算即饱和为 limit+1，"
            "故超限时恒为 limit+1，与真实条数无关。"
        ),
    )
    limit: int = Field(
        ..., description="单次最短路径查询的路径条数预算（固定 1000）。"
    )


# --------------------------------------------------------------------- #
# POST /install-plan 响应
# --------------------------------------------------------------------- #
class InstallBatchItemOut(BaseModel):
    """一个并行安装批次中的一个安装项：单包或一个循环强连通分量。

    以 ``cyclic`` 为鉴别字段：cyclic=false 时为单包（``name``）；
    cyclic=true 时为一个循环强连通分量（``packages`` 列出内部全部包，
    按规范化包名排序），必须作为一个原子安装项处理。
    """

    model_config = {"extra": "forbid"}

    cyclic: bool = Field(
        ...,
        description=(
            "false=单个包（非循环强连通分量），另带 name；"
            "true=循环强连通分量，另带 packages，分量内包互相可达、"
            "无法排序安装先后，须作为一个原子项安装。"
        ),
    )
    name: str | None = Field(
        None,
        description="单包安装项的 PEP 503 规范化包名；cyclic=true 时为 null。",
    )
    packages: list[str] | None = Field(
        None,
        description=(
            "循环分量内部的全部规范化包名，按包名排序；"
            "cyclic=false 时为 null。"
        ),
    )


class InstallPlanResponse(BaseModel):
    """锁有效时的依赖优先并行安装计划。"""

    model_config = {"extra": "forbid"}

    status: Literal["ok"]
    root: str = Field(..., description="规范化根包名。")
    batches: list[list[InstallBatchItemOut]] = Field(
        ...,
        description=(
            "并行安装批次，按安装先后排列：批次 0 的各项无任何依赖、"
            "可最先并行安装；同一批内的项互不依赖、可并行安装。"
            "任一依赖所在批次不会晚于依赖它的包，根包所在分量处于"
            "最后一批。单包项为 {\"cyclic\": false, \"name\": ...}，"
            "循环分量项为 {\"cyclic\": true, \"packages\": [...]}；"
            "批内按单包名/分量成员名元组的字典序确定性排序。"
        ),
    )


# --------------------------------------------------------------------- #
# POST /sbom 响应
# --------------------------------------------------------------------- #
class PackageMetadataOut(BaseModel):
    """候选版本随快照携带的元数据；未提供的字段为 null（只产生 warning）。"""

    model_config = {"extra": "forbid"}

    source_url: str | None = Field(
        ..., description="源码/分发包 URL；快照未提供时为 null。"
    )
    sha256: str | None = Field(
        ..., description="SHA-256 摘要（64 位十六进制，小写）；未提供时为 null。"
    )
    license: str | None = Field(
        ..., description="许可证标识/文本；未提供时为 null。"
    )


class SbomPackageOut(BaseModel):
    """SBOM 中的一个包（锁定版本）。"""

    model_config = {"extra": "forbid"}

    name: str = Field(..., description="PEP 503 规范化包名。")
    version: str = Field(..., description="锁定版本（PEP 440 字符串）。")
    purl: str = Field(
        ...,
        description="Package URL：pkg:pypi/<规范化名>@<版本>（版本做最小百分号编码）。",
    )
    dependencies: list[str] = Field(
        ...,
        description=(
            "该包锁定版本声明的已激活依赖的规范化名称（去重、按名称排序）；"
            "未激活 marker 依赖不出现。"
        ),
    )
    metadata: PackageMetadataOut = Field(
        ..., description="候选版本随快照携带的元数据；缺失字段为 null。"
    )


class SbomWarningOut(BaseModel):
    """一条元数据缺失提示：缺失字段不阻断导出。"""

    model_config = {"extra": "forbid"}

    name: str = Field(..., description="PEP 503 规范化包名。")
    missing: list[Literal["license", "sha256", "source_url"]] = Field(
        ...,
        description=(
            "该包锁定版本未提供的元数据字段名，按固定枚举次序排列；"
            "无缺失字段的包不产生 warning。"
        ),
    )


class SbomResponse(BaseModel):
    """锁有效时的 SBOM 导出结果。"""

    model_config = {"extra": "forbid"}

    status: Literal["ok"]
    root: str = Field(..., description="规范化根包名。")
    packages: list[SbomPackageOut] = Field(
        ...,
        description=(
            "沿已激活依赖图导出的全部包（含根包），按规范化包名排序。"
        ),
    )
    warnings: list[SbomWarningOut] = Field(
        ...,
        description=(
            "元数据缺失提示，按包名排序；仅列出至少缺一个元数据字段的包，"
            "不阻断导出。"
        ),
    )


# --------------------------------------------------------------------- #
# POST /license-policy 响应
# --------------------------------------------------------------------- #
class LicensePolicyEntryOut(BaseModel):
    """一个许可证策略命中包（违规或未知）。"""

    model_config = {"extra": "forbid"}

    name: str = Field(..., description="PEP 503 规范化包名。")
    license: str | None = Field(
        ...,
        description=(
            "该包锁定版本 metadata.license 的原始 SPDX 表达式文本；"
            "未提供许可证（null/空串）时为 null（只可能出现在 unknowns 中）。"
        ),
    )
    paths: list[list[str]] = Field(
        ...,
        description=(
            "根包到该包的所有最短包路径（每条为规范化包名序列，含首尾）；"
            "菱形依赖的等长路径全部保留；路径整体按字典序确定性排序。"
        ),
    )


class LicensePolicyResponse(BaseModel):
    """锁有效时的许可证策略判定结果。"""

    model_config = {"extra": "forbid"}

    status: Literal["ok"]
    root: str = Field(..., description="规范化根包名。")
    violations: list[LicensePolicyEntryOut] = Field(
        ...,
        description=(
            "许可证表达式判定为拒绝的包，按规范化包名排序；"
            "AND 中任一标识被 deny 即拒绝，OR 中全部标识被 deny 才拒绝。"
        ),
    )
    unknowns: list[LicensePolicyEntryOut] = Field(
        ...,
        description=(
            "许可证表达式判定为未知的包，按规范化包名排序；"
            "既未拒绝也未全部/任一允许，或锁定版本未提供 metadata.license。"
        ),
    )


# --------------------------------------------------------------------- #
# POST /lock-diff 响应
# --------------------------------------------------------------------- #
class LockChangeOut(BaseModel):
    """两份锁之间的一个根可达包变化。"""

    model_config = {"extra": "forbid"}

    name: str = Field(..., description="PEP 503 规范化包名。")
    before_version: str | None = Field(
        ...,
        description=(
            "before_lock 中该包的锁定版本（PEP 440 字符串）；"
            "added 时为 null。"
        ),
    )
    after_version: str | None = Field(
        ...,
        description=(
            "after_lock 中该包的锁定版本（PEP 440 字符串）；"
            "removed 时为 null。"
        ),
    )
    before_paths: list[list[str]] = Field(
        ...,
        description=(
            "before 依赖图中根包到该包的所有最短包路径（每条为规范化包名"
            "序列，含首尾，字典序确定性排序）；该侧不存在该包（added）时"
            "恒为空数组 []。"
        ),
    )
    after_paths: list[list[str]] = Field(
        ...,
        description=(
            "after 依赖图中根包到该包的所有最短包路径（语义同 "
            "before_paths）；该侧不存在该包（removed）时恒为空数组 []。"
        ),
    )


class LockDiffResponse(BaseModel):
    """两份锁均通过审计时的根可达包差异比较结果。"""

    model_config = {"extra": "forbid"}

    status: Literal["ok"]
    root: str = Field(..., description="规范化根包名。")
    added: list[LockChangeOut] = Field(
        ...,
        description=(
            "仅在 after 根可达的包（before_version/before_paths 分别为 "
            "null/[]），按规范化包名排序。"
        ),
    )
    removed: list[LockChangeOut] = Field(
        ...,
        description=(
            "仅在 before 根可达的包（after_version/after_paths 分别为 "
            "null/[]），按规范化包名排序。"
        ),
    )
    upgraded: list[LockChangeOut] = Field(
        ...,
        description=(
            "两侧均可达、after 版本严格高于 before 的包（PEP 440 比较），"
            "按规范化包名排序。"
        ),
    )
    downgraded: list[LockChangeOut] = Field(
        ...,
        description=(
            "两侧均可达、after 版本严格低于 before 的包（PEP 440 比较），"
            "按规范化包名排序。"
        ),
    )


class LockDiffInvalidLockOut(BaseModel):
    """一份锁的独立审计结果：valid=false 时 issues 与 /audit-lock 同形。"""

    model_config = {"extra": "forbid"}

    valid: bool = Field(..., description="该锁是否通过审计（issues 为空）。")
    issues: list[AuditIssueOut] = Field(
        ...,
        description=(
            "该锁的审计问题，与 /audit-lock 完全一致且确定性排序：先按类型"
            "（missing、unavailable、constraint_mismatch、extraneous），"
            "再按规范化包名。"
        ),
    )


class LockDiffInvalidResponse(BaseModel):
    """before_lock/after_lock 任一未通过审计：409，两侧结果分别标注。"""

    model_config = {"extra": "forbid"}

    status: Literal["invalid_lock"]
    message: str
    before: LockDiffInvalidLockOut = Field(
        ..., description="before_lock 的独立审计结果（valid/issues）。"
    )
    after: LockDiffInvalidLockOut = Field(
        ..., description="after_lock 的独立审计结果（valid/issues）。"
    )


# --------------------------------------------------------------------- #
# POST /explain-version 响应
# --------------------------------------------------------------------- #
class ExplainVersionAddedOut(BaseModel):
    """仅在反事实锁定清单中出现的包。"""

    model_config = {"extra": "forbid"}

    name: str = Field(..., description="PEP 503 规范化包名。")
    version: str = Field(..., description="反事实锁中该包的版本（PEP 440 字符串）。")


class ExplainVersionRemovedOut(BaseModel):
    """仅在基准锁定清单中出现的包。"""

    model_config = {"extra": "forbid"}

    name: str = Field(..., description="PEP 503 规范化包名。")
    version: str = Field(..., description="基准锁中该包的版本（PEP 440 字符串）。")


class ExplainVersionChangedOut(BaseModel):
    """两侧都锁定、但版本不同的包。"""

    model_config = {"extra": "forbid", "populate_by_name": True}

    name: str = Field(..., description="PEP 503 规范化包名。")
    from_: str = Field(
        ..., alias="from", description="基准锁中的版本（PEP 440 字符串）。"
    )
    to: str = Field(..., description="反事实锁中的版本（PEP 440 字符串）。")


class ExplainVersionResponse(BaseModel):
    """反事实求解可行时的解释结果。"""

    model_config = {"extra": "forbid", "populate_by_name": True}

    status: Literal["ok"]
    root: str = Field(..., description="规范化根包名。")
    root_version: str = Field(..., description="反事实锁中根包的版本。")
    target_package: str = Field(..., description="规范化后的目标包名。")
    target_version: str = Field(
        ..., description="强制使用的目标版本（PEP 440 规范化形式）。"
    )
    baseline_locked: dict[str, str] = Field(
        ...,
        description=(
            "按 /resolve 原规则求出的基准锁定清单（规范化包名 -> 版本），"
            "作为差异比较的基准。"
        ),
    )
    locked: dict[str, str] = Field(
        ...,
        description="强制目标版本后的反事实锁定清单（规范化包名 -> 版本）。",
    )
    added: list[ExplainVersionAddedOut] = Field(
        ...,
        description="仅在反事实锁中出现的包，按规范化包名排序；无时为 []。",
    )
    removed: list[ExplainVersionRemovedOut] = Field(
        ...,
        description="仅在基准锁中出现的包，按规范化包名排序；无时为 []。",
    )
    changed: list[ExplainVersionChangedOut] = Field(
        ...,
        description=(
            "两侧都锁定但版本不同的包（含目标包本身），按规范化包名排序；"
            "PEP 440 等价版本（1.0 与 1.0.0）不产生变化项。"
        ),
    )
