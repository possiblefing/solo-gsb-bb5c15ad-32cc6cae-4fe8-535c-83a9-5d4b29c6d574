"""确定性 JSON SBOM（软件物料清单）导出（POST /sbom）。

调用本模块前，请求的 ``current_lock`` 已由 :func:`app.audit.audit_lock`
判定为**有效**（无 missing / unavailable / constraint_mismatch /
extraneous）。因此这里不做任何版本选择与约束核对，只沿**已激活依赖图**
（与 /dependency-paths 同一张图：按锁定版本、目标环境下 marker 求值后
激活的依赖建图）逐项导出。

每个包条目包含：

* ``name``         PEP 503 规范化包名；
* ``version``      锁定版本（字符串）；
* ``purl``         Package URL（``pkg:pypi/<name>@<version>``）；
* ``dependencies`` 该包锁定版本声明的已激活依赖的**规范化名称**（去重、
  按名称排序；未激活 marker 依赖不出现）；
* ``metadata``     候选版本随快照携带的 source_url / sha256 / license，
  未提供的字段为 null。

元数据缺失（未提供的字段）**不阻断导出**，只在响应顶层的 ``warnings``
中逐项列出。整个 ``packages`` 列表按规范化包名排序，输出只取决于快照、
目标环境与锁定清单，与输入键顺序无关。
"""

from __future__ import annotations

from packaging.version import Version

from .audit import _find_candidate
from .repository import Repository

# PURL 版本段按 PURL-SPEC 允许的字符做最小百分号编码：
# 未保留字符 + 部分 pchar 子分隔符原样输出（PEP 440 版本号只会落在这些
# 字符上，如 1.0、2.0rc1、1.0a1.post1、1!2.0），其余字符百分号编码。
_PURL_VERSION_SAFE = set(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789-._~!$&'()*+,;=:@"
)


def package_url(name: str, version: str) -> str:
    """生成 PyPI 生态的 Package URL：``pkg:pypi/<name>@<version>``。

    名称已按 PEP 503 规范化（小写、``._-`` 折叠为 ``-``），无需编码；
    版本做确定性最小百分号编码，与输入大小写无关。
    """
    encoded = "".join(
        ch if ch in _PURL_VERSION_SAFE else f"%{ord(ch):02X}"
        for ch in version
    )
    return f"pkg:pypi/{name}@{encoded}"


def build_sbom(
    repo: Repository,
    *,
    root_name: str,
    current_lock: dict[str, Version],
    graph: dict[str, list[str]],
) -> dict:
    """沿已激活依赖图生成确定性 SBOM 文档。

    ``graph`` 为 :func:`app.paths.build_locked_graph` 产出的
    根可达子图（节点集恰为锁中全部包，邻接已按名称排序去重）。
    返回 ``{"packages": [...], "warnings": [...]}``。
    """
    packages: list[dict] = []
    warnings: list[dict] = []

    for name in sorted(graph):
        locked = current_lock[name]
        cand = _find_candidate(repo, name, locked)  # 有效锁：锁定版本必在快照
        assert cand is not None
        meta = cand.metadata
        missing = meta.any_missing()
        if missing:
            warnings.append({"name": name, "missing": list(missing)})

        packages.append(
            {
                "name": name,
                "version": str(locked),
                "purl": package_url(name, str(locked)),
                "dependencies": list(graph[name]),
                "metadata": {
                    "source_url": meta.source_url,
                    "sha256": meta.sha256,
                    "license": meta.license,
                },
            }
        )

    return {"packages": packages, "warnings": warnings}
