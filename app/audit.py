"""锁定清单审计（POST /audit-lock）：只审计、不重新求解。

与回溯求解器不同，审计不选择任何版本——版本完全由 ``current_lock`` 给定，
审计只做一件事：从根包出发，按锁定版本展开该版本在目标环境下**已激活**
的依赖，核对锁定清单是否自洽。

规则：
* 从根包开始，根约束（请求的 ``specifier``）与根包锁定版本先入队；
* 按依赖图做确定性遍历：每发现一个可达包，就把它在锁中的版本展开一次，
  其已激活依赖（已按 target_environment 求过 marker）入队；
* 依赖环 / 菱形中，同一个包**只展开一次**，但指向它的每一条入边约束都
  必须累计（环上回边的约束同样参与核对）；
* 包名按 PEP 503 规范化匹配，版本按 PEP 440 等价性判断（``1.0`` 与
  ``1.0.0`` 视为同一版本），约束的满足判断与求解器同一套预发布语义。

输出四类问题（每个问题只对应一个包的一个类型，确定性排序）：
* ``missing``              可达包未出现在 current_lock 中；
* ``unavailable``          锁定版本不在仓库快照里；
* ``constraint_mismatch``  锁定版本不满足根约束或任一入边依赖约束；
* ``extraneous``           锁中包从根包按锁定版本不可达。
"""

from __future__ import annotations

from packaging.specifiers import SpecifierSet
from packaging.version import Version

from .repository import (
    Candidate,
    Dependency,
    Repository,
    canonical,
    version_satisfies,
)

_ROOT = "root"  # 根请求在约束来源中的虚拟声明方，与 edges 输出一致


def _find_candidate(repo: Repository, name: str, version: Version) -> Candidate | None:
    """快照中按 PEP 440 等价性找到该锁定版本的候选（1.0 等价于 1.0.0）。"""
    for cand in repo.candidates(name):
        if cand.version == version:
            return cand
    return None


def _serialise_constraints(
    constraints: list[tuple[str, str]],
    *,
    locked: Version | None,
    allow_prereleases: bool,
    with_satisfies: bool,
) -> list[dict]:
    """把累计的入边约束（含根约束）转为对外 JSON。

    相同 (来源, 约束文本) 的重复声明只保留一条；按来源、约束文本排序。
    ``with_satisfies`` 仅在 constraint_mismatch 时为真：逐条标注锁定版本
    是否满足（此时列出的均为未满足约束，恒为 false）；missing /
    unavailable / extraneous 不输出该字段。
    """
    out: list[dict] = []
    for source, raw in sorted(set(constraints)):
        entry: dict = {"from": source, "specifier": raw}
        if with_satisfies:
            assert locked is not None
            entry["satisfies"] = version_satisfies(
                locked, SpecifierSet("" if raw == "*" else raw),
                allow_prereleases=allow_prereleases,
            )
        out.append(entry)
    return out


def audit_lock(
    repo: Repository,
    *,
    root_name: str,
    root_spec: SpecifierSet,
    root_raw: str,
    current_lock: dict[str, Version],
    allow_prereleases: bool = False,
) -> dict:
    """审计 current_lock，返回 ``{"valid": bool, "issues": [...]}``。

    入参与 :meth:`Resolver.resolve` 对齐：``root_spec`` 已解析的根约束，
    ``root_raw`` 为根约束的原始文本（空串规范化为 ``*``）。
    """
    root_name = canonical(root_name)

    # 每个可达包累计的全部约束：(声明方显示文本, 原始约束文本)。
    # 声明方为 'root'（根请求）或 'pkg==version'（锁定版本的依赖声明）。
    constraints: dict[str, list[tuple[str, str]]] = {
        root_name: [(_ROOT, root_raw.strip() or "*")]
    }
    expanded: set[str] = set()
    queue: list[str] = [root_name]
    head = 0

    def enqueue(dep: Dependency, owner_text: str) -> None:
        """累计一条入边约束；首次到达的包加入展开队列。"""
        subject = dep.name
        constraints.setdefault(subject, []).append((owner_text, dep.raw_spec))
        if subject not in expanded and subject not in queue:
            queue.append(subject)

    while head < len(queue):
        name = queue[head]
        head += 1
        # 环保护：只展开一次；后续入边已由 enqueue 累计，循环末尾仍会核对。
        if name in expanded:
            continue
        expanded.add(name)

        locked = current_lock.get(name)
        if locked is None:
            # missing：锁中没有该包，无法沿锁定版本继续遍历。
            continue
        cand = _find_candidate(repo, name, locked)
        if cand is None:
            # unavailable：锁定版本不在快照，依赖声明未知，无法继续遍历。
            continue

        owner_text = f"{name}=={locked}"
        for dep in cand.deps:  # 已激活依赖（marker 在构造快照时求值）
            enqueue(dep, owner_text)

    # ------------------------------ 问题判定 ------------------------------ #
    issues: list[dict] = []

    def available_versions(name: str) -> list[str]:
        return [str(c.version) for c in repo.candidates(name)]

    for name in sorted(constraints):
        locked = current_lock.get(name)
        incoming = constraints[name]

        if locked is None:
            issues.append({
                "type": "missing",
                "name": name,
                "locked_version": None,
                "available": available_versions(name),
                "constraints": _serialise_constraints(
                    incoming,
                    locked=None,
                    allow_prereleases=allow_prereleases,
                    with_satisfies=False,
                ),
            })
            continue

        cand = _find_candidate(repo, name, locked)
        if cand is None:
            issues.append({
                "type": "unavailable",
                "name": name,
                "locked_version": str(locked),
                "available": available_versions(name),
                "constraints": _serialise_constraints(
                    incoming,
                    locked=None,
                    allow_prereleases=allow_prereleases,
                    with_satisfies=False,
                ),
            })
            continue

        violated = [
            (source, raw)
            for source, raw in incoming
            if not version_satisfies(
                locked,
                SpecifierSet("" if raw == "*" else raw),
                allow_prereleases=allow_prereleases,
            )
        ]
        if violated:
            issues.append({
                "type": "constraint_mismatch",
                "name": name,
                "locked_version": str(locked),
                "available": available_versions(name),
                # 只列出未被满足的约束（已包含来源链信息），全部带 satisfies。
                "constraints": _serialise_constraints(
                    violated,
                    locked=locked,
                    allow_prereleases=allow_prereleases,
                    with_satisfies=True,
                ),
            })

    # extraneous：锁中存在、但从根包按锁定版本不可达的包。
    for name in sorted(set(current_lock) - set(constraints)):
        issues.append({
            "type": "extraneous",
            "name": name,
            "locked_version": str(current_lock[name]),
            "available": available_versions(name),
            "constraints": [],
        })

    # 确定性排序：先按问题类型（固定枚举次序），再按规范化包名。
    type_order = {
        "missing": 0,
        "unavailable": 1,
        "constraint_mismatch": 2,
        "extraneous": 3,
    }
    issues.sort(key=lambda issue: (type_order[issue["type"]], issue["name"]))
    return {"valid": not issues, "issues": issues}
