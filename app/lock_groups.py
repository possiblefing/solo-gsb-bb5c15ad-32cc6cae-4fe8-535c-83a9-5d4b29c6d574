"""跨环境锁组选择（POST /lock-groups）：用最少的锁文件覆盖全部目标环境。

输入阶段与 ``/resolve-matrix`` 相同：同一份仓库快照、根约束与 2～8 个带
唯一 id 的目标环境，先逐环境复用 ``/resolve`` 的既有规则各求出一份候选锁；
任一环境无解时整体 409（由路由层处理，本模块不参与）。

随后在全部环境上做**交叉校验**：把去重后的每一份候选锁，当作
``current_lock`` 在每个环境上按 ``/audit-lock`` 的同一套规则审计
（marker 按被审计环境求值）——锁只有在某个环境下无任何审计问题时，才算
*可覆盖* 该环境。每个环境自己求出的候选锁必然可覆盖自身，因此至少存在
一个可行覆盖。

最后做精确的最小集合覆盖（环境至多 8 个，候选锁去重后同样至多 8 份，
子集总数不超过 256，直接枚举即可，无需近似）：

* 目标：覆盖全部环境的锁文件数量最少；
* 并列最优时按**锁内容及环境 id 的稳定序**裁决：候选锁先按锁内容的稳定
  键（逐 (包名, 版本) 对的字典序）排列，再在该次序上对“每个环境 id（升序）
  被第几份候选锁覆盖”的索引元组取字典序最小者；
* 整个选择只取决于锁内容与环境 id 集合，与环境的请求顺序、各环境候选锁的
  产生顺序无关，同一输入结果确定。
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

# 锁组 id 的十六进制前缀长度（内容哈希截断，组内只可能至多 8 份锁）。
_GROUP_ID_PREFIX = 12


def lock_content_key(locked: dict[str, str]) -> tuple[tuple[str, str], ...]:
    """锁内容的稳定比较键：按规范化包名排序的 (包名, 版本) 对元组。

    只取决于锁内容本身（与锁的来源环境、字典输入顺序无关），用作并列最优
    时“锁内容稳定序”的裁决依据。
    """
    return tuple((name, locked[name]) for name in sorted(locked))


def lock_group_id(locked: dict[str, str]) -> str:
    """由锁内容派生的稳定组 id：``lg-`` + 内容指纹的十六进制前缀。

    指纹对按包名排序后的 (包名, 版本) 对做 SHA-256，因此同内容的锁
    （包括跨环境去重后的同一份锁）得到同一个 id；组 id 与请求顺序无关。
    """
    joined = "\n".join(f"{name}=={version}" for name, version in sorted(locked.items()))
    digest = hashlib.sha256(joined.encode("utf-8")).hexdigest()
    return f"lg-{digest[:_GROUP_ID_PREFIX]}"


@dataclass(frozen=True)
class CandidateLock:
    """一份去重后的候选锁及其通过交叉审计可覆盖的环境集合。"""

    locked: dict[str, str]
    covers: frozenset[str]


def select_lock_groups(
    candidates: list[CandidateLock], environment_ids: list[str]
) -> list[CandidateLock]:
    """精确选择覆盖全部环境所需数量最少的候选锁（最小集合覆盖）。

    ``candidates`` 为去重后的候选锁（每份至少覆盖一个环境）；
    ``environment_ids`` 为全部目标环境 id。

    枚举候选锁的全部非空子集，取并集覆盖全部环境且元素数最少者；并列时按
    锁内容及环境 id 的稳定序裁决（见模块 docstring）。正常调用必然存在
    可行覆盖（每份候选锁至少覆盖它自己的来源环境）。
    """
    target = frozenset(environment_ids)
    # 候选锁按锁内容稳定序排列；选择与裁决全部基于该次序，与输入顺序无关。
    ordered = sorted(candidates, key=lambda cand: lock_content_key(cand.locked))

    best: list[int] | None = None
    best_score: tuple[int, ...] = ()
    n = len(ordered)
    for bits in range(1, 1 << n):
        chosen = [i for i in range(n) if bits & (1 << i)]
        covered: frozenset[str] = frozenset()
        for i in chosen:
            covered |= ordered[i].covers
        if covered != target:
            continue
        if best is not None and len(chosen) > len(best):
            continue

        # 并列裁决：每个环境 id（升序）由内容序最靠前的可覆盖候选锁负责，
        # 取“负责候选锁索引”元组的字典序最小者。
        score = tuple(
            min(i for i in chosen if env_id in ordered[i].covers)
            for env_id in sorted(environment_ids)
        )
        if best is None or len(chosen) < len(best) or score < best_score:
            best = chosen
            best_score = score

    assert best is not None, "交叉审计后每个环境至少被自身候选锁覆盖"
    return [ordered[i] for i in best]
