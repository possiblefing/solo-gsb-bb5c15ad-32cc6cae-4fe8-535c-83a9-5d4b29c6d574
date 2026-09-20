"""仓库快照的规范化与解析。

使用 packaging（PEP 440 / PEP 503）完成名称规范化、版本与约束解析，
并按请求给出的目标环境对 PEP 508 marker 求值（仅保留激活的依赖）。
非法快照或 marker 在这里抛出 SnapshotError，由 API 层映射为 HTTP 422。
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit

from packaging.requirements import InvalidRequirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from .markers import (
    MarkerError,
    build_environment,
    marker_active,
    parse_marker,
)


def canonical(name: str) -> str:
    """PEP 503 规范化包名（小写，点/下划线/连续连字符折叠为单个 '-'）。"""
    return canonicalize_name(name)


class SnapshotError(ValueError):
    """快照或请求中存在非法（无法按 PEP 440/503 解析的）数据。"""


# SHA-256 摘要：恰好 64 个十六进制字符（大小写接受，内部统一为小写）。
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


@dataclass(frozen=True)
class CandidateMetadata:
    """候选版本随快照携带的 SBOM 元数据（全部可选，缺失项为 None）。"""

    source_url: str | None = None
    sha256: str | None = None
    license: str | None = None

    def any_missing(self) -> tuple[str, ...]:
        """缺失（值为 None）的元数据字段名，按固定枚举次序返回。"""
        return tuple(
            field_name
            for field_name, value in (
                ("license", self.license),
                ("sha256", self.sha256),
                ("source_url", self.source_url),
            )
            if value is None
        )


def _parse_candidate_metadata(
    item: Mapping, *, owner: str
) -> CandidateMetadata:
    """解析并校验候选版本的 source_url / sha256 / license 元数据。

    三项全部可选：字段缺失或为空字符串视为“未提供”（不阻断 SBOM 导出，
    只形成 warnings）；但一旦提供非空值就必须合法——sha256 须为 64 位
    十六进制，source_url 须为 http/https 绝对 URL，非法值抛 SnapshotError
    （API 层映射为 422）。
    """
    raw_meta = item.get("metadata")
    if raw_meta is None:
        return CandidateMetadata()

    source_url = (raw_meta.get("source_url") or "").strip() or None
    license_text = (raw_meta.get("license") or "").strip() or None
    sha256_text = (raw_meta.get("sha256") or "").strip()

    if source_url is not None:
        parts = urlsplit(source_url)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise SnapshotError(
                f"包 {owner!r} 的元数据 source_url {source_url!r} 不是合法的"
                " http/https 绝对 URL"
            )

    sha256_value: str | None = None
    if sha256_text:
        if not _SHA256_RE.match(sha256_text):
            raise SnapshotError(
                f"包 {owner!r} 的元数据 sha256 {raw_meta.get('sha256')!r}"
                " 不是合法的 SHA-256 摘要（应为 64 位十六进制字符）"
            )
        sha256_value = sha256_text.lower()

    return CandidateMetadata(
        source_url=source_url, sha256=sha256_value, license=license_text
    )


class Dependency:
    __slots__ = ("name", "raw_spec", "spec")

    def __init__(self, name: str, raw_spec: str, spec: SpecifierSet):
        self.name = canonical(name)
        self.raw_spec = raw_spec.strip() or "*"
        self.spec = spec

    def __repr__(self) -> str:  # pragma: no cover - 调试辅助
        return f"Dependency({self.name!r}, {self.raw_spec!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Dependency):
            return NotImplemented
        return self.name == other.name and self.spec == other.spec

    def __hash__(self) -> int:
        return hash((self.name, str(self.spec)))


class Candidate:
    __slots__ = ("version", "deps", "metadata")

    def __init__(
        self,
        version: Version,
        deps: list[Dependency],
        metadata: CandidateMetadata | None = None,
    ):
        self.version = version
        self.deps = deps
        self.metadata = metadata or CandidateMetadata()


class Repository:
    """按规范化包名索引的不可变快照；候选版本从高到低排列。"""

    def __init__(self, packages: dict[str, list[Candidate]]):
        self._packages = packages

    def candidates(self, name: str) -> list[Candidate]:
        return self._packages.get(canonical(name), [])

    def known(self, name: str) -> bool:
        return canonical(name) in self._packages


def _parse_specifier(raw: str, *, owner: str) -> SpecifierSet:
    text = (raw or "").strip()
    try:
        return SpecifierSet(text)
    except (InvalidSpecifier, InvalidRequirement) as exc:
        raise SnapshotError(f"包 {owner!r} 的版本约束 {raw!r} 不是合法的 PEP 440 约束: {exc}") from exc


def build_repository(
    raw: dict[str, list[dict]], target_environment: Mapping[str, str] | None = None
) -> Repository:
    """把 API 输入构造成 Repository。

    入参为纯字典（API 层对 Pydantic 模型 model_dump 后传入），形如::

        {"pkg": [{"version": "1.0",
                  "dependencies": [{"name": "dep", "specifier": ">=1.0"}],
                  "metadata": {"source_url": "https://...",
                               "sha256": "<64 位十六进制>",
                               "license": "MIT"}}]}

    候选可随版本携带可选的 ``metadata``（source_url / sha256 / license），
    供 POST /sbom 导出；三项均可缺省，但非空值必须合法（否则抛
    SnapshotError）。marker 等其余规则见下。

    ``target_environment`` 提供 ``python_version`` / ``sys_platform`` /
    ``platform_machine`` 三个键；每条依赖的 PEP 508 marker 在该环境下求值，
    **仅激活的依赖**会进入快照（环境值全部来自请求，不读取宿主机）。
    marker 语法非法或引用越界变量时抛 SnapshotError（API 层映射为 422）。

    候选列表顺序无关，内部按 PEP 440 版本降序排列，保证解析确定性。

    多个快照键按 PEP 503 规范化后可能同名（``Foo_Bar``、``foo.bar``、
    ``foo-bar`` 都规范化为 ``foo-bar``）：这些键下的候选版本**合并到同一
    个包**，一并参与 PEP 440 降序与全部端点，而不是后写覆盖先写。同一规范
    化版本在多个键（或同一键内）重复出现时，依赖声明（marker 按目标环境
    过滤后）与元数据完全一致则去重；不一致则抛 SnapshotError。键的遍历按
    规范化名与原始键文本排序，故合并结果与冲突报错都不随 JSON 键顺序变化。
    """
    try:
        env = build_environment(target_environment) if target_environment else None
    except MarkerError as exc:
        raise SnapshotError(str(exc)) from exc

    # 先汇总每个规范化名对应的全部原始键（排序后用于稳定的冲突提示），
    # 使报错内容只取决于快照内容、与 JSON 键顺序无关。
    alias_map: dict[str, list[str]] = {}
    for raw_name in raw:
        alias_map.setdefault(canonical(raw_name), []).append(raw_name)
    for names in alias_map.values():
        names.sort()

    # 规范化名 -> 该包全部候选（Version -> Candidate），跨等价键合并。
    buckets: dict[str, dict[Version, Candidate]] = {}

    # 按 (规范化名, 原始键文本) 稳定遍历：等价键的候选进入同一桶，先/后写
    # 不再互相覆盖；重复检测命中的第一个位置也与 JSON 键顺序无关。
    ordered_names = sorted(raw, key=lambda name: (canonical(name), name))
    for raw_name in ordered_names:
        cname = canonical(raw_name)
        bucket = buckets.setdefault(cname, {})
        raw_candidates = raw[raw_name]

        for item in raw_candidates:
            version_text = item["version"].strip()
            try:
                version = Version(version_text)
            except InvalidVersion as exc:
                raise SnapshotError(
                    f"包 {cname!r} 的版本 {item['version']!r} 不是合法的 PEP 440 版本"
                ) from exc

            deps: list[Dependency] = []
            owner = f"{cname}=={version}"
            metadata = _parse_candidate_metadata(item, owner=owner)
            for dep in item.get("dependencies", []):
                dep_name = dep["name"]
                spec_text = dep.get("specifier", "")
                spec = _parse_specifier(spec_text, owner=owner)
                try:
                    marker = parse_marker(
                        dep.get("marker", ""),
                        location=(
                            f"包 {owner!r} 对 {canonical(dep_name)!r} 的依赖"
                        ),
                    )
                    active = marker_active(marker, env) if env is not None else True
                except MarkerError as exc:
                    raise SnapshotError(str(exc)) from exc
                if not active:
                    # 未激活依赖：不进入约束、回溯、冲突来源链与边。
                    continue
                deps.append(Dependency(dep_name, spec_text.strip(), spec))

            candidate = Candidate(version, deps, metadata)
            if version in bucket:
                other = bucket[version]
                if other.deps != deps or other.metadata != metadata:
                    aliases = alias_map[cname]
                    if len(aliases) > 1:
                        keys_text = "、".join(repr(name) for name in aliases)
                        raise SnapshotError(
                            f"包 {cname!r} 的版本 {version} 在多个 PEP 503 等价键"
                            f"（{keys_text}）下重复出现，但依赖声明或元数据不一致"
                        )
                    raise SnapshotError(
                        f"包 {cname!r} 的版本 {version} 出现多次且依赖声明或元数据不一致"
                    )
                # 完全重复（同一键内或跨等价键）则忽略。
                continue
            bucket[version] = candidate

    packages: dict[str, list[Candidate]] = {}
    for cname in sorted(buckets):
        bucket = buckets[cname]
        # PEP 440 降序：候选总是从高到低尝试。
        packages[cname] = [bucket[v] for v in sorted(bucket, reverse=True)]

    return Repository(packages)


def parse_root_specifier(raw: str) -> SpecifierSet:
    return _parse_specifier(raw, owner="<root request>")


def parse_target_version(raw: str, *, label: str = "target_version") -> Version:
    """校验请求中强制使用的单个目标版本（PEP 440）。

    非法版本抛 SnapshotError（API 层映射为 422）；返回规范化后的
    Version，使钉版本约束文本与输入拼写（空白、前导零等）无关。
    """
    text = str(raw).strip()
    try:
        return Version(text)
    except InvalidVersion as exc:
        raise SnapshotError(
            f"{label} {raw!r} 不是合法的 PEP 440 版本"
        ) from exc


def version_satisfies(
    version: Version, spec: SpecifierSet, *, allow_prereleases: bool = False
) -> bool:
    """版本是否满足 PEP 440 约束集合。

    与求解器同一套 pip 跟随语义：默认排除预发布（dev/a/b/rc），除非
    ``allow_prereleases`` 放开、或约束谓词显式提到预发布版本
    （如 ``==1.0a1``，该谓词 ``prereleases=True``）。/resolve、/upgrade
    的候选过滤与 /audit-lock 的锁定版本审计共用本函数。
    """
    if allow_prereleases:
        return version in spec
    if version.is_prerelease or version.is_devrelease:
        if not any(s.prereleases for s in spec):
            return False
    return version in spec


def parse_current_lock(
    raw: dict[str, str], *, label: str = "current_lock"
) -> dict[str, Version]:
    """校验并规范化请求中的锁定清单：PEP 503 包名 -> PEP 440 版本。

    ``label`` 仅用于错误信息中标识被解析的锁字段（如 /lock-diff 的
    ``before_lock`` / ``after_lock``），默认 ``current_lock``。

    非法版本、或同一规范化包名对应多个不同版本时抛 SnapshotError
    （API 层映射为 422）。
    """
    lock: dict[str, Version] = {}
    for name, text in raw.items():
        cname = canonical(name)
        version_text = str(text).strip()
        try:
            version = Version(version_text)
        except InvalidVersion as exc:
            raise SnapshotError(
                f"{label} 中包 {cname!r} 的版本 {text!r} 不是合法的 PEP 440 版本"
            ) from exc
        if cname in lock and lock[cname] != version:
            raise SnapshotError(
                f"{label} 中包 {cname!r} 出现了多个不同版本"
            )
        lock[cname] = version
    return lock
