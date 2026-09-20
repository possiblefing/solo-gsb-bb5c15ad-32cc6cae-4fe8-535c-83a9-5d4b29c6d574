"""回归测试：PEP 503 等价包名键的候选合并（不得后写覆盖先写）。

当 repository 同时出现 ``Foo_Bar``、``foo.bar``、``foo-bar`` 等按 PEP 503
规范化后同名的键时：

* 各键下的候选版本必须**合并到同一个包**，按 PEP 440 降序参与解析；
* 同一规范化版本在多个键（或同一键内）重复出现时，依赖声明（marker 已按
  目标环境过滤）与元数据完全一致则去重，不一致抛 :class:`SnapshotError`
  （API 层映射为 422 ``invalid_snapshot``）；
* 合并结果、去重结果与冲突报错都**不得随 JSON 键顺序变化**。
"""

from __future__ import annotations

from itertools import permutations

import pytest

from app.repository import (
    SnapshotError,
    build_repository,
    canonical,
    parse_root_specifier,
)
from app.resolver import Resolver
from tests.test_resolver import DEFAULT_ENV, c, d

LINUX = DEFAULT_ENV
WIN32 = {
    "python_version": "3.11",
    "sys_platform": "win32",
    "platform_machine": "AMD64",
}


def resolve(raw_repo, env=LINUX):
    repo = build_repository(raw_repo, env)
    resolver = Resolver(repo)
    state = resolver.resolve(canonical("app"), parse_root_specifier(""), "")
    assert state is not None
    return resolver.build_output(state, "app")


# --------------------------------------------------------------------- #
# 1. 等价键候选合并：版本并集、PEP 440 降序、解析取到跨键最高版本
# --------------------------------------------------------------------- #
def test_equivalent_keys_merge_candidates_descending():
    repo = {
        "app": [c("1.0")],
        "Foo_Bar": [c("1.0", [d("only-in-first")]), c("2.0")],
        "foo.bar": [c("1.5"), c("3.0")],
        "FOO-BAR": [c("2.5")],
    }
    built = build_repository(repo, LINUX)
    # 三种拼写查到的是同一个合并后的桶
    for spelling in ("foo-bar", "Foo_Bar", "foo.bar", "FOO-BAR"):
        assert [str(x.version) for x in built.candidates(spelling)] == [
            "3.0", "2.5", "2.0", "1.5", "1.0",
        ]
    # 低版本键独有的依赖不丢失
    v1 = next(x for x in built.candidates("foo-bar") if str(x.version) == "1.0")
    assert [dep.name for dep in v1.deps] == ["only-in-first"]


def test_resolution_picks_highest_version_across_keys():
    repo = {
        # 根包约束写在 foo_bar 名下，但 2.5/3.0 由另外两个等价键提供
        "app": [c("1.0", [d("foo_bar", ">=2.5,<4")])],
        "foo_bar": [c("2.0"), c("2.5")],
        "foo.bar": [c("3.0")],
    }
    out = resolve(repo)
    assert out["locked"] == {"app": "1.0", "foo-bar": "3.0"}
    assert {"from": "app==1.0", "to": "foo-bar", "specifier": ">=2.5,<4"} in out["edges"]


def test_merge_result_invariant_under_all_key_permutations():
    def build(order):
        keys = {
            "app": [c("1.0", [d("foo-bar", ">=2")])],
            "Foo_Bar": [c("2.0"), c("1.0", [d("only-a")])],
            "foo.bar": [c("3.0"), c("1.5")],
            "foo---bar": [c("2.5")],  # 连续连字符同样折叠为 foo-bar
        }
        return {k: keys[k] for k in order}

    outputs = set()
    candidate_lists = set()
    for order in permutations(["app", "Foo_Bar", "foo.bar", "foo---bar"]):
        raw = build(order)
        built = build_repository(raw, LINUX)
        versions = tuple(str(x.version) for x in built.candidates("foo-bar"))
        candidate_lists.add(versions)
        outputs.add(tuple(sorted(resolve(raw)["locked"].items())))
    assert candidate_lists == {("3.0", "2.5", "2.0", "1.5", "1.0")}
    assert outputs == {(("app", "1.0"), ("foo-bar", "3.0"))}


# --------------------------------------------------------------------- #
# 2. 跨键同版本：完全一致去重；不一致稳定 422
# --------------------------------------------------------------------- #
def test_cross_key_identical_version_is_deduplicated():
    repo = {
        "Foo_Bar": [c("1.0", [d("shared-dep", ">=1.0")])],
        "foo.bar": [c("1.0", [d("shared-dep", ">=1.0")]), c("2.0")],
    }
    built = build_repository(repo, LINUX)
    assert [str(x.version) for x in built.candidates("foo-bar")] == ["2.0", "1.0"]


def test_cross_key_same_version_conflicting_deps_raises_regardless_of_order():
    def build(first, second):
        return {
            first: [c("1.0", [d("x")])],
            second: [c("1.0", [d("y")])],
        }

    messages = set()
    for first, second in (("Foo_Bar", "foo.bar"), ("foo.bar", "Foo_Bar")):
        with pytest.raises(SnapshotError) as exc:
            build_repository(build(first, second), LINUX)
        message = str(exc.value)
        assert "1.0" in message and "foo-bar" in message
        # 报错必须列出全部等价键，且排序稳定
        assert "'Foo_Bar'" in message and "'foo.bar'" in message
        messages.add(message)
    # 两种键顺序报错逐字一致
    assert len(messages) == 1


@pytest.mark.parametrize(
    "meta_a,meta_b",
    [
        ({"license": "MIT"}, {"license": "GPL-2.0-only"}),
        ({"source_url": "https://a.example/x.tar.gz"},
         {"source_url": "https://b.example/x.tar.gz"}),
        ({"sha256": "a" * 64}, {"sha256": "b" * 64}),
    ],
)
def test_cross_key_same_version_conflicting_metadata_raises(meta_a, meta_b):
    def build(order):
        variants = {
            "Foo_Bar": [{"version": "1.0", "metadata": meta_a}],
            "foo.bar": [{"version": "1.0", "metadata": meta_b}],
        }
        return {key: variants[key] for key in order}

    messages = []
    for order in (("Foo_Bar", "foo.bar"), ("foo.bar", "Foo_Bar")):
        with pytest.raises(SnapshotError) as exc:
            build_repository(build(order), LINUX)
        messages.append(str(exc.value))
    assert messages[0] == messages[1]


def test_three_way_conflict_message_lists_all_aliases_stably():
    """三个等价键中两个一致、一个冲突：任一键顺序下列出全部别名。"""
    def build(order):
        variants = {
            "Foo_Bar": [c("1.0", [d("x")])],
            "foo.bar": [c("1.0", [d("x")])],
            "FOO-BAR": [c("1.0", [d("y")])],
        }
        return {key: variants[key] for key in order}

    messages = set()
    for order in permutations(["Foo_Bar", "foo.bar", "FOO-BAR"]):
        with pytest.raises(SnapshotError) as exc:
            build_repository(build(order), LINUX)
        message = str(exc.value)
        for alias in ("'Foo_Bar'", "'foo.bar'", "'FOO-BAR'"):
            assert alias in message
        messages.add(message)
    assert len(messages) == 1


def test_single_key_duplicate_conflict_message_unchanged():
    """同一键内重复版本冲突沿用原报错（不附加等价键提示）。"""
    with pytest.raises(SnapshotError) as exc:
        build_repository(
            {"foo-bar": [c("1.0", [d("x")]), c("1.0", [d("y")])]}, LINUX
        )
    message = str(exc.value)
    assert "出现多次且依赖声明或元数据不一致" in message
    assert "等价键" not in message


# --------------------------------------------------------------------- #
# 3. marker 环境过滤后再比较：过滤后一致合法、不一致仍 422
# --------------------------------------------------------------------- #
def test_cross_key_dedup_compares_marker_filtered_deps_linux():
    repo = {
        "Foo_Bar": [c("1.0", [d("linux-lib", marker="sys_platform == 'linux'")])],
        "foo.bar": [
            c("1.0", [
                d("linux-lib", marker="sys_platform == 'linux'"),
                d("win-lib", marker="sys_platform == 'win32'"),
            ]),
            c("2.0"),
        ],
    }
    # Linux：win-lib 未激活，两键 1.0 的激活依赖集合一致（均为 linux-lib）-> 合并
    built = build_repository(repo, LINUX)
    assert [str(x.version) for x in built.candidates("foo-bar")] == ["2.0", "1.0"]
    v1 = next(x for x in built.candidates("foo-bar") if str(x.version) == "1.0")
    assert [dep.name for dep in v1.deps] == ["linux-lib"]


def test_cross_key_conflict_surfaced_after_marker_filtering_windows():
    repo = {
        "Foo_Bar": [c("1.0", [d("linux-lib", marker="sys_platform == 'linux'")])],
        "foo.bar": [
            c("1.0", [
                d("linux-lib", marker="sys_platform == 'linux'"),
                d("win-lib", marker="sys_platform == 'win32'"),
            ]),
        ],
    }
    # Windows：第一个键的依赖全部未激活（[]），第二个键激活 win-lib -> 不一致
    with pytest.raises(SnapshotError) as exc:
        build_repository(repo, WIN32)
    assert "1.0" in str(exc.value)


def test_cross_key_dedup_after_filtering_both_inactive_is_valid():
    """两侧声明在该环境下都过滤为空：视为完全一致，合法合并。"""
    repo = {
        "Foo_Bar": [c("1.0", [d("x", marker="sys_platform == 'linux'")])],
        "foo.bar": [c("1.0", [
            d("y", marker="sys_platform == 'linux'"),
            d("z", marker="python_version < '3.8'"),
        ])],
    }
    built = build_repository(repo, WIN32)
    v1 = next(x for x in built.candidates("foo-bar") if str(x.version) == "1.0")
    assert v1.deps == []


# --------------------------------------------------------------------- #
# 4. 非法快照的报错顺序也不再取决于 JSON 键顺序
# --------------------------------------------------------------------- #
def test_invalid_version_error_stable_across_key_permutation():
    def build(order):
        keys = {"zzz": [c("nope")], "aaa": [c("1.0")]}
        return {key: keys[key] for key in order}

    messages = set()
    for order in (("zzz", "aaa"), ("aaa", "zzz")):
        with pytest.raises(SnapshotError) as exc:
            build_repository(build(order), LINUX)
        messages.add(str(exc.value))
    assert len(messages) == 1
