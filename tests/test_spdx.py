"""SPDX 许可证表达式解析与 allow/deny 三态判定的单元测试。

覆盖：AND/OR/括号的三态真值表与优先级、未知标识、括号组合、大小写规则
（AND/OR 大小写不敏感、标识字面匹配）、尾随 "+"、LicenseRef 自定义
引用、策略集合解析（非法标识/空项/重叠/去重），以及各类非法表达式
（缺连接、括号不匹配、悬空运算符、AND/OR 两侧缺少空白分隔、WITH、
非法字符、空表达式、深度上限）。
"""

from __future__ import annotations

import pytest

from app.repository import SnapshotError
from app.spdx import (
    ALLOW,
    DENY,
    UNKNOWN,
    evaluate_spdx_expression,
    is_valid_spdx_identifier,
    parse_policy_sets,
    parse_spdx_expression,
)


def verdict(text, allow, deny):
    return evaluate_spdx_expression(parse_spdx_expression(text), allow, deny)


MIT = {"MIT"}
APACHE = {"Apache-2.0"}
GPL = {"GPL-3.0-only"}
PERMISSIVE = {"MIT", "Apache-2.0"}


# --------------------------------------------------------------------- #
# 1. 原子标识三态
# --------------------------------------------------------------------- #
def test_atom_allow_deny_unknown():
    assert verdict("MIT", MIT, set()) == ALLOW
    assert verdict("GPL-3.0-only", set(), GPL) == DENY
    assert verdict("Weird-Proprietary", MIT, GPL) == UNKNOWN


def test_deny_takes_precedence_over_allow_at_atom_level():
    """规则重叠在集合解析阶段就被 422 拦截；这里仅固定求值器的内部优先级。"""
    assert verdict("MIT", MIT, MIT) == DENY


def test_identifiers_are_case_sensitive_literal_match():
    assert verdict("mit", MIT, set()) == UNKNOWN
    assert verdict("BSD-3-Clause", {"bsd-3-clause"}, set()) == UNKNOWN
    assert verdict("BSD-3-Clause", {"BSD-3-Clause"}, set()) == ALLOW


def test_or_later_plus_suffix_is_part_of_identifier():
    assert verdict("Apache-2.0+", {"Apache-2.0+"}, set()) == ALLOW
    assert verdict("Apache-2.0+", APACHE, set()) == UNKNOWN


def test_license_ref_identifiers():
    assert verdict("LicenseRef-Proprietary", {"LicenseRef-Proprietary"}, set()) == ALLOW
    assert verdict(
        "DocumentRef-SPDX:LicenseRef-MIT-Style",
        {"DocumentRef-SPDX:LicenseRef-MIT-Style"},
        set(),
    ) == ALLOW


# --------------------------------------------------------------------- #
# 2. AND 三态：全部允许才通过，任一拒绝即违规
# --------------------------------------------------------------------- #
def test_and_all_allow():
    assert verdict("MIT AND Apache-2.0", PERMISSIVE, set()) == ALLOW


@pytest.mark.parametrize("expr", [
    "MIT AND GPL-3.0-only",
    "GPL-3.0-only AND MIT",
    "MIT AND Apache-2.0 AND GPL-3.0-only",
])
def test_and_any_deny(expr):
    assert verdict(expr, PERMISSIVE, GPL) == DENY


@pytest.mark.parametrize("expr", [
    "MIT AND Weird",
    "Weird AND MIT",
    "Weird AND Stranger",
])
def test_and_unknown_when_no_deny_and_not_all_allow(expr):
    assert verdict(expr, PERMISSIVE, GPL) == UNKNOWN


def test_and_deny_takes_precedence_over_unknown():
    assert verdict("Weird AND GPL-3.0-only AND MIT", PERMISSIVE, GPL) == DENY


# --------------------------------------------------------------------- #
# 3. OR 三态：任一允许即通过，全部拒绝才违规
# --------------------------------------------------------------------- #
@pytest.mark.parametrize("expr", [
    "MIT OR GPL-3.0-only",
    "GPL-3.0-only OR MIT",
    "Weird OR MIT",
    "MIT OR Weird OR GPL-3.0-only",
])
def test_or_any_allow(expr):
    assert verdict(expr, PERMISSIVE, GPL) == ALLOW


def test_or_all_deny():
    assert verdict("GPL-3.0-only OR AGPL-3.0-only", set(),
                   {"GPL-3.0-only", "AGPL-3.0-only"}) == DENY


@pytest.mark.parametrize("expr", [
    "Weird OR GPL-3.0-only",
    "GPL-3.0-only OR Stranger",
    "Weird OR Stranger",
])
def test_or_unknown_when_no_allow_and_not_all_deny(expr):
    assert verdict(expr, PERMISSIVE, GPL) == UNKNOWN


# --------------------------------------------------------------------- #
# 4. 括号、优先级、关键字大小写与嵌套
# --------------------------------------------------------------------- #
def test_parentheses_override_default_precedence():
    # 默认 AND 更紧：MIT OR (Apache AND GPL) 的等价括号写法；
    # 反过来 (MIT OR Apache) AND GPL 必然 deny。
    assert verdict("(MIT OR GPL-3.0-only) AND Apache-2.0",
                   PERMISSIVE, GPL) == ALLOW
    assert verdict("MIT OR GPL-3.0-only AND Apache-2.0",
                   PERMISSIVE, GPL) == ALLOW
    assert verdict("(MIT OR Apache-2.0) AND GPL-3.0-only",
                   PERMISSIVE, GPL) == DENY


def test_and_binds_tighter_than_or_without_parentheses():
    # GPL AND Unknown => unknown（无 deny/全 allow 都不成立）；
    # MIT OR unknown => allow。
    assert verdict("MIT OR GPL-3.0-only AND Unknown-Custom",
                   PERMISSIVE, GPL) == ALLOW
    # Deny AND unknown => deny；unknown OR deny => unknown。
    assert verdict("Unknown-Custom OR GPL-3.0-only AND Apache-2.0",
                   PERMISSIVE, GPL) == UNKNOWN


def test_nested_parentheses():
    expr = "((MIT OR GPL-3.0-only) AND (Apache-2.0 OR Weird))"
    assert verdict(expr, PERMISSIVE, GPL) == ALLOW


def test_keywords_and_or_are_case_insensitive():
    assert verdict("Weird oR Apache-2.0 aNd MIT", PERMISSIVE, set()) == ALLOW
    assert verdict("(MIT) aNd (Apache-2.0)", PERMISSIVE, set()) == ALLOW
    assert verdict("weird or strange", PERMISSIVE, set()) == UNKNOWN


def test_redundant_parentheses_around_atom():
    assert verdict("(((MIT)))", MIT, set()) == ALLOW


# --------------------------------------------------------------------- #
# 5. 非法表达式
# --------------------------------------------------------------------- #
@pytest.mark.parametrize("expr", [
    "",
    "   ",
    "MIT AND",
    "OR MIT",
    "MIT OR",
    "AND",
    "MIT Apache-2.0",        # 缺少连接符
    "(MIT OR Apache-2.0",    # 缺右括号
    "MIT OR Apache-2.0)",    # 多余右括号
    "()",                    # 空括号
    "(AND)",
    "MIT//Apache",           # 非法分隔字符
    "MIT++",                 # "+" 只能尾随单个
    "+",
    "GPL-2.0-only WITH Classpath-exception-2.0",  # WITH 不支持
    "MIT AND OR Apache-2.0",
    "MIT AND (Apache-2.0 OR)",
    "(((MIT",
    # AND/OR 两侧必须以空白分隔：紧贴括号或位于括号内侧一律非法
    "MIT OR(Apache-2.0)",
    "(MIT)AND(Apache-2.0)",
    "(MIT)AND (Apache-2.0)",
    "MIT AND(Apache-2.0)",
    "(MIT OR Apache-2.0)AND MIT",
    "MIT OR(Apache-2.0) AND MIT",
    "MIT oR(Apache-2.0)",
    "MIT OR(MIT)",
    "MIT\nOR(MIT)",
    "MIT AND (MIT OR)",
    "(MIT AND)",
])
def test_invalid_expressions_raise(expr):
    with pytest.raises(Exception):
        parse_spdx_expression(expr)


def test_invalid_expressions_are_syntax_error_type():
    from app.spdx import LicenseExpressionError
    for expr in ["MIT AND", "MIT 123", "((", "WITH"]:
        with pytest.raises(LicenseExpressionError):
            parse_spdx_expression(expr)


def test_unrecognized_character_reports_position():
    from app.spdx import LicenseExpressionError
    with pytest.raises(LicenseExpressionError, match="位置"):
        parse_spdx_expression("MIT / Apache-2.0")


def test_with_unsupported_message():
    from app.spdx import LicenseExpressionError
    with pytest.raises(LicenseExpressionError, match="WITH"):
        parse_spdx_expression("GPL-2.0-only WITH Classpath-exception-2.0")


def test_nesting_depth_limit():
    from app.spdx import LicenseExpressionError, _MAX_NESTING
    deep = "(" * (_MAX_NESTING + 5) + "MIT" + ")" * (_MAX_NESTING + 5)
    with pytest.raises(LicenseExpressionError, match="嵌套"):
        parse_spdx_expression(deep)


def test_and_or_cannot_be_license_identifiers():
    from app.spdx import LicenseExpressionError
    for word in ("AND", "OR", "WITH", "and", "or", "with"):
        with pytest.raises(LicenseExpressionError):
            parse_spdx_expression(word)
    with pytest.raises(LicenseExpressionError):
        parse_spdx_expression("MIT AND or")


# --------------------------------------------------------------------- #
# 5b. 回归：AND/OR 两侧必须以空白分隔（SPDX 词法规则）
# --------------------------------------------------------------------- #
@pytest.mark.parametrize("expr,operator", [
    ("MIT OR(Apache-2.0)", "OR"),          # 右侧紧贴左括号
    ("MIT AND(Apache-2.0)", "AND"),
    ("(MIT)AND(Apache-2.0)", "AND"),       # 两侧都紧贴括号
    ("(MIT) OR(Apache-2.0)", "OR"),
    ("(MIT)AND (Apache-2.0)", "AND"),      # 仅左侧紧贴右括号
    ("(MIT OR Apache-2.0)AND MIT", "AND"),
    ("MIT oR(Apache-2.0)", "oR"),          # 大小写不敏感的运算符同样受约束
    ("(MIT and Apache-2.0)Or(MIT)", "Or"),
])
def test_operator_missing_whitespace_rejected(expr, operator):
    from app.spdx import LicenseExpressionError
    with pytest.raises(LicenseExpressionError) as excinfo:
        parse_spdx_expression(expr)
    message = str(excinfo.value)
    # 错误必须定位到具体的违规运算符及其位置，而不是笼统的语法错误
    assert repr(operator) in message
    assert "位置" in message and "空白" in message


def test_first_violating_operator_is_reported():
    """两个运算符都违规时，按扫描顺序定位到靠前的那个（OR，而非后面的 AND）。"""
    from app.spdx import LicenseExpressionError
    with pytest.raises(LicenseExpressionError, match=r"位置 4 处的运算符 'OR'"):
        parse_spdx_expression("MIT OR(Apache-2.0)AND MIT")


@pytest.mark.parametrize("expr", [
    "MIT OR (Apache-2.0)",
    "(MIT) AND (Apache-2.0)",
    "(MIT OR Apache-2.0)",
    "MIT OR  (Apache-2.0)",                # 多个空白仍合法
    "MIT\tOR\t(Apache-2.0)",               # tab 也是空白
    "(MIT or Apache-2.0) anD BSD-3-Clause",
    "MIT OR\n(Apache-2.0)",
    "((MIT OR Apache-2.0) AND (BSD-3-Clause OR MIT))",
])
def test_whitespace_separated_operators_still_parse(expr):
    """合法的空白分隔、大小写混写与嵌套括号语义保持不变（不做 split 式破坏）。"""
    node = parse_spdx_expression(expr)
    assert node[0] in ("and", "or", "atom")


def test_operator_precedence_preserved_after_lexer_change():
    # AND 仍比 OR 更紧：MIT OR (GPL AND Apache)
    assert verdict(
        "MIT OR GPL-3.0-only AND Apache-2.0", PERMISSIVE, GPL
    ) == ALLOW
    assert verdict(
        "(MIT OR Apache-2.0) AND GPL-3.0-only", PERMISSIVE, GPL
    ) == DENY
    # 括号分组 + 三态的既有语义不受词法改动影响
    assert verdict("(MIT) AND (Apache-2.0)", PERMISSIVE, set()) == ALLOW
    assert verdict("(MIT) OR (GPL-3.0-only)", PERMISSIVE, GPL) == ALLOW


def test_operator_letter_fragments_inside_identifiers_untouched():
    """标识词中包含 AND/OR 字母片段时仍按单个标识词处理，不能被拆分。"""
    from app.spdx import LicenseExpressionError
    # ANDOR 是真实存在的 SPDX 许可证标识词，必须原样作为原子
    node = parse_spdx_expression("ANDOR")
    assert node == ("atom", "ANDOR")
    assert verdict("MIT AND ANDOR", {"MIT", "ANDOR"}, set()) == ALLOW
    assert verdict("ORBIT OR MIT", {"MIT"}, set()) == ALLOW
    # 标识符与运算符之间仍须空白：ANDOR(MIT) 是标识词紧贴括号，按既有
    # “缺少 AND/OR 连接”规则报错（而不是把 AND 当运算符）
    with pytest.raises(LicenseExpressionError):
        parse_spdx_expression("ANDOR(MIT)")


def test_dangling_operator_errors_locate_operator():
    """表达式边界上的悬空运算符同样稳定报错并定位运算符。"""
    from app.spdx import LicenseExpressionError
    with pytest.raises(LicenseExpressionError, match=r"'AND'.*右侧"):
        parse_spdx_expression("MIT AND")
    with pytest.raises(LicenseExpressionError, match=r"位置 0 处的运算符 'OR'"):
        parse_spdx_expression("OR MIT")
    with pytest.raises(LicenseExpressionError, match=r"'OR'.*\)"):
        parse_spdx_expression("MIT AND (MIT OR)")
    # 右侧与 ')' 间有空白时由语法层拦截，仍定位到运算符
    with pytest.raises(LicenseExpressionError, match=r"'OR'.*\)"):
        parse_spdx_expression("MIT AND (MIT OR )")


# --------------------------------------------------------------------- #
# 6. is_valid_spdx_identifier / parse_policy_sets
# --------------------------------------------------------------------- #
@pytest.mark.parametrize("text,expected", [
    ("MIT", True),
    ("Apache-2.0", True),
    ("GPL-3.0+", True),
    ("LicenseRef-Proprietary", True),
    ("DocumentRef-doc:LicenseRef-x", True),
    ("mit", True),                       # 合法标识（字面匹配在求值阶段）
    ("MIT AND Apache-2.0", False),       # 表达式不是单个标识
    ("", False),
    ("+MIT", False),
    ("MIT+Apache", False),
    ("LicenseRef-", False),
    ("(MIT)", False),
])
def test_identifier_validation(text, expected):
    assert is_valid_spdx_identifier(text) is expected


def test_parse_policy_sets_dedupes_and_preserves():
    allow, deny = parse_policy_sets(
        [" MIT ", "Apache-2.0", "MIT"], ["GPL-3.0-only"]
    )
    assert allow == {"MIT", "Apache-2.0"}
    assert deny == {"GPL-3.0-only"}


def test_parse_policy_sets_empty_defaults():
    assert parse_policy_sets([], []) == (set(), set())


def test_parse_policy_sets_rejects_expression_item():
    with pytest.raises(SnapshotError, match="allow"):
        parse_policy_sets(["MIT AND Apache-2.0"], [])


def test_parse_policy_sets_rejects_blank_item():
    with pytest.raises(SnapshotError, match="deny"):
        parse_policy_sets([], ["   "])


def test_parse_policy_sets_rejects_with_keyword_item():
    with pytest.raises(SnapshotError):
        parse_policy_sets(["WITH"], [])


def test_parse_policy_sets_overlap_rejected_with_sorted_names():
    with pytest.raises(SnapshotError, match="MIT、gpl-x"):
        parse_policy_sets(["gpl-x", "MIT"], ["MIT", "gpl-x"])
