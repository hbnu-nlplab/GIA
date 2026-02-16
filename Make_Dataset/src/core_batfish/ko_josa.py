"""
한국어 조사(助詞) 자동 교정 유틸리티

영어 장비명/숫자 뒤의 조사 '과/와'를 받침 유무에 따라 자동 교정합니다.
- 받침 있음(1,3,6,7,8,0) → 과
- 받침 없음(2,4,5,9)     → 와

사용처:
- rule_based_generator.py: L1~L3 질문 생성 후
- batfish_builder.py: L4/L5 질문 생성 후
- main_batfish.py: 템플릿 변수 치환 후
"""

from __future__ import annotations

import re

# 숫자 발음 기준 받침(종성) 유무
_DIGIT_HAS_BATCHIM = {
    "0": True,   # 영/공
    "1": True,   # 일
    "2": False,  # 이
    "3": True,   # 삼
    "4": False,  # 사
    "5": False,  # 오
    "6": True,   # 육
    "7": True,   # 칠
    "8": True,   # 팔
    "9": False,  # 구
}


def _has_batchim(char: str) -> bool:
    """한 글자의 받침(종성) 유무를 판별합니다."""
    if char.isdigit():
        return _DIGIT_HAS_BATCHIM.get(char, False)
    if "가" <= char <= "힣":
        return (ord(char) - 0xAC00) % 28 != 0
    # 영문자 등은 받침 없음 처리 (관행)
    return False


def fix_josa(text: str) -> str:
    """한국어 조사 '과/와'를 앞 글자의 받침 유무에 따라 자동 교정합니다.

    Examples:
        >>> fix_josa("leaf2과 leaf3")
        'leaf2와 leaf3'
        >>> fix_josa("pe1과 pe2")
        'pe1과 pe2'
        >>> fix_josa("p4과 pe1")
        'p4와 pe1'
    """
    # '과' → 받침 없으면 '와'로 교정
    text = re.sub(
        r"(\S)과(\s)",
        lambda m: m.group(1) + ("과" if _has_batchim(m.group(1)[-1]) else "와") + m.group(2),
        text,
    )
    # '와' → 받침 있으면 '과'로 교정
    text = re.sub(
        r"(\S)와(\s)",
        lambda m: m.group(1) + ("과" if _has_batchim(m.group(1)[-1]) else "와") + m.group(2),
        text,
    )
    return text
