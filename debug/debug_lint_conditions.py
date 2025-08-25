#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from generators.rule_based_generator import RuleBasedGenerator, RuleBasedGeneratorConfig
from parsers.universal_parser import UniversalParser
from assemblers.test_assembler import TestAssembler, AssembleOptions, _is_bad_value

def debug_lint_conditions(test):
    """lint_drop_unanswerable의 각 조건을 디버그"""
    q = (test.get("question") or "").strip()
    expected_answer = test.get("expected_answer") or {}
    ans = expected_answer.get("value") or expected_answer.get("ground_truth")
    at = (test.get("answer_type") or "").strip().lower()
    
    print(f"  Question: {q}")
    print(f"  Expected answer structure: {expected_answer}")
    print(f"  Answer: {ans}")
    print(f"  Answer type: {at}")
    
    # 조건 1: 템플릿 변수가 남아있는지
    if "{" in q and "}" in q:
        print(f"  ❌ 조건1 실패: 템플릿 변수 남아있음")
        return False
    print(f"  ✅ 조건1 통과: 템플릿 변수 없음")
    
    # 조건 2: bad value인지
    if _is_bad_value(ans):
        print(f"  ❌ 조건2 실패: bad value")
        return False
    print(f"  ✅ 조건2 통과: valid value")
    
    # 조건 3: answer type별 검증
    if at in ("set","list"):
        if not isinstance(ans, (list, set, tuple)) or len(ans) == 0:
            print(f"  ❌ 조건3 실패: set/list이지만 빈 값이거나 타입 불일치")
            print(f"    isinstance check: {isinstance(ans, (list, set, tuple))}")
            print(f"    length check: {len(ans) if hasattr(ans, '__len__') else 'no length'}")
            return False
        print(f"  ✅ 조건3 통과: set/list 유효")
    elif at in ("map","dict"):
        if not isinstance(ans, dict) or len(ans) == 0:
            print(f"  ❌ 조건3 실패: map/dict이지만 빈 값이거나 타입 불일치")
            return False
        print(f"  ✅ 조건3 통과: map/dict 유효")
    elif at == "text":
        if not isinstance(ans, str) or not ans.strip():
            print(f"  ❌ 조건3 실패: text이지만 빈 값이거나 타입 불일치")
            return False
        print(f"  ✅ 조건3 통과: text 유효")
    else:
        print(f"  ✅ 조건3 통과: 기타 타입 ({at})")
    
    print(f"  ✅ 모든 조건 통과")
    return True

def main():
    # 네트워크 팩트 파싱
    parser = UniversalParser()
    network_facts = parser.parse_dir("XML_Data")
    
    devices = network_facts.get('devices', [])
    
    # Rule generator 초기화
    config = RuleBasedGeneratorConfig(
        policies_path="policies/policies.json",
        min_per_cat=1,
        scenario_type="normal"
    )
    
    rule_generator = RuleBasedGenerator(config)
    
    # Security_Policy만 테스트
    dsl_items = rule_generator.compile(
        capabilities=network_facts,
        categories=["Security_Policy"],
        scenario_type="normal"
    )
    
    # 첫 번째 아이템만 사용
    if dsl_items:
        single_item = [dsl_items[0]]
        
        # TestAssembler 초기화
        assembler = TestAssembler(AssembleOptions(base_xml_dir="XML_Data"))
        
        # 확장된 DSL 생성
        variants = assembler._paraphrase_variants(single_item[0].get("pattern"))
        dsl_expanded = []
        for v in variants:
            tmp = dict(single_item[0])
            tmp["pattern"] = v
            dsl_expanded.append(tmp)
        
        # BuilderCore expand
        from utils.builder_core import BuilderCore
        builder = BuilderCore(devices)
        by_cat = assembler._expand_from_dsl(builder, dsl_expanded)
        
        # 각 테스트에 대해 lint 조건 디버그
        for cat, tests in by_cat.items():
            print(f"\n=== {cat} 카테고리 ===")
            for i, test in enumerate(tests):
                print(f"\nTest {i+1}:")
                debug_lint_conditions(test)

if __name__ == "__main__":
    main()
