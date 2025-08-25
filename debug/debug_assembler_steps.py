#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from generators.rule_based_generator import RuleBasedGenerator, RuleBasedGeneratorConfig
from parsers.universal_parser import UniversalParser
from assemblers.test_assembler import TestAssembler, AssembleOptions

def main():
    # 네트워크 팩트 파싱
    parser = UniversalParser()
    network_facts = parser.parse_dir("XML_Data")
    
    devices = network_facts.get('devices', [])
    print(f"파싱된 장비 수: {len(devices)}")
    
    # Rule generator 초기화
    config = RuleBasedGeneratorConfig(
        policies_path="policies/policies.json",
        min_per_cat=1,  # 줄여서 테스트
        scenario_type="normal"
    )
    
    rule_generator = RuleBasedGenerator(config)
    
    # Security_Policy만 테스트
    dsl_items = rule_generator.compile(
        capabilities=network_facts,
        categories=["Security_Policy"],
        scenario_type="normal"
    )
    
    print(f"Security_Policy DSL 아이템 수: {len(dsl_items)}")
    
    # 첫 번째 아이템만 사용
    if dsl_items:
        single_item = [dsl_items[0]]
        print(f"테스트용 DSL 아이템: {single_item[0]}")
        
        # TestAssembler 초기화
        assembler = TestAssembler(AssembleOptions(base_xml_dir="XML_Data"))
        
        # 단계별 디버그
        print(f"\n=== 1단계: paraphrase_variants ===")
        variants = assembler._paraphrase_variants(single_item[0].get("pattern"))
        print(f"Variants: {variants}")
        
        # 확장된 DSL 생성
        dsl_expanded = []
        for v in variants:
            tmp = dict(single_item[0])
            tmp["pattern"] = v
            dsl_expanded.append(tmp)
        
        print(f"\n=== 2단계: BuilderCore expand ===")
        from utils.builder_core import BuilderCore
        builder = BuilderCore(devices)
        by_cat = assembler._expand_from_dsl(builder, dsl_expanded)
        print(f"BuilderCore 결과: {sum(len(tests) for tests in by_cat.values())}개 테스트")
        
        print(f"\n=== 3단계: scenario 적용 ===")
        by_cat = assembler.apply_scenario(by_cat, None)
        print(f"시나리오 적용 후: {sum(len(tests) for tests in by_cat.values())}개 테스트")
        
        print(f"\n=== 4단계: task tags 할당 ===")
        from assemblers.test_assembler import assign_task_tags
        for cat, arr in by_cat.items():
            for t in arr:
                assign_task_tags(t)
        print(f"태그 할당 후: {sum(len(tests) for tests in by_cat.values())}개 테스트")
        
        print(f"\n=== 5단계: lint_drop_unanswerable ===")
        from assemblers.test_assembler import lint_drop_unanswerable
        by_cat = lint_drop_unanswerable(by_cat)
        print(f"Lint 후: {sum(len(tests) for tests in by_cat.values())}개 테스트")
        
        # 남은 테스트들 출력
        for cat, tests in by_cat.items():
            print(f"  {cat}: {len(tests)}개")
            for i, test in enumerate(tests):
                print(f"    Test {i+1}: {test.get('question')}")

if __name__ == "__main__":
    main()
