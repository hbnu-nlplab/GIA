#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from generators.rule_based_generator import RuleBasedGenerator, RuleBasedGeneratorConfig
from parsers.universal_parser import UniversalParser
from utils.builder_core import BuilderCore

def main():
    # 네트워크 팩트 파싱
    parser = UniversalParser()
    network_facts = parser.parse_dir("XML_Data")
    
    devices = network_facts.get('devices', [])
    print(f"파싱된 장비 수: {len(devices)}")
    
    # Rule generator 초기화
    config = RuleBasedGeneratorConfig(
        policies_path="policies/policies.json",
        min_per_cat=6,
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
    
    if dsl_items:
        # 첫 번째 아이템 상세 정보
        first_item = dsl_items[0]
        print(f"\n첫 번째 DSL 아이템:")
        print(f"  category: {first_item.get('category')}")
        print(f"  pattern: {first_item.get('pattern')}")
        print(f"  intent: {first_item.get('intent')}")
        
        # BuilderCore로 expand
        builder = BuilderCore(devices)
        
        print(f"\nBuilderCore expand 시도...")
        expanded = builder.expand_from_dsl([first_item])
        
        print(f"Expanded 결과:")
        for category, tests in expanded.items():
            print(f"  {category}: {len(tests)}개")
            for i, test in enumerate(tests):
                print(f"    Test {i+1}:")
                print(f"      question: {test.get('question')}")
                print(f"      expected_answer: {test.get('expected_answer')}")
                print(f"      answer_type: {test.get('answer_type')}")

if __name__ == "__main__":
    main()
