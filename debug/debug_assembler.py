#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from generators.rule_based_generator import RuleBasedGenerator, RuleBasedGeneratorConfig
from parsers.universal_parser import UniversalParser
from assemblers.test_assembler import TestAssembler, AssembleOptions

def main():
    # 네트워크 팩트 파싱
    parser = UniversalParser()
    network_facts = parser.parse_dir("XML_Data")
    
    print(f"파싱된 장비 수: {len(network_facts.get('devices', []))}")
    
    # Rule generator 초기화
    config = RuleBasedGeneratorConfig(
        policies_path="policies/policies.json",
        min_per_cat=6,
        scenario_type="normal"
    )
    
    rule_generator = RuleBasedGenerator(config)
    
    # 타겟 카테고리
    target_categories = [
        "BGP_Consistency",
        "VRF_Consistency", 
        "Security_Policy",
        "L2VPN_Consistency",
        "OSPF_Consistency"
    ]
    
    # DSL 생성
    dsl_items = rule_generator.compile(
        capabilities=network_facts,
        categories=target_categories,
        scenario_type="normal"
    )
    
    print(f"생성된 DSL 아이템 수: {len(dsl_items)}")
    
    # 어셈블러 초기화
    assembler = TestAssembler(
        AssembleOptions(base_xml_dir="XML_Data")
    )
    
    # 어셈블리 수행
    command_items = [d for d in dsl_items if d.get("category") == "Command_Generation"]
    dsl_items = [d for d in dsl_items if d.get("category") != "Command_Generation"]
    
    print(f"Command items: {len(command_items)}")
    print(f"Non-command DSL items: {len(dsl_items)}")
    
    assembled_tests = assembler.assemble(
        network_facts,
        dsl_items,
        scenario_conditions=None,
    )
    
    print(f"어셈블된 테스트 수: {sum(len(tests) for tests in assembled_tests.values())}")
    
    # 각 카테고리별 결과 확인
    for category, tests in assembled_tests.items():
        print(f"  {category}: {len(tests)}개")
        if len(tests) > 0:
            first_test = tests[0]
            print(f"    예시 질문: {first_test.get('question', '')[:50]}...")
            print(f"    예시 답변: {first_test.get('expected_answer', {})}")

if __name__ == "__main__":
    main()
