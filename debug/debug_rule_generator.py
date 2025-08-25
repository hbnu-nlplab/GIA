#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from generators.rule_based_generator import RuleBasedGenerator, RuleBasedGeneratorConfig
from parsers.universal_parser import UniversalParser

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
    
    print(f"로드된 정책 수: {len(rule_generator.policies)}")
    
    # 첫 번째 정책들 확인
    for i, pol in enumerate(rule_generator.policies[:5]):
        print(f"정책 {i}: category={pol.get('category')}, levels={list(pol.get('levels', {}).keys())}")
    
    # 타겟 카테고리
    target_categories = [
        "BGP_Consistency",
        "VRF_Consistency", 
        "Security_Policy",
        "L2VPN_Consistency",
        "OSPF_Consistency"
    ]
    
    print(f"타겟 카테고리: {target_categories}")
    
    # DSL 생성
    dsl_items = rule_generator.compile(
        capabilities=network_facts,
        categories=target_categories,
        scenario_type="normal"
    )
    
    print(f"생성된 DSL 아이템 수: {len(dsl_items)}")
    
    # 각 카테고리별 생성 수 확인
    by_category = {}
    for item in dsl_items:
        cat = item.get('category', 'unknown')
        by_category[cat] = by_category.get(cat, 0) + 1
    
    print("카테고리별 생성 수:")
    for cat, count in by_category.items():
        print(f"  {cat}: {count}")
    
    if len(dsl_items) > 0:
        print(f"\n첫 번째 아이템 예시:")
        print(f"  category: {dsl_items[0].get('category')}")
        print(f"  pattern: {dsl_items[0].get('pattern')}")
        print(f"  intent: {dsl_items[0].get('intent')}")

if __name__ == "__main__":
    main()
