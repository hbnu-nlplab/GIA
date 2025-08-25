#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from generators.rule_based_generator import RuleBasedGenerator, RuleBasedGeneratorConfig
from parsers.universal_parser import UniversalParser
from utils.builder_core import BuilderCore

def main():
    # 네트워크 팩트 파싱
    parser = UniversalParser()
    network_facts = parser.parse_dir("XML_Data")
    
    print(f"파싱된 장비 수: {len(network_facts.get('devices', []))}")
    
    # 첫 번째 장비 정보 확인
    devices = network_facts.get('devices', [])
    if devices:
        first_device = devices[0]
        print(f"첫 번째 장비 파일: {first_device.get('file')}")
        print(f"첫 번째 장비 시스템: {first_device.get('system', {})}")
        print(f"첫 번째 장비 보안: {first_device.get('security', {})}")
        print(f"첫 번째 장비 라우팅: {first_device.get('routing', {})}")
    
    # BuilderCore 초기화
    builder = BuilderCore(devices)
    
    # 몇 가지 기본 메트릭 테스트
    test_metrics = [
        ("ssh_enabled_devices", {"type": "GLOBAL"}),
        ("system_hostname_text", {"type": "DEVICE", "host": builder._hostname(devices[0]) if devices else "test"})
    ]
    
    for metric, scope in test_metrics:
        pre = builder._precompute()
        atype, val = builder._answer_for_metric(metric, scope, pre)
        is_supported = builder._is_supported_answer(atype, val)
        print(f"메트릭 {metric}: type={atype}, value={val}, supported={is_supported}")
    
    # Rule generator 초기화
    config = RuleBasedGeneratorConfig(
        policies_path="policies/policies.json",
        min_per_cat=6,
        scenario_type="normal"
    )
    
    rule_generator = RuleBasedGenerator(config)
    
    # 첫 번째 DSL 아이템만 테스트
    dsl_items = rule_generator.compile(
        capabilities=network_facts,
        categories=["Security_Policy"],
        scenario_type="normal"
    )
    
    print(f"\nSecurity_Policy DSL 아이템 수: {len(dsl_items)}")
    
    if dsl_items:
        first_item = dsl_items[0]
        print(f"첫 번째 아이템: {first_item}")
        
        # 이 아이템을 BuilderCore로 처리해보기
        expanded = builder.expand_from_dsl([first_item])
        print(f"확장된 결과: {expanded}")

if __name__ == "__main__":
    main()
