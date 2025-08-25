#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from parsers.universal_parser import UniversalParser
from utils.builder_core import BuilderCore

def main():
    # 네트워크 팩트 파싱
    parser = UniversalParser()
    network_facts = parser.parse_dir("XML_Data")
    
    devices = network_facts.get('devices', [])
    print(f"파싱된 장비 수: {len(devices)}")
    
    # BuilderCore 초기화
    builder = BuilderCore(devices)
    
    # SSH 관련 체크
    for i, device in enumerate(devices):
        hostname = builder._hostname(device)
        ssh_on = builder._ssh_on(device)
        print(f"장비 {i+1}: {hostname}, SSH: {ssh_on}")
        print(f"  security 구조: {device.get('security', {})}")
    
    # precompute 결과 확인
    pre = builder._precompute()
    print(f"\nSSH enabled devices: {pre.get('ssh_enabled', 'NOT_FOUND')}")
    print(f"SSH missing devices: {pre.get('ssh_missing', 'NOT_FOUND')}")
    
    # ssh_enabled_devices 메트릭 직접 테스트
    atype, val = builder._answer_for_metric("ssh_enabled_devices", {"type": "GLOBAL"}, pre)
    is_supported = builder._is_supported_answer(atype, val)
    print(f"\nssh_enabled_devices 메트릭:")
    print(f"  type: {atype}")
    print(f"  value: {val}")
    print(f"  supported: {is_supported}")

if __name__ == "__main__":
    main()
