#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from parsers.universal_parser import UniversalParser
import json

def main():
    # 네트워크 팩트 파싱
    parser = UniversalParser()
    network_facts = parser.parse_dir("XML_Data")
    
    devices = network_facts.get('devices', [])
    print(f"파싱된 장비 수: {len(devices)}")
    
    if devices:
        first_device = devices[0]
        print(f"\n첫 번째 장비 전체 구조:")
        print(json.dumps(first_device, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
