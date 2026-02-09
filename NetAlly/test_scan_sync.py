#!/usr/bin/env python3
"""
Phase 3.5 E2E Test: scan_and_sync
PNETLab ↔ NSO 동기화 테스트
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dotenv import load_dotenv
load_dotenv()

from agent.tools import scan_and_sync

def main():
    print("=" * 60)
    print("Phase 3.5 E2E Test: scan_and_sync")
    print("=" * 60)
    
    # Step 1: Scan only (비교만)
    print("\n[1] Running scan (comparison only)...")
    result = scan_and_sync.invoke({"action": "scan", "auto_onboard": False})
    
    if "error" in result:
        print(f"❌ Error: {result['error']}")
        return
    
    print(f"\n📊 Results:")
    print(f"   PNETLab 실행 노드: {len(result['pnetlab_nodes'])}개")
    for node in result['pnetlab_nodes']:
        print(f"      - {node['name']} (port: {node['telnet_port']})")
    
    print(f"\n   NSO 등록 장비: {len(result['nso_devices'])}개")
    for dev in result['nso_devices']:
        print(f"      - {dev}")
    
    print(f"\n   이미 등록됨: {result['already_registered']}")
    print(f"   누락 (등록 필요): {len(result['missing'])}개")
    for node in result['missing']:
        print(f"      - {node['name']} (port: {node['telnet_port']})")
    
    # Step 2: Ask for auto-onboard confirmation
    if result['missing']:
        print("\n" + "=" * 60)
        print("누락된 장비를 자동 등록하려면 다음 코드를 실행하세요:")
        print("=" * 60)
        print("""
from agent.tools import scan_and_sync
result = scan_and_sync.invoke({
    "action": "sync", 
    "auto_onboard": True,
    "oob_ip": "100.66.240.82"   # PNETLab host IP
})
print(result['onboarded'])     # 등록 성공
print(result['failed'])        # 등록 실패
        """)
    else:
        print("\n✅ 모든 PNETLab 노드가 NSO에 등록되어 있습니다!")

if __name__ == "__main__":
    main()
