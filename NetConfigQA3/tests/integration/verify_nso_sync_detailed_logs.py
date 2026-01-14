from pathlib import Path
"""
NSO Sync-from 상세 에러 조사 스크립트
"""

import sys
import os
import logging
import json

sys.path.insert(0, str(Path(__file__).parents[2]))

logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s - %(message)s'
)

from clients.nso import NSOClient
from config.settings import settings


def test_sync_with_details(client, device_name):
    """sync-from 실행하고 상세 응답 출력"""
    print(f"\n{'='*70}")
    print(f"🔍 {device_name} sync-from 상세 분석")
    print(f"{'='*70}\n")
    
    # sync-from 실행
    path = f"tailf-ncs:devices/device={device_name}/sync-from"
    res = client._run_action(path)
    
    print(f"📋 응답 타입: {type(res)}")
    print(f"📋 응답 내용:\n{json.dumps(res, indent=2, ensure_ascii=False)}")
    
    # 장비 상태 확인
    device_info = client.get_device_info(device_name)
    print(f"\n📋 장비 정보:\n{json.dumps(device_info, indent=2, ensure_ascii=False)}")
    
    return res


def main():
    print("\n" + "="*70)
    print("🔍 NSO Sync-from 상세 에러 조사")
    print("="*70)
    
    # NSO 클라이언트
    client = NSOClient(
        base_url=settings.nso.base_url,
        username=settings.nso.username,
        password=settings.nso.password
    )
    
    # 등록된 장비 목록
    devices = client.get_devices()
    print(f"\n등록된 장비: {', '.join(devices)}")
    
    if devices:
        # 첫 번째 장비로 테스트
        test_sync_with_details(client, devices[0])
    else:
        print("\n❌ 등록된 장비가 없습니다.")


if __name__ == "__main__":
    main()
