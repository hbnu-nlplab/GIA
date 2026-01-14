from pathlib import Path
"""
NSO Sync-from 테스트 스크립트
이미 등록된 장비들에 대해 sync-from만 실행합니다.
"""

import sys
import os
import logging

# 상위 디렉토리를 Python 경로에 추가
sys.path.insert(0, str(Path(__file__).parents[2]))

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

from clients.nso import NSOClient
from config.settings import settings
import json


def test_sync():
    """등록된 장비들의 sync-from 실행"""
    print("\n" + "=" * 70)
    print("🔄 NSO Sync-from 테스트")
    print("=" * 70)
    
    # NSO 클라이언트 초기화
    client = NSOClient(
        base_url=settings.nso.base_url,
        username=settings.nso.username,
        password=settings.nso.password
    )
    
    # 등록된 장비 목록 조회
    print("\n[1/2] 등록된 장비 목록 조회...")
    devices = client.get_devices()
    
    if not devices:
        print("❌ 등록된 장비가 없습니다.")
        return False
    
    print(f"✅ {len(devices)}개 장비 발견: {', '.join(devices)}\n")
    
    # 각 장비에 대해 sync-from 실행
    print("[2/2] Sync-from 실행...\n")
    
    success_count = 0
    fail_count = 0
    results = {"success": [], "failed": []}
    
    for idx, device in enumerate(devices, 1):
        print(f"[{idx}/{len(devices)}] {device} 동기화 중...")
        
        try:
            # sync-from 실행
            success = client.sync_from(device)
            
            if success:
                print(f"  ✅ {device} 동기화 성공!")
                success_count += 1
                results["success"].append(device)
            else:
                print(f"  ❌ {device} 동기화 실패 (result: false)")
                fail_count += 1
                results["failed"].append(device)
                
        except Exception as e:
            print(f"  ❌ {device} 동기화 에러: {e}")
            fail_count += 1
            results["failed"].append(device)
        
        print()
    
    # 결과 요약
    print("=" * 70)
    print("📊 Sync 결과")
    print("=" * 70)
    print(f"✅ 성공: {success_count}/{len(devices)}")
    print(f"❌ 실패: {fail_count}/{len(devices)}")
    
    if results["success"]:
        print(f"\n성공한 장비: {', '.join(results['success'])}")
    
    if results["failed"]:
        print(f"\n실패한 장비: {', '.join(results['failed'])}")
        print("\n💡 실패 원인 확인 방법:")
        print("   1. 장비가 SSH로 연결 가능한지 확인")
        print("   2. authgroup 인증 정보가 올바른지 확인")
        print("   3. NSO CLI에서 상세 로그 확인: show devices device <name> sync-from")
    
    print("\n" + "=" * 70)
    
    return success_count == len(devices)


if __name__ == "__main__":
    success = test_sync()
    sys.exit(0 if success else 1)
