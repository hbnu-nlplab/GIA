from pathlib import Path
"""
NSO 패키지 정보 확인 스크립트
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


def check_packages(client):
    """NSO 패키지 정보 확인"""
    print(f"\n{'='*70}")
    print("📦 NSO 패키지 정보 확인")
    print(f"{'='*70}\n")
    
    # packages/package 엔드포인트 확인
    path = "tailf-ncs:packages/package"
    res = client._request("GET", path)
    
    print(f"📋 응답 타입: {type(res)}")
    print(f"📋 응답 내용:\n{json.dumps(res, indent=2, ensure_ascii=False)}")
    
    return res


def check_device_types(client):
    """사용 가능한 장비 타입 확인"""
    print(f"\n{'='*70}")
    print("🔧 사용 가능한 NED 타입 확인")
    print(f"{'='*70}\n")
    
    # 장비 타입 정보 조회 (다양한 경로 시도)
    paths = [
        "tailf-ncs:device-types",
        "tailf-ncs:ned-settings",
        "tailf-ncs:packages/package?fields=name;package-version;component"
    ]
    
    for path in paths:
        print(f"\n🔍 경로: {path}")
        res = client._request("GET", path)
        if res and not (isinstance(res, dict) and res.get("status") == "not_found"):
            print(f"✅ 응답:\n{json.dumps(res, indent=2, ensure_ascii=False)}")
        else:
            print("❌ 데이터 없음")


def main():
    print("\n" + "="*70)
    print("🔍 NSO 패키지 및 NED 정보 조사")
    print("="*70)
    
    # NSO 클라이언트
    client = NSOClient(
        base_url=settings.nso.base_url,
        username=settings.nso.username,
        password=settings.nso.password
    )
    
    check_packages(client)
    check_device_types(client)


if __name__ == "__main__":
    main()
