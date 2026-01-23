from pathlib import Path
"""
NSO 패키지 재로드 스크립트
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


def reload_packages(client):
    """패키지 재로드 실행"""
    print(f"\n{'='*70}")
    print("🔄 NSO 패키지 재로드")
    print(f"{'='*70}\n")
    
    # packages/reload 액션 실행
    path = "tailf-ncs:packages/reload"
    res = client._run_action(path)
    
    print(f"📋 재로드 결과:\n{json.dumps(res, indent=2, ensure_ascii=False)}")
    
    return res


def check_package_status(client):
    """패키지 상태 확인"""
    print(f"\n{'='*70}")
    print("📊 패키지 상태 확인")
    print(f"{'='*70}\n")
    
    path = "tailf-ncs:packages/package?fields=name;oper-status"
    res = client._request("GET", path)
    
    if isinstance(res, dict) and "package" in res:
        for pkg in res["package"]:
            name = pkg.get("name", "unknown")
            status = pkg.get("oper-status", {})
            print(f"📦 {name}")
            print(f"   상태: {json.dumps(status, indent=6, ensure_ascii=False)}")
    else:
        print(f"응답:\n{json.dumps(res, indent=2, ensure_ascii=False)}")


def main():
    print("\n" + "="*70)
    print("🔄 NSO 패키지 재로드 및 상태 확인")
    print("="*70)
    
    # NSO 클라이언트
    client = NSOClient(
        base_url=settings.nso.base_url,
        username=settings.nso.username,
        password=settings.nso.password
    )
    
    # 재로드 전 상태
    print("\n⏹️  재로드 전 상태:")
    check_package_status(client)
    
    # 패키지 재로드
    reload_packages(client)
    
    # 재로드 후 상태
    print("\n⏹️  재로드 후 상태:")
    check_package_status(client)


if __name__ == "__main__":
    main()
