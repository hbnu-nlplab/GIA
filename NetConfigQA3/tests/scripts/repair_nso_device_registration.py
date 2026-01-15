from pathlib import Path
"""
NSO 장비 재등록 스크립트 (Refactored)
Unified SDK를 사용하여 장비 등록, 키 조회, 동기화를 일괄 처리합니다.
"""

import sys
import json
import logging
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parents[2]))

from clients.nso import NSOClient
from config.settings import settings

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("fix_nso_registration")

def load_device_info():
    """device_info_generated.json 로드"""
    # Root directory is at parents[2]
    config_file = Path(__file__).parents[2] / "device_info_generated.json"
    with open(config_file, 'r') as f:
        return json.load(f)

def main():
    print("\n" + "=" * 70)
    print("🚀 NSO 장비 재등록 (SDK 기반)")
    print("=" * 70)
    
    # 1. 설정 및 클라이언트 준비
    try:
        config = load_device_info()
    except FileNotFoundError:
        logger.error("device_info_generated.json file not found.")
        return False

    client = NSOClient(
        base_url=settings.nso.base_url,
        username=settings.nso.username,
        password=settings.nso.password
    )
    
    # 2. 기존 장비 삭제 (옵션)
    # SDK에는 delete_all이 없으므로 직접 순회
    print("🗑️  기존 장비 정리 중...")
    existing_devices = client.get_devices()
    for dev in existing_devices:
        client.delete_device(dev)
        print(f"  - Deleted {dev}")
        
    # 3. 등록할 장비 정보 구성
    global_settings = config["global_settings"]
    pnetlab_vm_ip = global_settings["pnetlab_vm_ip"]
    authgroup = global_settings["nso_authgroup"]
    ned_id = global_settings["nso_ned_id"]
    
    devices_to_onboard = []
    for d in config["devices"]:
        devices_to_onboard.append({
            "name": d["name"],
            "oob_ip": d["oob_ip"],
            "port": 22,
            "authgroup": authgroup,
            "ned_id": ned_id,
            "protocol": "ssh"
        })
    
    print(f"\n📝 {len(devices_to_onboard)}개 장비 등록 및 초기화 시작 (Unified Onboarding)...")
    
    # 4. 일괄 등록 및 초기화 (SDK 호출)
    results = client.onboard_devices(devices_to_onboard)
    
    # 5. 결과 출력
    print("\n" + "=" * 70)
    print("📊 최종 결과")
    print("=" * 70)
    print(f"Total: {results['total']}")
    print(f"Registered: {len(results['registered'])} {results['registered']}")
    print(f"Synced: {len(results['synced'])} {results['synced']}")
    
    if results['failed_registration']:
        print(f"❌ Failed Registration: {results['failed_registration']}")
    if results['failed_sync']:
        print(f"❌ Failed Sync: {results['failed_sync']}")
        
    print("=" * 70 + "\n")
    
    return len(results['failed_sync']) == 0

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
