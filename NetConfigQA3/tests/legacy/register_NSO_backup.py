from pathlib import Path
"""
Auto Onboard - 통합 워크플로우

PNETLab Lab을 NSO에 완전 자동으로 등록하는 통합 워크플로우

워크플로우:
1. PNETLab Topology 조회
2. Inventory 생성
3. SSH 설정 (Day0)
4. NSO 등록
5. 검증
"""


import asyncio
import logging
import json
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from clients.nso import NSOClient
from config.settings import settings
from tests.legacy.nso_onboarder import NSOOnboarder

# Logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

async def register_devices():
    logger.info("=" * 60)
    logger.info("📡 NSO Device Registration")
    logger.info("=" * 60)

    # 1. Load Inventory
    inventory_file = Path(__file__).parent.parent.parent / "device_info_generated.json"
    if not inventory_file.exists():
        logger.error(f"❌ Inventory file not found: {inventory_file}")
        logger.error("   Run test_end_to_end.py or onboard.py first to generate it.")
        return

    with open(inventory_file, 'r', encoding='utf-8') as f:
        inventory = json.load(f)
    
    devices = inventory.get('devices', [])
    logger.info(f"Loaded {len(devices)} devices from inventory.")

    # 2. Initialize NSO Client
    nso_client = NSOClient(
        base_url=settings.nso.base_url,
        username=settings.nso.username,
        password=settings.nso.password
    )

    # 3. Register & Sync
    logger.info("\nStarting registration process...")
    onboarder = NSOOnboarder(inventory, nso_client)
    
    # register_all_devices returns { 'registered': [], 'synced': [], 'failed_register': [], 'failed_sync': [] }
    results = onboarder.register_all_devices()

    # 4. Summary
    logger.info("\n" + "=" * 60)
    logger.info("✅ Registration Complete")
    logger.info("=" * 60)
    logger.info(f"Registered: {len(results['registered'])}/{len(devices)}")
    logger.info(f"Synced:     {len(results['synced'])}/{len(results['registered'])}")
    
    if results['failed_register']:
        logger.error(f"Failed to Register: {results['failed_register']}")
    if results['failed_sync']:
        logger.error(f"Failed to Sync:     {results['failed_sync']}")

if __name__ == "__main__":
    asyncio.run(register_devices())

