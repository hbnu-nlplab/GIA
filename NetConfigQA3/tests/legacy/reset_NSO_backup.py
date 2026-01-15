
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

async def reset_and_onboard():
    # 1. Load Inventory
    # __file__ is in NetConfigQA3/tests/legacy/
    # device_info_generated.json is in NetConfigQA3/
    inventory_file = Path(__file__).parent.parent.parent / "device_info_generated.json"
    if not inventory_file.exists():
        logger.error(f"Inventory file not found: {inventory_file}")
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

    # 3. DELETE all devices from NSO
    logger.info("\n" + "="*50)
    logger.info("🗑️  Cleaning up existing devices in NSO...")
    logger.info("="*50)
    
    for device in devices:
        name = device['name']
        path = f"tailf-ncs:devices/device={name}"
        
        # Check if exists (optional, but good for logging)
        check = nso_client._request("GET", path)
        if isinstance(check, dict) and "error" not in check:
            logger.info(f"Deleting device: {name}")
            # DELETE request
            res = nso_client._request("DELETE", path)
            if isinstance(res, dict) and res.get("status") == "error":
                logger.warning(f"Failed to delete {name}: {res.get('message')}")
            else:
                 logger.info(f"Deleted {name}")
        else:
            logger.info(f"Device {name} does not exist or already deleted.")

    # 4. Remove Authgroup (Optional but clean)
    # authgroup = inventory.get('global_settings', {}).get('nso_authgroup')
    # if authgroup:
    #     logger.info(f"Note: Authgroup '{authgroup}' is NOT deleted to allow easy re-registration.")

    logger.info("\n" + "="*50)
    logger.info("✅ NSO Reset Complete (Devices Unregistered)")
    logger.info("="*50)

if __name__ == "__main__":
    asyncio.run(reset_and_onboard())
