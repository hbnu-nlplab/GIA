#!/usr/bin/env python3
"""
Test NSO MCP Server with Real Lab
"""
import asyncio
import json
import logging
import sys
from pathlib import Path

# Project path setup
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from mcp_servers.nso_server import NSOServer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mcp_test")

async def test_tool(server, name, args):
    logger.info(f"\n--- Testing {name} ---")
    logger.info(f"Args: {args}")
    result = await server._handle_tool_call(name, args)
    logger.info(f"Result: {json.dumps(result, indent=2)}")
    return result

async def main():
    logger.info("Initializing NSOServer...")
    server = NSOServer()
    
    # 1. Get Devices
    devices_result = await test_tool(server, "nso.get_devices", {})
    devices = devices_result.get("devices", [])
    if not devices:
        logger.warning("No devices found in NSO. Some tests might be skipped.")
    else:
        logger.info(f"Found {len(devices)} devices: {devices}")
        
    # Pick a target device (vIOS10 if available, else first one)
    target_device = "vIOS10"
    if target_device not in devices and devices:
        target_device = devices[0]
        
    if target_device in devices:
        # 2. Check Sync
        await test_tool(server, "nso.check_sync", {"device_name": target_device})
        
        # 3. Get Interfaces
        await test_tool(server, "nso.get_interfaces", {"device": target_device})
        
        # 4. Sync From (Optional, might take time)
        # await test_tool(server, "nso.sync_from", {"device_name": target_device})
        
        # 5. Ping (to gateway)
        await test_tool(server, "nso.ping", {
            "device": target_device, 
            "target": "10.10.10.1", 
            "count": 2
        })
    else:
        logger.error(f"Target device {target_device} not found in NSO.")
        
    # 6. Lifecycle Test (Register & Delete Dummy)
    dummy_device = "test-dummy-mcp"
    logger.info(f"\n--- Lifecycle Test: {dummy_device} ---")
    
    # Register
    reg_args = {
        "name": dummy_device,
        "oob_ip": "1.2.3.4",
        "port": 22,
        "authgroup": "Test1",
        "ned_id": "cisco-ios-cli-6.110"
    }
    await test_tool(server, "nso.register_device", reg_args)
    
    # Check if registered
    dev_list = await test_tool(server, "nso.get_devices", {})
    if dummy_device in dev_list.get("devices", []):
        logger.info("✅ Dummy device registered successfully.")
    else:
        logger.error("❌ Dummy device registration failed.")
        
    # Delete
    await test_tool(server, "nso.delete_device", {"device_name": dummy_device})
    
    # Verify Deletion
    dev_list_after = await test_tool(server, "nso.get_devices", {})
    if dummy_device not in dev_list_after.get("devices", []):
        logger.info("✅ Dummy device deleted successfully.")
    else:
        logger.error("❌ Dummy device deletion failed.")

if __name__ == "__main__":
    asyncio.run(main())
