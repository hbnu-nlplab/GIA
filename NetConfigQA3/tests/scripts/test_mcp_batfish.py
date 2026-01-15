#!/usr/bin/env python3
"""
Test Batfish MCP Server
"""
import asyncio
import json
import logging
import sys
import shutil
from pathlib import Path

# Project path setup
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from mcp_servers.batfish_server import BatfishServer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("batfish_test")

async def test_tool(server, name, args):
    logger.info(f"\n--- Testing {name} ---")
    logger.info(f"Args: {args}")
    result = await server._handle_tool_call(name, args)
    logger.info(f"Result: {json.dumps(result, indent=2)}")
    return result

async def main():
    logger.info("Initializing BatfishServer...")
    server = BatfishServer()
    
    if not server.client.is_available:
        logger.error("❌ Batfish (pybatfish) not available. Skipping tests.")
        return

    # Dummy Configs
    topology_name = "test_topology_mcp"
    configs = {
        "R1": """
hostname R1
interface Loopback0
 ip address 1.1.1.1 255.255.255.255
!
interface Ethernet0/0
 ip address 10.0.0.1 255.255.255.0
!
router bgp 100
 neighbor 10.0.0.2 remote-as 200
""",
        "R2": """
hostname R2
interface Loopback0
 ip address 2.2.2.2 255.255.255.255
!
interface Ethernet0/0
 ip address 10.0.0.2 255.255.255.0
!
router bgp 200
 neighbor 10.0.0.1 remote-as 100
"""
    }
    
    device_info = {
        "description": "Test Topology for MCP Verification",
        "devices": ["R1", "R2"]
    }

    # 1. Init Snapshot
    logger.info("\n--- 1. Init Snapshot (File Creation) ---")
    args = {
        "topology_name": topology_name,
        "configs": configs,
        "device_info": device_info
    }
    result = await test_tool(server, "batfish.init_snapshot", args)
    
    # Verify Files
    pnetlab_data = Path(__file__).parent.parent.parent / "Pnetlab_Data"
    topo_dir = pnetlab_data / topology_name
    
    if topo_dir.exists() and (topo_dir / "configs" / "R1.cfg").exists():
        logger.info(f"✅ Directory populated: {topo_dir}")
    else:
        logger.error(f"❌ Directory not created correctly: {topo_dir}")
        
    # 2. Reachability (Mock configs might not establish BGP in real Batfish without parsing, but init should succeed)
    # We just check if the tool runs without exception
    await test_tool(server, "batfish.reachability", {
        "src": "R1", 
        "dst": "10.0.0.2"
    })

    # 3. Route Table
    await test_tool(server, "batfish.route_table", {"device": "R1"})

    # Cleanup
    # shutil.rmtree(topo_dir) 
    # logger.info("Cleanup completed")

if __name__ == "__main__":
    asyncio.run(main())
