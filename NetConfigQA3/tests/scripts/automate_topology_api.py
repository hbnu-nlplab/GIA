
import logging
import sys
import os
import asyncio
from typing import Dict, Any

# Add parent directory to path to import settings
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from clients.pnetlab import PnetlabClient
from config.settings import settings

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("api_topology_automator")

# Cookies from User (2026-01-15) - UPDATED
COOKIES = {
    "token": "a8c9a13f-518f-4f82-9b0f-40c8b9772ce3",
    "XSRF-TOKEN": "eyJpdiI6IjBGK3RUOEMyVXo4cmc0bU5STVZvaXc9PSIsInZhbHVlIjoiMGhKeklMcUxIQTVNcmR6SmJhUHhZOHVyYkswT2F6WTVCbnIyYnpaSUk5SHQ2d2NCVnl6Mk5uUVlRMGUwNzh2eSIsIm1hYyI6ImFkZWFjNWUwNWY0YjI1Y2M5OGFmMDQ3NDliYTcwZTAwNTUzYTQ3MDY3YzMxYzNkZGRhNGJmNTE5MmU4YjY3NzYifQ%3D%3D",
    "_session": "eyJpdiI6ImRHbFpWUlY2RWJvSnEwWGJKNlVJWFE9PSIsInZhbHVlIjoia0x2TXFZdWk4V3p6amwxSFo0ZlIydHd2SE43ZDh1eXJwR0U1VVVEQXh5YkFTbGNsNGhaVkloRTB2NHlURGQ3KyIsIm1hYyI6Ijk1OWRmMzkzZTM5Yzc0YTVhMTkyYmE3OWU0M2I0YWU2ODAzMDRlOGUyZWNiMWFjZWUzYzM0OWViNjQ0OTM4NDgifQ%3D%3D"
}

def main():
    logger.info("Initializing PNETLab Client with Cookies...")
    client = PnetlabClient(settings.pnetlab.base_url)
    
    # Inject Session
    client.set_session_from_browser(
        token=COOKIES["token"],
        session=COOKIES["_session"],
        xsrf=COOKIES["XSRF-TOKEN"]
    )
    
    # 1. Get Topology to Check for Network
    logger.info("--- 1. Checking Topology for Management Network ---")
    topology = client.get_session_topology()
    if "error" in topology:
        logger.error(f"Failed to get topology: {topology}")
        return

    mgmt_net_id = None
    networks = topology.get("data", {}).get("networks", {})
    
    # Find existing "Mgmt-Cloud" (pnet2)
    for net_id, net_info in networks.items():
        if net_info.get("type") == "pnet2":
            mgmt_net_id = net_id
            logger.info(f"Found existing Mgmt-Cloud Network: ID {net_id} ({net_info.get('name')})")
            break
            
    # Create if missing
    if not mgmt_net_id:
        logger.info("Mgmt-Cloud not found. Creating...")
        resp = client.add_network(name="Mgmt-Cloud", net_type="pnet2")
        if "error" in resp:
            logger.error(f"Failed to create network: {resp}")
            return
        
        # We need to find the ID of the new network. 
        # API might return it, or we fetch topology again.
        logger.info("Network created. Refreshing topology...")
        topology = client.get_session_topology()
        networks = topology.get("data", {}).get("networks", {})
        for net_id, net_info in networks.items():
            if net_info.get("type") == "pnet2":
                mgmt_net_id = net_id
                logger.info(f"New Management Network ID: {net_id}")
                break
        
        if not mgmt_net_id:
            logger.error("Failed to find created network.")
            return

    # 2. Connect Nodes
    logger.info(f"--- 2. Connecting Nodes to Network {mgmt_net_id} ---")
    nodes = client.get_nodes_from_topology(topology)
    
    # Filter for vIOS nodes (vIOS1 to vIOS10 usually)
    target_nodes = [n for n in nodes if "vIOS" in n["name"]]
    logger.info(f"Found {len(target_nodes)} target nodes.")
    
    for node in target_nodes:
        logger.info(f"Processing {node['name']} (ID: {node['id']})...")
        
        # Check interfaces
        # Note: 'get_node_interfaces' might not return 'connected' status clearly for all,
        # but let's try to connect Gi0/0 (ID 0).
        
        # Standard vIOS: Interface 0 is Gi0/0
        success = client.connect_node_interface(
            node_id=int(node['id']),
            interface_id=0,
            network_id=int(mgmt_net_id)
        )
        
        if success:
            logger.info(f"✅ {node['name']} Gi0/0 connected.")
        else:
            logger.error(f"❌ Failed to connect {node['name']}")

    logger.info("\n" + "="*50)
    logger.info("TOPOLOGY UPDATE COMPLETE via API")
    logger.info("Please verify connectivity in PNETLab UI.")
    logger.info("="*50)

if __name__ == "__main__":
    main()
