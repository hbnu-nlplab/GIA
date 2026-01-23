
import sys
import os
import logging
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from clients.pnetlab import PnetlabClient
from config.settings import settings

# Logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def cleanup_topology():
    logger.info("=" * 60)
    logger.info("🧹 PNETLab Topology Cleanup")
    logger.info("=" * 60)

    # 1. Initialize Client
    client = PnetlabClient(settings.pnetlab.base_url)
    
    # If not authenticated automatically via env, try manual settings
    if not client.is_authenticated:
        if settings.pnetlab.jwt_token:
            client.set_session_from_browser(
                token=settings.pnetlab.jwt_token,
                session=settings.pnetlab.session,
                xsrf=settings.pnetlab.xsrf_token
            )
        else:
            logger.error("❌ Authentication failed: Missing cookies in .env")
            return

    # 2. Get Topology
    topology = client.get_session_topology()
    if "error" in topology:
        logger.error(f"❌ Failed to get topology: {topology.get('error')}")
        return

    nodes = client.get_nodes_from_topology(topology)
    networks = topology.get("data", {}).get("networks", {})
    
    logger.info(f"Found {len(nodes)} nodes and {len(networks)} networks.")

    # 3. Delete Nodes
    if nodes:
        logger.info("\n--- Deleting Nodes ---")
        for node in nodes:
            node_id = int(node['id'])
            name = node['name']
            
            # Check status and stop if running
            if node.get('status') == 2:  # 2 usually means running in PNETLab API (check PnetlabClient.start_node logic if unsure, but safe to try stop)
                 logger.info(f"Stopping node {name} (ID: {node_id})...")
                 client.stop_node(node_id)
            
            # Safe to attempt stop even if status unknown
            client.stop_node(node_id)
            
            logger.info(f"Deleting node {name} (ID: {node_id})...")
            if client.delete_node(node_id):
                logger.info(f"✅ Deleted {name}")
            else:
                logger.error(f"❌ Failed to delete {name}")
    else:
        logger.info("No nodes to delete.")

    # 4. Delete Networks
    if networks:
        logger.info("\n--- Deleting Networks ---")
        for net_id, net_info in networks.items():
            name = net_info.get("name", f"Net-{net_id}")
            logger.info(f"Deleting network {name} (ID: {net_id})...")
            if client.delete_network(int(net_id)):
                logger.info(f"✅ Deleted {name}")
            else:
                logger.error(f"❌ Failed to delete {name}")
    else:
        logger.info("No networks to delete.")

    logger.info("\n" + "=" * 60)
    logger.info("✨ Cleanup Complete")
    logger.info("=" * 60)

if __name__ == "__main__":
    cleanup_topology()
