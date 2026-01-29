
import logging
from pathlib import Path
import sys

# Add src path
sys.path.append(str(Path(__file__).parent / "src"))

from core_batfish.batfish_builder import BatfishBuilder

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("DebugEdges")

lab_path = Path("Data/Pnetlab/Research_Institute_Internal_DC")

bf = BatfishBuilder(
    snapshot_path=str(lab_path), 
    network_name=lab_path.name
)
bf.initialize()

edges = bf.get_layer3_edges()
logger.info(f"Layer 3 Edges Found: {len(edges)}")
if edges:
    logger.info(f"First Edge: {edges[0]}")

ce_nodes = [n for n in bf.nodes if 'ce' in n.lower()]
logger.info(f"CE Nodes Found: {len(ce_nodes)} -> {ce_nodes}")

leaf_nodes = [n for n in bf.nodes if 'leaf' in n.lower()]
logger.info(f"Leaf Nodes Found: {len(leaf_nodes)} -> {leaf_nodes}")
