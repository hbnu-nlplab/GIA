
import socket
import sys
import logging
from pathlib import Path

# 프로젝트 경로 추가
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from clients.pnetlab import PnetlabClient
from config.settings import settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def check_telnet_connectivity():
    client = PnetlabClient(settings.pnetlab.base_url)
    topology = client.get_session_topology()
    nodes = client.get_nodes_from_topology(topology)
    
    pnet_vm_ip = "100.66.240.82" # Tailscale IP of PNETLab VM
    
    results = []
    for node in nodes:
        name = node["name"]
        port = node["telnet_port"]
        
        if port == 0:
            continue
            
        logger.info(f"Checking {name} on {pnet_vm_ip}:{port}...")
        
        try:
            # 타임아웃 2초로 연결 시도
            s = socket.create_connection((pnet_vm_ip, port), timeout=2)
            s.close()
            logger.info(f"  ✅ {name} Telnet port is OPEN")
            results.append((name, "OPEN"))
        except (socket.timeout, ConnectionRefusedError):
            logger.warning(f"  ❌ {name} Telnet port is CLOSED")
            results.append((name, "CLOSED"))
        except Exception as e:
            logger.error(f"  ❌ {name} Error: {e}")
            results.append((name, f"ERROR: {e}"))
            
    return results

if __name__ == "__main__":
    results = check_telnet_connectivity()
    print("\n" + "="*50)
    print("TELNET CONNECTIVITY SUMMARY")
    print("="*50)
    for name, status in results:
        print(f"{name.ljust(15)}: {status}")
    print("="*50)
