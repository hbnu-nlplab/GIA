
import paramiko
import logging
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parents[2]))
from config.settings import settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("config_gw")

def configure_gateway():
    host = settings.pnetlab.base_url.split("//")[-1].split(":")[0]
    user = "root"
    password = "pnet" 
    
    logger.info(f"Connecting to {host}...")
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, username=user, password=password)
        
        # Check if address already exists
        stdin, stdout, stderr = ssh.exec_command("ip addr show pnet2")
        out = stdout.read().decode()
        
        if "10.10.10.1" in out:
            logger.info("Gateway 10.10.10.1 already configured on pnet2")
        else:
            logger.info("Configuring 10.10.10.1/24 on pnet2...")
            cmds = [
                "ip addr add 10.10.10.1/24 dev pnet2",
                "ip link set pnet2 up"
            ]
            for cmd in cmds:
                ssh.exec_command(cmd)
                
            logger.info("Configuration applied.")
            
        ssh.close()
    except Exception as e:
        logger.error(f"Failed: {e}")

if __name__ == "__main__":
    configure_gateway()
