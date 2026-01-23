
import paramiko
import logging
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parents[2]))
from config.settings import settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("debug_ssh")

def run_diagnostics():
    host = settings.pnetlab.base_url.split("//")[-1].split(":")[0]
    user = "root"
    password = "pnet" # Confirmed working password
    
    logger.info(f"Connecting to {host}...")
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, username=user, password=password)
        
        commands = [
            "ping -c 2 10.10.10.11",
            "brctl show",
            "ip route",
            "unl_wrapper -a status"
        ]
        
        for cmd in commands:
            logger.info(f"\n--- Running: {cmd} ---")
            stdin, stdout, stderr = ssh.exec_command(cmd)
            out = stdout.read().decode().strip()
            err = stderr.read().decode().strip()
            if out: logger.info(out)
            if err: logger.error(err)
            
        ssh.close()
    except Exception as e:
        logger.error(f"SSH Failed: {e}")

if __name__ == "__main__":
    run_diagnostics()
