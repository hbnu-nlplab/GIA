
import paramiko
import logging
import time

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("manual_bridge")

def main():
    host = "100.66.240.82"
    user = "root"
    passw = "pnet"
    
    # Node range for default pod (user 0) is usually based on node ID.
    # From observation: vIOS1(ID 1) -> vunl113
    # It seems to shift by 112 (maybe lab ID offset or pod offset).
    # Interfaces for our 10 nodes: vunl113_0 to vunl122_0
    
    interfaces = [f"vunl{i}_0" for i in range(113, 123)]
    
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(host, username=user, password=passw)
        logger.info("Connected.")
        
        # Check if interfaces exist and are UP
        for iface in interfaces:
            logger.info(f"Checking {iface}...")
            # Ensure pnet2 exists
            ssh.exec_command("brctl addbr pnet2 2>/dev/null")
            ssh.exec_command("ip link set pnet2 up")
            ssh.exec_command("ip addr add 10.10.10.1/24 dev pnet2 2>/dev/null")
            
            # Add to bridge
            cmd = f"brctl addif pnet2 {iface}"
            stdin, stdout, stderr = ssh.exec_command(cmd)
            err = stderr.read().decode()
            if err and "device is already a member" not in err:
                 logger.warning(f"Error adding {iface}: {err.strip()}")
            else:
                 logger.info(f"Attached {iface} to pnet2")
        
        # Verify
        stdin, stdout, stderr = ssh.exec_command("brctl show pnet2")
        print("Bridge status:\n" + stdout.read().decode())
        
        # Ping check
        logger.info("Pinging vIOS1 (10.10.10.11)...")
        stdin, stdout, stderr = ssh.exec_command("ping -c 2 10.10.10.11")
        print(stdout.read().decode())

    except Exception as e:
        logger.error(f"Error: {e}")
    finally:
        ssh.close()

if __name__ == "__main__":
    main()
