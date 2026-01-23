
import paramiko
import logging
import re
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parents[2]))
from config.settings import settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("safe_topology")

def safe_modify_unl(content):
    # 1. Ensure <networks> exists under <topology>
    # Find <topology>
    m_topo = re.search(r'<topology>', content)
    if not m_topo:
        logger.error("Could not find <topology> tag")
        return None
    
    # Check if pnet2 network exists
    if 'type="pnet2"' not in content:
        logger.info("Injecting pnet2 network...")
        # Insert after <topology>
        networks_xml = '\n    <networks><network id="1" type="pnet2" name="Mgmt-Cloud" left="100" top="100" visibility="1" /></networks>'
        content = content.replace('<topology>', '<topology>' + networks_xml)

    # 2. Add interface to each node vIOS1 to vIOS10
    for i in range(1, 11):
        node_name = f"vIOS{i}"
        # Regex to find the node tag with this name
        # We look for <node ... name="vIOSi" ... /> or <node ... name="vIOSi" ...>
        pattern = rf'(<node [^>]*name="{node_name}"[^>]*)(/?>)'
        
        def replace_node(match):
            attribs = match.group(1)
            closing = match.group(2)
            
            # If it already has an interface for net 1, skip
            # (Simplification: if it has any interface tag we might skip or update)
            # But safer to just insert if not already there.
            
            if 'network_id="1"' in attribs or f'name="{node_name}"' not in attribs:
                return match.group(0)

            logger.info(f"Modifying node {node_name}...")
            if closing == '/>':
                # Convert to <node ...><interface ... /></node>
                return f'{attribs}><interface id="0" name="Gi0/0" network_id="1" /></node>'
            else:
                # Append interface after the opening tag
                return f'{match.group(0)}<interface id="0" name="Gi0/0" network_id="1" />'

        content = re.sub(pattern, replace_node, content)

    return content

def main():
    host = "100.66.240.82"
    user = "root"
    password = "pnet"
    lab_path = "/opt/unetlab/labs/Phase1/Test1.unl"

    logger.info(f"Connecting to {host}...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, username=user, password=password)

    # Read
    logger.info(f"Reading {lab_path}...")
    stdin, stdout, stderr = ssh.exec_command(f"cat '{lab_path}'")
    content = stdout.read().decode('utf-8', errors='ignore')

    # Modify
    new_content = safe_modify_unl(content)
    
    if new_content and new_content != content:
        # Save back
        logger.info("Uploading modified UNL...")
        sftp = ssh.open_sftp()
        with sftp.file(lab_path, 'w') as f:
            f.write(new_content)
        sftp.close()
        
        # Permissions
        ssh.exec_command("/opt/unetlab/wrappers/unl_wrapper -a fixpermissions")
        logger.info("Success! Please restart nodes in UI.")
    else:
        logger.info("No changes needed or error occurred.")

    ssh.close()

if __name__ == "__main__":
    main()
