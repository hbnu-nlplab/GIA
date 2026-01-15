
import paramiko
import time
import logging
import os
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parents[2]))
from config.settings import settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ssh_topology")

class PnetlabSSH:
    def __init__(self, host, username, password, port=22):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.client = None

    def connect(self):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.client.connect(self.host, port=self.port, username=self.username, password=self.password, timeout=10)
            logger.info(f"SSH Connected to {self.host}")
            return True
        except Exception as e:
            logger.error(f"SSH Connection failed: {e}")
            return False

    def close(self):
        if self.client:
            self.client.close()

    def run_command(self, cmd):
        if not self.client:
            return None, "Not connected"
        logger.info(f"Running: {cmd}")
        stdin, stdout, stderr = self.client.exec_command(cmd)
        out = stdout.read().decode().strip()
        err = stderr.read().decode().strip()
        if err:
            logger.warning(f"Stderr: {err}")
        return out, err

    def read_lab_file(self, lab_path):
        # We need to find the real path. Usually /opt/unetlab/labs/...
        # User lab path from API was "/PH1_L3VPN_GOLDEN.unl"
        # So it's likely /opt/unetlab/labs/PH1_L3VPN_GOLDEN.unl or /opt/unetlab/labs/Common...
        
        # Try to find it
        cmd = f"find /opt/unetlab/labs -name '{os.path.basename(lab_path)}'"
        out, _ = self.run_command(cmd)
        if not out:
            logger.error(f"Lab file not found for {lab_path}")
            return None
        
        real_path = out.split('\n')[0]
        logger.info(f"Found lab file at: {real_path}")
        
        # Read content
        cmd = f"cat '{real_path}'"
        content, _ = self.run_command(cmd)
        return content, real_path

    def upload_lab_file(self, local_content, remote_path):
        sftp = self.client.open_sftp()
        with sftp.file(remote_path, 'w') as f:
            f.write(local_content)
        logger.info(f"Uploaded updated lab file to {remote_path}")
        sftp.close()

    def fix_permissions(self):
        self.run_command("/opt/unetlab/wrappers/unl_wrapper -a fixpermissions")

def modify_lab_xml(xml_content, node_name="P1", interface_name="e0/0"):
    """
    Parses XML, ensures 'Cloud2' network exists, and connects node interface to it.
    """
    root = ET.fromstring(xml_content)
    
    # 1. Find or Create Cloud2 Network
    topo = root.find("topology")
    if topo is None:
         logger.error("Topology tag not found")
         return None
         
    networks = topo.find("networks")
    if networks is None:
        logger.info("Networks tag not found. Creating it...")
        networks = ET.SubElement(topo, "networks")
        # Ensure it's before nodes for clean XML but doesn't strictly matter
        # (Using SubElement appends to end)
        
    cloud2_net_id = None
    for net in networks.findall("network"):
        if net.get("type") == "pnet2":
            cloud2_net_id = net.get("id")
            logger.info(f"Found existing Cloud2 network: ID {cloud2_net_id}")
            break
            
    if not cloud2_net_id:
        logger.info("Cloud2 network not found. Creating it...")
        # Find next available ID
        existing_ids = [int(n.get("id")) for n in networks.findall("network")]
        new_id = str(max(existing_ids) + 1 if existing_ids else 1)
        
        new_net = ET.SubElement(networks, "network")
        new_net.set("id", new_id)
        new_net.set("type", "pnet2")
        new_net.set("name", "Mgmt-Cloud")
        new_net.set("left", "100")
        new_net.set("top", "100")
        new_net.set("visibility", "1")
        
        cloud2_net_id = new_id
        logger.info(f"Created Cloud2 network with ID {cloud2_net_id}")

    # 2. Connect Node Interface
    # Find the node
    target_node = None
    nodes = root.find("topology").find("nodes")
    
    found_node_names = []
    for node in nodes.findall("node"):
        n_name = node.get("name")
        n_id = node.get("id")
        n_label = node.get("label") # Sometimes label is what we see
        found_node_names.append(f"ID:{n_id} Name:{n_name} Label:{n_label}")
        
        # Check both name and label just in case
        if n_name == node_name or (n_label and n_label == node_name):
            target_node = node
            logger.info(f"Found target node: {n_name} (ID: {n_id})")
            break
            
    if target_node is None:
        logger.error(f"Node {node_name} not found in XML. Available nodes: {found_node_names}")
        return None
        
    # Find the interface (usually by ID)
    # e0/0 is usually interface id="0" for IOL
    # <interface id="0" name="e0/0" network_id="..."/>
    
    # We need to know which ID maps to interface_name.
    # For now, let's assume 'e0/0' is ID '0' (standard for IOL).
    # Or strict mapping if possible.
    
    interface_id = "0" # Default for e0/0
    
    # Check if interface tag exists
    found_iface = False
    for iface in target_node.findall("interface"):
        if iface.get("id") == interface_id:
            logger.info(f"Updating interface {interface_id} to network {cloud2_net_id}")
            iface.set("network_id", cloud2_net_id)
            found_iface = True
            break
            
    if not found_iface:
        logger.info(f"Interface tag {interface_id} not found. Creating it.")
        new_iface = ET.SubElement(target_node, "interface")
        new_iface.set("id", interface_id)
        new_iface.set("name", interface_name)
        new_iface.set("network_id", cloud2_net_id)

    return ET.tostring(root, encoding="unicode")

def main():
    # Settings
    pnet_host = settings.pnetlab.base_url.split("//")[-1].split(":")[0]
    ssh_user = "root" 
    candidate_passwords = ["pnet"] # User confirmed
    
    ssh = None
    for pwd in candidate_passwords:
        logger.info(f"Trying password: {'*' * len(pwd)}")
        ssh = PnetlabSSH(pnet_host, ssh_user, pwd)
        if ssh.connect():
            break
            
    if not ssh or not ssh.client:
        logger.error("Authentication failed.")
        return

    # 1. Get Lab File
    lab_name = "Test1.unl"
    content, remote_path = ssh.read_lab_file(lab_name)
    
    if content:
        # 2. Modify XML for all 10 nodes
        new_content = content
        for i in range(1, 11):
            node_name = f"vIOS{i}"
            logger.info(f"Adding interface connection for {node_name}...")
            # For qemu vIOS, Gi0/0 is usually ID 0
            modified = modify_lab_xml(new_content, node_name=node_name, interface_name="Gi0/0")
            if modified:
                new_content = modified
            else:
                logger.warning(f"Could not find or modify node {node_name}")
                
        # 3. Upload Back
        ssh.run_command(f"cp '{remote_path}' '{remote_path}.bak'")
        ssh.upload_lab_file(new_content, remote_path)
        logger.info("Done! Lab topology updated for all 10 nodes.")
        
        # 4. Mandatory User Interaction
        logger.info("\n" + "="*50)
        logger.info("TOPOLOGY UPDATED SUCCESSFULLY!")
        logger.info("IMPORTANT: Please RESTART all vIOS nodes in the PNETLab UI.")
        logger.info("="*50)
    
    ssh.close()

if __name__ == "__main__":
    main()
