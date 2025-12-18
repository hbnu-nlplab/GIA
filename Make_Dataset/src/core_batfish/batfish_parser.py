
import pandas as pd
from typing import Dict, Any, List
from pathlib import Path
import logging
import re
from pybatfish.client.session import Session
from pybatfish.datamodel import *
from pybatfish.datamodel.answer import *
from pybatfish.datamodel.flow import *

# 로깅 설정
logging.getLogger("pybatfish").setLevel(logging.WARN)

def get_batfish_session(host: str = "localhost", snapshot_dir: str = None) -> Session:
    """Batfish 세션을 초기화하고 스냅샷을 업로드합니다."""
    bf = Session(host=host)
    if snapshot_dir:
        bf.set_network("generate_dataset_network")
        # 스냅샷 이름에 타임스탬프나 고유값을 붙이면 좋지만, 여기선 덮어쓰기 모드
        bf.init_snapshot(snapshot_dir, name="dataset_snapshot", overwrite=True)
    return bf

def parse_text_config(config_path: Path) -> Dict[str, Any]:
    """
    Config 파일 텍스트를 파싱하여 Batfish가 제공하지 않는 설정(SSH, NTP, Logging 등)을 추출합니다.
    """
    text_facts = {
        "ssh": {"version": None, "enabled": False},
        "aaa": {"new_model": False, "protocol": "local"}, # Default local
        "logging": {"hosts": []},
        "ntp": {"servers": []},
        "users": [],
        "domain_name": None
    }
    
    try:
        content = config_path.read_text(encoding="utf-8")
        
        # 1. SSH
        # ip ssh version 2
        ssh_ver_match = re.search(r"ip ssh version (\d)", content)
        if ssh_ver_match:
            text_facts["ssh"]["version"] = ssh_ver_match.group(1)
            text_facts["ssh"]["enabled"] = True
        
        # transport input ssh (Interface line or line vty) - Simplified check
        if "transport input ssh" in content:
             text_facts["ssh"]["enabled"] = True

        # 2. AAA
        # aaa new-model or no aaa new-model
        if re.search(r"^aaa new-model", content, re.MULTILINE):
            text_facts["aaa"]["new_model"] = True
            # Check protocol (simplified)
            if "tacacs" in content.lower():
                text_facts["aaa"]["protocol"] = "TACACS+"
            elif "radius" in content.lower():
                text_facts["aaa"]["protocol"] = "RADIUS"
        else:
            text_facts["aaa"]["new_model"] = False

        # 3. Logging
        # logging host 1.2.3.4
        logging_hosts = re.findall(r"^logging host (\S+)", content, re.MULTILINE)
        text_facts["logging"]["hosts"] = logging_hosts

        # 4. NTP
        # ntp server 1.2.3.4
        ntp_servers = re.findall(r"^ntp server (\S+)", content, re.MULTILINE)
        text_facts["ntp"]["servers"] = ntp_servers

        # 5. Users
        # username admin ...
        users = re.findall(r"^username (\S+)", content, re.MULTILINE)
        text_facts["users"] = users

        # 6. Domain Name
        domain_match = re.search(r"^ip domain name (\S+)", content, re.MULTILINE) # underscore in command usually 'ip domain-name' on some generic Cisco, but IOS usually 'ip domain name'
        # Try both 'ip domain name' and 'ip domain-name'
        if domain_match:
            text_facts["domain_name"] = domain_match.group(1)
        else:
             domain_dash = re.search(r"^ip domain-name (\S+)", content, re.MULTILINE)
             if domain_dash:
                 text_facts["domain_name"] = domain_dash.group(1)

        # 7. MPLS LDP Router-ID
        # mpls ldp router-id Loopback0 force
        mpls_ldp_match = re.search(r"^mpls ldp router-id (\S+)", content, re.MULTILINE)
        if mpls_ldp_match:
            text_facts["mpls_ldp_rid"] = mpls_ldp_match.group(1)
        else:
            text_facts["mpls_ldp_rid"] = None

        # 8. System Version
        version_match = re.search(r'^version\s+([^\s]+)', content, re.MULTILINE)
        text_facts["version"] = version_match.group(1) if version_match else "15.0"

        # 9. VRF Details (RD, RT)
        vrfs = []
        # Find all 'vrf definition <name>' blocks
        vrf_blocks = re.finditer(r'^vrf definition\s+(?P<name>\S+)(?P<content>[\s\S]*?)(?=^vrf definition|^!|^interface|^router)', content, re.MULTILINE)
        
        for match in vrf_blocks:
            vrf_name = match.group("name")
            content_bk = match.group("content")
            
            rd_match = re.search(r'^\s*rd\s+(\S+)', content_bk, re.MULTILINE)
            rd = rd_match.group(1) if rd_match else None
            
            rt_imports = re.findall(r'^\s*route-target import\s+(\S+)', content_bk, re.MULTILINE)
            rt_exports = re.findall(r'^\s*route-target export\s+(\S+)', content_bk, re.MULTILINE)
            
            vrfs.append({
                "name": vrf_name,
                "rd": rd,
                "import_rts": rt_imports,
                "export_rts": rt_exports,
                "route_targets": list(set(rt_imports + rt_exports))
            })
        text_facts["vrfs"] = vrfs

    except Exception as e:
        print(f"[Warning] Failed to text parse {config_path}: {e}")

    return text_facts

def parse_batfish_datamodel(configs_dir: Path) -> Dict[str, Any]:
    """
    Batfish를 통해 설정을 파싱하고, 기존 parser와 호환되는 facts 구조를 반환합니다.
    """
    # 1. Batfish 세션 연결 및 스냅샷 업로드
    snapshot_dir = configs_dir.parent
    
    print(f"Initializing Batfish with snapshot: {snapshot_dir}")
    bf = get_batfish_session(snapshot_dir=str(snapshot_dir))
    
    facts_result = {"devices": []}
    
    # 2. 데이터 추출
    
    # 2.1 Interface Properties
    iface_props = bf.q.interfaceProperties().answer().frame()
    
    # 2.2 BGP Process / Peer Config
    try:
        bgp_proc = bf.q.bgpProcessConfiguration().answer().frame()
        # print(f"[DEBUG] bgp_proc columns: {bgp_proc.columns.tolist()}")
        bgp_peers = bf.q.bgpPeerConfiguration().answer().frame()
        # print(f"[DEBUG] bgp_peers columns: {bgp_peers.columns.tolist()}")
    except Exception as e:
        print(f"[Warning] Failed to get BGP info: {e}")
        bgp_proc = pd.DataFrame()
        bgp_peers = pd.DataFrame()

    # 2.3 OSPF Process / Area / Interface
    try:
        ospf_proc = bf.q.ospfProcessConfiguration().answer().frame()
        ospf_areas = bf.q.ospfAreaConfiguration().answer().frame()
        ospf_iface_df = bf.q.ospfInterfaceConfiguration().answer().frame()
    except Exception:
        ospf_proc = pd.DataFrame()
        ospf_areas = pd.DataFrame()
        ospf_iface_df = pd.DataFrame()

    # 2.4 VRF Properties (Regex-based from text parsing now)
    # Removing bf.q.vrfProperties() call as it is unreliable or missing in this version.


    # 3. 디바이스별로 데이터 정리
    # 모든 활성 노드 가져오기
    all_nodes = sorted(iface_props["Interface"].apply(lambda x: x.hostname).unique())
    
    for hostname in all_nodes:
        # 3.0 Preliminary: Text Parsing for System Info
        cfg_file_path = configs_dir / f"{hostname}.cfg"
        text_info = parse_text_config(cfg_file_path)

        device_facts = {
            "vendor": "cisco", 
            "system": {
                "hostname": hostname,
                "version": text_info.get("version", "15.0"), 
                "users": text_info["users"],
                "domain_name": text_info["domain_name"]
            },
            # BuilderCore expects SSH and AAA in 'security'
            "security": {
                "ssh": {
                    "present": text_info["ssh"]["enabled"],
                    "version": text_info["ssh"]["version"]
                },
                "aaa": {
                    "present": text_info["aaa"]["new_model"],
                    "authentication": text_info["aaa"]["protocol"]
                }
            },
            # BuilderCore expects logging in root
            "logging": text_info["logging"],
            "interfaces": [],
            "routing": {
                "bgp": {"local_as": None, "neighbors": [], "vrfs": []},
                "ospf": {"process_ids": [], "areas": {}}
            },
            "services": {
                # BuilderCore expects NTP in services
                "ntp": text_info["ntp"],
                "vrf": [],
                "mpls": {"ldp_interfaces": [], "ldp": {}} # LDP info here
            },
            "file": f"{hostname}.cfg" 
        }
        
        # --- Interfaces ---
        node_ifaces = iface_props[iface_props["Interface"].apply(lambda x: x.hostname == hostname)]
        for _, row in node_ifaces.iterrows():
            if_name = row["Interface"].interface
            
            # Primary IP
            ipv4 = None
            if row.get("Primary_Address"):
                ipv4 = str(row["Primary_Address"])
            
            status = "up" if row.get("Admin_Up") else "down"
            vrf = row.get("VRF", "default")
            
            # VLAN
            vlan = row.get("Access_VLAN") or row.get("Encapsulation_VLAN")
            
            device_facts["interfaces"].append({
                "name": if_name,
                "ipv4": ipv4,
                "vlan": int(vlan) if vlan else None,
                "vrf": vrf if vrf != "default" else None,
                "status": status
            })
            
        device_facts["num_interfaces"] = len(device_facts["interfaces"])
        
        # --- BGP ---
        # Local AS & Neighbors
        node_peers = bgp_peers[bgp_peers["Node"] == hostname]
        
        # 1. Local AS
        local_as = None
        if not node_peers.empty:
            # Try to get AS from default VRF first
            default_peers = node_peers[node_peers["VRF"] == "default"]
            if not default_peers.empty:
                 local_as = default_peers.iloc[0]["Local_AS"]
            else:
                 local_as = node_peers.iloc[0]["Local_AS"]
        
        if local_as:
            device_facts["routing"]["bgp"]["local_as"] = str(local_as)
            
        # 2. Neighbors
        if not node_peers.empty:
            for _, row in node_peers.iterrows():
                rid = str(row["Remote_IP"])
                ras = str(row["Remote_AS"])
                device_facts["routing"]["bgp"]["neighbors"].append({
                    "id": rid,
                    "remote_as": ras
                })
                
        # --- OSPF ---
        node_ospf = ospf_proc[ospf_proc["Node"] == hostname]
        if not node_ospf.empty:
            # Process IDs
            pids = sorted(node_ospf["Process_ID"].unique())
            device_facts["routing"]["ospf"]["process_ids"] = [str(p) for p in pids]
            
        # Area Mapping via Interface Configuration
        areas_map = {}
        if not ospf_iface_df.empty:
            # Ensure Node column exists
            if "Node" not in ospf_iface_df.columns and "Interface" in ospf_iface_df.columns:
                ospf_iface_df["Node"] = ospf_iface_df["Interface"].apply(lambda x: x.hostname)

            if "Node" in ospf_iface_df.columns:
                node_ospf_if = ospf_iface_df[ospf_iface_df["Node"] == hostname]
                for _, row in node_ospf_if.iterrows():
                    # Check if OSPF is actually enabled on this interface
                    if row.get("OSPF_Enabled"):
                        iface = row["Interface"].interface
                        val = row.get("OSPF_Area_Name")
                        if val is None:
                            val = row.get("OSPF_Area")
                        area = str(val)
                        if area not in areas_map:
                            areas_map[area] = []
                        areas_map[area].append(iface)
        device_facts["routing"]["ospf"]["areas"] = areas_map

        # --- VRF ---
        # Extract VRF details from Text Parsing (text_info)
        device_vrfs = [] # For services/vrf
        bgp_vrfs = []    # For routing/bgp/vrfs
        
        for v in text_info.get("vrfs", []):
             vrf_obj = {
                 "name": v["name"],
                 "rd": v["rd"],
                 "import_rts": v["import_rts"],
                 "export_rts": v["export_rts"],
                 "route_targets": v["route_targets"],
                 # Compatibility keys
                 "rt_import": v["import_rts"],
                 "rt_export": v["export_rts"]
             }
             device_vrfs.append(vrf_obj)
             bgp_vrfs.append(vrf_obj)
        
        device_facts["services"]["vrf"] = device_vrfs
        
        # Merge into existing BGP VRFs or initialize
        if device_facts["routing"]["bgp"]["vrfs"]:
             # If BGP VRFs already exist (maybe from batfish parsing), enrich them
             # But likely they are empty or basic. We'll simply append or overwrite carefully.
             # Actually, simpler to just use our robust text-parsed list
             device_facts["routing"]["bgp"]["vrfs"] = bgp_vrfs
        else:
             device_facts["routing"]["bgp"]["vrfs"] = bgp_vrfs
        
        # Fallback/Check interface VRFs
        existing_vrf_names = {v["name"] for v in device_vrfs}
        for i in device_facts["interfaces"]:
            if i["vrf"] and i["vrf"] not in existing_vrf_names:
                obj = {"name": i["vrf"]}
                device_facts["services"]["vrf"].append(obj)
                # Should we add to BGP VRFs too? Yes, for consistency
                device_facts["routing"]["bgp"]["vrfs"].append(obj)
                existing_vrf_names.add(i["vrf"])
                
        device_facts["services"]["vrf"].extend(device_vrfs)
        device_facts["routing"]["bgp"]["vrfs"].extend(bgp_vrfs)
        
        # --- MPLS (Hybrid/Text for now or LDP check) ---
        # mpls ldp router-id logic via text
        if text_info.get("mpls_ldp_rid"):
            m_rid = text_info["mpls_ldp_rid"]
            # Try resolve Loopback0 to IP
            rid_ip = None
            for iface in device_facts["interfaces"]:
                if iface["name"] == m_rid: # Exact match
                    rid_ip = iface["ipv4"].split("/")[0] if iface["ipv4"] else None
                    break
            
            # If resolved, use IP, else use name
            final_rid = rid_ip if rid_ip else m_rid
            
            # Builder expects ldp info in services/mpls/ldp
            device_facts["services"]["mpls"]["ldp"]["router_id"] = final_rid
            device_facts["services"]["mpls"]["ldp_enabled"] = True
            
        facts_result["devices"].append(device_facts)
        
    return facts_result

def parse_files(configs: List[Path]) -> Dict[str, Any]:
    # Batfish works on directory level, not file lists.
    # Take the parent dir of the first file.
    if not configs:
        return {"devices": []}
    
    configs_dir = configs[0].parent
    return parse_batfish_datamodel(configs_dir)
