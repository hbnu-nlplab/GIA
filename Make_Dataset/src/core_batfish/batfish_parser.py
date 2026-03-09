
import pandas as pd
from typing import Dict, Any, List, Tuple
from pathlib import Path
import logging
import re
from pybatfish.client.session import Session
from pybatfish.datamodel import *
from pybatfish.datamodel.answer import *
from pybatfish.datamodel.flow import *

# 로깅 설정
logger = logging.getLogger(__name__)
logging.getLogger("pybatfish").setLevel(logging.WARN)

def get_batfish_session(host: str = "localhost", snapshot_dir: str = None) -> Session:
    """Batfish 세션을 초기화하고 스냅샷을 업로드합니다."""
    # host:port 미지정 시 9996 -> 9997 순서로 시도 (환경별 차이 흡수)
    candidates: List[Tuple[str, int | None]] = []
    if ":" in host:
        base_host, port = host.split(":")
        candidates.append((base_host, int(port)))
    else:
        candidates.append((host, 9996))
        candidates.append((host, 9997))

    last_error = None
    bf = None
    for base_host, port in candidates:
        try:
            if port is None:
                bf = Session(host=base_host)
            else:
                bf = Session(host=base_host, port=port)
            logger.info(f"Connected to Batfish at {base_host}:{port if port is not None else 'default'}")
            break
        except Exception as e:
            last_error = e
            logger.warning(f"Failed Batfish session init at {base_host}:{port}: {e}")

    if bf is None:
        raise last_error if last_error else RuntimeError("Failed to initialize Batfish session")

    if snapshot_dir:
        bf.set_network("generate_dataset_network")
        # 스냅샷 이름에 타임스탬프나 고유값을 붙이면 좋지만, 여기선 덮어쓰기 모드
        bf.init_snapshot(snapshot_dir, name="dataset_snapshot", overwrite=True)
    return bf


def _remove_assumed_field(assumed_fields: List[str], field_name: str) -> None:
    """Explicit config line is found: remove that field from assumed provenance."""
    try:
        assumed_fields.remove(field_name)
    except ValueError:
        pass


def _dedupe_vrfs(vrfs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    VRF를 이름 기준으로 dedupe + 병합합니다.

    Batfish/텍스트 파싱 조합에서 동일 VRF가 중복 생성될 수 있어,
    단순 first-win 제거가 아니라 RT/RD 정보를 합쳐서 보존합니다.
    """
    merged: Dict[str, Dict[str, Any]] = {}

    for vrf in vrfs:
        if not isinstance(vrf, dict):
            continue

        name = str(vrf.get("name") or "").strip()
        if not name:
            continue
        key = name.lower()

        if key not in merged:
            merged[key] = {
                "name": name,
                "rd": None,
                "import_rts": [],
                "export_rts": [],
                "route_targets": [],
                # Compatibility keys
                "rt_import": [],
                "rt_export": [],
            }

        cur = merged[key]

        # RD는 비어있지 않은 첫 값을 우선 사용
        if not cur.get("rd") and vrf.get("rd"):
            cur["rd"] = vrf.get("rd")

        imp = {str(x).strip() for x in (vrf.get("import_rts") or vrf.get("rt_import") or []) if str(x).strip()}
        exp = {str(x).strip() for x in (vrf.get("export_rts") or vrf.get("rt_export") or []) if str(x).strip()}
        rt_all = {str(x).strip() for x in (vrf.get("route_targets") or []) if str(x).strip()}

        if not imp and rt_all:
            imp = set(rt_all)
        if not exp and rt_all:
            exp = set(rt_all)

        cur["import_rts"] = sorted(set(cur["import_rts"]) | imp)
        cur["export_rts"] = sorted(set(cur["export_rts"]) | exp)
        cur["rt_import"] = sorted(set(cur["rt_import"]) | imp)
        cur["rt_export"] = sorted(set(cur["rt_export"]) | exp)
        cur["route_targets"] = sorted(set(cur["route_targets"]) | rt_all | imp | exp)

    return list(merged.values())


def _extract_banner(content: str, banner_type: str) -> str | None:
    pattern = re.compile(
        rf"^\s*banner\s+{re.escape(banner_type)}\s+(?P<delim>\S)(?P<body>.*?)(?:\n(?P=delim)|(?P=delim)$)",
        re.IGNORECASE | re.MULTILINE | re.DOTALL,
    )
    match = pattern.search(content)
    if not match:
        return None
    return match.group("body").strip()

def parse_text_config(config_path: Path) -> Dict[str, Any]:
    """
    Config 파일 텍스트를 파싱하여 Batfish가 제공하지 않는 설정(SSH, NTP, Logging 등)을 추출합니다.
    """
    source_file = str(config_path)
    text_facts = {
        "ssh": {"version": None, "enabled": False},
        "aaa": {"new_model": False, "protocol": "local"},
        "logging": {"hosts": [], "buffered_severity": None},
        "ntp": {"servers": []},
        "users": [],
        "domain_name": None,
        "timezone": None,
        # New L1 Fields
        "service_password_encryption": False,
        "enable_secret": "None",
        "line_console_password": "None",
        "exec_timeout": "None",
        "banner_motd": "None",
        "banner_login": "None",
        "http_server": False, # Basic check
        "cdp": True, # Cisco default (assumed unless explicit line exists)
        "ip_source_route": True, # Cisco default (assumed unless explicit line exists)
        "snmp_communities": [],
        "loopback_interfaces": [],
        "name_servers": [],
        "ospf_processes": [],
        "bgp_as": [],
        "mpls_ldp": False,
        "default_route": [],
        "static_routes_count": 0,
        "acls_count": 0,
        "acl_interfaces": [],
        "prefix_lists_count": 0,
        "route_maps_count": 0,
        "class_maps": [],
        "netflow_monitors": [],
        "missing_descriptions_count": 0,
        "eigrp_as": [],
        "rip_enabled": False,
        "fhrp_groups": [],
        "multicast_enabled": False,
        "vrfs": [],
        "version": None,
        "_provenance": {
            "source_file": source_file,
            "config_found": True,
            "parse_warnings": [],
            "assumed_fields": ["configuration.security.cdp", "configuration.security.ip_source_route"],
        },
    }
    
    if not config_path.exists():
        text_facts["_provenance"]["config_found"] = False
        text_facts["_provenance"]["parse_warnings"].append(f"config file not found: {source_file}")
        return text_facts

    assumed_fields = text_facts["_provenance"]["assumed_fields"]

    try:
        content = config_path.read_text(encoding="utf-8")
        
        # 1. SSH
        ssh_ver_match = re.search(r"^\s*ip ssh version (\d)", content, re.MULTILINE)
        if ssh_ver_match:
            text_facts["ssh"]["version"] = ssh_ver_match.group(1)
            text_facts["ssh"]["enabled"] = True
        if "transport input ssh" in content:
             text_facts["ssh"]["enabled"] = True

        # 1.5 VTY Line Configuration (transport_input and login_mode)
        text_facts["line"] = {"vty": {"transport_input": "", "login_mode": ""}}
        
        # Find VTY block and extract transport input
        vty_block_match = re.search(r'line vty \d+ \d+([\s\S]*?)(?=^line |^!|^end)', content, re.MULTILINE)
        if vty_block_match:
            vty_block = vty_block_match.group(1)
            # Extract transport input (ssh, telnet, all, none)
            transport_match = re.search(r'transport input (\S+)', vty_block)
            if transport_match:
                text_facts["line"]["vty"]["transport_input"] = transport_match.group(1)
            # Extract login mode (local, line, etc.)
            login_match = re.search(r'login (\S+)', vty_block)
            if login_match:
                text_facts["line"]["vty"]["login_mode"] = login_match.group(1)

        # 2. AAA
        if re.search(r"^aaa new-model", content, re.MULTILINE):
            text_facts["aaa"]["new_model"] = True
            if "tacacs" in content.lower():
                text_facts["aaa"]["protocol"] = "TACACS+"
            elif "radius" in content.lower():
                text_facts["aaa"]["protocol"] = "RADIUS"
        
        # 3. Logging & NTP & Users & Domain
        text_facts["logging"]["hosts"] = re.findall(r"^\s*logging host (\S+)", content, re.MULTILINE)
        text_facts["logging"]["hosts"].extend(
            re.findall(r"^\s*logging\s+(\d+\.\d+\.\d+\.\d+)\b", content, re.MULTILINE)
        )
        sev_match = re.search(
            r"^\s*logging\s+buffered(?:\s+\d+)?\s+(emergencies|alerts|critical|errors|warnings|notifications|informational|debugging)\b",
            content,
            re.IGNORECASE | re.MULTILINE,
        )
        if sev_match:
            text_facts["logging"]["buffered_severity"] = sev_match.group(1).lower()
        text_facts["ntp"]["servers"] = re.findall(r"^\s*ntp server (\S+)", content, re.MULTILINE)
        text_facts["users"] = re.findall(r"^\s*username (\S+)", content, re.MULTILINE)
        
        domain_match = re.search(r"^ip domain[ -]name (\S+)", content, re.MULTILINE)
        if domain_match:
            text_facts["domain_name"] = domain_match.group(1)

        timezone_match = re.search(r"^\s*clock timezone (\S+ \S+)", content, re.MULTILINE)
        if timezone_match:
            text_facts["timezone"] = timezone_match.group(1)

        # --- New L1 Metrics Parsing ---

        # Security
        if re.search(r"^\s*service password-encryption", content, re.MULTILINE):
            text_facts["service_password_encryption"] = True
            
        enable_secret_match = re.search(r"^enable secret (\d) ", content, re.MULTILINE)
        if enable_secret_match:
            text_facts["enable_secret"] = enable_secret_match.group(1) # '5' etc.
        elif re.search(r"^enable secret ", content, re.MULTILINE):
             text_facts["enable_secret"] = "Unknown Type"

        # Line Console Password
        # Simplified: Look for 'line console 0' then 'password ...' nearby? 
        # For simplicity in regex without lookahead complex:
        if re.search(r"line console 0[\s\S]{0,100}password \S+", content):
             pass_match = re.search(r"line console 0[\s\S]{0,100}password (\S+)", content)
             if pass_match: text_facts["line_console_password"] = pass_match.group(1)

        # Exec Timeout (check anywhere for now, usually under line vty/con)
        exec_match = re.search(r"exec-timeout (\d+ \d+)", content)
        if exec_match:
            text_facts["exec_timeout"] = exec_match.group(1)

        # Banners
        motd_banner = _extract_banner(content, "motd")
        if motd_banner:
            text_facts["banner_motd"] = motd_banner

        login_banner = _extract_banner(content, "login")
        if login_banner:
            text_facts["banner_login"] = login_banner

        # HTTP Server
        if re.search(r"^\s*no ip http server", content, re.MULTILINE):
            text_facts["http_server"] = False
        elif re.search(r"^\s*ip http server", content, re.MULTILINE):
            text_facts["http_server"] = True
            
        # CDP
        if re.search(r"^\s*no cdp run", content, re.MULTILINE):
            text_facts["cdp"] = False
            _remove_assumed_field(assumed_fields, "configuration.security.cdp")
        elif re.search(r"^\s*cdp run", content, re.MULTILINE):
            text_facts["cdp"] = True
            _remove_assumed_field(assumed_fields, "configuration.security.cdp")

        # IP Source Route
        if re.search(r"^\s*no ip source-route", content, re.MULTILINE):
            text_facts["ip_source_route"] = False
            _remove_assumed_field(assumed_fields, "configuration.security.ip_source_route")
        elif re.search(r"^\s*ip source-route", content, re.MULTILINE):
            text_facts["ip_source_route"] = True
            _remove_assumed_field(assumed_fields, "configuration.security.ip_source_route")

        # Operational & Routing Lists
        text_facts["snmp_communities"] = re.findall(r"^\s*snmp-server community (\S+)", content, re.MULTILINE)
        
        # Loopback Interfaces (checking names in `interface ...` block)
        text_facts["loopback_interfaces"] = re.findall(r"^\s*interface (Loopback\d+)", content, re.MULTILINE)
        
        text_facts["name_servers"] = re.findall(r"^\s*ip name-server (\S+)", content, re.MULTILINE)
        
        text_facts["ospf_processes"] = sorted(list(set(re.findall(r"^\s*router ospf (\d+)", content, re.MULTILINE))))
        
        text_facts["bgp_as"] = sorted(list(set(re.findall(r"^\s*router bgp (\d+)", content, re.MULTILINE))))
        
        if re.search(r"^\s*mpls ip", content, re.MULTILINE) or re.search(r"^\s*mpls ldp router-id", content, re.MULTILINE):
            text_facts["mpls_ldp"] = True
            
        mpls_ldp_match = re.search(r"^\s*mpls ldp router-id (\S+)", content, re.MULTILINE)
        text_facts["mpls_ldp_rid"] = mpls_ldp_match.group(1) if mpls_ldp_match else None

        text_facts["default_route"] = re.findall(r"^\s*ip route 0\.0\.0\.0 0\.0\.0\.0 (\S+)", content, re.MULTILINE)
        
        text_facts["static_routes_count"] = len(re.findall(r"^\s*ip route ", content, re.MULTILINE))

        # ACLs & Advanced
        text_facts["acls_count"] = len(re.findall(r"^\s*(?:access-list|ip access-list) ", content, re.MULTILINE))
        
        # ACL applied interfaces
        # Look for 'ip access-group ... in' or 'out' under interfaces
        # Simplified: Find all access-group lines, assumes they are under some interface
        text_facts["acl_interfaces"] = [] # To be populated by complex parsing if needed, or simplied count
        # Let's try to extract interface names that have access-group
        # Regex to find interface blocks and check content
        iface_blocks = re.finditer(r'^\s*interface\s+(\S+)([\s\S]*?)(?=^\s*interface|^\s*!|^\s*router)', content, re.MULTILINE)
        for match in iface_blocks:
            ifname = match.group(1)
            block = match.group(2)
            if "ip access-group" in block:
                text_facts["acl_interfaces"].append(ifname)
            if "description" not in block:
                text_facts["missing_descriptions_count"] += 1
                
        # Fix: Count UNIQUE names, not just lines
        prefix_matches = re.findall(r"^\s*ip prefix-list\s+(\S+)", content, re.MULTILINE)
        route_matches = re.findall(r"^\s*route-map\s+(\S+)", content, re.MULTILINE)
        
        text_facts["prefix_lists_count"] = len(set(prefix_matches))
        text_facts["route_maps_count"] = len(set(route_matches))
        
        text_facts["class_maps"] = re.findall(r"^\s*class-map (?:match-\w+ )?(\S+)", content, re.MULTILINE)
        text_facts["netflow_monitors"] = re.findall(r"^\s*flow monitor (\S+)", content, re.MULTILINE)
        
        text_facts["eigrp_as"] = sorted(list(set(re.findall(r"^\s*router eigrp (\d+)", content, re.MULTILINE))))
        
        if re.search(r"^\s*router rip", content, re.MULTILINE):
            text_facts["rip_enabled"] = True
            
        text_facts["fhrp_groups"] = sorted(list(set(re.findall(r"^\s*(?:standby|vrrp) (\d+) ", content, re.MULTILINE))))
        
        if re.search(r"^\s*ip multicast-routing", content, re.MULTILINE):
            text_facts["multicast_enabled"] = True

        # System Version
        version_match = re.search(r'^version\s+([^\s]+)', content, re.MULTILINE)
        text_facts["version"] = version_match.group(1) if version_match else None

        # VRF Details
        vrfs = []
        vrf_blocks = re.finditer(r'^vrf definition\s+(?P<name>\S+)(?P<content>[\s\S]*?)(?=^vrf definition|^!|^interface|^router)', content, re.MULTILINE)
        for match in vrf_blocks:
            vrf_name = match.group("name")
            content_bk = match.group("content")
            rd_match = re.search(r'^\s*rd\s+(\S+)', content_bk, re.MULTILINE)
            rd = rd_match.group(1) if rd_match else None
            rt_imports = re.findall(r'^\s*route-target import\s+(\S+)', content_bk, re.MULTILINE)
            rt_exports = re.findall(r'^\s*route-target export\s+(\S+)', content_bk, re.MULTILINE)
            # route-target both X 는 import/export 모두에 해당
            rt_both = re.findall(r'^\s*route-target both\s+(\S+)', content_bk, re.MULTILINE)
            if rt_both:
                rt_imports.extend(rt_both)
                rt_exports.extend(rt_both)
            vrfs.append({
                "name": vrf_name, "rd": rd, "import_rts": rt_imports, "export_rts": rt_exports,
                "route_targets": list(set(rt_imports + rt_exports))
            })
        # 동일 VRF 중복 블록이 존재할 수 있어 name 기준으로 병합
        text_facts["vrfs"] = _dedupe_vrfs(vrfs)

    except Exception as e:
        msg = f"Failed to text parse {config_path}: {e}"
        print(f"[Warning] {msg}")
        text_facts["_provenance"]["parse_warnings"].append(msg)

    return text_facts

def parse_batfish_datamodel(
    configs_dir: Path,
    batfish_host: str = "localhost",
    fail_on_missing_config: bool = False,
) -> Dict[str, Any]:
    """
    Batfish를 통해 설정을 파싱하고, 기존 parser와 호환되는 facts 구조를 반환합니다.
    """
    # snapshot_dir은 'configs' 폴더를 포함하는 상위 폴더여야 함.
    if configs_dir.name == "configs":
        snapshot_dir = configs_dir.parent
    else:
        snapshot_dir = configs_dir
    
    print(f"[BatfishParser] configs_dir: {configs_dir}")
    print(f"[BatfishParser] snapshot_dir: {snapshot_dir} (host: {batfish_host})")
    bf = get_batfish_session(host=batfish_host, snapshot_dir=str(snapshot_dir))
    
    facts_result = {"devices": [], "parser_warnings": []}
    
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
        # Case-insensitive file lookup
        cfg_file_path = configs_dir / f"{hostname}.cfg"
        if not cfg_file_path.exists():
            # Try finding the file case-insensitively
            for f in configs_dir.iterdir():
                if f.is_file() and f.suffix.lower() == ".cfg" and f.stem.lower() == hostname.lower():
                    cfg_file_path = f
                    break
        if not cfg_file_path.exists():
            warn_msg = f"[BatfishParser] Config file not found for node '{hostname}' (expected: {configs_dir / (hostname + '.cfg')})"
            logger.error(warn_msg)
            facts_result["parser_warnings"].append(warn_msg)
            if fail_on_missing_config:
                raise FileNotFoundError(warn_msg)
        
        text_info = parse_text_config(cfg_file_path)
        text_prov = text_info.get("_provenance", {}) if isinstance(text_info, dict) else {}
        assumed_fields = set(text_prov.get("assumed_fields", [])) if isinstance(text_prov, dict) else set()
        config_found = bool(text_prov.get("config_found", False)) if isinstance(text_prov, dict) else False
        parse_warnings = text_prov.get("parse_warnings", []) if isinstance(text_prov, dict) else []
        for warn in parse_warnings:
            facts_result["parser_warnings"].append(f"{hostname}: {warn}")

        version = text_info.get("version")
        if not version:
            version = "15.0"
            assumed_fields.add("system.version")

        device_facts = {
            "vendor": "cisco", 
            "system": {
                "hostname": hostname,
                "version": version,
                "users": text_info["users"],
                "domain_name": text_info["domain_name"],
                "timezone": text_info["timezone"]
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
                "snmp": {"communities": text_info["snmp_communities"]},
                "vrf": [],
                "mpls": {"ldp_interfaces": [], "ldp": {}} # LDP info here
            },
            # New L1 Configuration Dictionary
            "configuration": {
                "security": {
                    "password_encryption": text_info["service_password_encryption"],
                    "enable_secret": text_info["enable_secret"],
                    "console_password": text_info["line_console_password"],
                    "exec_timeout": text_info["exec_timeout"],
                    "banner_motd": text_info["banner_motd"],
                    "banner_login": text_info["banner_login"],
                    "http_server": text_info["http_server"],
                    "cdp": text_info["cdp"],
                    "ip_source_route": text_info["ip_source_route"]
                },
                "operational": {
                    "snmp_communities": text_info["snmp_communities"],
                    "loopback_interfaces": text_info["loopback_interfaces"],
                    "name_servers": text_info["name_servers"]
                },
                "routing": {
                    "ospf_processes": text_info["ospf_processes"],
                    "bgp_as": text_info["bgp_as"],
                    "mpls_ldp_enabled": text_info["mpls_ldp"],
                    "mpls_ldp_rid": text_info.get("mpls_ldp_rid"),
                    "default_route_next_hops": text_info["default_route"],
                    "static_routes_count": text_info["static_routes_count"]
                },
                "advanced": {
                    "acls_count": text_info["acls_count"],
                    "acl_interfaces": text_info["acl_interfaces"],
                    "prefix_lists_count": text_info["prefix_lists_count"],
                    "route_maps_count": text_info["route_maps_count"],
                    "class_maps": text_info["class_maps"],
                    "netflow_monitors": text_info["netflow_monitors"],
                    "missing_descriptions_count": text_info["missing_descriptions_count"],
                    "eigrp_as": text_info["eigrp_as"],
                    "rip_enabled": text_info["rip_enabled"],
                    "fhrp_groups": text_info["fhrp_groups"],
                    "multicast_enabled": text_info["multicast_enabled"]
                }
            },
            "line": text_info.get("line", {"vty": {"transport_input": "", "login_mode": ""}}),
            "parser_provenance": {
                "source_file": text_prov.get("source_file", str(cfg_file_path)),
                "config_found": config_found,
                "assumed_fields": sorted(assumed_fields),
                "parse_warnings": parse_warnings,
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
            device_facts["routing"]["bgp"]["local_as"] = int(local_as)
            
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
        
        # Fallback/Check interface VRFs
        existing_vrf_names = {v["name"] for v in device_vrfs}
        for i in device_facts["interfaces"]:
            if i["vrf"] and i["vrf"] not in existing_vrf_names:
                obj = {"name": i["vrf"]}
                device_vrfs.append(obj)
                bgp_vrfs.append(obj)
                existing_vrf_names.add(i["vrf"])

        device_facts["services"]["vrf"] = _dedupe_vrfs(device_vrfs)
        device_facts["routing"]["bgp"]["vrfs"] = _dedupe_vrfs(bgp_vrfs)
        
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
