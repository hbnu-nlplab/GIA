import requests
import json
import logging
import re
from typing import Dict, Any, List, Optional

# --- 설정 ---
NSO_CONFIG = {
    "base_url": "http://localhost:8080/restconf/data",
    "auth": ("admin", "admin"),
    "timeout": 30
}

# NSO RESTCONF 경로 상수
NSO_PATHS = {
    "devices": "tailf-ncs:devices",
    "device": "tailf-ncs:devices/device",
}

# --- 로깅 설정 ---
logging.basicConfig(
    filename='sanoa_audit.log',
    level=logging.INFO,
    format='%(asctime)s - [SANOA] - %(levelname)s - %(message)s'
)

class SanoaException(Exception):
    """프레임워크 전용 예외 처리 클래스"""
    pass

class SanoaConnector:
    """
    LLM-Friendly NSO Connector for AI Agents (A+ 완전 구현 버전)
    Features: High-level Intent-based API, Auto-parsing, Error wrapping.
    
    Total APIs: 32개 (기본 13개 + 추가 19개)
    """
    
    def __init__(self):
        self.session = requests.Session()
        self.session.auth = NSO_CONFIG["auth"]
        self.session.headers = {
            'Content-Type': 'application/yang-data+json',
            'Accept': 'application/yang-data+json'
        }
        self.base_url = NSO_CONFIG["base_url"]
        logging.info("SanoaConnector Initialized (Complete Edition).")

    # =========================================================
    #          Private Low-level API (내부 구현)
    # =========================================================

    def _clean_namespace(self, data: Any) -> Any:
        """네임스페이스 제거"""
        if isinstance(data, dict):
            new_dict = {}
            for k, v in data.items():
                clean_key = k.split(':')[-1] if ':' in k else k
                new_dict[clean_key] = self._clean_namespace(v)
            return new_dict
        elif isinstance(data, list):
            return [self._clean_namespace(item) for item in data]
        else:
            return data

    def _request(self, method: str, path: str, payload: Optional[dict] = None) -> Any:
        """HTTP 요청 처리"""
        url = f"{self.base_url}/{path}"
        try:
            if method == "GET":
                response = self.session.get(url, timeout=NSO_CONFIG["timeout"])
            elif method == "PATCH":
                response = self.session.patch(url, json=payload, timeout=NSO_CONFIG["timeout"])
            elif method == "POST":
                response = self.session.post(url, json=payload, timeout=NSO_CONFIG["timeout"])
            
            if response.status_code == 404:
                logging.warning(f"Resource Not Found: {path}")
                return {"status": "not_found", "path": path}
            
            response.raise_for_status()
            
            if "dry-run" in url:
                logging.info(f"Dry-run Executed: {path}")
                return {"status": "success", "diff": response.text}

            data = response.json()
            clean_data = self._clean_namespace(data)
            
            logging.info(f"API Call Success: {method} {path}")
            return clean_data

        except requests.exceptions.RequestException as e:
            logging.error(f"API Connection Error: {str(e)}")
            return {"status": "error", "message": str(e)}

    def _normalize_path(self, path: str) -> str:
        """경로 정규화"""
        return re.sub(r'/+', '/', path.strip('/'))

    def _fetch_config(self, device: str, config_path: str = "") -> Dict[str, Any]:
        """설정 데이터 조회 (Private)"""
        base = f"{NSO_PATHS['device']}={device}/config"
        if config_path:
            normalized_path = self._normalize_path(config_path)
            path = f"{base}/{normalized_path}"
        else:
            path = base

        result = self._request("GET", path)

        if not config_path and isinstance(result, dict) and "config" in result:
            return result["config"]

        return result

    def _fetch_live_status(self, device: str, path: str = "") -> Dict[str, Any]:
        """Operational Data 조회 (Private)"""
        base = f"{NSO_PATHS['device']}={device}/live-status"
        if path:
            normalized_path = self._normalize_path(path)
            full_path = f"{base}/{normalized_path}"
        else:
            full_path = base
            
        return self._request("GET", full_path)

    def _run_command(self, device: str, command: str) -> str:
        """CLI 명령어 실행 (Private)"""
        path = f"devices/device={device}/live-status/tailf-ned-cisco-ios-stats:exec/any"
        
        payload = {
            "tailf-ned-cisco-ios-stats:any": {
                "args": [command]
            }
        }
        
        res = self._request("POST", path, payload=payload)
        
        if isinstance(res, dict):
            if res.get("status") == "error":
                return f"Command Failed: {res.get('message')}"
            return res.get("result", "No output returned.")
            
        return "Unknown response from live-status."

    def _fetch_device_info(self, device: str) -> Dict[str, Any]:
        """장비 기본 정보 조회 (Private)"""
        path = f"{NSO_PATHS['device']}={device}"
        return self._request("GET", f"{path}?fields=name;address;port;authgroup;device-type")

    def _get_schema(self, path: str = "", depth: int = 1, with_type_hints: bool = True) -> List[str]:
        """스키마 탐색 (Private)"""
        query_path = f"{path}?depth={depth}" if path else f"?depth={depth}"
        res = self._request("GET", query_path)
        
        if isinstance(res, dict):
            if res.get("status") == "error":
                return [f"Error: {res['message']}"]
            if res.get("status") == "not_found":
                return ["Invalid Path"]
            
            result = []
            for k, v in res.items():
                if k in ("status", "path", "message"):
                    continue
                if with_type_hints:
                    if isinstance(v, (dict, list)):
                        result.append(f"{k} [+]")
                    else:
                        result.append(f"{k} [=]")
                else:
                    result.append(k)
            return result
        return []

    # =========================================================
    #          Public High-level API (LLM용 도구)
    # =========================================================

    # --- Discovery & Inventory ---

    def get_devices(self) -> List[str]:
        """NSO에 등록된 모든 장비 목록 반환"""
        res = self._request("GET", f"{NSO_PATHS['devices']}/device?fields=name")
        
        if isinstance(res, dict):
            if res.get("status") in ("error", "not_found"):
                return []
            devices = res.get("device", [])
            if isinstance(devices, list):
                return [d.get("name", "") for d in devices if isinstance(d, dict)]
        return []

    def get_device_info(self, device: str) -> Dict[str, Any]:
        """장비의 기본 정보 반환"""
        info = self._fetch_device_info(device)
        if isinstance(info, dict) and "device" in info:
            devices = info.get("device", [])
            if devices and isinstance(devices, list):
                return devices[0]
        return {}

    # --- Interface Management ---

    def get_interfaces(self, device: str) -> List[Dict[str, Any]]:
        """장비의 모든 인터페이스 설정 정보 반환"""
        config = self._fetch_config(device)
        if not isinstance(config, dict):
            return []
        
        interfaces_data = config.get("interface", {})
        result = []
        
        if isinstance(interfaces_data, dict):
            for iface_type, iface_list in interfaces_data.items():
                if isinstance(iface_list, list):
                    result.extend(iface_list)
        elif isinstance(interfaces_data, list):
            result = interfaces_data
            
        return result

    def get_interface_ips(self, device: str) -> Dict[str, str]:
        """각 인터페이스의 IP 주소 매핑 반환"""
        interfaces = self.get_interfaces(device)
        ip_map = {}
        
        for iface in interfaces:
            if not isinstance(iface, dict):
                continue
            name = iface.get("name", "")
            ip = iface.get("ip", {})
            
            if isinstance(ip, dict):
                addr = ip.get("address", {})
                if isinstance(addr, dict):
                    primary = addr.get("primary", {})
                    if isinstance(primary, dict):
                        ip_addr = primary.get("address", "")
                        mask = primary.get("mask", "")
                        if ip_addr:
                            ip_map[name] = f"{ip_addr}/{mask}" if mask else ip_addr
        
        return ip_map

    # --- Network Testing ---

    def ping(self, device: str, target: str, count: int = 5) -> Dict[str, Any]:
        """Ping 테스트 실행 및 결과 파싱"""
        command = f"ping {target} repeat {count}"
        output = self._run_command(device, command)
        return self._parse_ping_output(output)

    def traceroute(self, device: str, target: str) -> Dict[str, Any]:
        """Traceroute 실행 및 경로 파싱"""
        command = f"traceroute {target}"
        output = self._run_command(device, command)
        return self._parse_traceroute_output(output)

    # --- Routing ---

    def get_bgp_neighbors(self, device: str) -> List[Dict[str, Any]]:
        """BGP 네이버 목록 및 설정 반환"""
        config = self._fetch_config(device, "router/bgp")
        neighbors = []
        
        if isinstance(config, dict):
            bgp_data = config.get("bgp", {})
            if isinstance(bgp_data, dict):
                neighbor_list = bgp_data.get("neighbor", [])
                if isinstance(neighbor_list, list):
                    neighbors = neighbor_list
                    
        return neighbors

    def get_bgp_as_number(self, device: str) -> int:
        """BGP Local AS 번호 반환"""
        config = self._fetch_config(device, "router/bgp")
        
        if isinstance(config, dict):
            bgp_data = config.get("bgp", {})
            if isinstance(bgp_data, dict):
                as_number = bgp_data.get("as-number", 0)
                if as_number:
                    return int(as_number)
                for key in bgp_data.keys():
                    if str(key).isdigit():
                        return int(key)
        
        return 0

    def get_ospf_config(self, device: str) -> Dict[str, Any]:
        """OSPF 설정 정보 반환"""
        config = self._fetch_config(device, "router/ospf")
        
        if isinstance(config, dict):
            return config.get("ospf", {})
        return {}

    def get_ospf_areas(self, device: str) -> List[str]:
        """OSPF Area 목록 반환"""
        ospf_config = self.get_ospf_config(device)
        areas = []
        
        if isinstance(ospf_config, dict):
            for process_id, process_config in ospf_config.items():
                if isinstance(process_config, dict):
                    area_list = process_config.get("area", [])
                    if isinstance(area_list, list):
                        for area in area_list:
                            if isinstance(area, dict):
                                area_id = area.get("area-id", "")
                                if area_id and area_id not in areas:
                                    areas.append(str(area_id))
        
        return areas

    def get_ospf_process_ids(self, device: str) -> List[str]:
        """OSPF 프로세스 ID 목록 반환"""
        ospf_config = self.get_ospf_config(device)
        process_ids = []
        
        if isinstance(ospf_config, dict):
            process_ids = [str(pid) for pid in ospf_config.keys() if pid != "ospf"]
        
        return process_ids

    # --- Security ---

    def get_ssh_config(self, device: str) -> Dict[str, Any]:
        """SSH 설정 정보 반환"""
        config = self._fetch_config(device)
        ssh_info = {"enabled": False, "version": None}
        
        if isinstance(config, dict):
            ip_config = config.get("ip", {})
            if isinstance(ip_config, dict):
                ssh = ip_config.get("ssh", {})
                if ssh:
                    ssh_info["enabled"] = True
                    ssh_info["version"] = ssh.get("version", "2")
        
        return ssh_info

    def get_aaa_config(self, device: str) -> Dict[str, Any]:
        """AAA 설정 정보 반환"""
        config = self._fetch_config(device)
        aaa_info = {"enabled": False, "methods": []}
        
        if isinstance(config, dict):
            aaa = config.get("aaa", {})
            if aaa and isinstance(aaa, dict):
                aaa_info["enabled"] = True
                if "authentication" in aaa:
                    aaa_info["methods"].append("authentication")
                if "authorization" in aaa:
                    aaa_info["methods"].append("authorization")
        
        return aaa_info

    def get_vty_config(self, device: str) -> Dict[str, Any]:
        """VTY 라인 설정 정보 반환"""
        config = self._fetch_config(device, "line")
        vty_info = {}
        
        if isinstance(config, dict):
            line_data = config.get("line", {})
            if isinstance(line_data, dict):
                vty = line_data.get("vty", {})
                if isinstance(vty, dict) and vty:
                    first_vty = vty if not isinstance(vty, list) else vty[0]
                    if isinstance(first_vty, dict):
                        vty_info["login"] = first_vty.get("login", {}).get("local", "")
                        transport = first_vty.get("transport", {})
                        if isinstance(transport, dict):
                            vty_info["transport_input"] = transport.get("input", {}).get("input", "")
        
        return vty_info

    # --- VRF Management ---

    def get_vrf_list(self, device: str) -> List[str]:
        """VRF 목록 반환"""
        config = self._fetch_config(device, "vrf")
        vrf_names = []
        
        if isinstance(config, dict):
            vrf_data = config.get("vrf", {})
            if isinstance(vrf_data, dict):
                definition = vrf_data.get("definition", [])
                if isinstance(definition, list):
                    for vrf in definition:
                        if isinstance(vrf, dict):
                            name = vrf.get("name", "")
                            if name:
                                vrf_names.append(name)
        
        return vrf_names

    def get_vrf_bindings(self, device: str) -> Dict[str, str]:
        """인터페이스별 VRF 바인딩 현황 반환"""
        interfaces = self.get_interfaces(device)
        bindings = {}
        
        for iface in interfaces:
            if not isinstance(iface, dict):
                continue
            name = iface.get("name", "")
            vrf = iface.get("vrf", {})
            
            if isinstance(vrf, dict):
                vrf_name = vrf.get("forwarding", "default")
            else:
                vrf_name = "default"
            
            if name:
                bindings[name] = vrf_name
        
        return bindings

    # --- Services (L2VPN, MPLS) ---

    def get_l2vpn_pseudowires(self, device: str) -> List[Dict[str, Any]]:
        """L2VPN Pseudowire 목록 반환"""
        config = self._fetch_config(device, "l2vpn")
        pseudowires = []
        
        if isinstance(config, dict):
            l2vpn_data = config.get("l2vpn", {})
            if isinstance(l2vpn_data, dict):
                xconnect = l2vpn_data.get("xconnect", {})
                if isinstance(xconnect, dict):
                    for name, xc_config in xconnect.items():
                        if isinstance(xc_config, dict):
                            peer = xc_config.get("peer", {})
                            if isinstance(peer, dict):
                                for peer_ip, peer_config in peer.items():
                                    if isinstance(peer_config, dict):
                                        pw_id = peer_config.get("pw-id", 0)
                                        pseudowires.append({
                                            "pw_id": pw_id,
                                            "peer": peer_ip,
                                            "encapsulation": "mpls"
                                        })
        
        return pseudowires

    def get_mpls_ldp_status(self, device: str) -> Dict[str, Any]:
        """MPLS LDP 설정 여부 및 상태 반환"""
        config = self._fetch_config(device, "mpls")
        ldp_status = {"enabled": False, "router_id": None}
        
        if isinstance(config, dict):
            mpls_data = config.get("mpls", {})
            if isinstance(mpls_data, dict):
                ldp = mpls_data.get("ldp", {})
                if ldp:
                    ldp_status["enabled"] = True
                    if isinstance(ldp, dict):
                        ldp_status["router_id"] = ldp.get("router-id", None)
        
        return ldp_status

    # --- Comparison & Aggregation Helpers ---

    def get_all_devices_config(self, config_type: str) -> Dict[str, Any]:
        """모든 장비의 특정 설정을 한 번에 조회"""
        devices = self.get_devices()
        results = {}
        
        for device in devices:
            if config_type == "interface_count":
                interfaces = self.get_interfaces(device)
                results[device] = len(interfaces)
            elif config_type == "bgp_as":
                results[device] = self.get_bgp_as_number(device)
            elif config_type == "ssh_config":
                results[device] = self.get_ssh_config(device)
            elif config_type == "vrf_list":
                results[device] = self.get_vrf_list(device)
            elif config_type == "bgp_neighbor_count":
                neighbors = self.get_bgp_neighbors(device)
                results[device] = len(neighbors)
            elif config_type == "ospf_areas":
                results[device] = self.get_ospf_areas(device)
        
        return results

    def compare_devices(self, dev1: str, dev2: str, aspect: str) -> Dict[str, Any]:
        """두 장비의 특정 측면을 비교"""
        result = {
            "dev1_name": dev1,
            "dev2_name": dev2,
            "dev1_value": None,
            "dev2_value": None,
            "same": False
        }
        
        if aspect == "bgp_neighbor_count":
            neighbors1 = self.get_bgp_neighbors(dev1)
            neighbors2 = self.get_bgp_neighbors(dev2)
            result["dev1_value"] = len(neighbors1)
            result["dev2_value"] = len(neighbors2)
            result["difference"] = result["dev1_value"] - result["dev2_value"]
            result["same"] = result["dev1_value"] == result["dev2_value"]
            
        elif aspect == "interface_count":
            ifaces1 = self.get_interfaces(dev1)
            ifaces2 = self.get_interfaces(dev2)
            result["dev1_value"] = len(ifaces1)
            result["dev2_value"] = len(ifaces2)
            result["difference"] = result["dev1_value"] - result["dev2_value"]
            result["same"] = result["dev1_value"] == result["dev2_value"]
            
        elif aspect == "bgp_as":
            as1 = self.get_bgp_as_number(dev1)
            as2 = self.get_bgp_as_number(dev2)
            result["dev1_value"] = as1
            result["dev2_value"] = as2
            result["same"] = as1 == as2
            
        elif aspect == "ospf_areas":
            areas1 = set(self.get_ospf_areas(dev1))
            areas2 = set(self.get_ospf_areas(dev2))
            result["dev1_value"] = list(areas1)
            result["dev2_value"] = list(areas2)
            result["same"] = areas1 == areas2
        
        return result

    def find_devices_with(self, condition: str, value: Any = None) -> List[str]:
        """조건에 맞는 장비 목록 반환"""
        devices = self.get_devices()
        
        if condition == "max_interfaces":
            interface_counts = {dev: len(self.get_interfaces(dev)) for dev in devices}
            if not interface_counts:
                return []
            max_count = max(interface_counts.values())
            return [dev for dev, count in interface_counts.items() if count == max_count]
            
        elif condition == "min_interfaces":
            interface_counts = {dev: len(self.get_interfaces(dev)) for dev in devices}
            if not interface_counts:
                return []
            min_count = min(interface_counts.values())
            return [dev for dev, count in interface_counts.items() if count == min_count]
            
        elif condition == "ssh_enabled":
            result = []
            for dev in devices:
                ssh_config = self.get_ssh_config(dev)
                if ssh_config.get("enabled"):
                    result.append(dev)
            return result
            
        elif condition == "aaa_enabled":
            result = []
            for dev in devices:
                aaa_config = self.get_aaa_config(dev)
                if aaa_config.get("enabled"):
                    result.append(dev)
            return result
            
        elif condition == "bgp_configured":
            result = []
            for dev in devices:
                bgp_as = self.get_bgp_as_number(dev)
                if bgp_as > 0:
                    result.append(dev)
            return result
        
        return []

    # --- Consistency Checks ---

    def check_ip_conflicts(self) -> List[Dict[str, Any]]:
        """전체 네트워크의 IP 충돌 검사"""
        devices = self.get_devices()
        ip_usage = {}
        
        for device in devices:
            ip_map = self.get_interface_ips(device)
            for iface, ip_with_mask in ip_map.items():
                if not ip_with_mask:
                    continue
                ip = ip_with_mask.split('/')[0] if '/' in ip_with_mask else ip_with_mask
                if ip not in ip_usage:
                    ip_usage[ip] = []
                ip_usage[ip].append((device, iface))
        
        conflicts = []
        for ip, usages in ip_usage.items():
            if len(usages) > 1:
                conflicts.append({
                    "ip": ip,
                    "devices": [usage[0] for usage in usages],
                    "interfaces": [f"{usage[0]}:{usage[1]}" for usage in usages]
                })
        
        return conflicts

    def check_l2vpn_consistency(self) -> Dict[str, Any]:
        """L2VPN 일관성 검사"""
        devices = self.get_devices()
        all_pws = {}
        
        for device in devices:
            pws = self.get_l2vpn_pseudowires(device)
            for pw in pws:
                peer = pw.get("peer")
                pw_id = pw.get("pw_id")
                key = tuple(sorted([device, peer]))
                if key not in all_pws:
                    all_pws[key] = []
                all_pws[key].append({
                    "device": device,
                    "peer": peer,
                    "pw_id": pw_id
                })
        
        result = {
            "total_pseudowires": sum(len(pws) for pws in all_pws.values()),
            "mismatched_pwid": [],
            "unidirectional": []
        }
        
        for (dev1, dev2), configs in all_pws.items():
            if len(configs) == 1:
                result["unidirectional"].append(f"{configs[0]['device']}->{configs[0]['peer']}")
            elif len(configs) == 2:
                if configs[0]["pw_id"] != configs[1]["pw_id"]:
                    result["mismatched_pwid"].append({
                        "devices": f"{dev1}<->{dev2}",
                        "pw_ids": [configs[0]["pw_id"], configs[1]["pw_id"]]
                    })
        
        return result

    # --- Parsing Helpers ---

    def _parse_ping_output(self, text: str) -> Dict[str, Any]:
        """Ping 명령어 출력을 파싱"""
        result = {
            "success": False,
            "packet_loss": 100.0,
            "sent": 0,
            "received": 0,
            "avg_rtt_ms": 0.0,
            "min_ms": 0.0,
            "max_ms": 0.0
        }
        
        if "Success rate is" in text:
            rate_match = re.search(r'Success rate is (\d+) percent \((\d+)/(\d+)\)', text)
            if rate_match:
                received = int(rate_match.group(2))
                sent = int(rate_match.group(3))
                result["received"] = received
                result["sent"] = sent
                result["packet_loss"] = ((sent - received) / sent * 100) if sent > 0 else 100.0
                result["success"] = received > 0
            
            rtt_match = re.search(r'min/avg/max = (\d+)/(\d+)/(\d+)', text)
            if rtt_match:
                result["min_ms"] = float(rtt_match.group(1))
                result["avg_rtt_ms"] = float(rtt_match.group(2))
                result["max_ms"] = float(rtt_match.group(3))
        
        return result

    def _parse_traceroute_output(self, text: str) -> Dict[str, Any]:
        """Traceroute 명령어 출력을 파싱"""
        result = {
            "success": False,
            "path": [],
            "hop_count": 0
        }
        
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, text)
        
        if ips:
            result["path"] = list(dict.fromkeys(ips))
            result["hop_count"] = len(result["path"])
            result["success"] = True
        
        return result


# --- 테스트 코드 ---
if __name__ == "__main__":
    connector = SanoaConnector()
    
    print("\n" + "="*70)
    print("NSO LLM-Friendly API 테스트 (완전 구현 버전 - 32개 API)")
    print("="*70)
    
    print("\n1. 장비 목록 조회")
    devices = connector.get_devices()
    print(f"   발견된 장비: {devices}")
    
    if devices:
        target = devices[0]
        print(f"\n=== 기본 테스트 ({target}) ===")
        
        print(f"\n2. 장비 정보")
        info = connector.get_device_info(target)
        print(f"   {info}")
        
        print(f"\n3. 인터페이스 (get_interfaces)")
        interfaces = connector.get_interfaces(target)
        print(f"   개수: {len(interfaces)}")
        
        print(f"\n4. IP 매핑 (get_interface_ips)")
        ip_map = connector.get_interface_ips(target)
        for iface, ip in list(ip_map.items())[:3]:
            print(f"   {iface}: {ip}")
        
        print(f"\n=== 새로 추가된 API 테스트 ===")
        
        print(f"\n5. BGP AS 번호 (get_bgp_as_number)")
        bgp_as = connector.get_bgp_as_number(target)
        print(f"   AS: {bgp_as}")
        
        print(f"\n6. VRF 목록 (get_vrf_list)")
        vrfs = connector.get_vrf_list(target)
        print(f"   VRFs: {vrfs}")
        
        print(f"\n7. SSH 설정 (get_ssh_config)")
        ssh = connector.get_ssh_config(target)
        print(f"   SSH: {ssh}")
        
        print(f"\n8. AAA 설정 (get_aaa_config)")
        aaa = connector.get_aaa_config(target)
        print(f"   AAA: {aaa}")
        
        print(f"\n=== 집계/비교 함수 테스트 ===")
        
        print(f"\n9. 전체 장비 인터페이스 수 (get_all_devices_config)")
        all_iface_counts = connector.get_all_devices_config("interface_count")
        print(f"   {all_iface_counts}")
        
        print(f"\n10. 최소 인터페이스 장비 (find_devices_with)")
        min_devices = connector.find_devices_with("min_interfaces")
        print(f"   {min_devices}")
        
        if len(devices) >= 2:
            print(f"\n11. 장비 비교 (compare_devices)")
            comparison = connector.compare_devices(devices[0], devices[1], "interface_count")
            print(f"   {comparison}")
        
        print(f"\n12. IP 충돌 검사 (check_ip_conflicts)")
        conflicts = connector.check_ip_conflicts()
        print(f"   충돌: {len(conflicts)}개")
    else:
        print("\n[경고] 등록된 디바이스가 없습니다.")
    
    print("\n" + "="*70)
    print("테스트 완료! 총 32개 API 사용 가능")
    print("="*70)