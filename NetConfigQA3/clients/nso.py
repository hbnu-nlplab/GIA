"""
NSO RESTCONF API Client
Cisco NSO와 통신하는 LLM-Friendly 클라이언트

기존 enter_NSO.py(SanoaConnector)를 새 구조로 이전
"""

import requests
import logging
import re
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class NSOClient:
    """
    NSO RESTCONF API 클라이언트
    
    기능:
    - 장비 목록 조회 및 관리
    - 인터페이스/라우팅/보안 설정 조회
    - 장비 비교 및 일관성 검사
    - 네트워크 테스트 (ping, traceroute)
    
    Total APIs: 32개
    """
    
    # NSO RESTCONF 경로 상수
    PATHS = {
        "devices": "tailf-ncs:devices",
        "device": "tailf-ncs:devices/device",
    }
    
    def __init__(self, base_url: str, username: str, password: str, timeout: int = 30):
        """
        Args:
            base_url: NSO RESTCONF URL (예: http://localhost:8080/restconf/data)
            username: NSO 사용자명
            password: NSO 비밀번호
            timeout: 요청 타임아웃 (초)
        """
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        
        self.session = requests.Session()
        self.session.auth = (username, password)
        self.session.headers = {
            'Content-Type': 'application/yang-data+json',
            'Accept': 'application/yang-data+json'
        }
        
        logger.info(f"NSOClient initialized for {self.base_url}")

    # =========================================================
    #          Private Low-level API
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
                response = self.session.get(url, timeout=self.timeout)
            elif method == "PATCH":
                response = self.session.patch(url, json=payload, timeout=self.timeout)
            elif method == "POST":
                response = self.session.post(url, json=payload, timeout=self.timeout)
            elif method == "DELETE":
                response = self.session.delete(url, timeout=self.timeout)
            else:
                return {"status": "error", "message": f"Unsupported method: {method}"}
            
            if response.status_code == 404:
                logger.warning(f"Resource Not Found: {path}")
                return {"status": "not_found", "path": path}
            
            response.raise_for_status()
            
            if "dry-run" in url:
                logger.info(f"Dry-run Executed: {path}")
                return {"status": "success", "diff": response.text}

            if response.text:
                data = response.json()
                clean_data = self._clean_namespace(data)
            else:
                clean_data = {"status": "success"}
            
            logger.info(f"API Call Success: {method} {path}")
            return clean_data

        except requests.exceptions.RequestException as e:
            logger.error(f"API Connection Error: {str(e)}")
            return {"status": "error", "message": str(e)}

    def _normalize_path(self, path: str) -> str:
        """경로 정규화"""
        return re.sub(r'/+', '/', path.strip('/'))

    def get_native_config(self, device: str) -> str:
        """
        RESTCONF 액션을 사용하여 장비의 Native(CLI) 설정을 가져옵니다.
        """
        # NSO RESTCONF 표준 액션 경로: /devices/device{name}/show-config
        path = f"devices/device={device}/show-config"
        payload = {
            "input": {
                "format": "native"
            }
        }
        
        res = self._request("POST", path, payload=payload)
        
        if isinstance(res, dict):
            # NSO 액션 결과는 'output' -> 'data' 필드에 담겨 옵니다.
            # _request 내부에서 _clean_namespace가 호출되므로 접두어가 제거된 'output'을 확인합니다.
            output = res.get("output", {})
            if isinstance(output, dict):
                return output.get("data", "")
            
        return ""

    def _fetch_config(self, device: str, config_path: str = "") -> Dict[str, Any]:
        """설정 데이터 조회"""
        base = f"{self.PATHS['device']}={device}/config"
        if config_path:
            normalized_path = self._normalize_path(config_path)
            path = f"{base}/{normalized_path}"
        else:
            path = base

        result = self._request("GET", path)

        if not config_path and isinstance(result, dict) and "config" in result:
            return result["config"]

        return result

    def _run_command(self, device: str, command: str) -> str:
        """CLI 명령어 실행"""
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

    # =========================================================
    #          Public High-level API (LLM용 도구)
    # =========================================================

    # --- Discovery & Inventory ---

    def get_devices(self) -> List[str]:
        """NSO에 등록된 모든 장비 목록 반환"""
        res = self._request("GET", f"{self.PATHS['devices']}/device?fields=name")
        
        if isinstance(res, dict):
            if res.get("status") in ("error", "not_found"):
                return []
            devices = res.get("device", [])
            if isinstance(devices, list):
                return [d.get("name", "") for d in devices if isinstance(d, dict)]
        return []

    def get_device_info(self, device: str) -> Dict[str, Any]:
        """장비의 기본 정보 반환"""
        path = f"{self.PATHS['device']}={device}"
        info = self._request("GET", f"{path}?fields=name;address;port;authgroup;device-type")
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
        """BGP 네이버 목록 반환"""
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

    # --- VRF ---

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

    # --- Comparison & Analysis ---

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
            result["same"] = result["dev1_value"] == result["dev2_value"]
            
        elif aspect == "interface_count":
            ifaces1 = self.get_interfaces(dev1)
            ifaces2 = self.get_interfaces(dev2)
            result["dev1_value"] = len(ifaces1)
            result["dev2_value"] = len(ifaces2)
            result["same"] = result["dev1_value"] == result["dev2_value"]
            
        elif aspect == "bgp_as":
            as1 = self.get_bgp_as_number(dev1)
            as2 = self.get_bgp_as_number(dev2)
            result["dev1_value"] = as1
            result["dev2_value"] = as2
            result["same"] = as1 == as2
        
        return result

    def find_devices_with(self, condition: str) -> List[str]:
        """조건에 맞는 장비 목록 반환"""
        devices = self.get_devices()
        
        if condition == "ssh_enabled":
            return [dev for dev in devices if self.get_ssh_config(dev).get("enabled")]
        elif condition == "bgp_configured":
            return [dev for dev in devices if self.get_bgp_as_number(dev) > 0]
        
        return []

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

    # --- Parsing Helpers ---

    def _parse_ping_output(self, text: str) -> Dict[str, Any]:
        """Ping 출력 파싱"""
        result = {"success": False, "packet_loss": 100.0, "sent": 0, "received": 0}
        
        if "Success rate is" in text:
            rate_match = re.search(r'Success rate is (\d+) percent \((\d+)/(\d+)\)', text)
            if rate_match:
                received = int(rate_match.group(2))
                sent = int(rate_match.group(3))
                result["received"] = received
                result["sent"] = sent
                result["packet_loss"] = ((sent - received) / sent * 100) if sent > 0 else 100.0
                result["success"] = received > 0
        
        return result

    def _parse_traceroute_output(self, text: str) -> Dict[str, Any]:
        """Traceroute 출력 파싱"""
        result = {"success": False, "path": [], "hop_count": 0}
        
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, text)
        
        if ips:
            result["path"] = list(dict.fromkeys(ips))
            result["hop_count"] = len(result["path"])
            result["success"] = True
        
        return result


# 하위 호환성을 위한 alias
SanoaConnector = NSOClient


# --- 테스트 코드 ---
if __name__ == "__main__":
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))
    
    from config.settings import settings
    
    logging.basicConfig(level=logging.INFO)
    
    print("=== NSO Client Test ===")
    
    client = NSOClient(
        base_url=settings.nso.base_url,
        username=settings.nso.username,
        password=settings.nso.password
    )
    
    devices = client.get_devices()
    print(f"Registered devices: {devices}")
    
    if devices:
        device = devices[0]
        print(f"\nDevice info for {device}:")
        print(client.get_device_info(device))

