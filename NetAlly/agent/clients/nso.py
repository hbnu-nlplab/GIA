"""
NSO RESTCONF API Client
Cisco NSO와 통신하는 LLM-Friendly 클라이언트

기존 enter_NSO.py(SanoaConnector)를 새 구조로 이전
"""

import requests
import logging
import re
import os
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ConfigExportResult:
    """cfg/xml/yang 추출 결과 (하이브리드 전략)"""
    device: str
    success: bool
    cfg_path: Optional[str] = None       # Native CLI (Batfish용)
    xml_path: Optional[str] = None       # XML (레거시)
    yang_path: Optional[str] = None      # YANG JSON (향후 확장)
    cfg_size: int = 0
    xml_size: int = 0
    yang_size: int = 0
    error: Optional[str] = None



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
    
    def __init__(self, base_url: str, username: str, password: str, timeout: int = 30, docker_container: str = "cisco-nso-dev"):
        """
        Args:
            base_url: NSO RESTCONF base URL (예: http://localhost:8080/restconf)
            username: NSO 사용자명
            password: NSO 비밀번호
            timeout: 요청 타임아웃 (초)
            docker_container: NSO Docker 컨테이너 이름 (CLI 실행용)
        """
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.docker_container = docker_container
        
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
        # RESTCONF 경로 구성: 데이터스토어 작업은 /data 추가, 작업/액션은 그대로
        # 데이터스토어 경로: tailf-ncs:, cisco-ios: 등으로 시작
        # 액션/오퍼레이션 경로: /{operation_name}, /operations/ 포함
        if path.startswith('tailf-ncs:') or path.startswith('cisco-') or (
            '/' in path and not path.startswith('operations/') and 
            '/operations/' not in path and not path.startswith('running/')
        ):
            # 이미 /data로 시작하지 않으면 추가
            if not path.startswith('data/'):
                url = f"{self.base_url}/data/{path}"
            else:
                url = f"{self.base_url}/{path}"
        else:
            url = f"{self.base_url}/{path}"
        
        try:
            if method == "GET":
                response = self.session.get(url, timeout=self.timeout)
            elif method == "PATCH":
                response = self.session.patch(url, json=payload, timeout=self.timeout)
            elif method == "PUT":
                response = self.session.put(url, json=payload, timeout=self.timeout)
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

        except requests.exceptions.HTTPError as e:
            body = ""
            response = getattr(e, "response", None)
            if response is not None:
                try:
                    body = str(response.text or "").strip()
                except Exception:
                    body = ""
            message = str(e)
            if body:
                message = f"{message} | {body[:1000]}"
            logger.error(f"API Connection Error: {message}")
            return {"status": "error", "message": message}

        except requests.exceptions.RequestException as e:
            logger.error(f"API Connection Error: {str(e)}")
            return {"status": "error", "message": str(e)}

    def _normalize_path(self, path: str) -> str:
        """경로 정규화"""
        return re.sub(r'/+', '/', path.strip('/'))

    def _normalize_ned_id(self, ned_id: str) -> str:
        """NSO identityref 형식으로 NED ID를 정규화합니다."""
        value = str(ned_id or "").strip()
        if not value:
            return value
        if ":" in value:
            return value
        return f"{value}:{value}"

    def _get_known_ned_ids(self) -> List[str]:
        """
        NSO에 이미 등록된 장비에서 사용 중인 NED ID를 수집합니다.
        """
        res = self._request("GET", f"{self.PATHS['devices']}/device?fields=device-type")
        if not isinstance(res, dict) or res.get("status") in ("error", "not_found"):
            return []

        out: List[str] = []
        devices = res.get("device", [])
        if not isinstance(devices, list):
            return out

        for dev in devices:
            if not isinstance(dev, dict):
                continue
            dev_type = dev.get("device-type", {})
            if not isinstance(dev_type, dict):
                continue
            cli = dev_type.get("cli", {})
            if not isinstance(cli, dict):
                continue
            ned = cli.get("ned-id")
            if not ned:
                continue
            normalized = self._normalize_ned_id(str(ned))
            if normalized:
                out.append(normalized)

        deduped: List[str] = []
        seen = set()
        for item in out:
            if item in seen:
                continue
            seen.add(item)
            deduped.append(item)
        return deduped

    def _get_installed_ned_ids(self) -> List[str]:
        """
        NSO packages에서 설치된 NED ID를 수집합니다.
        """
        res = self._request("GET", "tailf-ncs:packages")
        if not isinstance(res, dict) or res.get("status") in ("error", "not_found"):
            return []

        root = res.get("packages")
        if not isinstance(root, dict):
            return []
        packages = root.get("package", [])
        if not isinstance(packages, list):
            return []

        out: List[str] = []
        for pkg in packages:
            if not isinstance(pkg, dict):
                continue
            components = pkg.get("component", [])
            if not isinstance(components, list):
                continue
            for comp in components:
                if not isinstance(comp, dict):
                    continue
                ned = comp.get("ned", {})
                if not isinstance(ned, dict):
                    continue
                cli = ned.get("cli", {})
                if not isinstance(cli, dict):
                    continue
                ned_id = cli.get("ned-id")
                if not ned_id:
                    continue
                normalized = self._normalize_ned_id(str(ned_id))
                if normalized:
                    out.append(normalized)

        deduped: List[str] = []
        seen = set()
        for item in out:
            if item in seen:
                continue
            seen.add(item)
            deduped.append(item)
        return deduped

    def _candidate_ned_ids(self, requested_ned: str) -> List[str]:
        """
        Build ordered candidate NED IDs for registration.
        """
        raw_candidates: List[str] = []
        if requested_ned:
            raw_candidates.append(requested_ned)

        env_ned = str(os.getenv("NSO_NED_ID", "")).strip()
        if env_ned:
            raw_candidates.append(env_ned)

        raw_candidates.extend(self._get_installed_ned_ids())
        raw_candidates.extend(self._get_known_ned_ids())
        # Common Cisco IOS NEDs used in lab environments.
        raw_candidates.extend(["cisco-ios-cli-3.8", "cisco-ios-cli-6.110"])

        normalized: List[str] = []
        seen = set()
        for raw in raw_candidates:
            ned = self._normalize_ned_id(raw)
            if not ned or ned in seen:
                continue
            seen.add(ned)
            normalized.append(ned)
        return normalized

    @staticmethod
    def _is_invalid_ned_error(message: str) -> bool:
        text = str(message or "").lower()
        return "ned-id" in text and "valid value" in text

    @staticmethod
    def _is_unsupported_ssh_algorithms_error(message: str) -> bool:
        text = str(message or "").lower()
        return "unknown element: ssh-algorithms" in text

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

    def _run_action(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """NSO Action 실행"""
        payload = params or {}
        res = self._request("POST", path, payload=payload)
        
        if isinstance(res, dict):
             # Action 결과는 보통 output 키 안에 있음
            if "output" in res:
                return res["output"]
            return res
        return {"status": "unknown", "raw": str(res)}

    # =========================================================
    #          Public High-level API (LLM용 도구)
    # =========================================================

    # --- Onboarding & Management ---

    def create_authgroup(self, group: str, username: str, password: str) -> bool:
        """Authgroup 생성 (이미 존재하면 True 반환)"""
        path = "tailf-ncs:devices/authgroups"
        
        # Authgroup 생성 (POST 사용)
        payload = {
            "tailf-ncs:group": [
                {
                    "name": group,
                    "default-map": {
                        "remote-name": username,
                        "remote-password": password
                    }
                }
            ]
        }
        
        # POST를 사용하여 새 authgroup 생성
        res = self._request("POST", path, payload=payload)
        if isinstance(res, dict) and res.get("status") == "error":
            error_msg = res.get("message", "")
            # 409 Conflict = 이미 존재함 → 성공으로 처리
            if "409" in error_msg or "Conflict" in error_msg:
                logger.info(f"Authgroup '{group}' already exists")
                return True
            return False
        return True

    def register_device(self, device_info: Dict[str, Any]) -> bool:
        """장비 등록 (이미 존재하면 True 반환)"""
        name = device_info["name"]
        address = device_info["oob_ip"]
        port = device_info.get("port", 22)
        authgroup = device_info.get("authgroup", "default")
        requested_ned = str(device_info.get("ned_id", "")).strip()
        protocol = device_info.get("protocol", "ssh")

        last_error = ""
        include_ssh_algorithms = protocol == "ssh"
        for ned_id in self._candidate_ned_ids(requested_ned):
            for use_ssh_algorithms in ([include_ssh_algorithms, False] if include_ssh_algorithms else [False]):
                # 장비 등록 Payload
                device_data = {
                    "name": name,
                    "address": address,
                    "port": port,
                    "authgroup": authgroup,
                    "device-type": {
                        "cli": {
                            "ned-id": ned_id,
                            "protocol": protocol
                        }
                    },
                    "state": {
                        "admin-state": "unlocked"
                    }
                }

                # SSH일 경우에만 알고리즘 설정 추가 (구형 NSO에서는 거부될 수 있음)
                if use_ssh_algorithms:
                    device_data["ssh-algorithms"] = {
                        "public-key": ["ssh-rsa"]
                    }

                # PUT을 사용하여 생성 또는 덮어쓰기 (Create or Replace)
                # NSO RESTCONF에서 개별 장비 경로는 devices/device={name}
                res = self._request(
                    "PUT",
                    f"tailf-ncs:devices/device={name}",
                    payload={"tailf-ncs:device": device_data},
                )

                if not (isinstance(res, dict) and res.get("status") == "error"):
                    if requested_ned and self._normalize_ned_id(requested_ned) != ned_id:
                        logger.info(
                            "NED fallback applied for %s: requested=%s effective=%s",
                            name,
                            requested_ned,
                            ned_id,
                        )
                    if include_ssh_algorithms and not use_ssh_algorithms:
                        logger.info(
                            "ssh-algorithms omitted for %s due NSO schema compatibility",
                            name,
                        )
                    return True

                err = str(res.get("message", ""))
                last_error = err
                if self._is_unsupported_ssh_algorithms_error(err) and use_ssh_algorithms:
                    logger.warning(
                        "ssh-algorithms rejected for %s, retrying without ssh-algorithms",
                        name,
                    )
                    continue

                if self._is_invalid_ned_error(err):
                    logger.warning("NED rejected for %s with %s, trying fallback", name, ned_id)
                    break

                logger.error(f"Failed to register/update device {name}: {err}")
                return False

        logger.error(f"Failed to register/update device {name}: {last_error}")
        return False

    def fetch_host_keys(self, device_name: str) -> bool:
        """SSH 호스트 키 가져오기 (SSH 프로토콜인 경우만 실행)"""
        # 먼저 장비 정보를 조회하여 프로토콜 확인
        info = self.get_device_info(device_name)
        protocol = "ssh" # 기본값
        
        if info and "device-type" in info:
            cli = info["device-type"].get("cli", {})
            protocol = cli.get("protocol", "ssh")
            
        if protocol != "ssh":
            logger.info(f"Skipping fetch-host-keys for {device_name} (protocol: {protocol})")
            return True
            
        path = f"tailf-ncs:devices/device={device_name}/ssh/fetch-host-keys"
        res = self._run_action(path)
        
        # 결과 확인 ("result": "fetched" 등)
        full_res = str(res)
        return "fetched" in full_res or "result" in full_res

    def sync_from(self, device_name: str) -> bool:
        """Sync-from 실행"""
        path = f"tailf-ncs:devices/device={device_name}/sync-from"
        res = self._run_action(path)
        
        # 결과 확인 ("result": true)
        if isinstance(res, dict):
            success = str(res.get("result", "")).lower() == "true"
            if not success:
                error_info = res.get("info", "No additional info provided by NSO")
                logger.error(f"Sync-from failed for {device_name}. Reason: {error_info}")
            return success
        return False

    def check_sync(self, device_name: str) -> bool:
        """Check-sync 실행"""
        path = f"tailf-ncs:devices/device={device_name}/check-sync"
        res = self._run_action(path)
        
        if isinstance(res, dict):
            return str(res.get("result", "")).lower() == "in-sync"
        return False

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

    def get_logs(self, device: str, lines: int = 50) -> str:
        """장비 로그 조회 (Live Status)"""
        # 'show logging | last N' is tricky in IOS, so we just get all and tail in python or try 'show logging'
        # Some IOS versions support 'show logging last <N>'
        # For safety, just 'show logging' and slice in Python
        output = self._run_command(device, "show logging")
        
        if not output:
             return ""
             
        lines_list = output.splitlines()
        if len(lines_list) > lines:
            return "\n".join(lines_list[-lines:])
        return output

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

    def delete_device(self, device_name: str) -> bool:
        """장비를 삭제합니다."""
        path = f"tailf-ncs:devices/device={device_name}"
        result = self._request("DELETE", path)
        
        # _request returns None on success (204) or dict on error
        if isinstance(result, dict) and "errors" in result:
            logger.error(f"Failed to delete device {device_name}: {result}")
            return False
            
        logger.info(f"Deleted device: {device_name}")
        return True

    # =========================================================================
    #          Orchestration & High-level Workflows (SDK)
    # =========================================================================

    def onboard_devices(self, devices: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        장비 일괄 등록 및 초기화 (Registration -> Host Key -> Sync)
        
        Args:
            devices: 장비 정보 리스트
                     [{"name": "P1", "oob_ip": "...", "port": ..., "protocol": "telnet", ...}]
        
        Returns:
            결과 요약
        """
        results = {
            "total": len(devices),
            "registered": [],
            "failed_registration": [],
            "synced": [],
            "failed_sync": []
        }
        
        for dev in devices:
            name = dev["name"]
            logger.info(f"Onboarding device: {name}")
            
            # 1. Register
            if self.register_device(dev):
                results["registered"].append(name)
            else:
                results["failed_registration"].append(name)
                continue
                
            # 2. Fetch Host Keys (SSH Only)
            # fetch_host_keys handles protocol check internally
            try:
                self.fetch_host_keys(name)
            except Exception as e:
                logger.warning(f"Fetch host keys warning for {name}: {e}")
                
            # 3. Sync-from
            if self.sync_from(name):
                results["synced"].append(name)
            else:
                results["failed_sync"].append(name)
                
        return results

    def check_device_connectivity(self, device: str) -> bool:
        """
        장비 연결 상태 확인
        """
        # Simple implementation: check sync status first
        if self.check_sync(device):
            return True
        # If not in sync, try to sync
        return self.sync_from(device)

    def auto_onboard_from_pnetlab(
        self,
        device_name: str,
        telnet_port: int,
        oob_ip: str = "localhost",
        protocol: str = "telnet",
        authgroup: str = "default",
        ned_id: str = "cisco-ios-cli-6.110"
    ) -> Dict[str, Any]:
        """
        PNETLab 노드를 NSO에 자동 등록합니다.
        
        Telnet 포트를 기반으로 장비 정보를 생성하고,
        register_device() → fetch-host-keys (SSH only) → sync-from 순서로 실행합니다.
        
        Args:
            device_name: 장비 이름 (예: "vIOS11")
            telnet_port: PNETLab Telnet 포트 (예: 30037)
            oob_ip: OOB IP 주소 (기본: "localhost")
            protocol: 연결 프로토콜 ("telnet" 또는 "ssh")
            authgroup: NSO Authgroup 이름
            ned_id: NED ID
            
        Returns:
            결과 딕셔너리 {"success": bool, "device": str, "steps": [...], "error": str | None}
        """
        result = {
            "success": False,
            "device": device_name,
            "steps": [],
            "error": None
        }
        
        try:
            # 1. 장비 정보 구성
            device_info = {
                "name": device_name,
                "oob_ip": oob_ip,
                "port": telnet_port,
                "protocol": protocol,
                "authgroup": authgroup,
                "ned_id": ned_id
            }
            
            logger.info(f"Auto-onboarding PNETLab node: {device_name} (port: {telnet_port})")
            
            # 2. 장비 등록
            if not self.register_device(device_info):
                result["error"] = f"Failed to register device {device_name}"
                result["steps"].append({"register": "failed"})
                return result
            result["steps"].append({"register": "success"})
            
            # 3. SSH Host Keys (SSH only)
            if protocol == "ssh":
                try:
                    self.fetch_host_keys(device_name)
                    result["steps"].append({"fetch_host_keys": "success"})
                except Exception as e:
                    logger.warning(f"Fetch host keys warning for {device_name}: {e}")
                    result["steps"].append({"fetch_host_keys": f"warning: {e}"})
            else:
                result["steps"].append({"fetch_host_keys": "skipped (telnet)"})
            
            # 4. Sync-from
            if self.sync_from(device_name):
                result["steps"].append({"sync_from": "success"})
                result["success"] = True
            else:
                result["steps"].append({"sync_from": "failed"})
                result["error"] = f"sync-from failed for {device_name}"
                
        except Exception as e:
            logger.error(f"Auto-onboard error for {device_name}: {e}")
            result["error"] = str(e)
            
        return result

    # =========================================================================
    #          Batfish Config Export
    # =========================================================================
    
    def export_batfish_configs(
        self,
        devices: Optional[List[str]] = None,
        output_dir: str = ".",
        export_xml: bool = True,
        export_yang_json: bool = True
    ) -> Dict[str, Any]:
        """
        Batfish 분석용 cfg/xml 파일 + YANG JSON 추출 (하이브리드 전략)
        """
        # 1. 장비 목록 확보
        if not devices:
            devices = self.get_devices()
        
        if not devices:
            return {"error": "No devices found", "results": []}
        
        # 2. 디렉토리 생성
        configs_dir = Path(output_dir) / "configs"
        xml_dir = Path(output_dir) / "xml" if export_xml else None
        yang_dir = Path(output_dir) / "yang" if export_yang_json else None
        
        configs_dir.mkdir(parents=True, exist_ok=True)
        if xml_dir:
            xml_dir.mkdir(parents=True, exist_ok=True)
        if yang_dir:
            yang_dir.mkdir(parents=True, exist_ok=True)
        
        # 3. 각 장비 설정 추출
        results: List[ConfigExportResult] = []
        
        for device in devices:
            result = self._export_device_config(device, configs_dir, xml_dir, yang_dir)
            results.append(result)
        
        # 4. 결과 요약
        success_count = sum(1 for r in results if r.success)
        
        return {
            "status": "completed",
            "total": len(devices),
            "success": success_count,
            "failed": len(devices) - success_count,
            "configs_dir": str(configs_dir),
            "xml_dir": str(xml_dir) if xml_dir else None,
            "yang_dir": str(yang_dir) if yang_dir else None,
            "results": [
                {
                    "device": r.device,
                    "success": r.success,
                    "cfg_path": r.cfg_path,
                    "xml_path": r.xml_path,
                    "yang_path": r.yang_path,
                    "error": r.error
                }
                for r in results
            ]
        }
    
    def _export_device_config(
        self,
        device: str,
        configs_dir: Path,
        xml_dir: Optional[Path],
        yang_dir: Optional[Path] = None
    ) -> ConfigExportResult:
        """단일 장비 설정 추출"""
        result = ConfigExportResult(device=device, success=False)
        
        try:
            # === 1. CFG 추출 (Native CLI) - Batfish용 ===
            cmd_cfg = f"show running-config devices device {device} config"
            raw_cfg = self._run_nso_docker_cmd(cmd_cfg)
            
            if not raw_cfg:
                result.error = "Failed to get native config via CLI"
                return result
            
            # CFG 정제 및 저장
            cleaned_cfg = self._clean_config(raw_cfg)
            cfg_path = configs_dir / f"{device}.cfg"
            
            with open(cfg_path, "w", encoding="utf-8") as f:
                f.write(cleaned_cfg)
            
            result.cfg_path = str(cfg_path)
            result.cfg_size = len(cleaned_cfg)
            logger.info(f"✅ Exported Native CLI: {cfg_path} ({result.cfg_size} bytes)")
            
            # === 2. XML 추출 (선택적) ===
            if xml_dir:
                cmd_xml = f"show running-config devices device {device} config | display xml"
                raw_xml = self._run_nso_docker_cmd(cmd_xml)
                
                if raw_xml:
                    cleaned_xml = self._clean_xml_output(raw_xml)
                    xml_path = xml_dir / f"{device}.xml"
                    with open(xml_path, "w", encoding="utf-8") as f:
                        f.write(cleaned_xml)
                    
                    result.xml_path = str(xml_path)
                    result.xml_size = len(cleaned_xml)
                    logger.info(f"✅ Exported XML: {xml_path} ({result.xml_size} bytes)")
            
            # === 3. YANG JSON 추출 (선택적) ===
            if yang_dir:
                yang_config = self._fetch_config(device)
                
                if yang_config:
                    import json
                    yang_path = yang_dir / f"{device}.json"
                    with open(yang_path, "w", encoding="utf-8") as f:
                        json.dump(yang_config, f, ensure_ascii=False, indent=2)
                    
                    yang_json_str = json.dumps(yang_config, ensure_ascii=False, indent=2)
                    result.yang_path = str(yang_path)
                    result.yang_size = len(yang_json_str)
                    logger.info(f"✅ Exported YANG JSON: {yang_path} ({result.yang_size} bytes)")
            
            result.success = True
            
        except Exception as e:
            result.error = str(e)
            logger.error(f"❌ Export error for {device}: {e}")
        
        return result
    
    def _run_nso_docker_cmd(self, cmd_input: str) -> str:
        """NSO Docker CLI 명령 실행"""
        bash_cmd = f'cd ~/ncs-instance && source ~/nso-6.6/ncsrc && ncs_cli -C -u admin <<< "{cmd_input}"'
        full_cmd = ['docker', 'exec', self.docker_container, 'bash', '-c', bash_cmd]
        
        try:
            result = subprocess.run(full_cmd, capture_output=True, text=False, timeout=self.timeout)
            
            stdout_text = ""
            if result.stdout:
                for encoding in ['utf-8', 'cp949']:
                    try:
                        stdout_text = result.stdout.decode(encoding)
                        break
                    except UnicodeDecodeError:
                        continue
                else:
                    stdout_text = result.stdout.decode('utf-8', errors='ignore')
            
            return stdout_text
            
        except subprocess.TimeoutExpired:
            raise TimeoutError(f"Command timed out after {self.timeout}s")
        except Exception as e:
            raise RuntimeError(f"Docker command failed: {e}")
    
    def _clean_config(self, raw_config: str) -> str:
        """설정 텍스트 정제"""
        lines = raw_config.splitlines()
        cleaned_lines = []
        skip_until_config = True
        in_banner = False
        banner_delimiter = ""
        
        for line in lines:
            if "admin@ncs#" in line or "admin@ncs%" in line:
                continue
            if "live-status exec" in line or "devices device" in line:
                continue
            if line.strip().endswith("#") and len(line.strip().split()) == 1:
                continue
            if "Building configuration" in line or "Current configuration" in line:
                continue
            if line.strip().startswith("result"):
                continue
            
            if skip_until_config:
                if line.strip() and (line.strip().startswith("!") or line.strip().startswith("version")):
                    skip_until_config = False
                    cleaned_lines.append(line)
                continue
            
            if line.strip().startswith("banner "):
                banner_delimiter = line.strip()[-1]
                in_banner = True
                continue
            
            if in_banner:
                if line.strip().endswith(banner_delimiter):
                    in_banner = False
                continue
            
            cleaned_lines.append(line)
        
        return "\n".join(cleaned_lines)
    
    def _clean_xml_output(self, raw_output: str) -> str:
        """XML 출력 정제"""
        lines = raw_output.splitlines()
        xml_lines = []
        in_xml = False
        in_banner_xml = False
        
        for line in lines:
            if "admin@ncs#" in line or "admin@ncs%" in line:
                continue
            if line.strip().startswith("show "):
                continue
            
            if line.strip().startswith("<") and not in_xml:
                in_xml = True
            
            if in_xml:
                if "<banner" in line:
                    in_banner_xml = True
                
                if in_banner_xml:
                    if "</banner>" in line:
                        in_banner_xml = False
                    continue
                
                xml_lines.append(line)
        
        return "\n".join(xml_lines)


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
