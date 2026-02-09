"""
PNETLab REST API Client
PNETLab/EVE-NG 실험실 환경과 통신하는 클라이언트

인증 방식:
- PNETLab은 외부 인증 서버(authen.pnetlab.com)를 사용
- JWT 토큰으로 로컬 VM API에 접근
- captcha가 있어서 완전 자동 로그인은 어려움
- 대안: 브라우저에서 로그인 후 JWT 토큰을 환경변수로 저장
"""

import requests
import logging
import os
import base64
import re
from typing import Dict, Any, List, Optional
from urllib.parse import unquote

logger = logging.getLogger(__name__)


class PnetlabClient:
    """
    PNETLab REST API 클라이언트
    
    인증 방식:
    1. JWT 토큰 방식 (권장): 브라우저에서 로그인 후 토큰을 환경변수로 저장
    2. 쿠키 직접 설정: 브라우저에서 복사한 쿠키 사용
    
    사용 예:
        # 방법 1: JWT 토큰 사용 (환경변수 PNETLAB_JWT_TOKEN 설정)
        client = PnetlabClient("http://100.66.240.82")
        client.set_jwt_token(os.getenv("PNETLAB_JWT_TOKEN"))
        topology = client.get_session_topology()
        
        # 방법 2: 쿠키 직접 설정
        client = PnetlabClient("http://100.66.240.82")
        client.set_session_from_browser(token="...", session="...", xsrf="...")
        topology = client.get_session_topology()
    """
    
    def __init__(self, base_url: str, username: str = "", password: str = "", timeout: int = 30):
        """
        Args:
            base_url: PNETLab 서버 URL (예: http://100.66.240.82)
            username: (선택) 로그인 사용자명
            password: (선택) 로그인 비밀번호
            timeout: 요청 타임아웃 (초)
        """
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self.timeout = timeout
        
        self.session = requests.Session()
        self.session.headers.update({
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) SANOA-Agent/1.0'
        })
        
        self._xsrf_token: Optional[str] = None
        self._jwt_token: Optional[str] = None
        self._is_authenticated = False
        
        # 환경변수에서 인증 정보 자동 로드
        # 방법 1: 전체 쿠키 문자열 (가장 편함!)
        cookies_str = os.getenv("PNETLAB_COOKIES")
        if cookies_str:
            self._load_cookies_from_string(cookies_str)
            logger.info("Auth cookies loaded from PNETLAB_COOKIES")
        else:
            # 방법 2: 개별 토큰 (하위 호환성)
            jwt_from_env = os.getenv("PNETLAB_JWT_TOKEN")
            session_from_env = os.getenv("PNETLAB_SESSION")
            xsrf_from_env = os.getenv("PNETLAB_XSRF_TOKEN")
            
            if jwt_from_env and session_from_env and xsrf_from_env:
                self.set_session_from_browser(
                    token=jwt_from_env,
                    session=session_from_env,
                    xsrf=xsrf_from_env
                )
                logger.info("Auth cookies loaded from environment")
            elif jwt_from_env:
                # 토큰만 있는 경우
                self.set_jwt_token(jwt_from_env)
                logger.warning("Only JWT token loaded - session and XSRF may be needed")

        # 방법 3: 계정 기반 자동 로그인 (선택)
        auto_login = os.getenv("PNETLAB_AUTO_LOGIN", "false").lower() == "true"
        if not self._is_authenticated and auto_login and self.username and self.password:
            login_res = self.login()
            if "error" in login_res:
                logger.warning(f"PNETLab auto-login failed: {login_res.get('error')}")
        
        logger.info(f"PnetlabClient initialized for {self.base_url}")
    
    def _load_cookies_from_string(self, cookies_str: str) -> None:
        """
        쿠키 문자열을 파싱하여 세션을 설정합니다.
        
        Args:
            cookies_str: 쿠키 문자열 (예: "token=abc; _session=def; XSRF-TOKEN=ghi")
        """
        cookies = {}
        for item in cookies_str.split(';'):
            item = item.strip()
            if '=' in item:
                key, value = item.split('=', 1)
                cookies[key.strip()] = value.strip()
        
        token = cookies.get('token', '')
        session = cookies.get('_session', '')
        xsrf = cookies.get('XSRF-TOKEN', '')
        
        if token and session and xsrf:
            self.set_session_from_browser(token=token, session=session, xsrf=xsrf)
            logger.info("Parsed 3 cookies from string")
        else:
            logger.warning(f"Incomplete cookies: token={bool(token)}, session={bool(session)}, xsrf={bool(xsrf)}")
    
    def set_jwt_token(self, jwt_token: str) -> None:
        """
        JWT 토큰을 설정합니다.
        
        브라우저에서 로그인 후, 쿠키의 'token' 값을 복사해서 사용하세요.
        브라우저 개발자도구 → Application → Cookies → token
        
        Args:
            jwt_token: JWT 토큰 문자열 (eyJ...로 시작)
        """
        self._jwt_token = jwt_token
        self.session.cookies.set('token', jwt_token, domain=self.base_url.split('//')[1].split(':')[0])
        self._is_authenticated = True
        logger.info("JWT token set")
    
    def set_session_from_browser(
        self, 
        token: str,
        session: str,
        xsrf: str
    ) -> None:
        """
        브라우저에서 복사한 쿠키 값들로 세션을 설정합니다.
        
        Args:
            token: JWT 토큰 (쿠키명: token) - URL 인코딩 여부 상관없음
            session: 세션 값 (쿠키명: _session)
            xsrf: XSRF 토큰 (쿠키명: XSRF-TOKEN) - URL 인코딩된 상태여야 함 (%3D 등 포함)
        """
        if '//' in self.base_url:
            domain = self.base_url.split('//')[1].split(':')[0]
        else:
            domain = self.base_url.split(':')[0]
        
        # 쿠키 설정 (도메인 지정)
        self.session.cookies.set('token', token, domain=domain)
        self.session.cookies.set('_session', session, domain=domain)
        self.session.cookies.set('XSRF-TOKEN', xsrf, domain=domain)
        self.session.cookies.set('privacy', 'true', domain=domain)
        
        # 헤더 설정
        # 1. XSRF-TOKEN 헤더는 URL 디코딩된 값을 원본값으로 사용
        from urllib.parse import unquote
        self._xsrf_token = unquote(xsrf)
        self.session.headers['X-XSRF-TOKEN'] = self._xsrf_token
        
        # 2. 브라우저 모방 헤더
        self.session.headers.update({
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "X-Requested-With": "XMLHttpRequest",
            "Referer": f"{self.base_url}/legacy/topology",
            "Origin": self.base_url
        })
        
        self._jwt_token = token
        self._is_authenticated = True
        
        logger.info("Session set from browser cookies with full headers")

    def login(self) -> Dict[str, Any]:
        """
        계정 기반 로그인 (EVE-NG/PNETLab API 호환).
        성공 시 세션 쿠키를 획득합니다.
        """
        url = f"{self.base_url}/api/auth/login"
        payload = {
            "username": self.username,
            "password": self.password
        }
        try:
            resp = self.session.post(url, json=payload, timeout=self.timeout)
            if resp.status_code != 200:
                return {"error": f"HTTP {resp.status_code}", "message": resp.text}

            # 쿠키는 requests.Session에 자동 저장됨
            xsrf = self.session.cookies.get("XSRF-TOKEN")
            if xsrf:
                self._xsrf_token = unquote(xsrf)
                self.session.headers["X-XSRF-TOKEN"] = self._xsrf_token

            self._is_authenticated = True
            return {"status": "success"}
        except Exception as e:
            return {"error": str(e)}

    def add_network(self, name: str, net_type: str = "pnet2", left: int = 100, top: int = 100) -> Dict[str, Any]:
        """
        새로운 네트워크를 추가합니다.
        
        Args:
            name: 네트워크 이름 (예: "Mgmt-Cloud")
            net_type: 네트워크 타입 (bridge, ovs, pnet0~9 등. pnet2=Cloud2)
            left: X 좌표
            top: Y 좌표
            
        Returns:
            API 응답
        """
        if not self._is_authenticated:
            return {"error": "Not authenticated"}
            
        url = f"{self.base_url}/api/labs/session/networks/add"
        payload = {
            "count": 1,
            "name": name,
            "type": net_type,
            "left": str(left),
            "top": str(top),
            "visibility": 1
        }
        
        try:
            resp = self.session.post(url, json=payload, timeout=self.timeout)
            logger.info(f"Add network response: {resp.status_code}")
            if resp.status_code in [200, 201]:
                return resp.json()
            return {"error": f"HTTP {resp.status_code}", "message": resp.text}
        except Exception as e:
            return {"error": str(e)}

    def get_node_interfaces(self, node_id: int) -> Dict[str, Any]:
        """노드의 인터페이스 목록 조회"""
        if not self._is_authenticated: return {"error": "Not authenticated"}
        url = f"{self.base_url}/api/labs/session/nodes/{node_id}/interfaces"
        try:
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code == 200: return resp.json()
            return {"error": f"HTTP {resp.status_code}"}
        except Exception as e: return {"error": str(e)}

    def get_node_details(self, node_id: int) -> Dict[str, Any]:
        """노드 상세 정보 조회"""
        if not self._is_authenticated:
            return {"error": "Not authenticated"}
        url = f"{self.base_url}/api/labs/session/nodes/{node_id}"
        try:
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                return resp.json()
            return {"error": f"HTTP {resp.status_code}", "message": resp.text}
        except Exception as e:
            return {"error": str(e)}

    def connect_node_interface(self, node_id: int, interface_id: int, network_id: int) -> bool:
        """
        노드 인터페이스를 네트워크에 연결합니다.
        
        Args:
            node_id: 노드 ID
            interface_id: 인터페이스 ID (0=Gi0/0, 1=Gi0/1...)
            network_id: 연결할 네트워크 ID (0 또는 "" = 연결 해제)
        
        Returns:
            성공 여부
        """
        if not self._is_authenticated: 
            logger.warning("Not authenticated")
            return False
        
        # PNETLab API: POST /api/labs/session/interfaces/edit
        # 정확한 페이로드 형식: {"node_id": "1", "data": {"0": "1"}}
        # - node_id: 문자열
        # - data: {인터페이스ID문자열: 네트워크ID문자열}
        # - 연결 해제: {"node_id": "1", "data": {"0": ""}}
        url = f"{self.base_url}/api/labs/session/interfaces/edit"
            
        # 네트워크 ID가 0이면 연결 해제 (빈 문자열)
        net_id_str = str(network_id) if network_id > 0 else ""
        
        payload = {
            "node_id": str(node_id),
            "data": {
                str(interface_id): net_id_str
            }
        }
        
        try:
            logger.info(f"Connecting Node {node_id} Iface {interface_id} to Net {network_id}...")
            logger.debug(f"Payload: {payload}")
            resp = self.session.post(url, json=payload, timeout=self.timeout)
            
            if resp.status_code == 200:
                # 응답에서 실제 network_id 확인
                try:
                    resp_json = resp.json()
                    update_node = resp_json.get("update", {}).get("nodes", {}).get(str(node_id), {})
                    actual_net_id = update_node.get("ethernets", {}).get(str(interface_id), {}).get("network_id", -1)
                    if actual_net_id == network_id:
                        logger.info(f"Connected successfully (verified: network_id={actual_net_id})")
                        return True
                    else:
                        logger.warning(f"API returned 200 but network_id mismatch: expected {network_id}, got {actual_net_id}")
                        return actual_net_id == network_id
                except:
                    logger.info(f"Connected successfully (status 200)")
                    return True
            else:
                logger.error(f"Failed to connect: {resp.status_code} {resp.text[:200]}")
                return False
        except Exception as e:
            logger.error(f"Connect interface error: {e}")
            return False
    
    def add_node(
        self,
        name: str,
        template: str = "vios",
        image: str = "vios-adventerprisek9-m.vmdk.SPA.157-3.M3",
        left: int = 400,
        top: int = 300,
        ethernet: int = 4,
        ram: int = 1024,
        cpu: int = 1
    ) -> Dict[str, Any]:
        """
        새로운 노드(장비)를 토폴로지에 추가합니다.
        
        Args:
            name: 노드 이름 (예: "vIOS11")
            template: 장비 템플릿 (vios, csr1000v 등)
            image: 디스크 이미지 파일명
            left: X 좌표
            top: Y 좌표
            ethernet: 이더넷 인터페이스 수
            ram: RAM (MB)
            cpu: CPU 코어 수
            
        Returns:
            API 응답 (성공 시 노드 정보 포함)
        """
        if not self._is_authenticated:
            return {"error": "Not authenticated"}
        
        url = f"{self.base_url}/api/labs/session/nodes/add"
        payload = {
            "template": template,
            "type": "qemu",
            "image": image,
            "name": name,
            "count": "1",
            "ethernet": ethernet,
            "ram": ram,
            "cpu": cpu,
            "cpulimit": 1,
            "left": left,
            "top": top,
            "icon": "Router.png",
            "console": "telnet",
            "console_2nd": "",
            "config": 0,
            "config_script": "config_vios.py",
            "script_timeout": 1200,
            "delay": 0,
            "description": f"Cisco {template} Router",
            "qemu_arch": "x86_64",
            "qemu_nic": "e1000",
            "qemu_options": "-machine type=pc,accel=kvm -serial mon:stdio -nographic -no-user-config -nodefaults -rtc base=utc -cpu host",
            "qemu_version": "2.12.0",
            "username": "",
            "password": "",
            "firstmac": "",
            "first_nic": "",
            "map_port": "",
            "map_port_2nd": "",
            "size": "",
            "uuid": "",
            "postfix": 0
        }
        
        try:
            logger.info(f"Adding node '{name}' (template: {template})...")
            resp = self.session.post(url, json=payload, timeout=self.timeout)
            
            if resp.status_code == 201:
                result = resp.json()
                logger.info(f"Node '{name}' created successfully")
                
                # Extract node ID from response: {"update": {"nodes": {"18": {...}}}}
                # Use max() to get the newly created node (highest ID)
                nodes = result.get("update", {}).get("nodes", {})
                if nodes:
                    node_id = max([int(k) for k in nodes.keys()])
                    return {"node_id": node_id, "full_response": result}
                else:
                    return result
            else:
                logger.error(f"Failed to add node: {resp.status_code} {resp.text[:200]}")
                return {"error": f"HTTP {resp.status_code}", "message": resp.text}
        except Exception as e:
            logger.error(f"Add node error: {e}")
            return {"error": str(e)}
    
    def delete_node(self, node_id: int) -> bool:
        """
        토폴로지에서 노드를 삭제합니다.
        
        Args:
            node_id: 삭제할 노드 ID
            
        Returns:
            성공 여부
        """
        if not self._is_authenticated:
            logger.warning("Not authenticated")
            return False
        
        url = f"{self.base_url}/api/labs/session/nodes/delete"
        payload = {"id": str(node_id)}
        
        try:
            logger.info(f"Deleting node {node_id}...")
            resp = self.session.post(url, json=payload, timeout=self.timeout)
            
            # PNETLab returns 201 for successful deletions
            if resp.status_code in [200, 201]:
                logger.info(f"Node {node_id} deleted successfully")
                return True
            else:
                logger.error(f"Failed to delete node: {resp.status_code} {resp.text[:200]}")
                return False
        except Exception as e:
            logger.error(f"Delete node error: {e}")
            return False
    
    def delete_network(self, network_id: int) -> bool:
        """
        토폴로지에서 네트워크(Cloud 등)를 삭제합니다.
        
        Args:
            network_id: 삭제할 네트워크 ID
            
        Returns:
            성공 여부
        """
        if not self._is_authenticated:
            logger.warning("Not authenticated")
            return False
        
        url = f"{self.base_url}/api/labs/session/networks/delete"
        payload = {"id": str(network_id)}
        
        try:
            logger.info(f"Deleting network {network_id}...")
            resp = self.session.post(url, json=payload, timeout=self.timeout)
            
            if resp.status_code == 200:
                logger.info(f"Network {network_id} deleted successfully")
                return True
            else:
                logger.error(f"Failed to delete network: {resp.status_code} {resp.text[:200]}")
                return False
        except Exception as e:
            logger.error(f"Delete network error: {e}")
            return False
    
    @property
    def is_authenticated(self) -> bool:
        """인증 상태 반환"""
        return self._is_authenticated

    # =========================================================================
    # Restored Methods
    # =========================================================================

    def get_session_topology(self) -> Dict[str, Any]:
        """
        현재 열려있는 Lab의 토폴로지 정보를 조회합니다.
        
        Returns:
            토폴로지 JSON (networks, nodes 등 포함)
        """
        if not self._is_authenticated:
            logger.warning("Not authenticated. Call login() first.")
            return {"error": "Not authenticated"}
        
        try:
            url = f"{self.base_url}/api/labs/session/topology"
            
            # 디버깅: 전송되는 쿠키와 헤더 확인
            logger.debug(f"Request URL: {url}")
            logger.debug(f"Cookies: {dict(self.session.cookies)}")
            logger.debug(f"Headers: {dict(self.session.headers)}")
            
            response = self.session.get(url, timeout=self.timeout)
            
            logger.debug(f"Response status: {response.status_code}")
            if response.status_code != 200:
                logger.error(f"Response body: {response.text[:500]}")
            
            if response.status_code == 200:
                data = response.json()
                logger.info("Topology retrieved successfully")
                return data
            else:
                logger.error(f"Failed to get topology: {response.status_code}")
                return {"error": f"HTTP {response.status_code}", "message": response.text}
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Topology request error: {e}")
            return {"error": str(e)}

    def get_nodes_from_topology(self, topology: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        토폴로지 JSON에서 노드(장비) 목록을 추출합니다.
        
        Args:
            topology: get_session_topology()의 결과
            
        Returns:
            노드 정보 리스트 (위치, 인터페이스 정보 포함)
        """
        nodes = []
        
        try:
            data = topology.get("data", {})
            nodes_data = data.get("nodes", {})
            
            if isinstance(nodes_data, dict):
                for node_id, node_info in nodes_data.items():
                    if isinstance(node_info, dict):
                        # 포트 추출: "port" 필드가 있으면 우선 사용, 없으면 URL에서 파싱
                        telnet_port = 0
                        port_val = node_info.get("port")
                        if port_val:
                            try:
                                telnet_port = int(port_val)
                            except (ValueError, TypeError):
                                pass
                        
                        url = node_info.get("url", "")
                        if telnet_port == 0 and url and ":" in url:
                            try:
                                # url 형식: "telnet://100.66.240.82:30037"
                                telnet_port = int(url.split(":")[-1])
                            except (ValueError, IndexError):
                                logger.debug(f"Failed to parse telnet port from URL: {url}")
                        
                        # 인터페이스 정보 추출
                        ethernets = node_info.get("ethernets", {})
                        
                        nodes.append({
                            "id": node_id,
                            "name": node_info.get("name", f"node_{node_id}"),
                            "type": node_info.get("type", "unknown"),
                            "template": node_info.get("template", ""),
                            "status": node_info.get("status", "unknown"),
                            "console": node_info.get("console", ""),
                            "url": url,
                            "telnet_port": telnet_port,
                            # 일부 환경에서 IP 정보가 포함될 수 있음
                            "ip": node_info.get("ip", ""),
                            "mgmt_ip": node_info.get("mgmt_ip", ""),
                            "address": node_info.get("address", ""),
                            # 위치 정보 추가
                            "left": node_info.get("left", 0),
                            "top": node_info.get("top", 0),
                            # 인터페이스 연결 정보 추가
                            "ethernets": ethernets
                        })
            
            logger.info(f"Extracted {len(nodes)} nodes from topology")
            
        except Exception as e:
            logger.error(f"Error extracting nodes: {e}")
        
        return nodes

    def get_node_ip_by_name(self, name: str) -> Optional[str]:
        """
        노드 이름으로 관리 IP를 추출합니다.
        (토폴로지/상태 응답에 포함된 IP 필드를 best-effort로 사용)
        """
        logger.info("Looking up node IP by name: %s", name)
        topology = self.get_session_topology()
        if "error" in topology:
            logger.warning("Topology lookup failed: %s", topology.get("error"))
            return None
        nodes = self.get_nodes_from_topology(topology)
        for node in nodes:
            if node.get("name", "").lower() == name.lower():
                for key in ("mgmt_ip", "ip", "address", "ipv4", "management_ip"):
                    val = node.get(key)
                    if val:
                        logger.info("IP found in topology: %s=%s", key, val)
                        return val

        status = self.get_nodes_status()
        nodes_status = status.get("data", {}).get("nodes", {}) if isinstance(status, dict) else {}
        for _, info in nodes_status.items():
            if str(info.get("name", "")).lower() == name.lower():
                for key in ("mgmt_ip", "ip", "address", "ipaddr", "ipv4", "management_ip"):
                    val = info.get(key)
                    if val:
                        logger.info("IP found in nodestatus: %s=%s", key, val)
                        return val

        # 노드 ID로 상세 조회 시도
        node_id = self.get_node_id_by_name(name)
        if node_id is not None:
            logger.info("Fetching node details for %s (id=%s)", name, node_id)
            details = self.get_node_details(node_id)
            data = details.get("data", details) if isinstance(details, dict) else {}
            for key in ("mgmt_ip", "ip", "address", "ipaddr", "ipv4", "management_ip"):
                val = data.get(key)
                if val:
                    logger.info("IP found in node details: %s=%s", key, val)
                    return val
        logger.warning("IP not found for node: %s", name)
        return None
    
    def get_layer1_topology(self, topology: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        PNETLab 토폴로지에서 Layer1 연결 정보를 Batfish 형식으로 추출합니다.
        
        Returns:
            {
                "nodes": [{"hostname": "...", "left": x, "top": y, ...}, ...],
                "edges": [{"node1": {...}, "node2": {...}}, ...]
            }
        """
        if topology is None:
            topology = self.get_session_topology()
            if "error" in topology:
                return {"error": topology.get("error"), "nodes": [], "edges": []}
        
        nodes = self.get_nodes_from_topology(topology)
        
        # network_id별로 연결된 인터페이스 수집
        # {network_id: [(node_name, iface_id, iface_name), ...]}
        network_connections: Dict[str, List[tuple]] = {}
        
        for node in nodes:
            node_name = node.get("name", "").lower()
            ethernets = node.get("ethernets", {})
            
            if isinstance(ethernets, dict):
                for iface_id, iface_info in ethernets.items():
                    if isinstance(iface_info, dict):
                        network_id = iface_info.get("network_id")
                        iface_name = iface_info.get("name", f"GigabitEthernet0/{iface_id}")
                        
                        # network_id가 있고 0이 아닌 경우 (연결됨)
                        if network_id and str(network_id) != "0":
                            net_key = str(network_id)
                            if net_key not in network_connections:
                                network_connections[net_key] = []
                            network_connections[net_key].append((node_name, iface_id, iface_name))
        
        # 같은 network_id 공유하는 인터페이스 쌍을 edge로 변환
        edges = []
        for net_id, connections in network_connections.items():
            # 2개 인터페이스가 같은 네트워크에 연결 = 직접 연결
            if len(connections) == 2:
                n1, iface1_id, iface1_name = connections[0]
                n2, iface2_id, iface2_name = connections[1]
                edges.append({
                    "node1": {
                        "hostname": n1,
                        "interfaceName": iface1_name
                    },
                    "node2": {
                        "hostname": n2,
                        "interfaceName": iface2_name
                    }
                })
            elif len(connections) > 2:
                # 3개 이상 = broadcast network (모든 쌍 연결)
                logger.debug(f"Broadcast network {net_id} with {len(connections)} connections")
        
        # 노드 정보 (위치 포함)
        node_list = [{
            "hostname": n.get("name", "").lower(),
            "left": n.get("left", 0),
            "top": n.get("top", 0),
            "type": n.get("type", "unknown"),
            "template": n.get("template", ""),
            "status": n.get("status", "unknown")
        } for n in nodes]
        
        logger.info(f"Extracted Layer1 topology: {len(node_list)} nodes, {len(edges)} edges")
        
        return {
            "nodes": node_list,
            "edges": edges
        }
    
    def export_layer1_topology_json(self, output_path: str = None) -> Dict[str, Any]:
        """
        Layer1 토폴로지를 Batfish 형식의 JSON 파일로 내보냅니다.
        
        Args:
            output_path: 저장할 파일 경로 (None이면 파일 저장 안 함)
            
        Returns:
            Batfish layer1_topology.json 형식
        """
        import json
        
        l1_topo = self.get_layer1_topology()
        
        # Batfish 형식으로 변환
        batfish_format = {
            "edges": l1_topo.get("edges", [])
        }
        
        if output_path:
            with open(output_path, 'w') as f:
                json.dump(batfish_format, f, indent=2)
            logger.info(f"Layer1 topology exported to {output_path}")
        
        return batfish_format


    def get_console_link(self, node_id: int, index: int = 1) -> Dict[str, Any]:
        """
        노드의 콘솔 링크 정보를 조회합니다. (Guacamole)
        여기서 telnet 포트 정보를 얻을 수 있습니다.
        
        Args:
            node_id: 노드 ID
            index: 콘솔 인덱스 (기본값: 1)
        
        Returns:
            dict: 콘솔 링크 정보 (telnet 포트 포함)
        """
        if not self._is_authenticated:
            logger.warning("Not authenticated")
            return {"error": "Not authenticated"}
        
        try:
            url = f"{self.base_url}/api/labs/session/console_guac_link"
            params = {"node_id": node_id, "index": index}
            response = self.session.get(url, params=params, timeout=self.timeout)
            
            logger.debug(f"Console link response for node {node_id}: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                logger.debug(f"Console link data: {data}")
                return data
            else:
                logger.error(f"Failed to get console link for node {node_id}: {response.status_code}")
                return {"error": f"HTTP {response.status_code}"}
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Console link request error: {e}")
            return {"error": str(e)}

    def extract_telnet_port_from_guacamole(self, guac_link: str) -> Optional[int]:
        """
        Guacamole 링크에서 telnet 포트를 추출합니다.
        
        Args:
            guac_link: Guacamole 링크 (예: "/html5/#/client/MzAwMjExAGMAbXlzcWw=?token=...")
        
        Returns:
            int: Telnet 포트 번호 또는 None
        """
        try:
            # Base64 부분 추출: /html5/#/client/{base64}?token=...
            match = re.search(r'/client/([^?]+)', guac_link)
            if not match:
                logger.debug(f"No base64 found in guacamole link: {guac_link}")
                return None
            
            base64_str = match.group(1)
            
            # Base64 디코딩
            decoded = base64.b64decode(base64_str).decode('utf-8', errors='ignore')
            logger.debug(f"Decoded guacamole link: {repr(decoded)}")
            
            # Guacamole connection ID 형식: <port><node_id>\x00c\x00mysql
            # 예: "300211\x00c\x00mysql" → 포트 30021 (5자리) + 노드 ID 1
            # 포트 번호 추출 (앞 5자리가 포트)
            port_match = re.match(r'^(\d{5})', decoded)
            if port_match:
                port = int(port_match.group(1))
                logger.debug(f"Extracted telnet port: {port}")
                return port
            
            # 다른 형식 시도: 숫자만 추출
            numbers = re.findall(r'\d+', decoded)
            if numbers:
                # 가장 긴 숫자 (포트일 가능성 높음)
                port = int(max(numbers, key=len))
                if 30000 <= port <= 40000:  # 일반적인 telnet 포트 범위
                    logger.debug(f"Extracted telnet port (alternative): {port}")
                    return port
            
            logger.warning(f"Could not extract port from decoded: {repr(decoded)}")
            return None
            
        except Exception as e:
            logger.error(f"Error extracting telnet port: {e}")
            return None

    def get_nodes_status(self) -> Dict[str, Any]:
        """
        현재 세션의 노드 상태를 조회합니다.
        (노드가 시작되었는지, telnet 포트가 할당되었는지 등)
        
        Returns:
            dict: 노드 상태 정보
        """
        if not self._is_authenticated:
            logger.warning("Not authenticated")
            return {"error": "Not authenticated"}
        
        try:
            url = f"{self.base_url}/api/labs/session/nodestatus"
            response = self.session.post(url, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                logger.info("Node status retrieved successfully")
                return data
            else:
                logger.error(f"Failed to get node status: {response.status_code}")
                return {"error": f"HTTP {response.status_code}"}
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Node status request error: {e}")
            return {"error": str(e)}

    def start_node(self, node_id: int) -> bool:
        """
        노드를 시작합니다.
        
        Args:
            node_id: 노드 ID
        
        Returns:
            bool: 성공 여부
        """
        if not self._is_authenticated:
            logger.warning("Not authenticated")
            return False
        
        try:
            url = f"{self.base_url}/api/labs/session/nodes/start"
            payload = {"id": str(node_id)}
            response = self.session.post(url, json=payload, timeout=self.timeout)
            
            if response.status_code == 200:
                logger.info(f"Node {node_id} started successfully")
                return True
            else:
                logger.error(f"Failed to start node {node_id}: {response.status_code}")
                return False
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Start node error: {e}")
            return False

    def stop_node(self, node_id: int) -> bool:
        """
        노드를 정지합니다.
        
        Args:
            node_id: 노드 ID
        
        Returns:
            bool: 성공 여부
        """
        if not self._is_authenticated:
            logger.warning("Not authenticated")
            return False
        
        try:
            url = f"{self.base_url}/api/labs/session/nodes/stop"
            payload = {"id": str(node_id)}
            response = self.session.post(url, json=payload, timeout=self.timeout)
            
            if response.status_code == 200:
                logger.info(f"Node {node_id} stopped successfully")
                return True
            else:
                logger.error(f"Failed to stop node {node_id}: {response.status_code}")
                return False
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Stop node error: {e}")
            return False
            
    # =========================================================================
    # High-level Methods (SDK)
    # =========================================================================

    def get_node_id_by_name(self, name: str) -> Optional[int]:
        """장비명으로 Node ID 검색"""
        # 캐싱된 토폴로지가 없으면 조회
        topology = self.get_session_topology()
        if "error" in topology:
            return None
            
        nodes = self.get_nodes_from_topology(topology)
        for node in nodes:
            if node["name"].lower() == name.lower():
                return int(node["id"])
        return None

    def get_inventory(self) -> Dict[str, Any]:
        """전체 장비 목록 및 상세 정보 (High-level)"""
        if not self.is_authenticated:
            if not self.login():
                return {"error": "Authentication failed"}
            
        topology = self.get_session_topology()
        if "error" in topology:
            return topology
            
        nodes = self.get_nodes_from_topology(topology)
        
        return {
            "status": "success",
            "lab_name": topology.get("name", "Unknown"),
            "lab_path": topology.get("path", "Unknown"),
            "total_nodes": len(nodes),
            "nodes": nodes
        }

    def get_console_url_by_name(self, device_name: str) -> Dict[str, Any]:
        """
        장비명으로 콘솔 접속 URL 반환 (Server Logic)
        """
        inventory = self.get_inventory()
        if "error" in inventory:
            return inventory
            
        for node in inventory.get("nodes", []):
            if node["name"].lower() == device_name.lower():
                console = node.get("console")
                if console:
                    return {
                        "status": "success",
                        "device": device_name,
                        "console_link": f"{self.base_url}/console/{console}",
                        "console_port": console,
                        "node_id": node.get("id")
                    }
                else:
                    return {"error": f"No console available for {device_name}"}
        
        return {"error": f"Device not found: {device_name}"}


# --- 테스트 코드 ---
if __name__ == "__main__":
    import sys
    # sys.path.insert(0, str(__file__).rsplit('/', 2)[0])
    
    # from config.settings import settings (Removed: LabMate doesn't have this)
    
    logging.basicConfig(level=logging.INFO)
    
    print("=== PNETLab Client Test ===")
    
    # Use environment variables or defaults for testing
    import os
    base_url = os.getenv("PNETLAB_URL", "http://localhost")
    username = os.getenv("PNETLAB_USERNAME", "admin")
    password = os.getenv("PNETLAB_PASSWORD", "pnetlab")

    client = PnetlabClient(
        base_url=base_url,
        username=username,
        password=password
    )
    
    # 로그인 테스트 (if needed)
    # Note: PnetlabClient in LabMate uses cookie/token auth primarily
    # which might not be fully automated here without browser tokens.
    print(f"Client initialized for {base_url}")
    
    # login() verify logic removed as it's not implemented in the ported version in the same way
    # or relies on valid cookies being present.
    # login() verify logic removed as it's not implemented in the ported version in the same way
    # or relies on valid cookies being present.
    # if "error" not in topology:
    #     print("✅ Topology retrieved")
    #     
    #     nodes = client.get_nodes_from_topology(topology)
    #     print(f"   Found {len(nodes)} nodes:")
    #     for node in nodes:
    #         print(f"   - {node['name']} ({node['type']})")
    # else:
    #     print(f"❌ Topology error: {topology}")
    # else:
    #     print("❌ Login failed")
