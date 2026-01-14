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
        
        브라우저 개발자도구 → Network → 아무 요청 클릭 → Headers → Cookie에서 복사
        
        Args:
            token: JWT 토큰 (쿠키명: token)
            session: 세션 값 (쿠키명: _session)
            xsrf: XSRF 토큰 (쿠키명: XSRF-TOKEN)
        """
        domain = self.base_url.split('//')[1].split(':')[0]
        
        self.session.cookies.set('token', token, domain=domain)
        self.session.cookies.set('_session', session, domain=domain)
        self.session.cookies.set('XSRF-TOKEN', xsrf, domain=domain)
        self.session.cookies.set('privacy', 'true', domain=domain)
        
        # XSRF 토큰은 URL 디코딩 필요할 수 있음
        self._xsrf_token = unquote(xsrf)
        self.session.headers['X-XSRF-TOKEN'] = self._xsrf_token
        
        self._jwt_token = token
        self._is_authenticated = True
        
        logger.info("Session set from browser cookies")
    
    def login(self) -> bool:
        """
        PNETLab에 로그인을 시도합니다.
        
        ⚠️ 주의: PNETLab은 외부 인증 서버(authen.pnetlab.com)를 사용하고
        captcha가 있어서 완전 자동 로그인이 어렵습니다.
        
        대안:
        1. 브라우저에서 로그인 후 JWT 토큰을 환경변수로 저장
        2. set_jwt_token() 또는 set_session_from_browser() 사용
        
        Returns:
            bool: 인증 상태 (이미 토큰이 설정되어 있으면 True)
        """
        # 이미 JWT 토큰이 있으면 성공으로 간주
        if self._jwt_token:
            logger.info("Already authenticated with JWT token")
            return True
        
        # 환경변수에서 토큰 확인
        jwt_from_env = os.getenv("PNETLAB_JWT_TOKEN")
        if jwt_from_env:
            self.set_jwt_token(jwt_from_env)
            return True
        
        logger.warning(
            "PNETLab 자동 로그인은 지원되지 않습니다. "
            "브라우저에서 로그인 후 PNETLAB_JWT_TOKEN 환경변수를 설정하세요."
        )
        return False
    
    def set_session_from_cookies(self, cookies: Dict[str, str], xsrf_token: str) -> None:
        """
        (하위 호환성) 수동으로 세션 쿠키와 XSRF 토큰을 설정합니다.
        
        Args:
            cookies: 쿠키 딕셔너리
            xsrf_token: XSRF 토큰 값
        """
        for name, value in cookies.items():
            self.session.cookies.set(name, value)
        
        self._xsrf_token = xsrf_token
        self.session.headers['X-XSRF-TOKEN'] = xsrf_token
        self._is_authenticated = True
        
        if 'token' in cookies:
            self._jwt_token = cookies['token']
        
        logger.info("PNETLab session set from cookies")
    
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
            노드 정보 리스트
        """
        nodes = []
        
        try:
            data = topology.get("data", {})
            nodes_data = data.get("nodes", {})
            
            if isinstance(nodes_data, dict):
                for node_id, node_info in nodes_data.items():
                    if isinstance(node_info, dict):
                        # URL에서 telnet 포트 추출
                        url = node_info.get("url", "")
                        telnet_port = 0
                        if url and ':' in url:
                            try:
                                # url 형식: "telnet://100.66.240.82:30037"
                                telnet_port = int(url.split(':')[-1])
                            except (ValueError, IndexError):
                                logger.debug(f"Failed to parse telnet port from URL: {url}")
                        
                        nodes.append({
                            "id": node_id,
                            "name": node_info.get("name", f"node_{node_id}"),
                            "type": node_info.get("type", "unknown"),
                            "template": node_info.get("template", ""),
                            "status": node_info.get("status", "unknown"),
                            "console": node_info.get("console", ""),
                            "url": url,
                            "telnet_port": telnet_port
                        })
            
            logger.info(f"Extracted {len(nodes)} nodes from topology")
            
        except Exception as e:
            logger.error(f"Error extracting nodes: {e}")
        
        return nodes
    
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
    
    @property
    def is_authenticated(self) -> bool:
        """인증 상태 반환"""
        return self._is_authenticated


# --- 테스트 코드 ---
if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(__file__).rsplit('/', 2)[0])
    
    from config.settings import settings
    
    logging.basicConfig(level=logging.INFO)
    
    print("=== PNETLab Client Test ===")
    
    client = PnetlabClient(
        base_url=settings.pnetlab.base_url,
        username=settings.pnetlab.username,
        password=settings.pnetlab.password
    )
    
    # 로그인 테스트
    if client.login():
        print("✅ Login successful")
        
        # 토폴로지 조회
        topology = client.get_session_topology()
        if "error" not in topology:
            print("✅ Topology retrieved")
            
            nodes = client.get_nodes_from_topology(topology)
            print(f"   Found {len(nodes)} nodes:")
            for node in nodes:
                print(f"   - {node['name']} ({node['type']})")
        else:
            print(f"❌ Topology error: {topology}")
    else:
        print("❌ Login failed")

