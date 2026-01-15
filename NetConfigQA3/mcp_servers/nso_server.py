"""
NSO MCP Server

NSO RESTCONF API 및 Docker CLI를 통한 네트워크 설정 관리
cfg 추출 기능 포함 (Batfish 입력용)

도구:
- nso.get_devices: 장비 목록 조회
- nso.get_config: 설정 조회
- nso.export_batfish_configs: Batfish용 cfg/xml 추출
- nso.run_command: CLI 명령 실행
"""

import os
import sys
import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional

# MCP SDK import
try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import Tool, TextContent
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False

# 프로젝트 경로 설정
sys.path.insert(0, str(Path(__file__).parent.parent))

from clients.nso import NSOClient
from config.settings import settings

logger = logging.getLogger(__name__)


class NSOServer:
    """
    NSO MCP 서버
    
    RESTCONF API와 Docker CLI를 통해 NSO와 상호작용
    """
    
    def __init__(
        self,
        base_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        docker_container: str = "cisco-nso-dev",
        timeout: int = 60
    ):
        """
        Args:
            base_url: NSO RESTCONF URL
            username: NSO 사용자명
            password: NSO 비밀번호
            docker_container: NSO Docker 컨테이너 이름
            timeout: 요청 타임아웃
        """
        self.base_url = base_url or settings.nso.base_url
        self.username = username or settings.nso.username
        self.password = password or settings.nso.password
        self.docker_container = docker_container
        self.timeout = timeout
        
        # NSOClient 초기화
        self._client: Optional[NSOClient] = None
        
        # MCP 서버 초기화
        if MCP_AVAILABLE:
            self._server = Server("nso-server")
            self._register_tools()
        else:
            self._server = None
            logger.warning("MCP SDK not available. Server functionality disabled.")
    
    @property
    def client(self) -> NSOClient:
        """NSOClient 싱글톤"""
        if self._client is None:
            self._client = NSOClient(
                base_url=self.base_url,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
                docker_container=self.docker_container
            )
        return self._client
    
    def _register_tools(self):
        """MCP 도구 등록"""
        if not self._server:
            return
        
        @self._server.list_tools()
        async def list_tools() -> List[Tool]:
            return [
                # --- 기존 도구 ---
                Tool(
                    name="nso.get_devices",
                    description="NSO에 등록된 모든 장비 목록을 조회합니다",
                    inputSchema={
                        "type": "object",
                        "properties": {},
                        "required": []
                    }
                ),
                Tool(
                    name="nso.get_config",
                    description="장비의 설정을 조회합니다",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "device": {"type": "string", "description": "장비명"},
                            "config_path": {"type": "string", "description": "설정 경로 (예: router/bgp)"}
                        },
                        "required": ["device"]
                    }
                ),
                Tool(
                    name="nso.export_batfish_configs",
                    description="Batfish 분석용 cfg 파일 + YANG JSON을 추출합니다 (하이브리드 전략)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "devices": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "추출할 장비 목록 (비어있으면 전체)"
                            },
                            "output_dir": {"type": "string", "description": "출력 디렉토리"},
                            "export_xml": {"type": "boolean", "description": "XML도 추출할지 여부", "default": True},
                            "export_yang_json": {"type": "boolean", "description": "YANG JSON도 추출할지 여부 (향후 확장성)", "default": True}
                        },
                        "required": ["output_dir"]
                    }
                ),
                Tool(
                    name="nso.run_command",
                    description="장비에서 CLI 명령을 실행합니다",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "device": {"type": "string", "description": "장비명"},
                            "command": {"type": "string", "description": "실행할 명령어"}
                        },
                        "required": ["device", "command"]
                    }
                ),
                
                # --- 신규 추가 도구 (Lifecycle) ---
                Tool(
                    name="nso.register_device",
                    description="새 장비를 NSO에 등록합니다",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "name": {"type": "string", "description": "장비 호스트명"},
                            "oob_ip": {"type": "string", "description": "관리 IP 주소"},
                            "port": {"type": "integer", "description": "SSH 포트 (기본 22)", "default": 22},
                            "authgroup": {"type": "string", "description": "인증 그룹명 (기본 'default')", "default": "default"},
                            "ned_id": {"type": "string", "description": "NED ID (기본 'cisco-ios-cli-6.110')", "default": "cisco-ios-cli-6.110"},
                            "protocol": {"type": "string", "description": "통신 프로토콜 (ssh/telnet)", "default": "ssh"}
                        },
                        "required": ["name", "oob_ip"]
                    }
                ),
                Tool(
                    name="nso.delete_device",
                    description="NSO에서 장비를 삭제합니다",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "device_name": {"type": "string", "description": "삭제할 장비명"}
                        },
                        "required": ["device_name"]
                    }
                ),
                Tool(
                    name="nso.create_authgroup",
                    description="인증 그룹(Authgroup)을 생성합니다",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "group": {"type": "string", "description": "그룹명"},
                            "username": {"type": "string", "description": "장비 접속 ID"},
                            "password": {"type": "string", "description": "장비 접속 PW"}
                        },
                        "required": ["group", "username", "password"]
                    }
                ),
                
                # --- 신규 추가 도구 (Sync & Keys) ---
                Tool(
                    name="nso.sync_from",
                    description="장비 설정을 NSO로 동기화(sync-from)합니다",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "device_name": {"type": "string", "description": "장비명"}
                        },
                        "required": ["device_name"]
                    }
                ),
                Tool(
                    name="nso.check_sync",
                    description="장비가 NSO와 동기화 상태인지(in-sync) 확인합니다",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "device_name": {"type": "string", "description": "장비명"}
                        },
                        "required": ["device_name"]
                    }
                ),
                Tool(
                    name="nso.fetch_host_keys",
                    description="SSH 호스트 키를 가져옵니다 (SSH 장비만 해당)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "device_name": {"type": "string", "description": "장비명"}
                        },
                        "required": ["device_name"]
                    }
                ),
                
                # --- 신규 추가 도구 (High-level Workflow) ---
                Tool(
                    name="nso.onboard_devices",
                    description="여러 장비를 일괄 등록하고 초기화(Key Fetch, Sync)합니다",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "devices": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "name": {"type": "string"},
                                        "oob_ip": {"type": "string"},
                                        "port": {"type": "integer"},
                                        "authgroup": {"type": "string"},
                                        "ned_id": {"type": "string"},
                                        "protocol": {"type": "string"}
                                    },
                                    "required": ["name", "oob_ip"]
                                },
                                "description": "등록할 장비 정보 리스트"
                            }
                        },
                        "required": ["devices"]
                    }
                ),
                
                # --- 신규 추가 도구 (Network Tools) ---
                Tool(
                    name="nso.ping",
                    description="장비에서 특정 대상으로 Ping을 수행합니다",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "device": {"type": "string", "description": "소스 장비명"},
                            "target": {"type": "string", "description": "목적지 IP 또는 호스트"},
                            "count": {"type": "integer", "description": "핑 횟수", "default": 5}
                        },
                        "required": ["device", "target"]
                    }
                ),
                Tool(
                    name="nso.traceroute",
                    description="장비에서 특정 대상으로 Traceroute를 수행합니다",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "device": {"type": "string", "description": "소스 장비명"},
                            "target": {"type": "string", "description": "목적지 IP 또는 호스트"}
                        },
                        "required": ["device", "target"]
                    }
                ),
                Tool(
                    name="nso.check_ip_conflicts",
                    description="전체 네트워크에서 IP 중복/충돌을 검사합니다",
                    inputSchema={
                        "type": "object",
                        "properties": {},
                        "required": []
                    }
                ),
                Tool(
                    name="nso.get_interfaces",
                    description="장비의 인터페이스 목록과 상세 정보를 조회합니다",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "device": {"type": "string", "description": "장비명"}
                        },
                        "required": ["device"]
                    }
                ),
            ]
        
        @self._server.call_tool()
        async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
            result = await self._handle_tool_call(name, arguments)
            return [TextContent(type="text", text=json.dumps(result, ensure_ascii=False, indent=2))]
    
    async def _handle_tool_call(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """도구 호출 처리"""
        try:
            # --- 조회 / 설정 ---
            if name == "nso.get_devices":
                return {"devices": self.get_devices()}
            
            elif name == "nso.get_config":
                device = arguments.get("device")
                config_path = arguments.get("config_path", "")
                return self.get_config(device, config_path)
            
            elif name == "nso.export_batfish_configs":
                devices = arguments.get("devices", [])
                output_dir = arguments.get("output_dir")
                export_xml = arguments.get("export_xml", True)
                export_yang_json = arguments.get("export_yang_json", True)
                return self.export_batfish_configs(devices, output_dir, export_xml, export_yang_json)
            
            elif name == "nso.run_command":
                device = arguments.get("device")
                command = arguments.get("command")
                return {"output": self.run_command(device, command)}
            
            # --- Lifecycle ---
            elif name == "nso.register_device":
                # 인자 매핑 (NSOClient.register_device는 dict를 받음)
                return {"success": self.client.register_device(arguments)}
                
            elif name == "nso.delete_device":
                device_name = arguments.get("device_name")
                return {"success": self.client.delete_device(device_name)}
                
            elif name == "nso.create_authgroup":
                group = arguments.get("group")
                username = arguments.get("username")
                password = arguments.get("password")
                return {"success": self.client.create_authgroup(group, username, password)}
            
            # --- Sync & Keys ---
            elif name == "nso.sync_from":
                device_name = arguments.get("device_name")
                return {"success": self.client.sync_from(device_name)}
                
            elif name == "nso.check_sync":
                device_name = arguments.get("device_name")
                return {"in_sync": self.client.check_sync(device_name)}
                
            elif name == "nso.fetch_host_keys":
                device_name = arguments.get("device_name")
                return {"success": self.client.fetch_host_keys(device_name)}
                
            # --- Workflows ---
            elif name == "nso.onboard_devices":
                devices = arguments.get("devices", [])
                return self.client.onboard_devices(devices)
            
            # --- Network Tools ---
            elif name == "nso.ping":
                device = arguments.get("device")
                target = arguments.get("target")
                count = arguments.get("count", 5)
                return self.client.ping(device, target, count)
                
            elif name == "nso.traceroute":
                device = arguments.get("device")
                target = arguments.get("target")
                return self.client.traceroute(device, target)
                
            elif name == "nso.check_ip_conflicts":
                return {"conflicts": self.client.check_ip_conflicts()}
                
            elif name == "nso.get_interfaces":
                device = arguments.get("device")
                return {"interfaces": self.client.get_interfaces(device)}
            
            else:
                return {"error": f"Unknown tool: {name}"}
                
        except Exception as e:
            logger.error(f"Tool call error: {e}")
            return {"error": str(e)}
    
    # =========================================================================
    # Public API Methods
    # =========================================================================
    
    def get_devices(self) -> List[str]:
        """NSO에 등록된 장비 목록 반환"""
        return self.client.get_devices()
    
    def get_config(self, device: str, config_path: str = "") -> Dict[str, Any]:
        """장비 설정 조회"""
        return self.client._fetch_config(device, config_path)
    
    def run_command(self, device: str, command: str) -> str:
        """장비에서 CLI 명령 실행"""
        return self.client._run_command(device, command)
    
    def get_device_info(self, device: str) -> Dict[str, Any]:
        """장비 상세 정보 조회"""
        return self.client.get_device_info(device)
    
    def get_interfaces(self, device: str) -> List[Dict[str, Any]]:
        """장비 인터페이스 목록"""
        return self.client.get_interfaces(device)
    
    # =========================================================================
    # Batfish Config Export (3-Config_Export_Batfish.py 통합)
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
        return self.client.export_batfish_configs(
            devices=devices,
            output_dir=output_dir,
            export_xml=export_xml,
            export_yang_json=export_yang_json
        )
    
    # =========================================================================
    # MCP Server Lifecycle
    # =========================================================================
    
    async def run(self):
        """MCP 서버 실행"""
        if not MCP_AVAILABLE:
            raise RuntimeError("MCP SDK not available")
        
        async with stdio_server() as (read_stream, write_stream):
            await self._server.run(read_stream, write_stream)


# CLI Entry Point
if __name__ == "__main__":
    import asyncio
    
    logging.basicConfig(level=logging.INFO)
    server = NSOServer()
    asyncio.run(server.run())
