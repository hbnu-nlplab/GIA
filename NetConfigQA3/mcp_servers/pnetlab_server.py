"""
PNETLab MCP Server

PNETLab 실험실 관리

도구:
- pnetlab.show_inventory: 현재 Lab 장비 목록
- pnetlab.get_status: 장비 상태 조회
- pnetlab.get_console_link: 콘솔 접속 링크
- pnetlab.sync_to_nso: Lab → NSO 동기화
"""

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

from clients.pnetlab import PnetlabClient
from config.settings import settings

logger = logging.getLogger(__name__)


class PnetlabServer:
    """
    PNETLab MCP 서버
    
    PNETLab API를 통한 실험실 관리
    """
    
    def __init__(
        self,
        base_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        jwt_token: Optional[str] = None
    ):
        """
        Args:
            base_url: PNETLab URL
            username: 사용자명
            password: 비밀번호
            jwt_token: JWT 토큰
        """
        self.base_url = base_url or settings.pnetlab.base_url
        self.username = username or settings.pnetlab.username
        self.password = password or settings.pnetlab.password
        self.jwt_token = jwt_token or settings.pnetlab.jwt_token
        
        self._client: Optional[PnetlabClient] = None
        
        # MCP 서버 초기화
        if MCP_AVAILABLE:
            self._server = Server("pnetlab-server")
            self._register_tools()
        else:
            self._server = None
            logger.warning("MCP SDK not available. Server functionality disabled.")
    
    @property
    def client(self) -> PnetlabClient:
        """PnetlabClient 싱글톤"""
        if self._client is None:
            self._client = PnetlabClient(self.base_url)
        return self._client
    
    def _register_tools(self):
        """MCP 도구 등록"""
        if not self._server:
            return
        
        @self._server.list_tools()
        async def list_tools() -> List[Tool]:
            return [
                # ===== 조회 도구 =====
                Tool(
                    name="pnetlab.show_inventory",
                    description="현재 Lab의 장비 목록을 조회합니다",
                    inputSchema={
                        "type": "object",
                        "properties": {},
                        "required": []
                    }
                ),
                Tool(
                    name="pnetlab.get_status",
                    description="Lab 장비의 상태를 조회합니다",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "device": {"type": "string", "description": "장비명 (비어있으면 전체)"}
                        },
                        "required": []
                    }
                ),
                Tool(
                    name="pnetlab.get_console_link",
                    description="장비의 콘솔 접속 링크를 반환합니다",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "device": {"type": "string", "description": "장비명"}
                        },
                        "required": ["device"]
                    }
                ),
                # ===== 토폴로지 관리 도구 =====
                Tool(
                    name="pnetlab.add_node",
                    description="토폴로지에 새로운 장비(노드)를 추가합니다. 예: vIOS 라우터",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "name": {"type": "string", "description": "장비 이름 (예: vIOS1)"},
                            "template": {"type": "string", "description": "템플릿 (기본값: vios)", "default": "vios"},
                            "left": {"type": "integer", "description": "X 좌표 (기본값: 400)", "default": 400},
                            "top": {"type": "integer", "description": "Y 좌표 (기본값: 300)", "default": 300}
                        },
                        "required": ["name"]
                    }
                ),
                Tool(
                    name="pnetlab.delete_node",
                    description="토폴로지에서 장비를 삭제합니다. 장비 이름으로 찾아서 삭제합니다.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "name": {"type": "string", "description": "삭제할 장비 이름"}
                        },
                        "required": ["name"]
                    }
                ),
                Tool(
                    name="pnetlab.add_network",
                    description="토폴로지에 네트워크(Cloud등)를 추가합니다",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "name": {"type": "string", "description": "네트워크 이름 (예: Mgmt-Cloud)"},
                            "net_type": {"type": "string", "description": "유형 (pnet0~pnet9, bridge)", "default": "pnet2"},
                            "left": {"type": "integer", "description": "X 좌표", "default": 300},
                            "top": {"type": "integer", "description": "Y 좌표", "default": 150}
                        },
                        "required": ["name"]
                    }
                ),
                Tool(
                    name="pnetlab.delete_network",
                    description="토폴로지에서 네트워크를 삭제합니다",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "name": {"type": "string", "description": "삭제할 네트워크 이름"}
                        },
                        "required": ["name"]
                    }
                ),
                Tool(
                    name="pnetlab.connect_interface",
                    description="장비의 인터페이스를 네트워크에 연결합니다",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "device_name": {"type": "string", "description": "장비 이름"},
                            "interface_id": {"type": "integer", "description": "인터페이스 ID (0=Gi0/0, 1=Gi0/1)", "default": 0},
                            "network_name": {"type": "string", "description": "연결할 네트워크 이름"}
                        },
                        "required": ["device_name", "network_name"]
                    }
                ),
                Tool(
                    name="pnetlab.disconnect_interface",
                    description="장비의 인터페이스 연결을 해제합니다",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "device_name": {"type": "string", "description": "장비 이름"},
                            "interface_id": {"type": "integer", "description": "인터페이스 ID (0=Gi0/0, 1=Gi0/1)", "default": 0}
                        },
                        "required": ["device_name"]
                    }
                ),
                # ===== 장비 제어 도구 =====
                Tool(
                    name="pnetlab.start_node",
                    description="장비를 시작(실행)합니다",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "name": {"type": "string", "description": "시작할 장비 이름"}
                        },
                        "required": ["name"]
                    }
                ),
                Tool(
                    name="pnetlab.stop_node",
                    description="장비를 중지합니다",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "name": {"type": "string", "description": "중지할 장비 이름"}
                        },
                        "required": ["name"]
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
            # 조회 도구
            if name == "pnetlab.show_inventory":
                return self.show_inventory()
            elif name == "pnetlab.get_status":
                return self.get_status(arguments.get("device"))
            elif name == "pnetlab.get_console_link":
                return self.get_console_link(arguments.get("device"))
            
            # 토폴로지 관리 도구
            elif name == "pnetlab.add_node":
                return self.add_node(
                    name=arguments["name"],
                    template=arguments.get("template", "vios"),
                    left=arguments.get("left", 400),
                    top=arguments.get("top", 300)
                )
            elif name == "pnetlab.delete_node":
                return self.delete_node(arguments["name"])
            elif name == "pnetlab.add_network":
                return self.add_network(
                    name=arguments["name"],
                    net_type=arguments.get("net_type", "pnet2"),
                    left=arguments.get("left", 300),
                    top=arguments.get("top", 150)
                )
            elif name == "pnetlab.delete_network":
                return self.delete_network(arguments["name"])
            elif name == "pnetlab.connect_interface":
                return self.connect_interface(
                    device_name=arguments["device_name"],
                    interface_id=arguments.get("interface_id", 0),
                    network_name=arguments["network_name"]
                )
            elif name == "pnetlab.disconnect_interface":
                return self.disconnect_interface(
                    device_name=arguments["device_name"],
                    interface_id=arguments.get("interface_id", 0)
                )
            elif name == "pnetlab.start_node":
                return self.start_node(arguments["name"])
            elif name == "pnetlab.stop_node":
                return self.stop_node(arguments["name"])
            else:
                return {"error": f"Unknown tool: {name}"}
                
        except Exception as e:
            logger.error(f"Tool call error: {e}")
            return {"error": str(e)}
    
    # =========================================================================
    # Public API Methods
    # =========================================================================
    
    def show_inventory(self) -> Dict[str, Any]:
        """
        현재 Lab의 장비 목록 조회
        
        Returns:
            장비 목록 및 요약 정보
        """
        try:
            return self.client.get_inventory()
            
        except Exception as e:
            logger.error(f"Show inventory error: {e}")
            return {"error": str(e)}
    
    def get_status(self, device: Optional[str] = None) -> Dict[str, Any]:
        """
        장비 상태 조회
        
        Args:
            device: 장비명 (None이면 전체)
            
        Returns:
            상태 정보
        """
        try:
            inventory = self.show_inventory()
            if "error" in inventory:
                return inventory
            
            nodes = inventory.get("nodes", [])
            
            if device:
                nodes = [n for n in nodes if n["name"].lower() == device.lower()]
            
            return {
                "status": "success",
                "device_filter": device,
                "nodes": nodes,
                "count": len(nodes)
            }
            
        except Exception as e:
            logger.error(f"Get status error: {e}")
            return {"error": str(e)}
    
    def get_console_link(self, device: str) -> Dict[str, Any]:
        """
        장비의 콘솔 접속 링크 반환
        
        Args:
            device: 장비명
            
        Returns:
            콘솔 링크 정보
        """
        try:
            return self.client.get_console_url_by_name(device)
            
        except Exception as e:
            logger.error(f"Get console link error: {e}")
            return {"error": str(e)}
    
    # =========================================================================
    # Topology Management Methods
    # =========================================================================
    
    def _get_node_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """이름으로 노드 찾기"""
        topology = self.client.get_session_topology()
        nodes = self.client.get_nodes_from_topology(topology)
        for n in nodes:
            if n.get("name") == name:
                return n
        return None
    
    def _get_network_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """이름으로 네트워크 찾기"""
        topology = self.client.get_session_topology()
        networks = topology.get("data", {}).get("networks", {})
        for net_id, net_info in networks.items():
            if net_info.get("name") == name:
                return {"id": int(net_id), **net_info}
        return None
    
    def add_node(self, name: str, template: str = "vios", left: int = 400, top: int = 300) -> Dict[str, Any]:
        """
        토폴로지에 장비 추가
        """
        try:
            result = self.client.add_node(name=name, template=template, left=left, top=top)
            if "error" not in result:
                return {
                    "status": "success",
                    "message": f"장비 '{name}' 생성됨",
                    "node_id": result.get("node_id")
                }
            return result
        except Exception as e:
            logger.error(f"Add node error: {e}")
            return {"error": str(e)}
    
    def delete_node(self, name: str) -> Dict[str, Any]:
        """
        토폴로지에서 장비 삭제 (이름으로 검색)
        """
        try:
            node = self._get_node_by_name(name)
            if not node:
                return {"error": f"장비 '{name}'를 찾을 수 없습니다"}
            
            node_id = int(node["id"])
            if self.client.delete_node(node_id):
                return {"status": "success", "message": f"장비 '{name}' (ID: {node_id}) 삭제됨"}
            return {"error": f"장비 '{name}' 삭제 실패"}
        except Exception as e:
            logger.error(f"Delete node error: {e}")
            return {"error": str(e)}
    
    def add_network(self, name: str, net_type: str = "pnet2", left: int = 300, top: int = 150) -> Dict[str, Any]:
        """
        토폴로지에 네트워크 추가
        """
        try:
            result = self.client.add_network(name=name, net_type=net_type, left=left, top=top)
            if "error" not in result:
                return {
                    "status": "success",
                    "message": f"네트워크 '{name}' 생성됨"
                }
            return result
        except Exception as e:
            logger.error(f"Add network error: {e}")
            return {"error": str(e)}
    
    def delete_network(self, name: str) -> Dict[str, Any]:
        """
        토폴로지에서 네트워크 삭제 (이름으로 검색)
        """
        try:
            network = self._get_network_by_name(name)
            if not network:
                return {"error": f"네트워크 '{name}'를 찾을 수 없습니다"}
            
            net_id = network["id"]
            if self.client.delete_network(net_id):
                return {"status": "success", "message": f"네트워크 '{name}' (ID: {net_id}) 삭제됨"}
            return {"error": f"네트워크 '{name}' 삭제 실패"}
        except Exception as e:
            logger.error(f"Delete network error: {e}")
            return {"error": str(e)}
    
    def connect_interface(self, device_name: str, interface_id: int, network_name: str) -> Dict[str, Any]:
        """
        장비 인터페이스를 네트워크에 연결
        """
        try:
            node = self._get_node_by_name(device_name)
            if not node:
                return {"error": f"장비 '{device_name}'를 찾을 수 없습니다"}
            
            network = self._get_network_by_name(network_name)
            if not network:
                return {"error": f"네트워크 '{network_name}'를 찾을 수 없습니다"}
            
            node_id = int(node["id"])
            net_id = network["id"]
            
            if self.client.connect_node_interface(node_id, interface_id, net_id):
                return {
                    "status": "success",
                    "message": f"'{device_name}' Gi0/{interface_id} → '{network_name}' 연결됨"
                }
            return {"error": "연결 실패"}
        except Exception as e:
            logger.error(f"Connect interface error: {e}")
            return {"error": str(e)}
    
    def disconnect_interface(self, device_name: str, interface_id: int = 0) -> Dict[str, Any]:
        """
        장비 인터페이스 연결 해제
        """
        try:
            node = self._get_node_by_name(device_name)
            if not node:
                return {"error": f"장비 '{device_name}'를 찾을 수 없습니다"}
            
            node_id = int(node["id"])
            
            if self.client.connect_node_interface(node_id, interface_id, 0):
                return {
                    "status": "success",
                    "message": f"'{device_name}' Gi0/{interface_id} 연결 해제됨"
                }
            return {"error": "연결 해제 실패"}
        except Exception as e:
            logger.error(f"Disconnect interface error: {e}")
            return {"error": str(e)}
    
    def start_node(self, name: str) -> Dict[str, Any]:
        """
        장비 시작 (이름으로 검색)
        """
        try:
            node = self._get_node_by_name(name)
            if not node:
                return {"error": f"장비 '{name}'를 찾을 수 없습니다"}
            
            node_id = int(node["id"])
            if self.client.start_node(node_id):
                return {"status": "success", "message": f"장비 '{name}' 시작됨"}
            return {"error": f"장비 '{name}' 시작 실패"}
        except Exception as e:
            logger.error(f"Start node error: {e}")
            return {"error": str(e)}
    
    def stop_node(self, name: str) -> Dict[str, Any]:
        """
        장비 중지 (이름으로 검색)
        """
        try:
            node = self._get_node_by_name(name)
            if not node:
                return {"error": f"장비 '{name}'를 찾을 수 없습니다"}
            
            node_id = int(node["id"])
            if self.client.stop_node(node_id):
                return {"status": "success", "message": f"장비 '{name}' 중지됨"}
            return {"error": f"장비 '{name}' 중지 실패"}
        except Exception as e:
            logger.error(f"Stop node error: {e}")
            return {"error": str(e)}
    
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
    server = PnetlabServer()
    asyncio.run(server.run())
