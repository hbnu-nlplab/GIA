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
            ]
        
        @self._server.call_tool()
        async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
            result = await self._handle_tool_call(name, arguments)
            return [TextContent(type="text", text=json.dumps(result, ensure_ascii=False, indent=2))]
    
    async def _handle_tool_call(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """도구 호출 처리"""
        try:
            if name == "pnetlab.show_inventory":
                return self.show_inventory()
            
            elif name == "pnetlab.get_status":
                return self.get_status(arguments.get("device"))
            
            elif name == "pnetlab.get_console_link":
                return self.get_console_link(arguments.get("device"))
            
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
