"""
Batfish MCP Server

Batfish를 통한 네트워크 검증 및 분석

도구:
- batfish.init_snapshot: 스냅샷 초기화
- batfish.reachability: 도달성 검증
- batfish.traceroute: 경로 추적
- batfish.bgp_session: BGP 세션 상태
- batfish.route_table: 라우팅 테이블 조회
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

from clients.batfish import BatfishClient

logger = logging.getLogger(__name__)


class BatfishServer:
    """
    Batfish MCP 서버
    
    clients.batfish.BatfishClient를 통해 분석 수행
    """
    
    def __init__(
        self,
        host: str = "localhost"
    ):
        """
        Args:
            host: Batfish 서버 호스트
        """
        self.host = host
        self._client = BatfishClient(host)
        
        # MCP 서버 초기화
        if MCP_AVAILABLE:
            self._server = Server("batfish-server")
            self._register_tools()
        else:
            self._server = None
            logger.warning("MCP SDK not available. Server functionality disabled.")
    
    @property
    def client(self) -> BatfishClient:
        return self._client
    
    def _register_tools(self):
        """MCP 도구 등록"""
        if not self._server:
            return
        
        @self._server.list_tools()
        async def list_tools() -> List[Tool]:
            return [
                Tool(
                    name="batfish.init_snapshot",
                    description="설정 파일 저장 및 Batfish 스냅샷 초기화",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "topology_name": {"type": "string", "description": "토폴로지 이름 (폴더명)"},
                            "configs": {
                                "type": "object", 
                                "description": "설정 파일 내용 ({hostname: content})"
                            },
                            "device_info": {
                                "type": "object",
                                "description": "장비 정보 (JSON 메타데이터)"
                            }
                        },
                        "required": ["topology_name", "configs"]
                    }
                ),
                Tool(
                    name="batfish.reachability",
                    description="두 지점 간 도달성을 검증합니다",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "src": {"type": "string", "description": "출발지 (IP 또는 노드명)"},
                            "dst": {"type": "string", "description": "목적지 (IP 또는 노드명)"},
                            "protocol": {"type": "string", "description": "프로토콜 (tcp/udp/icmp)", "default": "icmp"},
                            "dst_port": {"type": "integer", "description": "목적지 포트 (TCP/UDP용)"}
                        },
                        "required": ["src", "dst"]
                    }
                ),
                Tool(
                    name="batfish.traceroute",
                    description="출발지에서 목적지까지의 경로를 추적합니다",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "src": {"type": "string", "description": "출발지 노드"},
                            "dst": {"type": "string", "description": "목적지 IP"}
                        },
                        "required": ["src", "dst"]
                    }
                ),
                Tool(
                    name="batfish.bgp_session",
                    description="BGP 세션 상태를 조회합니다",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "device": {"type": "string", "description": "장비명 (비어있으면 전체)"}
                        },
                        "required": []
                    }
                ),
                Tool(
                    name="batfish.route_table",
                    description="라우팅 테이블을 조회합니다",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "device": {"type": "string", "description": "장비명"}
                        },
                        "required": ["device"]
                    }
                )
            ]
        
        @self._server.call_tool()
        async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
            result = await self._handle_tool_call(name, arguments)
            return [TextContent(type="text", text=json.dumps(result, ensure_ascii=False, indent=2))]
    
    async def _handle_tool_call(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """도구 호출 처리"""
        try:
            if name == "batfish.init_snapshot":
                return self.client.init_snapshot(
                    topology_name=arguments["topology_name"],
                    configs=arguments["configs"],
                    device_info=arguments.get("device_info")
                )
            
            elif name == "batfish.reachability":
                return self.client.check_reachability(
                    src=arguments.get("src"),
                    dst=arguments.get("dst"),
                    protocol=arguments.get("protocol", "icmp"),
                    dst_port=arguments.get("dst_port")
                )
            
            elif name == "batfish.traceroute":
                return self.client.traceroute(
                    src=arguments.get("src"),
                    dst=arguments.get("dst")
                )
            
            elif name == "batfish.bgp_session":
                return {"sessions": self.client.get_bgp_sessions(arguments.get("device"))}
            
            elif name == "batfish.route_table":
                return {"routes": self.client.get_route_table(arguments.get("device"))}
            
            else:
                return {"error": f"Unknown tool: {name}"}
                
        except Exception as e:
            logger.error(f"Tool call error: {e}")
            return {"error": str(e)}
    
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
    server = BatfishServer()
    asyncio.run(server.run())
