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

# 프로젝트 경로 설정 (Make_Dataset/src/core_batfish 접근용)
MAKE_DATASET_PATH = Path(__file__).parent.parent.parent / "Make_Dataset" / "src"
sys.path.insert(0, str(MAKE_DATASET_PATH))

# Batfish 모듈 import (선택적)
try:
    from core_batfish.batfish_builder import BatfishBuilder
    from core_batfish.batfish_base import BATFISH_AVAILABLE
except ImportError:
    BatfishBuilder = None
    BATFISH_AVAILABLE = False

logger = logging.getLogger(__name__)


class BatfishServer:
    """
    Batfish MCP 서버
    
    기존 Make_Dataset/src/core_batfish 코드를 래핑하여 MCP 인터페이스 제공
    """
    
    def __init__(
        self,
        host: str = "localhost",
        network_name: str = "netconfig_qa",
        snapshot_path: Optional[str] = None
    ):
        """
        Args:
            host: Batfish 서버 호스트
            network_name: 네트워크 이름
            snapshot_path: 스냅샷 경로 (configs 폴더 포함)
        """
        self.host = host
        self.network_name = network_name
        self.snapshot_path = snapshot_path
        
        self._builder: Optional[BatfishBuilder] = None
        self._initialized = False
        
        # MCP 서버 초기화
        if MCP_AVAILABLE:
            self._server = Server("batfish-server")
            self._register_tools()
        else:
            self._server = None
            logger.warning("MCP SDK not available. Server functionality disabled.")
    
    @property
    def builder(self) -> Optional[BatfishBuilder]:
        """BatfishBuilder 인스턴스"""
        return self._builder
    
    @property
    def is_available(self) -> bool:
        """Batfish 사용 가능 여부"""
        return BATFISH_AVAILABLE and BatfishBuilder is not None
    
    def _register_tools(self):
        """MCP 도구 등록"""
        if not self._server:
            return
        
        @self._server.list_tools()
        async def list_tools() -> List[Tool]:
            return [
                Tool(
                    name="batfish.init_snapshot",
                    description="Batfish 스냅샷을 초기화합니다 (configs 폴더 필요)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "snapshot_path": {"type": "string", "description": "스냅샷 경로 (configs 폴더 포함)"}
                        },
                        "required": ["snapshot_path"]
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
                            "device": {"type": "string", "description": "장비명"},
                            "vrf": {"type": "string", "description": "VRF 이름 (기본: default)"}
                        },
                        "required": ["device"]
                    }
                ),
                Tool(
                    name="batfish.get_nodes",
                    description="스냅샷의 모든 노드 목록을 반환합니다",
                    inputSchema={
                        "type": "object",
                        "properties": {},
                        "required": []
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
            if name == "batfish.init_snapshot":
                snapshot_path = arguments.get("snapshot_path")
                return self.init_snapshot(snapshot_path)
            
            elif name == "batfish.reachability":
                return self.check_reachability(
                    src=arguments.get("src"),
                    dst=arguments.get("dst"),
                    protocol=arguments.get("protocol", "icmp"),
                    dst_port=arguments.get("dst_port")
                )
            
            elif name == "batfish.traceroute":
                return self.traceroute(
                    src=arguments.get("src"),
                    dst=arguments.get("dst")
                )
            
            elif name == "batfish.bgp_session":
                return self.get_bgp_sessions(
                    device=arguments.get("device")
                )
            
            elif name == "batfish.route_table":
                return self.get_route_table(
                    device=arguments.get("device"),
                    vrf=arguments.get("vrf", "default")
                )
            
            elif name == "batfish.get_nodes":
                return {"nodes": self.get_nodes()}
            
            else:
                return {"error": f"Unknown tool: {name}"}
                
        except Exception as e:
            logger.error(f"Tool call error: {e}")
            return {"error": str(e)}
    
    # =========================================================================
    # Public API Methods
    # =========================================================================
    
    def init_snapshot(self, snapshot_path: str) -> Dict[str, Any]:
        """
        Batfish 스냅샷 초기화
        
        Args:
            snapshot_path: 스냅샷 경로 (configs 폴더 포함)
            
        Returns:
            초기화 결과 (nodes, interfaces 등)
        """
        if not self.is_available:
            return {"error": "Batfish not available. Install pybatfish."}
        
        try:
            self.snapshot_path = snapshot_path
            self._builder = BatfishBuilder(
                snapshot_path=snapshot_path,
                batfish_host=self.host,
                network_name=self.network_name
            )
            
            if self._builder.initialize():
                self._initialized = True
                return {
                    "status": "initialized",
                    "nodes": self._builder.nodes,
                    "node_count": len(self._builder.nodes),
                    "snapshot_path": snapshot_path
                }
            else:
                return {"error": "Failed to initialize Batfish"}
                
        except Exception as e:
            logger.error(f"Init snapshot error: {e}")
            return {"error": str(e)}
    
    def check_reachability(
        self,
        src: str,
        dst: str,
        protocol: str = "icmp",
        dst_port: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        도달성 검증
        
        Args:
            src: 출발지 (IP 또는 노드명)
            dst: 목적지 (IP 또는 노드명)
            protocol: 프로토콜
            dst_port: 목적지 포트
            
        Returns:
            도달성 검증 결과
        """
        if not self._initialized:
            return {"error": "Batfish not initialized. Call init_snapshot first."}
        
        try:
            # BatfishBuilder의 reachability 분석 사용
            # 기존 L4AnalyzerMixin 코드 활용
            from pybatfish.datamodel.flow import HeaderConstraints
            
            headers = HeaderConstraints(
                srcIps=src if "." in src else None,
                dstIps=dst if "." in dst else None,
                ipProtocols=[protocol.upper()],
                dstPorts=[str(dst_port)] if dst_port else None
            )
            
            # src_location 설정
            src_location = src if "." not in src else None
            
            result = self._builder.bf.q.reachability(
                pathConstraints={"startLocation": src_location} if src_location else None,
                headers=headers
            ).answer().frame()
            
            if result.empty:
                return {
                    "reachable": False,
                    "reason": "No path found",
                    "src": src,
                    "dst": dst
                }
            
            # 결과 분석
            first_row = result.iloc[0]
            flow_disposition = str(first_row.get("Flow_Disposition", "UNKNOWN"))
            
            return {
                "reachable": "ACCEPTED" in flow_disposition,
                "disposition": flow_disposition,
                "src": src,
                "dst": dst,
                "protocol": protocol,
                "hops": len(first_row.get("Traces", [[]])[0]) if "Traces" in first_row else 0
            }
            
        except Exception as e:
            logger.error(f"Reachability check error: {e}")
            return {"error": str(e), "src": src, "dst": dst}
    
    def traceroute(self, src: str, dst: str) -> Dict[str, Any]:
        """
        경로 추적
        
        Args:
            src: 출발지 노드
            dst: 목적지 IP
            
        Returns:
            경로 정보
        """
        if not self._initialized:
            return {"error": "Batfish not initialized. Call init_snapshot first."}
        
        try:
            from pybatfish.datamodel.flow import HeaderConstraints
            
            result = self._builder.bf.q.traceroute(
                startLocation=src,
                headers=HeaderConstraints(dstIps=dst)
            ).answer().frame()
            
            if result.empty:
                return {"path": [], "hops": 0, "src": src, "dst": dst}
            
            # 경로 추출
            traces = result.iloc[0].get("Traces", [])
            path = []
            
            if traces:
                for hop in traces[0]:
                    node = getattr(hop, 'node', str(hop))
                    path.append(node)
            
            return {
                "path": path,
                "hops": len(path),
                "src": src,
                "dst": dst,
                "disposition": str(result.iloc[0].get("Flow_Disposition", "UNKNOWN"))
            }
            
        except Exception as e:
            logger.error(f"Traceroute error: {e}")
            return {"error": str(e), "src": src, "dst": dst}
    
    def get_bgp_sessions(self, device: Optional[str] = None) -> Dict[str, Any]:
        """
        BGP 세션 상태 조회
        
        Args:
            device: 장비명 (None이면 전체)
            
        Returns:
            BGP 세션 목록
        """
        if not self._initialized:
            return {"error": "Batfish not initialized. Call init_snapshot first."}
        
        try:
            result = self._builder.bf.q.bgpSessionStatus().answer().frame()
            
            sessions = []
            for _, row in result.iterrows():
                node = str(row.get("Node", ""))
                
                # 장비 필터링
                if device and device.lower() not in node.lower():
                    continue
                
                sessions.append({
                    "node": node,
                    "remote_node": str(row.get("Remote_Node", "")),
                    "local_as": row.get("Local_AS"),
                    "remote_as": row.get("Remote_AS"),
                    "status": str(row.get("Established_Status", "UNKNOWN"))
                })
            
            return {
                "sessions": sessions,
                "total": len(sessions),
                "device_filter": device
            }
            
        except Exception as e:
            logger.error(f"BGP session query error: {e}")
            return {"error": str(e)}
    
    def get_route_table(self, device: str, vrf: str = "default") -> Dict[str, Any]:
        """
        라우팅 테이블 조회
        
        Args:
            device: 장비명
            vrf: VRF 이름
            
        Returns:
            라우팅 테이블
        """
        if not self._initialized:
            return {"error": "Batfish not initialized. Call init_snapshot first."}
        
        try:
            result = self._builder.bf.q.routes(
                nodes=device,
                vrfs=vrf
            ).answer().frame()
            
            routes = []
            for _, row in result.iterrows():
                routes.append({
                    "network": str(row.get("Network", "")),
                    "next_hop": str(row.get("Next_Hop", "")),
                    "next_hop_ip": str(row.get("Next_Hop_IP", "")),
                    "protocol": str(row.get("Protocol", "")),
                    "metric": row.get("Metric", 0),
                    "admin_distance": row.get("Admin_Distance", 0)
                })
            
            return {
                "device": device,
                "vrf": vrf,
                "routes": routes,
                "count": len(routes)
            }
            
        except Exception as e:
            logger.error(f"Route table query error: {e}")
            return {"error": str(e), "device": device}
    
    def get_nodes(self) -> List[str]:
        """스냅샷의 모든 노드 반환"""
        if not self._initialized:
            return []
        return self._builder.nodes if self._builder else []
    
    def get_layer3_edges(self) -> List[Dict[str, Any]]:
        """L3 링크 목록 반환"""
        if not self._initialized or not self._builder:
            return []
        return self._builder.get_layer3_edges()
    
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
    server = BatfishServer()
    asyncio.run(server.run())
