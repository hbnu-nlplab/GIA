"""
NetAlly FastAPI Backend
- SSE 스트리밍 채팅 API
- 토폴로지 API
- Evidence(검증 결과) API
"""

import os
import json
import asyncio
from typing import List, Optional, Any, Dict
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel, Field
from dotenv import load_dotenv
import logging

load_dotenv()

# Logger Config
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("NetAlly")

# =============================================================================
# Pydantic Models
# =============================================================================

class ChatMessage(BaseModel):
    """채팅 메시지"""
    role: str  # "user" | "assistant"
    content: str


class ChatRequest(BaseModel):
    """채팅 요청"""
    message: str = Field(..., description="사용자 질문")
    history: List[ChatMessage] = Field(default_factory=list, description="대화 기록")
    answer_type: str = Field(default="text", description="답변 형식: text, numeric, set, map, boolean")


class TopologyNode(BaseModel):
    """토폴로지 노드"""
    id: str
    type: str = "router"  # "router" | "switch" | "server"
    data: Dict[str, Any] = Field(default_factory=dict)


class TopologyEdge(BaseModel):
    """토폴로지 엣지"""
    source: str
    target: str
    label: Optional[str] = None


class TopologyResponse(BaseModel):
    """토폴로지 응답"""
    nodes: List[TopologyNode]
    edges: List[TopologyEdge]


# =============================================================================
# Lifespan (startup/shutdown)
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """앱 시작/종료 시 실행"""
    # Startup
    print("[NetAlly] Starting up...")
    
    # LangGraph 그래프 임포트 (지연 로딩)
    from agent.graph import graph
    app.state.graph = graph
    print("[NetAlly] Agent graph loaded.")
    
    yield
    
    # Shutdown
    print("[NetAlly] Shutting down...")


# =============================================================================
# App Initialization
# =============================================================================

app = FastAPI(
    title="NetAlly",
    description="Multi-Agent System for Network Configuration Management",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS 설정 (개발용)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 프로덕션에서는 특정 origin으로 제한
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 정적 파일 서빙 (프론트엔드 빌드 결과)
static_path = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_path):
    app.mount("/", StaticFiles(directory=static_path, html=True), name="static")


# =============================================================================
# Health Check
# =============================================================================

@app.get("/api/health")
async def health():
    """헬스 체크"""
    return {"status": "ok", "service": "netally"}


# =============================================================================
# Chat API (SSE Streaming)
# =============================================================================

async def chat_stream_generator(request: ChatRequest, graph):
    """SSE 스트리밍 제너레이터"""
    
    # 초기 상태 구성
    initial_state = {
        "question": request.message,
        "answer_type": request.answer_type,
        "selected_skills": [],
        "reasoning": "",
        "enabled_tools": [],
        "skill_prompt": "",
        "messages": [],
        "final_answer": "",
        "step_count": 0,
        "is_complete": False,
    }
    
    try:
        # 스트리밍 실행
        async for event in graph.astream(initial_state, stream_mode="updates"):
            for node_name, node_output in event.items():
                
                # Orchestrator 결과
                if node_name == "orchestrator":
                    data = {
                        "type": "planning",
                        "skills": node_output.get("selected_skills", []),
                        "reasoning": node_output.get("reasoning", "")
                    }
                    yield f"event: planning\ndata: {json.dumps(data)}\n\n"
                
                # Executor 결과
                elif node_name == "executor":
                    messages = node_output.get("messages", [])
                    if messages:
                        last_msg = messages[-1]
                        # 도구 호출
                        if hasattr(last_msg, "tool_calls") and last_msg.tool_calls:
                            for tc in last_msg.tool_calls:
                                data = {
                                    "type": "tool_call",
                                    "tool": tc.get("name", ""),
                                    "input": tc.get("args", {})
                                }
                                yield f"event: tool_call\ndata: {json.dumps(data)}\n\n"
                        # 최종 답변
                        elif node_output.get("is_complete"):
                            data = {
                                "type": "answer",
                                "content": node_output.get("final_answer", "")
                            }
                            yield f"event: answer\ndata: {json.dumps(data)}\n\n"
                
                # 도구 실행 결과
                elif node_name == "tools":
                    messages = node_output.get("messages", [])
                    if messages:
                        last_msg = messages[-1]
                        data = {
                            "type": "tool_output",
                            "content": str(last_msg.content) if hasattr(last_msg, "content") else str(last_msg)
                        }
                        yield f"event: tool_output\ndata: {json.dumps(data)}\n\n"
        
        # 완료 신호
        yield f"event: complete\ndata: {json.dumps({'type': 'complete'})}\n\n"
        
    except Exception as e:
        error_data = {"type": "error", "message": str(e)}
        yield f"event: error\ndata: {json.dumps(error_data)}\n\n"


@app.post("/api/chat")
async def chat(request: ChatRequest):
    """SSE 스트리밍 채팅 엔드포인트"""
    graph = app.state.graph
    
    return StreamingResponse(
        chat_stream_generator(request, graph),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # nginx 버퍼링 비활성화
        }
    )


# =============================================================================
# Topology API
# =============================================================================

@app.get("/api/topology", response_model=TopologyResponse)
async def get_topology():
    """
    Batfish L3 토폴로지 반환
    - layer3Edges로 실제 네트워크 연결 정보 표시
    - BGP/OSPF 관계 포함
    """
    try:
        from agent.clients.batfish import BatfishClient
        from agent.clients.nso import NSOClient
        
        batfish = BatfishClient(host=os.getenv("BATFISH_HOST", "localhost"))
        
        # Batfish를 통한 L3 토폴로지 얻기
        # 스냅샷이 로드되지 않았다면 로드 시도
        if batfish.is_available:
            if not batfish._builder:
                # 기본 토폴로지 로드 시도
                batfish.load_snapshot("Research_Institute_Internal_DC")
            
            if batfish._builder:
                topology_data = get_batfish_l3_topology(batfish)
                if topology_data:
                    return topology_data
        
        # Fallback: NSO에서 장비 리스트만 가져오기
        nso = NSOClient(
            base_url=os.getenv("NSO_BASE_URL", "http://localhost:8080/restconf"),
            username=os.getenv("NSO_USERNAME", "admin"),
            password=os.getenv("NSO_PASSWORD", "admin")
        )
        
        devices = nso.get_devices()
        nodes = []
        for idx, dev in enumerate(devices):
            nodes.append(TopologyNode(
                id=dev.get("name", f"device-{idx}"),
                type="router",  # 기본값
                data={
                    "mgmt_ip": dev.get("address"),
                    "platform": dev.get("platform", {}).get("name"),
                    "device_type": dev.get("device-type", {})
                }
            ))
        
        return TopologyResponse(nodes=nodes, edges=[])
        
    except Exception as e:
        logger.error(f"Topology error: {e}")
        return TopologyResponse(nodes=[], edges=[])


def get_batfish_l3_topology(batfish: "BatfishClient") -> Optional[TopologyResponse]:
    """
    Batfish에서 L3 토폴로지 추출
    - layer3Edges: 인터페이스 레벨 연결
    - bgpEdges: BGP 피어링
    - 노드 속성: 플랫폼, 인터페이스 정보
    """
    try:
        bf = batfish._builder.bf
        
        # 1. 노드 속성 가져오기
        node_props = bf.q.nodeProperties().answer().frame()
        nodes = []
        node_map = set()
        
        for _, row in node_props.iterrows():
            node_name = str(row.get("Node", ""))
            if not node_name or node_name in node_map:
                continue
            node_map.add(node_name)
            
            # 장비 유형 추론 (간단화: 이름 기반)
            device_type = "router"
            if "sw" in node_name.lower() or "switch" in node_name.lower():
                device_type = "switch"
            elif "host" in node_name.lower() or "srv" in node_name.lower():
                device_type = "server"
            
            nodes.append(TopologyNode(
                id=node_name,
                type=device_type,
                data={
                    "platform": str(row.get("Platform", "Unknown")),
                    "vendor": str(row.get("Vendor", "Unknown"))
                }
            ))
        
        # 2. Layer3 Edges (실제 IP 연결)
        edges = []
        edge_set = set()  # 중복 방지
        
        try:
            l3_edges = bf.q.layer3Edges().answer().frame()
            for _, row in l3_edges.iterrows():
                src_iface = row.get("Interface")
                dst_iface = row.get("Remote_Interface")
                
                # Interface 객체에서 속성 추출
                src_node = getattr(src_iface, 'hostname', '') if src_iface else ''
                src_port = getattr(src_iface, 'interface', '') if src_iface else ''
                dst_node = getattr(dst_iface, 'hostname', '') if dst_iface else ''
                dst_port = getattr(dst_iface, 'interface', '') if dst_iface else ''
                
                if src_node and dst_node:
                    # 양방향 중복 제거
                    edge_key = tuple(sorted([src_node, dst_node]))
                    if edge_key not in edge_set:
                        edge_set.add(edge_key)
                        edges.append(TopologyEdge(
                            source=src_node,
                            target=dst_node,
                            label=f"{src_port} ↔ {dst_port}"
                        ))
        except Exception as e:
            logger.warning(f"L3 edges fetch failed: {e}")
        
        # 3. BGP Edges (논리적 피어링)
        try:
            bgp_edges = bf.q.bgpEdges().answer().frame()
            for _, row in bgp_edges.iterrows():
                src_node = str(row.get("Node", ""))
                dst_node = str(row.get("Remote_Node", ""))
                
                if src_node and dst_node:
                    edge_key = tuple(sorted([src_node, dst_node]))
                    if edge_key not in edge_set:
                        edge_set.add(edge_key)
                        edges.append(TopologyEdge(
                            source=src_node,
                            target=dst_node,
                            label="BGP"
                        ))
        except Exception as e:
            logger.warning(f"BGP edges fetch failed: {e}")
        
        return TopologyResponse(nodes=nodes, edges=edges)
        
    except Exception as e:
        logger.error(f"Batfish topology extraction failed: {e}")
        return None


# =============================================================================
# Device Detail API
# =============================================================================

@app.get("/api/device/{device_id}")
async def get_device_detail(device_id: str):
    """
    장비 상세 정보 조회
    - NSO에서 설정 가져오기
    - Batfish에서 인터페이스/라우팅 정보 가져오기
    """
    try:
        from agent.clients.nso import NSOClient
        from agent.clients.batfish import BatfishClient
        
        nso = NSOClient(
            base_url=os.getenv("NSO_BASE_URL", "http://localhost:8080/restconf"),
            username=os.getenv("NSO_USERNAME", "admin"),
            password=os.getenv("NSO_PASSWORD", "admin")
        )
        
        # NSO에서 장비 정보
        devices = nso.get_devices()
        device_info = next((d for d in devices if d.get("name") == device_id), None)
        
        if not device_info:
            raise HTTPException(status_code=404, detail="Device not found")
        
        # Batfish에서 인터페이스 및 라우팅 정보
        batfish = BatfishClient()
        interfaces = []
        bgp_neighbors = []
        
        if batfish.is_available and batfish._builder:
            try:
                bf = batfish._builder.bf
                
                # 인터페이스 속성
                iface_props = bf.q.interfaceProperties(nodes=device_id).answer().frame()
                for _, row in iface_props.iterrows():
                    interfaces.append({
                        "name": str(row.get("Interface", "")),
                        "ip": str(row.get("Primary_Address", "")),
                        "status": "up" if row.get("Active", False) else "down",
                        "protocol": str(row.get("Routing_Protocol", ""))
                    })
                
                # BGP 네이버
                bgp_sessions = batfish.get_bgp_sessions(device_filter=device_id)
                for session in bgp_sessions:
                    bgp_neighbors.append({
                        "peer": session.get("remote_node", ""),
                        "as": "Unknown",  # Batfish에서 AS 번호 조회 필요 시 추가
                        "state": session.get("status", "Unknown")
                    })
            except Exception as e:
                logger.warning(f"Batfish detail fetch failed for {device_id}: {e}")
        
        return {
            "hostname": device_id,
            "platform": device_info.get("platform", {}).get("name"),
            "version": device_info.get("platform", {}).get("version"),
            "mgmt_ip": device_info.get("address"),
            "interfaces": interfaces,
            "bgp_neighbors": bgp_neighbors,
            "routes": len(batfish.get_route_table(device_id)) if batfish.is_available else 0,
            "configs": None  # 설정 내용은 별도 API로 분리 가능
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Device detail error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Evidence API (향후 확장)
# =============================================================================

@app.get("/api/evidence/{run_id}")
async def get_evidence(run_id: str):
    """특정 실행의 Evidence 조회"""
    # TODO: Evidence Store에서 조회
    return {"run_id": run_id, "status": "not_implemented"}


# =============================================================================
# Run (개발용)
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)), reload=True)
