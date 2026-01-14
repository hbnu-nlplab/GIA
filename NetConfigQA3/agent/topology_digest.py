"""
Batfish 기반 네트워크 토폴로지 요약 도구

에이전트 초기 컨텍스트(Context)로 제공하기 위한 네트워크 요약 정보를 생성합니다.
"""

import sys
import json
from pathlib import Path

# 프로젝트 경로 설정
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from config.settings import settings
from mcp_servers.batfish_server import BatfishServer

def generate_topology_digest(snapshot_path: str) -> str:
    """
    네트워크 토폴로지 요약 리포트 생성
    """
    # Batfish 서버 초기화 (MCP 서버 로직 재사용)
    server = BatfishServer(
        host=settings.batfish.host,
        network_name=settings.batfish.network_name
    )
    
    if not server.is_available:
        return "⚠️ Batfish is not available. Using limited context."
    
    try:
        print(f"Initializing snapshot: {snapshot_path}")
        init_res = server.init_snapshot(snapshot_path)
        
        if "error" in init_res:
             return f"⚠️ Failed to initialize snapshot: {init_res['error']}"
        
        # 1. 노드 정보 수집
        nodes = server.get_nodes()
        nodes_count = len(nodes)
        
        # 2. L3 엣지(링크) 정보 수집
        l3_edges = server.get_layer3_edges()
        link_count = len(l3_edges)
        
        # 3. 요약 생성
        summary = []
        summary.append(f"## 🌐 Network Topology Digest")
        summary.append(f"- **Nodes**: {nodes_count} devices ({', '.join(nodes[:5])}{'...' if nodes_count > 5 else ''})")
        summary.append(f"- **L3 Links**: {link_count} connections")
        
        if link_count > 0:
            summary.append("\n### 🔗 Key Connections:")
            # 주요 링크 5개만 표시
            for i, edge in enumerate(l3_edges[:5]):
                node1 = edge.get('node1', 'unknown')
                int1 = edge.get('interface1', 'unknown')
                node2 = edge.get('node2', 'unknown')
                int2 = edge.get('interface2', 'unknown')
                summary.append(f"  - {node1}[{int1}] <--> {node2}[{int2}]")
            if link_count > 5:
                summary.append(f"  - ... and {link_count - 5} more links")

        # 4. 라우팅 프로토콜 요약 (Optional / Requires more Batfish queries)
        # 시간 관계상 기본 정보만 우선 요약
        
        return "\n".join(summary)
        
    except Exception as e:
        return f"⚠️ Error generating digest: {str(e)}"

if __name__ == "__main__":
    # 테스트용 스냅샷 경로 (실제 경로 확인 필요)
    # 임시로 'configs' 폴더가 있다고 가정
    test_snapshot = str(project_root / "configs")
    digest = generate_topology_digest(test_snapshot)
    print("\n" + "="*50)
    print(digest)
    print("="*50)
