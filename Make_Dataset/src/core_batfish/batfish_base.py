"""
Batfish 세션 관리 및 기본 쿼리 베이스 클래스

BatfishBase:
- Batfish 세션 초기화 및 스냅샷 관리
- 노드/인터페이스 정보 수집
- 기본 유틸리티 메서드 (get_node_pairs, get_layer3_edges 등)
"""

import logging
from typing import Dict, List, Optional, Tuple
from itertools import combinations

from .models import FlowSpec, AnswerResult, build_evidence

# Batfish 로드 (선택적)
try:
    from pybatfish.client.session import Session
    from pybatfish.datamodel.flow import HeaderConstraints, PathConstraints
    BATFISH_AVAILABLE = True
except ImportError:
    BATFISH_AVAILABLE = False
    Session = None
    HeaderConstraints = None
    PathConstraints = None

logger = logging.getLogger(__name__)


class BatfishBase:
    """
    Batfish 세션 관리 및 기본 쿼리 베이스 클래스
    
    이 클래스는 다른 Mixin들(L4AnalyzerMixin, L5AnalyzerMixin)과 함께 사용됩니다.
    """
    
    def __init__(self, 
                 snapshot_path: str,
                 batfish_host: str = "localhost",
                 network_name: str = "netconfig_qa"):
        """
        Args:
            snapshot_path: Batfish 스냅샷 경로 (configs/ 폴더 포함)
            batfish_host: Batfish 서버 호스트
            network_name: 네트워크 이름
        """
        if not BATFISH_AVAILABLE:
            raise RuntimeError("pybatfish is not installed. Run: pip install pybatfish")
        
        self.snapshot_path = snapshot_path
        self.batfish_host = batfish_host
        self.network_name = network_name
        
        self.bf: Optional[Session] = None
        self.nodes: List[str] = []
        self.interfaces: Dict[str, List[Dict]] = {}
        self.node_ips: Dict[str, List[str]] = {}
        
        # 스냅샷 이름 관리
        self.snapshot_name = "baseline"
        self._initialized = False
    
    def initialize(self) -> bool:
        """Batfish 세션 초기화 및 스냅샷 로드"""
        try:
            logger.info(f"Connecting to Batfish at {self.batfish_host}...")
            self.bf = Session(host=self.batfish_host)
            
            logger.info(f"Setting network: {self.network_name}")
            self.bf.set_network(self.network_name)
            
            logger.info(f"Loading snapshot from: {self.snapshot_path}")
            self.snapshot_name = 'baseline'
            self.bf.init_snapshot(self.snapshot_path, name=self.snapshot_name, overwrite=True)
            
            # 노드 정보 수집
            self._collect_node_info()
            
            self._initialized = True
            logger.info(f"Batfish initialized. Found {len(self.nodes)} nodes.")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize Batfish: {e}")
            return False
    
    def _collect_node_info(self):
        """노드 및 인터페이스 정보 수집"""
        # 노드 목록
        nodes_df = self.bf.q.nodeProperties().answer().frame()
        self.nodes = nodes_df['Node'].tolist()
        
        # 인터페이스 정보
        ifaces_df = self.bf.q.interfaceProperties().answer().frame()
        for _, row in ifaces_df.iterrows():
            node = row['Interface'].hostname
            if node not in self.interfaces:
                self.interfaces[node] = []
                self.node_ips[node] = []
            
            iface_info = {
                'name': str(row['Interface']),
                'active': row.get('Active', False),
                'primary_address': row.get('Primary_Address', '')
            }
            self.interfaces[node].append(iface_info)
            
            # IP 주소 수집
            if iface_info['primary_address']:
                ip = str(iface_info['primary_address']).split('/')[0]
                if ip and ip != 'None':
                    self.node_ips[node].append(ip)
    
    def _make_evidence(self, query_name: str, params: dict) -> dict:
        """BatfishBuilder 내부용 evidence 생성 헬퍼"""
        return build_evidence(query_name, params, self.snapshot_name)
    
    # =========================================================================
    # 노드 및 토폴로지 쿼리
    # =========================================================================
    
    def get_node_pairs(self) -> List[Tuple[str, str]]:
        """모든 노드 쌍 반환 (도달성 테스트용)"""
        return list(combinations(self.nodes, 2))
    
    def get_representative_flows(self) -> List[FlowSpec]:
        """대표적인 트래픽 흐름 생성"""
        flows = []
        
        for src_node, dst_node in self.get_node_pairs():
            src_ips = self.node_ips.get(src_node, [])
            dst_ips = self.node_ips.get(dst_node, [])
            
            if src_ips and dst_ips:
                # SSH 트래픽
                flows.append(FlowSpec(
                    src_ip=src_ips[0],
                    dst_ip=dst_ips[0],
                    dst_port=22,
                    protocol="TCP",
                    src_location=src_node,
                    dst_location=dst_node
                ))
                
                # ICMP 트래픽
                flows.append(FlowSpec(
                    src_ip=src_ips[0],
                    dst_ip=dst_ips[0],
                    dst_port=0,
                    protocol="ICMP",
                    src_location=src_node,
                    dst_location=dst_node
                ))
        
        return flows
    
    def get_layer3_edges(self) -> List[Dict]:
        """
        L3 링크(Edges) 목록 반환
        Target: LINK_FAILURE 시나리오용
        """
        if not self._initialized: 
            return []
        try:
            edges_df = self.bf.q.layer3Edges().answer().frame()
            edges = []
            if not edges_df.empty:
                for _, row in edges_df.iterrows():
                    # Interface 객체의 hostname 속성 처리
                    iface = row['Interface']
                    remote_iface = row['Remote_Interface']
                    
                    n1 = getattr(iface, 'hostname', str(iface).split('[')[0])
                    n2 = getattr(remote_iface, 'hostname', str(remote_iface).split('[')[0])
                    
                    edges.append({
                        "node1": n1,
                        "node2": n2,
                        "interface1": str(iface),
                        "interface2": str(remote_iface)
                    })
            return edges
        except Exception as e:
            logger.warning(f"get_layer3_edges error: {e}")
            return []

    def get_vrfs(self) -> List[str]:
        """VRF 목록 반환"""
        if not self._initialized: 
            return []
        try:
            vrfs = set()
            ifaces_df = self.bf.q.interfaceProperties().answer().frame()
            if 'VRF' in ifaces_df.columns:
                unique_vrfs = ifaces_df['VRF'].dropna().unique()
                for v in unique_vrfs:
                    if v.lower() not in ['default', 'management']:
                        vrfs.add(v)
            return list(vrfs)
        except Exception as e:
            logger.warning(f"get_vrfs error: {e}")
            return []
            
    def get_pe_nodes(self) -> List[str]:
        """PE 장비(Edge Router) 목록 반환 (이름 기반)"""
        return [n for n in self.nodes if 'pe' in n.lower()]
    
    def get_ce_nodes(self) -> List[str]:
        """CE 장비(Customer Edge) 목록 반환 (이름 기반)"""
        return [n for n in self.nodes if 'ce' in n.lower()]
    
    def get_spine_nodes(self) -> List[str]:
        """Spine 장비 목록 반환 (이름 기반)"""
        return [n for n in self.nodes if 'spine' in n.lower()]
    
    def get_leaf_nodes(self) -> List[str]:
        """Leaf 장비 목록 반환 (이름 기반)"""
        return [n for n in self.nodes if 'leaf' in n.lower()]
