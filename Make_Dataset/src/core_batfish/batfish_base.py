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
        
        # Loopback0 존재 여부 캐시 (성능 최적화)
        self._loopback_cache: Dict[str, bool] = {}
    
    def _populate_loopback_cache(self):
        """
        모든 노드의 Loopback0 존재 여부를 한 번에 수집 (Batch Loading)
        
        성능 최적화: 노드별 개별 쿼리 대신 전체 노드를 한 번에 조회.
        - Before: 8개 노드 × 3초 = 24초
        - After: 1번 쿼리 = 3초
        """
        if not self._initialized or not self.bf:
            print("[DEBUG] _populate_loopback_cache: Batfish not initialized")
            logger.debug("_populate_loopback_cache: Batfish not initialized")
            return
        
        try:
            print(f"[DEBUG] _populate_loopback_cache: Starting batch query for all {len(self.nodes)} nodes...")
            logger.debug("_populate_loopback_cache: Querying all nodes at once...")
            
            import time
            t_start = time.time()
            
            # 전체 노드의 인터페이스 정보를 한 번에 조회 (파라미터 생략 = 전체 조회)
            print("[DEBUG] _populate_loopback_cache: Calling bf.q.interfaceProperties()...")
            iface_props = self.bf.q.interfaceProperties().answer().frame()
            
            elapsed = time.time() - t_start
            print(f"[DEBUG] _populate_loopback_cache: Query completed in {elapsed:.2f}s")
            print(f"[DEBUG] _populate_loopback_cache: Got {len(iface_props)} interface records")
            
            # 모든 노드를 False로 초기화
            print("[DEBUG] _populate_loopback_cache: Initializing cache...")
            for node in self.nodes:
                self._loopback_cache[node] = False
            
            # Loopback0이 있는 노드만 True로 변경
            print("[DEBUG] _populate_loopback_cache: Scanning for Loopback0...")
            loopback_count = 0
            if not iface_props.empty:
                for _, row in iface_props.iterrows():
                    iface = row.get('Interface', {})
                    node_name = getattr(iface, 'hostname', '')
                    iface_name = getattr(iface, 'interface', '')
                    if iface_name.lower() == 'loopback0':
                        self._loopback_cache[node_name] = True
                        loopback_count += 1
                        print(f"[DEBUG] _populate_loopback_cache: Found Loopback0 on {node_name}")
                        logger.debug(f"_populate_loopback_cache: Found Loopback0 on {node_name}")
            
            print(f"[DEBUG] _populate_loopback_cache: Completed! Cached {len(self._loopback_cache)} nodes ({loopback_count} with Loopback0)")
            logger.debug(f"_populate_loopback_cache: Cached {len(self._loopback_cache)} nodes")
            
        except Exception as e:
            print(f"[DEBUG] _populate_loopback_cache: ERROR: {e}")
            logger.debug(f"_populate_loopback_cache: Error: {e}")
            import traceback
            traceback.print_exc()
            # 에러 발생 시 모든 노드를 False로 설정 (안전한 fallback)
            for node in self.nodes:
                self._loopback_cache[node] = False
    
    def _has_loopback0(self, node_name: str) -> bool:
        """
        노드에 Loopback0이 있는지 확인 (캐시 사용)
        
        첫 호출 시 모든 노드의 정보를 한 번에 수집 (Lazy Batch Loading).
        이후 호출은 캐시에서 즉시 반환.
        
        Args:
            node_name: 확인할 노드 이름
            
        Returns:
            True if Loopback0 exists, False otherwise
        """
        # 캐시가 비어있으면 한 번만 전체 노드 정보 수집
        if not self._loopback_cache:
            print(f"[DEBUG] _has_loopback0: Cache is empty, triggering batch loading...")
            logger.debug("_has_loopback0: Cache empty, populating...")
            self._populate_loopback_cache()
            print(f"[DEBUG] _has_loopback0: Batch loading completed")
        
        # 캐시에서 조회 (즉시 반환)
        result = self._loopback_cache.get(node_name, False)
        print(f"[DEBUG] _has_loopback0: {node_name} = {result} (from cache)")
        logger.debug(f"_has_loopback0: {node_name} = {result} (from cache)")
        return result
    
    def _fix_start_location(self, location: str) -> str:
        """
        VRF 문제 방지: Loopback0이 있는 노드만 [Loopback0] 추가
        
        VRF 환경에서 PE/P 라우터는 Loopback0을 명시하여 global routing table 사용.
        Leaf 등 Access layer 장비는 Loopback이 없으므로 노드 이름만 사용.
        
        일반성: 모든 네트워크 토폴로지에 자동 적용 (명명 규칙 무관)
        확장성: 새로운 장비 타입 추가 시 코드 수정 불필요
        안정성: 캐싱으로 성능 최적화, 에러 시 안전한 fallback
        
        Args:
            location: 노드 이름 또는 "노드[인터페이스]" 형식
            
        Returns:
            Loopback0 있으면: "노드[Loopback0]"
            Loopback0 없으면: "노드" (첫 번째 활성 인터페이스를 Batfish가 자동 선택)
            이미 인터페이스 명시: 그대로 반환
        """
        if '[' not in location:
            # 해당 노드에 Loopback0이 있는지 확인 (캐시 사용)
            if self._has_loopback0(location):
                logger.debug(f"_fix_start_location: {location} -> {location}[Loopback0]")
                return f"{location}[Loopback0]"
            else:
                logger.debug(f"_fix_start_location: {location} -> {location} (no Loopback0)")
                return location
        
        return location
    
    def initialize(self) -> bool:
        """Batfish 세션 초기화 및 스냅샷 로드"""
        try:
            logger.info(f"Connecting to Batfish at {self.batfish_host}...")
            # host:port 형식 처리
            if ":" in self.batfish_host:
                base_host, port = self.batfish_host.split(":")
                self.bf = Session(host=base_host, port=int(port))
            else:
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
