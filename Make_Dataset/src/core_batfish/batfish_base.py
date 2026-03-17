"""
Batfish 세션 관리 및 기본 쿼리 베이스 클래스

BatfishBase:
- Batfish 세션 초기화 및 스냅샷 관리
- 노드/인터페이스 정보 수집
- 기본 유틸리티 메서드 (get_node_pairs, get_layer3_edges 등)
"""

import logging
import re
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
        
        # 시작 인터페이스 캐시
        # - _loopback_cache: 하위 호환을 위해 유지 (True면 루프백 계열 시작 인터페이스 존재)
        # - _preferred_start_iface_cache: 노드별로 traceroute/reachability startLocation에 붙일 인터페이스
        self._loopback_cache: Dict[str, bool] = {}
        self._preferred_start_iface_cache: Dict[str, str] = {}

    @staticmethod
    def _is_loopback_iface_name(iface_name: str) -> bool:
        """벤더별 표기 차이를 고려해 루프백 계열 인터페이스인지 판별."""
        lowered = iface_name.lower()
        return lowered.startswith("loopback") or lowered.startswith("lo")

    @staticmethod
    def _loopback_iface_rank(iface_name: str) -> Tuple[int, int, str]:
        """
        루프백 인터페이스 우선순위.
        - 1순위: loopback0 / lo0
        - 2순위: 기타 loopback/lo 인터페이스 (숫자 오름차순)
        """
        lowered = iface_name.lower()
        exact = 0 if lowered in ("loopback0", "lo0") else 1
        digits = "".join(ch for ch in lowered if ch.isdigit())
        number = int(digits) if digits else 9999
        return (exact, number, lowered)

    @staticmethod
    def _generic_iface_rank(iface_name: str) -> Tuple[int, Tuple[int, ...], str]:
        """
        활성 L3 인터페이스 선택 우선순위.
        - 1순위: loopback 계열
        - 2순위: 일반 데이터플레인 인터페이스
        - 3순위: management / null 계열
        숫자 토큰을 분리해 GigabitEthernet0/0 < GigabitEthernet0/7 같은 순서를 유지한다.
        """
        lowered = iface_name.lower()
        if BatfishBase._is_loopback_iface_name(iface_name):
            return (0, BatfishBase._loopback_iface_rank(iface_name)[:2], lowered)

        if any(token in lowered for token in ("mgmt", "management", "null", "dialer")):
            kind_rank = 2
        else:
            kind_rank = 1

        numeric_parts = tuple(int(part) for part in re.findall(r"\d+", lowered)) or (9999,)
        return (kind_rank, numeric_parts, lowered)
    
    def _populate_loopback_cache(self):
        """
        모든 노드의 traceroute/reachability용 선호 시작 인터페이스를 한 번에 수집.
        루프백 계열이 있으면 최우선으로 사용하고, 없으면 활성 L3 인터페이스 중
        가장 일반적인 데이터플레인 인터페이스를 fallback으로 선택한다.
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
            
            # 캐시 초기화
            print("[DEBUG] _populate_loopback_cache: Initializing cache...")
            for node in self.nodes:
                node_key = str(node).lower()
                self._loopback_cache[node_key] = False
                self._preferred_start_iface_cache[node_key] = ""
            
            # 활성 L3 인터페이스 후보 수집 후 노드별 최적 인터페이스 선택
            print("[DEBUG] _populate_loopback_cache: Scanning active L3 interfaces...")
            loopback_count = 0
            preferred_count = 0
            candidates: Dict[str, List[str]] = {str(node).lower(): [] for node in self.nodes}
            if not iface_props.empty:
                for _, row in iface_props.iterrows():
                    iface = row.get('Interface', {})
                    node_name = getattr(iface, 'hostname', '')
                    iface_name = getattr(iface, 'interface', '')
                    node_key = str(node_name).lower()
                    
                    if not node_name or not iface_name:
                        continue
                    if node_key not in candidates:
                        candidates[node_key] = []

                    val_active = row.get('Active', False)
                    val_ip = row.get('Primary_Address')

                    # Active 상태이고 IP가 있어야 유효한 Source로 간주
                    if val_active and val_ip:
                        candidates[node_key].append(iface_name)

                for node_name, ifaces in candidates.items():
                    if not ifaces:
                        continue
                    preferred = min(ifaces, key=self._generic_iface_rank)
                    self._preferred_start_iface_cache[node_name] = preferred
                    preferred_count += 1
                    if any(self._is_loopback_iface_name(iface) for iface in ifaces):
                        self._loopback_cache[node_name] = True
                        loopback_count += 1
                    print(
                        f"[DEBUG] _populate_loopback_cache: "
                        f"Selected {preferred} for {node_name}"
                    )
                    logger.debug(
                        "_populate_loopback_cache: Selected %s for %s",
                        preferred,
                        node_name,
                    )
            
            print(
                "[DEBUG] _populate_loopback_cache: Completed! "
                f"Cached {len(self._loopback_cache)} nodes "
                f"({loopback_count} with loopback-like source, "
                f"{preferred_count} with explicit active source)"
            )
            logger.debug(f"_populate_loopback_cache: Cached {len(self._loopback_cache)} nodes")
            
        except Exception as e:
            print(f"[DEBUG] _populate_loopback_cache: ERROR: {e}")
            logger.debug(f"_populate_loopback_cache: Error: {e}")
            import traceback
            traceback.print_exc()
            # 에러 발생 시 모든 노드를 False로 설정 (안전한 fallback)
            for node in self.nodes:
                self._loopback_cache[node] = False
                self._preferred_start_iface_cache[node] = ""

    def _get_preferred_start_iface(self, node_name: str) -> str:
        """
        노드별 선호 시작 인터페이스 반환.
        반환값이 빈 문자열이면 인터페이스를 명시하지 않고 노드명만 사용.
        """
        if not self._preferred_start_iface_cache:
            self._populate_loopback_cache()
        return self._preferred_start_iface_cache.get(str(node_name).lower(), "")
    
    def _has_loopback0(self, node_name: str) -> bool:
        """
        노드에 루프백 계열 시작 인터페이스가 있는지 확인 (하위 호환 이름)
        
        첫 호출 시 모든 노드의 정보를 한 번에 수집 (Lazy Batch Loading).
        이후 호출은 캐시에서 즉시 반환.
        
        Args:
            node_name: 확인할 노드 이름
            
        Returns:
            True if loopback-like start interface exists, False otherwise
        """
        # 캐시가 비어있으면 한 번만 전체 노드 정보 수집
        if not self._loopback_cache:
            print(f"[DEBUG] _has_loopback0: Cache is empty, triggering batch loading...")
            logger.debug("_has_loopback0: Cache empty, populating...")
            self._populate_loopback_cache()
            print(f"[DEBUG] _has_loopback0: Batch loading completed")
        
        preferred_iface = self._get_preferred_start_iface(node_name)
        result = self._loopback_cache.get(str(node_name).lower(), False)
        print(
            f"[DEBUG] _has_loopback0: {node_name} = {result} "
            f"(preferred_iface={preferred_iface or 'none'})"
        )
        logger.debug(f"_has_loopback0: {node_name} = {result} (from cache)")
        return result
    
    def _fix_start_location(self, location: str) -> str:
        """
        VRF 문제 방지: 루프백 계열 인터페이스가 있는 노드만 [인터페이스] 추가
        
        VRF 환경에서 PE/P 라우터는 루프백 인터페이스를 명시하여 global routing table 사용.
        Leaf 등 Access layer 장비는 Loopback이 없으므로 노드 이름만 사용.
        
        일반성: 모든 네트워크 토폴로지에 자동 적용 (명명 규칙 무관)
        확장성: 새로운 장비 타입 추가 시 코드 수정 불필요
        안정성: 캐싱으로 성능 최적화, 에러 시 안전한 fallback
        
        Args:
            location: 노드 이름 또는 "노드[인터페이스]" 형식
            
        Returns:
            루프백 계열 인터페이스 있으면: "노드[인터페이스]"
            없으면: "노드" (첫 번째 활성 인터페이스를 Batfish가 자동 선택)
            이미 인터페이스 명시: 그대로 반환
        """
        if '[' not in location:
            preferred_iface = self._get_preferred_start_iface(location)
            if preferred_iface:
                logger.debug(
                    "_fix_start_location: %s -> %s[%s]",
                    location,
                    location,
                    preferred_iface,
                )
                return f"{location}[{preferred_iface}]"

            logger.debug(
                "_fix_start_location: %s -> %s (no loopback-like interface)",
                location,
                location,
            )
            return location
        
        return location
    
    def initialize(self) -> bool:
        """Batfish 세션 초기화 및 스냅샷 로드"""
        try:
            logger.info(f"Connecting to Batfish at {self.batfish_host}...")
            # host:port 형식 처리 (port 미지정 시 9996 -> 9997 순서로 시도)
            if ":" in self.batfish_host:
                base_host, port = self.batfish_host.split(":")
                self.bf = Session(host=base_host, port=int(port))
            else:
                last_error = None
                for port in (9996, 9997):
                    try:
                        self.bf = Session(host=self.batfish_host, port=port)
                        logger.info(f"Connected to Batfish at {self.batfish_host}:{port}")
                        break
                    except Exception as e:
                        last_error = e
                        logger.warning(f"Failed Batfish session init at {self.batfish_host}:{port}: {e}")
                if self.bf is None:
                    raise last_error if last_error else RuntimeError("Failed to initialize Batfish session")
            
            logger.info(f"Setting network: {self.network_name}")
            self.bf.set_network(self.network_name)
            
            logger.info(f"Loading snapshot from: {self.snapshot_path}")
            self.snapshot_name = 'baseline'
            self.bf.init_snapshot(self.snapshot_path, name=self.snapshot_name, overwrite=True)
            
            # 노드 정보 수집
            self._collect_node_info()
            self._loopback_cache.clear()
            self._preferred_start_iface_cache.clear()
            
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
            
    # =========================================================================
    # Topology-Inferred Node Role Detection
    # =========================================================================
    # 이전: 이름 기반 휴리스틱 ('ce' in name.lower()) — 다른 토폴로지에서 실패
    # 현재: Batfish BGP 세션 분석 + Edge Degree로 역할 추론 → 토폴로지 독립적
    # Fallback: Batfish 데이터 없으면 이름 기반 휴리스틱 사용
    # =========================================================================
    
    _node_roles_cache: Optional[Dict[str, str]] = None

    def _infer_node_roles(self) -> Dict[str, str]:
        """
        Batfish BGP 세션 + L3 Edge Degree를 분석하여 노드 역할을 추론합니다.
        
        분류 기준:
        - 'edge' (CE/Leaf): eBGP 세션만 있거나, L3 연결이 1~2개인 단말 노드
        - 'provider_edge' (PE/Spine): eBGP + iBGP 세션 모두 보유한 경계 노드
        - 'core' (P/Transit): iBGP 세션만 있고, L3 연결이 3개 이상인 중계 노드
        - 'unknown': 분류 불가
        
        Returns:
            Dict[str, str]: {node_name: role} 매핑
        """
        if self._node_roles_cache is not None:
            return self._node_roles_cache
        
        roles: Dict[str, str] = {n: 'unknown' for n in self.nodes}
        
        if not self._initialized or not self.bf:
            # Batfish 미초기화 시 이름 기반 fallback
            logger.debug("_infer_node_roles: Batfish not initialized, using name-based fallback")
            roles = self._name_based_fallback()
            self._node_roles_cache = roles
            return roles
        
        try:
            # Step 1: BGP 세션 정보로 eBGP/iBGP 관계 파악
            bgp_sessions = self.bf.q.bgpSessionCompatibility().answer().frame()
            
            node_has_ebgp: set = set()
            node_has_ibgp: set = set()
            
            if not bgp_sessions.empty:
                for _, row in bgp_sessions.iterrows():
                    node = getattr(row.get('Node', ''), 'hostname', str(row.get('Node', '')))
                    session_type = str(row.get('Session_Type', ''))
                    
                    if 'ebgp' in session_type.lower():
                        node_has_ebgp.add(node)
                    elif 'ibgp' in session_type.lower():
                        node_has_ibgp.add(node)
            
            # Step 2: L3 Edge Degree 파악
            edges = self.get_layer3_edges()
            degree: Dict[str, int] = {n: 0 for n in self.nodes}
            for e in edges:
                n1, n2 = e.get('node1', ''), e.get('node2', '')
                if n1 in degree:
                    degree[n1] += 1
                if n2 in degree:
                    degree[n2] += 1
            
            # Step 3: 역할 분류
            for node in self.nodes:
                has_ebgp = node in node_has_ebgp
                has_ibgp = node in node_has_ibgp
                deg = degree.get(node, 0)
                
                if has_ebgp and not has_ibgp:
                    # eBGP만 → Customer Edge (외부 AS에만 연결)
                    roles[node] = 'edge'
                elif has_ebgp and has_ibgp:
                    # eBGP + iBGP → Provider Edge (내외부 경계)
                    roles[node] = 'provider_edge'
                elif has_ibgp and not has_ebgp:
                    if deg >= 3:
                        # iBGP만 + 높은 연결도 → Core Transit
                        roles[node] = 'core'
                    else:
                        # iBGP만 + 낮은 연결도 → Provider Edge
                        roles[node] = 'provider_edge'
                else:
                    # BGP 없는 노드 → Degree 기반 추론
                    if deg <= 2:
                        roles[node] = 'edge'
                    else:
                        roles[node] = 'core'
            
            logger.info(f"_infer_node_roles: Inferred roles: {roles}")
            
        except Exception as e:
            logger.warning(f"_infer_node_roles: Topology inference failed ({e}), using name-based fallback")
            roles = self._name_based_fallback()
        
        self._node_roles_cache = roles
        return roles
    
    def _name_based_fallback(self) -> Dict[str, str]:
        """이름 기반 역할 추론 (Fallback)"""
        roles: Dict[str, str] = {}
        for n in self.nodes:
            nl = n.lower()
            if 'ce' in nl or 'leaf' in nl:
                roles[n] = 'edge'
            elif 'pe' in nl or 'spine' in nl:
                roles[n] = 'provider_edge'
            elif nl.startswith('p') and not nl.startswith('pe'):
                roles[n] = 'core'
            else:
                roles[n] = 'unknown'
        return roles
    
    def get_edge_nodes(self) -> List[str]:
        """Edge 노드(CE/Leaf) 목록 반환 — 토폴로지 추론 기반"""
        roles = self._infer_node_roles()
        return [n for n, r in roles.items() if r == 'edge']
    
    def get_provider_edge_nodes(self) -> List[str]:
        """Provider Edge 노드(PE/Spine) 목록 반환 — 토폴로지 추론 기반"""
        roles = self._infer_node_roles()
        return [n for n, r in roles.items() if r == 'provider_edge']
    
    def get_core_nodes(self) -> List[str]:
        """Core Transit 노드(P) 목록 반환 — 토폴로지 추론 기반"""
        roles = self._infer_node_roles()
        return [n for n, r in roles.items() if r == 'core']
    
    def get_transit_nodes(self) -> List[str]:
        """Transit 노드(PE + P, 즉 Spine/PE/P) 목록 반환 — 토폴로지 추론 기반"""
        roles = self._infer_node_roles()
        return [n for n, r in roles.items() if r in ('provider_edge', 'core')]

    # Backward-compatible aliases
    def get_pe_nodes(self) -> List[str]:
        """PE 장비 목록 반환 — 토폴로지 추론 기반 (이전: 이름 기반)"""
        return self.get_provider_edge_nodes()
    
    def get_ce_nodes(self) -> List[str]:
        """CE 장비 목록 반환 — 토폴로지 추론 기반 (이전: 이름 기반)"""
        return self.get_edge_nodes()
    
    def get_spine_nodes(self) -> List[str]:
        """Spine 장비 목록 반환 — 토폴로지 추론 기반 (이전: 이름 기반)"""
        return self.get_provider_edge_nodes()
    
    def get_leaf_nodes(self) -> List[str]:
        """Leaf 장비 목록 반환 — 토폴로지 추론 기반 (이전: 이름 기반)"""
        return self.get_edge_nodes()
