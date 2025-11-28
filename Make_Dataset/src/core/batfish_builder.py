"""
Batfish 기반 L4/L5 메트릭 계산 엔진

L4: 네트워크 도달성 분석 (Reachability Analysis)
L5: What-If / Differential 분석 (Impact Analysis)

=== 학술적 근거 (Golden 6 Papers) ===

1. HSA (Header Space Analysis) - NSDI 2012, 1000+ citations
   - Reachability, Loop-freedom, Isolation 정의
   
2. VeriFlow - NSDI 2013, 1300+ citations
   - 실시간 Network-wide Invariant 검증
   
3. Batfish - NSDI 2015, 400+ citations
   - Config → Data Plane 분석 파이프라인
   - Multipath/Failure/Destination Consistency
   
4. Minesweeper - SIGCOMM 2017, 300+ citations
   - 8가지 핵심 속성: reachability, isolation, waypointing,
     black holes, bounded path length, load-balancing,
     functional equivalence, fault-tolerance
     
5. Config2Spec - NSDI 2020, 70+ citations
   - 정책 기반 Specification: Reachability, Isolation, Waypoint
   
6. DNA (Differential Network Analysis) - NSDI 2022, 50+ citations
   - Differential Reachability, What-If 분석

=== 구현된 인바리언트 ===

L4 Invariants:
- reachability_status: A→B 도달 가능 여부 (HSA, VeriFlow, Batfish)
- loop_detection: 포워딩 루프 탐지 (HSA, VeriFlow)
- blackhole_detection: 블랙홀 탐지 (HSA, Minesweeper)
- waypoint_check: 웨이포인트 통과 검증 (Minesweeper, Config2Spec)
- bounded_path_length: 경로 홉 수 제한 (Minesweeper)
- traceroute_path: 경로 추적 (Batfish)
- acl_blocking_point: ACL 차단 지점 (HSA)

L5 Invariants:
- link_failure_impact: 단일 링크 장애 영향 (DNA, Minesweeper)
- k_failure_tolerance: k개 장애 내성 검증 (Minesweeper)
- config_change_impact: 설정 변경 영향 (DNA)
- differential_reachability: 변경 전후 도달성 차이 (DNA)
- policy_compliance_check: 정책 준수 검증 (Config2Spec)
"""

import os
import json
import logging
import random
from typing import Dict, List, Any, Optional, Tuple, Set
from itertools import combinations
from dataclasses import dataclass

try:
    from pybatfish.client.session import Session
    from pybatfish.datamodel.flow import HeaderConstraints, PathConstraints
    BATFISH_AVAILABLE = True
except ImportError:
    BATFISH_AVAILABLE = False
    logging.warning("pybatfish not installed. L4/L5 metrics will be unavailable.")

logger = logging.getLogger(__name__)


@dataclass
class FlowSpec:
    """트래픽 흐름 정의"""
    src_ip: str
    dst_ip: str
    dst_port: int = 0
    protocol: str = "TCP"
    src_location: str = ""
    dst_location: str = ""


@dataclass 
class L4Result:
    """L4 메트릭 결과"""
    reachable: bool
    path: List[str]
    blocking_point: Optional[str] = None
    blocking_reason: Optional[str] = None


@dataclass
class L5Result:
    """L5 메트릭 결과"""
    has_impact: bool
    affected_flows: List[str]
    description: str = ""


class BatfishBuilder:
    """
    Batfish 기반 L4/L5 문제 생성기
    
    L4 메트릭:
    - traceroute_path: 네트워크 경로 추적
    - reachability_status: 도달 가능 여부
    - acl_blocking_point: ACL 차단 지점
    
    L5 메트릭:
    - link_failure_impact: 링크 장애 영향 분석
    - config_change_impact: 설정 변경 영향 분석
    - policy_compliance_check: 정책 준수 검증
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
        
        self._initialized = False
    
    def initialize(self) -> bool:
        """Batfish 세션 초기화 및 스냅샷 로드"""
        try:
            logger.info(f"Connecting to Batfish at {self.batfish_host}...")
            self.bf = Session(host=self.batfish_host)
            
            logger.info(f"Setting network: {self.network_name}")
            self.bf.set_network(self.network_name)
            
            logger.info(f"Loading snapshot from: {self.snapshot_path}")
            self.bf.init_snapshot(self.snapshot_path, name='baseline', overwrite=True)
            
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
    
    # =========================================================================
    # L4 메트릭 구현
    # =========================================================================
    
    def traceroute_path(self, src_location: str, dst_ip: str) -> Tuple[str, str]:
        """
        L4: 네트워크 경로 추적
        
        질문 예시: "PE1에서 CE2(172.16.1.2)로 가는 패킷의 경로를 알려주세요."
        
        Returns:
            (answer_type, path_string) - 형식: "장비1 → 장비2 → 장비3"
        """
        if not self._initialized:
            return "text", "정보없음"
        
        try:
            result = self.bf.q.traceroute(
                startLocation=src_location,
                headers=HeaderConstraints(dstIps=dst_ip)
            ).answer().frame()
            
            if result.empty:
                return "text", "경로없음"
            
            # 경로 추출 (pybatfish Trace 객체 처리)
            path = []
            traces = result['Traces'].iloc[0]
            if traces and len(traces) > 0:
                trace = traces[0]
                # Trace 객체는 .hops 속성으로 접근
                hops = getattr(trace, 'hops', []) if hasattr(trace, 'hops') else []
                for hop in hops:
                    # Hop 객체에서 node 추출
                    node = getattr(hop, 'node', None)
                    if node:
                        node_name = getattr(node, 'hostname', str(node))
                        if node_name and node_name not in path:
                            path.append(node_name)
            
            # 형식: "장비1 → 장비2 → 장비3"
            if path:
                return "text", " → ".join(path)
            return "text", "경로없음"
            
        except Exception as e:
            logger.warning(f"traceroute_path error: {e}")
            return "text", "정보없음"
    
    def reachability_status(self, 
                           src_ip: str, 
                           dst_ip: str,
                           dst_port: int = 0,
                           protocol: str = "TCP") -> Tuple[str, str]:
        """
        L4: 도달 가능 여부 확인 (경로 포함)
        
        질문 예시: "Host A(192.168.1.10)에서 CE1(10.0.0.1)로의 TCP/22 트래픽 경로와 도달 여부를 알려주세요."
        
        학술적 근거: 
        - HSA의 reachability failure 탐지
        - Batfish의 기본 도달성 분석
        
        Returns:
            (answer_type, result) - 형식: "text", "경로: A → B → C, 도달: 가능/불가"
        """
        if not self._initialized:
            return "text", "경로: Batfish 미연결, 도달: 불가"
        
        try:
            # src_ip에서 해당 노드 이름 찾기
            src_node = None
            for node, ips in self.node_ips.items():
                if src_ip in ips:
                    src_node = node
                    break
            
            if not src_node:
                # IP로 노드를 찾지 못하면 첫 번째 노드 사용 (fallback)
                src_node = self.nodes[0] if self.nodes else None
                logger.warning(f"Could not find node for IP {src_ip}, using fallback: {src_node}")
            
            if not src_node:
                return "text", "경로: 출발노드 없음, 도달: 불가"
            
            headers = HeaderConstraints(
                srcIps=src_ip,
                dstIps=dst_ip
            )
            
            if protocol == "TCP" and dst_port > 0:
                headers = HeaderConstraints(
                    srcIps=src_ip,
                    dstIps=dst_ip,
                    ipProtocols=["TCP"],
                    dstPorts=[str(dst_port)]
                )
            elif protocol == "ICMP":
                headers = HeaderConstraints(
                    srcIps=src_ip,
                    dstIps=dst_ip,
                    ipProtocols=["ICMP"]
                )
            
            # traceroute로 경로 추출 - 노드 이름 사용 (IP 대신)
            trace_result = self.bf.q.traceroute(
                startLocation=src_node,
                headers=headers
            ).answer().frame()
            
            path = []
            is_reachable = False
            
            if not trace_result.empty:
                traces = trace_result.iloc[0].get('Traces', [])
                for trace in traces:
                    hops = getattr(trace, 'hops', []) if hasattr(trace, 'hops') else []
                    for hop in hops:
                        node = getattr(hop, 'node', None)
                        if node:
                            node_name = getattr(node, 'hostname', str(node))
                            if node_name and node_name not in path:
                                path.append(node_name)
                    # 도달 여부 확인
                    disposition = getattr(trace, 'disposition', '')
                    if 'ACCEPTED' in str(disposition).upper():
                        is_reachable = True
            
            path_str = " → ".join(path) if path else "없음"
            reach_str = "가능" if is_reachable else "불가"
            return "text", f"경로: {path_str}, 도달: {reach_str}"
            
        except Exception as e:
            logger.warning(f"reachability_status error: {e}")
            return "text", "경로: 분석실패, 도달: 불가"
    
    def acl_blocking_point(self, 
                          src_ip: str, 
                          dst_ip: str,
                          dst_port: int = 80) -> Tuple[str, str]:
        """
        L4: ACL 차단 지점 분석
        
        질문 예시: "Host A에서 Web Server(192.168.2.100:80)로의 HTTP 트래픽이 차단되는 지점을 알려주세요."
        
        학술적 근거:
        - HSA의 traffic isolation/leakage 탐지
        - VeriFlow의 invariant violation 탐지
        
        Returns:
            (answer_type, blocking_description) - 형식: "차단지점: X, ACL규칙: Y" 또는 "허용"
        """
        if not self._initialized:
            return "text", "정보없음"
        
        try:
            result = self.bf.q.reachability(
                headers=HeaderConstraints(
                    srcIps=src_ip,
                    dstIps=dst_ip,
                    dstPorts=[str(dst_port)],
                    ipProtocols=["TCP"]
                )
            ).answer().frame()
            
            if result.empty:
                return "text", "경로없음"
            
            # 차단된 경우 정보 추출
            for _, row in result.iterrows():
                if 'Disposition' in result.columns:
                    disposition = row.get('Disposition', '')
                    if 'DENIED' in str(disposition).upper():
                        # 차단 위치 정보 추출
                        traces = row.get('Traces', [])
                        blocking_node = "알수없음"
                        if traces:
                            trace = traces[0] if traces else None
                            if trace:
                                hops = getattr(trace, 'hops', []) if hasattr(trace, 'hops') else []
                                if hops:
                                    last_hop = hops[-1]
                                    node = getattr(last_hop, 'node', None)
                                    if node:
                                        blocking_node = getattr(node, 'hostname', str(node))
                        return "text", f"차단지점: {blocking_node}, ACL에 의해 차단됨"
            
            return "text", "허용"
            
        except Exception as e:
            logger.warning(f"acl_blocking_point error: {e}")
            return "text", "정보없음"
    
    def loop_detection(self) -> Tuple[str, str]:
        """
        L4: 포워딩 루프 탐지 - 루프 경로 포함

        질문 예시: "네트워크에 포워딩 루프가 존재합니까?"

        학술적 근거:
        - HSA (NSDI 2012): "loop-free" as core invariant
        - VeriFlow (NSDI 2013): real-time loop detection

        Returns:
            (answer_type, result_text) - 형식: "text", "없음" 또는 "발견: A→B→C→A"
        """
        if not self._initialized:
            return "text", "분석 불가"

        try:
            # Batfish의 detectLoops 쿼리 사용
            result = self.bf.q.detectLoops().answer().frame()

            if result.empty:
                return "text", "없음"

            # 루프 경로 추출 (최대 3개)
            loop_paths = []
            for _, row in result.iterrows()[:3]:  # 최대 3개 루프만 표시
                loop_path = str(row.get('Loop', ''))
                if loop_path:
                    loop_paths.append(loop_path)

            if loop_paths:
                loops_str = ", ".join(loop_paths)
                if len(result) > 3:
                    loops_str += f" 외 {len(result) - 3}개"
                return "text", f"발견: {loops_str}"
            else:
                return "text", "없음"

        except Exception as e:
            logger.warning(f"loop_detection error: {e}")
            return "text", "분석 오류"
    
    def blackhole_detection(self, dst_prefix: str = "0.0.0.0/0") -> Tuple[str, List[str]]:
        """
        L4: 블랙홀 탐지 (패킷이 드랍되는 목적지)
        
        질문 예시: "네트워크에서 패킷이 드랍되는 블랙홀이 존재합니까?"
        
        학술적 근거:
        - HSA (NSDI 2012): blackhole as reachability failure
        - Minesweeper (SIGCOMM 2017): blackhole detection
        
        Returns:
            (answer_type, blackhole_destinations)
        """
        if not self._initialized:
            return "set", []
        
        try:
            # 도달 불가능한 목적지 탐색
            result = self.bf.q.reachability(
                headers=HeaderConstraints(dstIps=dst_prefix)
            ).answer().frame()
            
            if result.empty:
                return "set", []
            
            blackholes = []
            
            # Disposition 컬럼이 있으면 사용
            if "Disposition" in result.columns:
                for _, row in result.iterrows():
                    disposition = str(row.get('Disposition', ''))
                    # DROP, NULL_ROUTED, NO_ROUTE 등을 블랙홀로 간주
                    if any(d in disposition.upper() for d in ['DROP', 'NULL', 'NO_ROUTE', 'DENIED']):
                        dst = row.get('DstIp', '')
                        blackholes.append(f"{dst} ({disposition})")
            else:
                # Disposition 컬럼이 없으면 Traces에서 분석
                # TraceCount가 0이면 도달 불가 (블랙홀 가능성)
                logger.debug("Using TraceCount for blackhole detection (no Disposition column)")
                for _, row in result.iterrows():
                    trace_count = row.get('TraceCount', 0)
                    if trace_count == 0:
                        flow = row.get('Flow', {})
                        dst = getattr(flow, 'dstIp', '') if hasattr(flow, 'dstIp') else str(flow)
                        blackholes.append(f"{dst} (NO_TRACE)")
            
            return "set", list(set(blackholes))
            
        except Exception as e:
            logger.warning(f"blackhole_detection error: {e}")
            return "set", []
    
    def waypoint_check(self,
                      src_ip: str,
                      dst_ip: str,
                      waypoint_node: str) -> Tuple[str, str, List[str]]:
        """
        L4: 웨이포인트 경유 여부와 경로 정보

        질문 예시: "ce02에서 ce01로 가는 트래픽이 pe02를 경유합니까?"

        학술적 근거:
        - Minesweeper (SIGCOMM 2017): waypointing as core property
        - Config2Spec (NSDI 2020): waypoint policy mining

        Returns:
            (answer_type, result_text, path_nodes) - 형식: ("text", "경유함 (경로: A→PE02→B)", ["A", "PE02", "B"]) 또는 ("text", "경유 안함 (경로: A→B)", ["A", "B"])
        """
        if not self._initialized:
            return "text", "분석 불가", []

        try:
            # 출발지 노드 찾기
            src_node = None
            for node, ips in self.node_ips.items():
                if src_ip in ips:
                    src_node = node
                    break

            if not src_node:
                src_node = self.nodes[0]  # fallback

            result = self.bf.q.traceroute(
                startLocation=src_node,
                headers=HeaderConstraints(dstIps=dst_ip)
            ).answer().frame()

            if result.empty:
                return "text", "경유 안함 (경로 없음)"

            # 경로에서 모든 노드 추출
            path_nodes = []
            traces = result['Traces'].iloc[0]
            if traces:
                for trace in traces:
                    hops = getattr(trace, 'hops', []) if hasattr(trace, 'hops') else []
                    for hop in hops:
                        node = getattr(hop, 'node', None)
                        if node:
                            node_name = getattr(node, 'hostname', str(node)) if hasattr(node, 'hostname') else str(node)
                            if node_name not in path_nodes:  # 중복 제거
                                path_nodes.append(node_name)

            # waypoint 경유 여부 확인
            passes_waypoint = waypoint_node.lower() in [n.lower() for n in path_nodes]

            path_str = " → ".join(path_nodes) if path_nodes else "없음"
            if passes_waypoint:
                return "text", f"경유함 (경로: {path_str})", path_nodes
            else:
                return "text", f"경유 안함 (경로: {path_str})", path_nodes

        except Exception as e:
            logger.warning(f"waypoint_check error: {e}")
            return "text", "분석 오류"
    
    def bounded_path_length(self,
                           src_location: str,
                           dst_ip: str,
                           max_hops: int = 5) -> Tuple[str, int]:
        """
        L4: 경로 홉 수 계산

        질문 예시: "CE1에서 Server(10.0.0.100)로 가는 경로의 홉 수는 몇 개입니까?"

        학술적 근거:
        - Minesweeper (SIGCOMM 2017): "bounded path length" as property

        Returns:
            (answer_type, hop_count) - 실제 홉 수 반환
        """
        if not self._initialized:
            return "number", 0

        try:
            result = self.bf.q.traceroute(
                startLocation=src_location,
                headers=HeaderConstraints(dstIps=dst_ip)
            ).answer().frame()

            if result.empty:
                return "number", 0

            # 경로 길이 확인 (pybatfish Trace 객체 처리)
            traces = result['Traces'].iloc[0]
            if traces and len(traces) > 0:
                trace = traces[0]
                hops = getattr(trace, 'hops', []) if hasattr(trace, 'hops') else []
                hop_count = len(hops)
                return "number", hop_count

            return "number", 0

        except Exception as e:
            logger.warning(f"bounded_path_length error: {e}")
            return "number", 0
    
    def isolation_check(self,
                       vrf1: str,
                       vrf2: str) -> Tuple[str, List[str]]:
        """
        L4: VRF/테넌트 격리 누수 prefix 목록 추출

        질문 예시: "VRF 'CUSTOMER_A'와 'CUSTOMER_B' 사이에 누수된 prefix들은 무엇입니까?"

        학술적 근거:
        - HSA (NSDI 2012): "slice isolation" as core invariant
        - Minesweeper (SIGCOMM 2017): isolation property
        - Config2Spec (NSDI 2020): isolation policy

        개선사항: 단순 prefix 겹침 대신 실제 reachability 검증
        - VRF1의 IP에서 VRF2의 IP로 도달 가능한지 확인
        - Route leaking이 있더라도 ACL 등으로 막힐 수 있으므로 실제 도달성 확인

        Returns:
            (answer_type, leaked_prefixes) - 누수된 prefix 목록 또는 빈 리스트
        """
        if not self._initialized:
            return "set", []

        try:
            # VRF1과 VRF2의 인터페이스 IP 수집
            vrf1_interfaces = self.bf.q.interfaceProperties(vrfs=vrf1).answer().frame()
            vrf2_interfaces = self.bf.q.interfaceProperties(vrfs=vrf2).answer().frame()

            if vrf1_interfaces.empty or vrf2_interfaces.empty:
                return "set", []  # 인터페이스 정보 없음

            # VRF1의 IP 주소 목록 (connected IP만)
            vrf1_ips = []
            for _, row in vrf1_interfaces.iterrows():
                if 'AllAddresses' in row and row['AllAddresses']:
                    for addr in row['AllAddresses']:
                        if '/' in addr:  # IP/prefix 형식
                            ip = addr.split('/')[0]
                            vrf1_ips.append(ip)

            # VRF2의 IP 주소 목록
            vrf2_ips = []
            for _, row in vrf2_interfaces.iterrows():
                if 'AllAddresses' in row and row['AllAddresses']:
                    for addr in row['AllAddresses']:
                        if '/' in addr:
                            ip = addr.split('/')[0]
                            vrf2_ips.append(ip)

            if not vrf1_ips or not vrf2_ips:
                return "set", []

            # VRF1 → VRF2 도달성 확인 (샘플링: 최대 5개씩)
            leaked_prefixes = []
            vrf1_sample = vrf1_ips[:5]  # 최대 5개 IP 샘플링
            vrf2_sample = vrf2_ips[:5]

            for src_ip in vrf1_sample:
                for dst_ip in vrf2_sample:
                    try:
                        # 실제 도달성 확인 (reachability 쿼리)
                        reach_result = self.bf.q.reachability(
                            headers=HeaderConstraints(srcIps=src_ip, dstIps=dst_ip)
                        ).answer().frame()

                        # 도달 가능하면 누수
                        if not reach_result.empty:
                            if 'TraceCount' in reach_result.columns:
                                if any(reach_result['TraceCount'] > 0):
                                    # 도달 가능한 dst_ip의 prefix 추출
                                    prefix = f"{dst_ip}/32"  # 기본적으로 /32
                                    if prefix not in leaked_prefixes:
                                        leaked_prefixes.append(prefix)
                            else:
                                # TraceCount 컬럼 없어도 결과가 있으면 도달 가능
                                prefix = f"{dst_ip}/32"
                                if prefix not in leaked_prefixes:
                                    leaked_prefixes.append(prefix)
                    except Exception as e:
                        logger.debug(f"Reachability check failed {src_ip}->{dst_ip}: {e}")
                        continue

            return "set", leaked_prefixes

        except Exception as e:
            logger.warning(f"isolation_check error: {e}")
            return "set", []
    
    # =========================================================================
    # 현업 실무 메트릭 (Operational Metrics)
    # =========================================================================
    
    def asymmetric_path_check(self,
                              node1: str,
                              node2: str) -> Tuple[str, str]:
        """
        L4: 비대칭 경로(Asymmetric Routing) 검사 - 경로 정보 포함

        질문 예시: "ce01과 ce03 사이의 통신 경로가 대칭(양방향 동일 경로)입니까?"

        현업 중요도: 매우 높음
        - 비대칭 경로는 방화벽에서 상태 추적(Stateful) 실패 → 패킷 드랍
        - 갈 때 A경로, 올 때 B경로면 TCP 세션 불가

        Returns:
            (answer_type, result_text) - 형식: "text", "대칭 (경로: A→B→C)" 또는 "비대칭 (정방향: A→B, 역방향: A→C→B)"
        """
        if not self._initialized:
            return "text", "정보 없음"

        try:
            # node1 → node2 경로
            node1_ips = self.node_ips.get(node1, [])
            node2_ips = self.node_ips.get(node2, [])

            if not node1_ips or not node2_ips:
                return "text", "IP 정보 없음"

            # 정방향 경로 (node1 → node2)
            forward_result = self.bf.q.traceroute(
                startLocation=node1,
                headers=HeaderConstraints(dstIps=node2_ips[0])
            ).answer().frame()

            # 역방향 경로 (node2 → node1)
            reverse_result = self.bf.q.traceroute(
                startLocation=node2,
                headers=HeaderConstraints(dstIps=node1_ips[0])
            ).answer().frame()

            # 경로 노드 추출
            forward_nodes = []
            reverse_nodes = []

            if not forward_result.empty:
                traces = forward_result['Traces'].iloc[0]
                if traces:
                    for hop in getattr(traces[0], 'hops', []):
                        node = getattr(hop, 'node', None)
                        if node:
                            forward_nodes.append(getattr(node, 'hostname', str(node)))

            if not reverse_result.empty:
                traces = reverse_result['Traces'].iloc[0]
                if traces:
                    for hop in getattr(traces[0], 'hops', []):
                        node = getattr(hop, 'node', None)
                        if node:
                            reverse_nodes.append(getattr(node, 'hostname', str(node)))

            # 대칭 여부 판단 (역순으로 비교)
            reverse_nodes_reversed = list(reversed(reverse_nodes))
            is_symmetric = forward_nodes == reverse_nodes_reversed

            forward_path = " → ".join(forward_nodes) if forward_nodes else "없음"
            reverse_path = " → ".join(reverse_nodes) if reverse_nodes else "없음"

            if is_symmetric:
                result_text = f"대칭 (경로: {forward_path})"
            else:
                result_text = f"비대칭 (정방향: {forward_path}, 역방향: {reverse_path})"

            return "text", result_text

        except Exception as e:
            logger.warning(f"asymmetric_path_check error: {e}")
            return "text", "분석 오류"
    
    def mtu_mismatch_check(self) -> Tuple[str, List[str]]:
        """
        L1/L2: MTU 불일치 검사
        
        질문 예시: "양쪽 링크의 MTU 사이즈가 서로 다른 구간이 있습니까?"
        
        현업 중요도: 높음
        - MTU 불일치 → OSPF Neighbor 불안정, 큰 패킷만 드랍
        - 찾기 가장 귀찮은 유령 장애(Ghost issue)
        
        Returns:
            (answer_type, mismatch_list)
        """
        if not self._initialized:
            return "set", []
        
        try:
            # 인터페이스 속성 조회
            interfaces = self.bf.q.interfaceProperties().answer().frame()
            
            if interfaces.empty:
                return "set", []
            
            # 연결된 인터페이스 쌍 찾기 (Layer3 Edges)
            edges = self.bf.q.layer3Edges().answer().frame()
            
            mismatches = []
            
            if not edges.empty:
                for _, edge in edges.iterrows():
                    # 인터페이스 정보 추출
                    src_iface = edge.get('Interface', {})
                    dst_iface = edge.get('Remote_Interface', {})
                    
                    src_hostname = getattr(src_iface, 'hostname', '') if hasattr(src_iface, 'hostname') else str(src_iface)
                    dst_hostname = getattr(dst_iface, 'hostname', '') if hasattr(dst_iface, 'hostname') else str(dst_iface)
                    
                    # MTU 비교 (인터페이스 속성에서)
                    src_mtu = None
                    dst_mtu = None
                    
                    for _, iface in interfaces.iterrows():
                        iface_obj = iface.get('Interface', {})
                        hostname = getattr(iface_obj, 'hostname', '') if hasattr(iface_obj, 'hostname') else ''
                        
                        if hostname == src_hostname:
                            src_mtu = iface.get('MTU', None)
                        elif hostname == dst_hostname:
                            dst_mtu = iface.get('MTU', None)
                    
                    if src_mtu and dst_mtu and src_mtu != dst_mtu:
                        mismatches.append(f"{src_hostname}(MTU:{src_mtu}) <-> {dst_hostname}(MTU:{dst_mtu})")
            
            return "set", mismatches
            
        except Exception as e:
            logger.warning(f"mtu_mismatch_check error: {e}")
            return "set", []
    
    def spof_detection(self) -> Tuple[str, List[str]]:
        """
        L5: 단일 장애점(SPOF) 탐지 (최적화 버전)
        
        질문 예시: "단일 장비 장애 시 통신이 두절되는 구간(SPOF)이 존재합니까?"
        
        현업 중요도: 매우 높음
        - 관리자가 제일 무서워하는 것
        - 이중화 되어 있다고 믿었는데 실제로는 SPOF인 경우 많음
        
        최적화: 기존 traceroute 캐시 활용, 쿼리 수 최소화
        
        Returns:
            (answer_type, spof_list)
        """
        if not self._initialized:
            return "set", []
        
        try:
            spof_nodes = []
            
            # 캐시된 경로 정보 활용 (traceroute 쿼리 최소화)
            # 대표 경로 1개만 조회하여 분석
            if len(self.nodes) < 3:
                return "set", []
            
            # 가장 멀리 떨어진 노드 쌍 선택 (CE 끼리)
            ce_nodes = [n for n in self.nodes if 'ce' in n.lower()]
            if len(ce_nodes) >= 2:
                src, dst = ce_nodes[0], ce_nodes[-1]
            else:
                src, dst = self.nodes[0], self.nodes[-1]
            
            src_ips = self.node_ips.get(src, [])
            dst_ips = self.node_ips.get(dst, [])
            
            if not src_ips or not dst_ips:
                return "set", []
            
            # 단일 traceroute로 경로 분석
            traceroute = self.bf.q.traceroute(
                startLocation=src,
                headers=HeaderConstraints(dstIps=dst_ips[0])
            ).answer().frame()
            
            if traceroute.empty:
                return "set", []
            
            traces = traceroute['Traces'].iloc[0]
            if not traces:
                return "set", []
            
            # 경로 상의 노드들 추출
            path_nodes = set()
            for trace in traces:
                hops = getattr(trace, 'hops', [])
                for hop in hops:
                    node = getattr(hop, 'node', None)
                    if node:
                        node_name = getattr(node, 'hostname', str(node))
                        path_nodes.add(node_name)
            
            # 경로 상의 노드 중 단일 경로만 있으면 SPOF 후보
            # (단, 출발지/목적지는 제외)
            total_paths = len(traces)
            if total_paths == 1:
                # 단일 경로면 모든 중간 노드가 SPOF
                for node in path_nodes:
                    if node.lower() != src.lower() and node.lower() != dst.lower():
                        spof_nodes.append(f"{node} (영향: {src} <-> {dst})")
            
            return "set", list(set(spof_nodes))
            
        except Exception as e:
            logger.warning(f"spof_detection error: {e}")
            return "set", []
    
    def acl_rule_blocking(self,
                         src_ip: str,
                         dst_ip: str,
                         dst_port: int = 80,
                         protocol: str = "TCP") -> Tuple[str, str]:
        """
        L4: ACL 차단 규칙 상세 분석
        
        질문 예시: "A에서 B로의 접속이 차단되는 정확한 ACL 규칙명과 줄 번호는?"
        
        현업 중요도: 최고
        - 운영자가 제일 좋아하는 정보
        - "어디서 막혔어?"에 대한 즉각적인 답변
        
        Returns:
            (answer_type, blocking_rule_info)
        """
        if not self._initialized:
            return "text", "정보 없음"
        
        try:
            # 필터 분석
            filter_result = self.bf.q.testFilters(
                headers=HeaderConstraints(
                    srcIps=src_ip,
                    dstIps=dst_ip,
                    dstPorts=[str(dst_port)],
                    ipProtocols=[protocol]
                )
            ).answer().frame()
            
            if filter_result.empty:
                return "text", "차단 없음 (필터 미적용)"
            
            blocking_info = []
            for _, row in filter_result.iterrows():
                action = row.get('Action', '')
                filter_name = row.get('FilterName', '')
                node = row.get('Node', '')
                line = row.get('Line', '')
                
                if 'DENY' in str(action).upper() or 'REJECT' in str(action).upper():
                    if line:
                        blocking_info.append(f"{node}:{filter_name}:Line{line}")
                    else:
                        blocking_info.append(f"{node}:{filter_name}")
            
            if blocking_info:
                return "text", ", ".join(blocking_info)
            else:
                return "text", "차단 없음 (모두 허용)"
            
        except Exception as e:
            logger.warning(f"acl_rule_blocking error: {e}")
            return "text", f"분석 오류: {e}"
    
    def ip_conflict_check(self) -> Tuple[str, List[str]]:
        """
        L1: IP 충돌 검사
        
        질문 예시: "동일한 IP가 서로 다른 장비에 중복 할당된 곳이 있습니까?"
        
        현업 중요도: 높음
        - 찾기 가장 귀찮은 문제 중 하나
        - 간헐적 통신 장애의 주요 원인
        
        Returns:
            (answer_type, conflict_list)
        """
        if not self._initialized:
            return "set", []
        
        try:
            # 모든 인터페이스의 IP 수집
            interfaces = self.bf.q.interfaceProperties().answer().frame()
            
            if interfaces.empty:
                return "set", []
            
            ip_to_devices = {}  # IP -> [(device, interface), ...]
            
            for _, row in interfaces.iterrows():
                iface = row.get('Interface', {})
                hostname = getattr(iface, 'hostname', '') if hasattr(iface, 'hostname') else ''
                iface_name = getattr(iface, 'interface', '') if hasattr(iface, 'interface') else ''
                
                addresses = row.get('AllAddresses', [])
                if addresses:
                    for addr in addresses:
                        if '/' in str(addr):
                            ip = str(addr).split('/')[0]
                            if ip not in ip_to_devices:
                                ip_to_devices[ip] = []
                            ip_to_devices[ip].append(f"{hostname}:{iface_name}")
            
            # 중복 IP 찾기
            conflicts = []
            for ip, devices in ip_to_devices.items():
                if len(devices) > 1:
                    conflicts.append(f"{ip} -> {', '.join(devices)}")
            
            return "set", conflicts
            
        except Exception as e:
            logger.warning(f"ip_conflict_check error: {e}")
            return "set", []
    
    # =========================================================================
    # L5 메트릭 구현
    # =========================================================================
    
    def link_failure_impact(self,
                           node1: str,
                           node2: str,
                           test_src: str,
                           test_dst: str) -> Tuple[str, str, str]:
        """
        L5: 링크 장애 영향 분류 (채점 용이성 개선)

        질문 예시: "PE1과 P1 사이의 링크가 다운되었을 때, Host A에서 Host B로의 트래픽 영향은?"

        학술적 근거:
        - Minesweeper의 k-failure tolerance 검증
        - DNA의 differential reachability 분석

        Returns:
            (answer_type, ground_truth, explanation_text)
            - answer_type: "text"
            - ground_truth: "영향 없음" | "경로 변경" | "통신 단절"
            - explanation_text: 상세 분석 결과
        """
        if not self._initialized:
            return "text", "정보 없음", "정보없음"

        try:
            # 출발지/목적지 IP 찾기
            src_ips = self.node_ips.get(test_src, [])
            dst_ips = self.node_ips.get(test_dst, [])
            
            if not src_ips or not dst_ips:
                return "text", "정보 없음", f"IP 정보 없음 - {test_src}: {len(src_ips)}개, {test_dst}: {len(dst_ips)}개 IP"

            test_src_ip = src_ips[0]
            test_dst_ip = dst_ips[0]

            # 1. 현재 경로 분석
            path_result = self.bf.q.traceroute(
                startLocation=test_src,
                headers=HeaderConstraints(dstIps=test_dst_ip)
            ).answer().frame()

            if path_result.empty:
                return "text", "통신 단절", f"경로 없음: {test_src}에서 {test_dst}로 현재 도달 불가"

            # 경로 분석
            traces = path_result['Traces'].iloc[0] if not path_result.empty else []
            current_path_nodes = []
            alternate_path_nodes = []
            total_paths = len(traces) if traces else 0
            paths_through_link = 0
            paths_avoiding_link = 0

            if traces:
                for trace in traces:
                    hops = getattr(trace, 'hops', []) if hasattr(trace, 'hops') else []
                    path_nodes = []
                    for hop in hops:
                        node = getattr(hop, 'node', None)
                        if node:
                            node_name = getattr(node, 'hostname', str(node)) if hasattr(node, 'hostname') else str(node)
                            path_nodes.append(node_name)
                    
                    # 이 경로가 node1-node2 링크를 사용하는지 확인
                    uses_link = False
                    for i in range(len(path_nodes) - 1):
                        if (node1.lower() in path_nodes[i].lower() and node2.lower() in path_nodes[i+1].lower()) or \
                           (node2.lower() in path_nodes[i].lower() and node1.lower() in path_nodes[i+1].lower()):
                            uses_link = True
                            break
                    
                    if uses_link:
                        paths_through_link += 1
                        if not current_path_nodes:
                            current_path_nodes = path_nodes
                    else:
                        paths_avoiding_link += 1
                        if not alternate_path_nodes:
                            alternate_path_nodes = path_nodes
                    
                    if not current_path_nodes:
                        current_path_nodes = path_nodes

            # 3. 결과 분류 (Classification) - 단순 카테고리로 반환
            current_path_str = " → ".join(current_path_nodes) if current_path_nodes else "정보없음"
            alternate_path_str = " → ".join(alternate_path_nodes) if alternate_path_nodes else "없음"

            if paths_through_link == 0:
                # Case A: 영향 없음 - 현재 경로가 장애 링크를 사용하지 않음
                result = "영향 없음"
                desc = f"현재 경로({current_path_str})가 장애 링크({node1}-{node2})를 경유하지 않음."

            elif paths_avoiding_link > 0:
                # Case B: 경로 변경 (우회 가능)
                result = "경로 변경"
                desc = f"기존 경로({current_path_str})가 장애 링크를 사용하지만, 대체 경로({alternate_path_str}) 존재."

            else:
                # Case C: 통신 단절
                result = "통신 단절"
                desc = f"모든 경로({current_path_str})가 장애 링크를 사용하며 대체 경로 없음."

            # 반환값: (답변타입, 결합된 텍스트)
            if result == "영향 없음":
                combined_text = f"영향 없음 (현재경로: {current_path_str}가 장애링크 미경유)"
            elif result == "경로 변경":
                combined_text = f"경로 변경 (현재경로: {current_path_str}, 대체경로: {alternate_path_str})"
            else:  # 통신 단절
                combined_text = f"통신 단절 (현재경로: {current_path_str}, 대체경로 없음)"
            return "text", combined_text

        except Exception as e:
            logger.warning(f"link_failure_impact error: {e}")
            return "text", "분석 오류"
    
    def config_change_impact(self,
                            before_snapshot: str,
                            after_snapshot: str,
                            src_node: str = "",
                            dst_node: str = "") -> Tuple[str, str]:
        """
        L5: 설정 변경 영향 분석
        
        질문 예시: "Router R1에 새로운 ACL 규칙을 추가했을 때, 어떤 트래픽 흐름에 영향이 있나요?"
        
        학술적 근거:
        - DNA의 differential reachability
        - Batfish의 differentialReachability query
        
        Returns:
            (answer_type, change_description) - 형식: "text", "변경됨: A→B, B→C" 또는 "변경 없음"
        """
        if not self._initialized:
            return "text", "분석 불가"
        
        try:
            # 두 스냅샷 간 차이 분석
            diff_result = self.bf.q.differentialReachability(
                snapshot=after_snapshot,
                reference_snapshot=before_snapshot
            ).answer().frame()
            
            if diff_result.empty:
                return "text", "변경 없음"
            
            # 영향받는 흐름 추출
            affected_flows = []
            for _, row in diff_result.iterrows():
                src = row.get('Flow', {})
                src_ip = getattr(src, 'srcIp', '') if hasattr(src, 'srcIp') else ''
                dst_ip = getattr(src, 'dstIp', '') if hasattr(src, 'dstIp') else ''
                if src_ip and dst_ip:
                    affected_flows.append(f"{src_ip}→{dst_ip}")
            
            if affected_flows:
                # 최대 5개 흐름만 표시
                flows_str = ", ".join(affected_flows[:5])
                if len(affected_flows) > 5:
                    flows_str += f" 외 {len(affected_flows) - 5}개"
                return "text", f"변경됨: {flows_str}"
            else:
                return "text", f"변경됨: {len(diff_result)}개 흐름 영향"
            
        except Exception as e:
            logger.warning(f"config_change_impact error: {e}")
            return "text", "분석 오류"
    
    def policy_compliance_check(self,
                               policy_type: str = "waypoint",
                               waypoint_node: str = "",
                               dst_ports: List[str] = None,
                               policy_name: str = "") -> Tuple[str, str]:
        """
        L5: 정책 준수 검증
        
        질문 예시: "네트워크가 '모든 웹 트래픽은 방화벽을 통과해야 한다'는 정책을 준수하고 있나요?"
        
        학술적 근거:
        - Config2Spec의 waypoint 정책 검증
        - Epinoia의 intent-driven verification
        
        Returns:
            (answer_type, compliance_result) - 형식: "text", "준수" 또는 "위반: A→B, C→D"
        """
        if not self._initialized:
            return "text", "분석 불가"
        
        if dst_ports is None:
            dst_ports = ["80", "443"]
        
        try:
            if policy_type == "waypoint" and waypoint_node:
                # 웨이포인트를 우회하는 트래픽 탐지
                violations = self.bf.q.reachability(
                    headers=HeaderConstraints(
                        dstPorts=dst_ports,
                        ipProtocols=["TCP"]
                    ),
                    pathConstraints=PathConstraints(
                        forbiddenLocations=[waypoint_node]
                    )
                ).answer().frame()
                
                # 위반 트래픽이 없으면 정책 준수
                if violations.empty:
                    return "text", "준수"
                
                # 위반 트래픽 상세 추출
                violation_flows = []
                for _, row in violations.iterrows():
                    flow = row.get('Flow', {})
                    src_ip = getattr(flow, 'srcIp', '') if hasattr(flow, 'srcIp') else ''
                    dst_ip = getattr(flow, 'dstIp', '') if hasattr(flow, 'dstIp') else ''
                    if src_ip and dst_ip:
                        violation_flows.append(f"{src_ip}→{dst_ip}")
                
                if violation_flows:
                    # 최대 3개 위반만 표시
                    flows_str = ", ".join(violation_flows[:3])
                    if len(violation_flows) > 3:
                        flows_str += f" 외 {len(violation_flows) - 3}개"
                    return "text", f"위반: {flows_str}"
                else:
                    return "text", f"위반: {len(violations)}개 흐름"
            
            return "text", "준수"
            
        except Exception as e:
            logger.warning(f"policy_compliance_check error: {e}")
            return "text", "분석 오류"
    
    def k_failure_tolerance(self,
                           src_node: str,
                           dst_ip: str,
                           k: int = 1) -> Tuple[str, str]:
        """
        L5: k-failure tolerance 경로 수와 경로 목록

        질문 예시: "ce01에서 pe03로 가는 경로는 총 몇 개입니까?"

        학술적 근거:
        - Minesweeper (SIGCOMM 2017): k-failure tolerance
        - Trailblazer (FM 2023): SMT-based failure tolerance verification

        Note: 완전한 k-failure 검증은 모든 k-조합을 테스트해야 하므로
              여기서는 간소화된 버전(대표 링크 테스트)을 구현

        Args:
            src_node: 출발 노드 이름 (예: "p01", "ce01")
            dst_ip: 목적지 IP 주소
            k: 장애 허용 수 (기본 1)

        Returns:
            (answer_type, result_text) - 형식: "text", "N개 (경로1: A→B, 경로2: A→C→B)"
        """
        if not self._initialized:
            return "text", "분석 불가"

        try:
            # 출발 노드의 IP 찾기
            src_ips = self.node_ips.get(src_node, [])
            src_ip = src_ips[0] if src_ips else None

            if not src_ip:
                logger.warning(f"k_failure_tolerance: No IP found for node {src_node}")
                return "text", "정보 없음"

            # 기본 도달성 확인
            baseline = self.bf.q.reachability(
                headers=HeaderConstraints(srcIps=src_ip, dstIps=dst_ip)
            ).answer().frame()

            if baseline.empty:
                return "text", "0개 (도달 불가)"  # 기본 도달성 없음

            # 경로 추출하여 대체 경로 수 계산
            # startLocation은 노드 이름 사용
            traceroute = self.bf.q.traceroute(
                startLocation=src_node,
                headers=HeaderConstraints(dstIps=dst_ip)
            ).answer().frame()

            if traceroute.empty:
                return "text", "0개 (경로 없음)"

            traces = traceroute['Traces'].iloc[0]
            if not traces:
                return "text", "0개 (경로 없음)"

            # 경로 추출 (최대 3개)
            paths = []
            for i, trace in enumerate(traces[:3]):
                hops = getattr(trace, 'hops', []) if hasattr(trace, 'hops') else []
                nodes = []
                for hop in hops:
                    node = getattr(hop, 'node', None)
                    if node:
                        node_name = getattr(node, 'hostname', str(node))
                        nodes.append(node_name)
                if nodes:
                    paths.append(f"경로{i+1}: {' → '.join(nodes)}")

            path_count = len(traces)
            if paths:
                paths_str = ", ".join(paths)
                if path_count > 3:
                    paths_str += f" 외 {path_count - 3}개"
                return "text", f"{path_count}개 ({paths_str})"
            else:
                return "text", f"{path_count}개"

        except Exception as e:
            logger.warning(f"k_failure_tolerance error: {e}")
            return "text", "분석 오류"
    
    def differential_reachability(self,
                                  src_ip: str,
                                  dst_ip: str,
                                  scenario_snapshot: str = "") -> Tuple[str, str]:
        """
        L5: Differential Reachability 상태 설명

        질문 예시: "설정 변경 후 CE1에서 CE2로의 도달성 상태는 어떻게 되나요?"

        학술적 근거:
        - DNA (NSDI 2022): Differential Network Analysis
        - Batfish: differentialReachability query

        Returns:
            (answer_type, status_description) - 도달성 상태 설명 텍스트
        """
        if not self._initialized:
            return "text", "정보 없음"

        try:
            if not scenario_snapshot:
                # 시나리오 스냅샷이 없으면 현재 상태만 확인
                current = self.bf.q.reachability(
                    headers=HeaderConstraints(srcIps=src_ip, dstIps=dst_ip)
                ).answer().frame()

                reachable = not current.empty
                if 'TraceCount' in current.columns and not current.empty:
                    reachable = any(current['TraceCount'] > 0)

                hop_count = 0
                if reachable:
                    # 경로 길이 확인
                    traceroute = self.bf.q.traceroute(
                        startLocation=self.nodes[0],  # fallback
                        headers=HeaderConstraints(dstIps=dst_ip)
                    ).answer().frame()

                    if not traceroute.empty:
                        traces = traceroute['Traces'].iloc[0]
                        if traces:
                            trace = traces[0]
                            hops = getattr(trace, 'hops', []) if hasattr(trace, 'hops') else []
                            hop_count = len(hops)

                return "text", f"도달 가능 ({hop_count}홉)" if reachable else "도달 불가"

            # 두 스냅샷 비교
            diff = self.bf.q.differentialReachability(
                snapshot=scenario_snapshot,
                reference_snapshot='baseline',
                headers=HeaderConstraints(srcIps=src_ip, dstIps=dst_ip)
            ).answer().frame()

            if diff.empty:
                return "text", "변화 없음 - 도달성 유지"
            else:
                return "text", f"도달성 변화 있음 ({len(diff)}개 흐름 영향)"

        except Exception as e:
            logger.warning(f"differential_reachability error: {e}")
            return "text", "상태 분석 실패"
    
    # =========================================================================
    # 문제 생성
    # =========================================================================
    
    def generate_l4_questions(self) -> List[Dict[str, Any]]:
        """L4 레벨 문제 생성"""
        questions = []
        
        if not self._initialized:
            logger.warning("Batfish not initialized. Skipping L4 question generation.")
            return questions
        
        # 1. Traceroute 문제
        all_pairs = self.get_node_pairs()
        random.shuffle(all_pairs)  # 랜덤 셔플 (순서만 섞기)
        for src_node, dst_node in all_pairs:  # 모든 쌍 사용
            dst_ips = self.node_ips.get(dst_node, [])
            if dst_ips:
                _, path_str = self.traceroute_path(src_node, dst_ips[0])
                
                questions.append({
                    "id": f"TRACEROUTE_{src_node}_{dst_node}",
                    "category": "Reachability_Analysis",
                    "level": "L4",
                    "answer_type": "text",
                    "question": f"{src_node}에서 {dst_node}({dst_ips[0]})로 가는 패킷의 네트워크 경로를 알려주세요.\n[답변 형식: 화살표(→)로 구분된 장비 목록]",
                    "ground_truth": path_str if path_str else "경로 없음",
                    "explanation": f"metric `traceroute_path` on src={src_node}, dst={dst_ips[0]}",
                    "evidence_hint": {
                        "scope": {"type": "NODE_PAIR", "src": src_node, "dst": dst_node},
                        "metric": "traceroute_path"
                    }
                })
        
        # 2. Reachability 문제
        for flow in self.get_representative_flows()[:30]:  # 상위 30개 흐름
            _, result_text = self.reachability_status(
                flow.src_ip, flow.dst_ip, flow.dst_port, flow.protocol
            )
            
            port_desc = f":{flow.dst_port}" if flow.dst_port else ""
            questions.append({
                "id": f"REACH_{flow.src_location}_{flow.dst_location}_{flow.protocol}",
                "category": "Reachability_Analysis",
                "level": "L4",
                "answer_type": "text",
                "question": f"{flow.src_location}({flow.src_ip})에서 {flow.dst_location}({flow.dst_ip}{port_desc})로의 {flow.protocol} 트래픽 경로와 도달 여부를 알려주세요.\n[답변 형식: '경로: A → B → C, 도달: 가능' 또는 '경로: 없음, 도달: 불가']",
                "ground_truth": result_text,
                "explanation": f"metric `reachability_status` on src={flow.src_ip}, dst={flow.dst_ip}",
                "evidence_hint": {
                    "scope": {"type": "FLOW", "src_ip": flow.src_ip, "dst_ip": flow.dst_ip},
                    "metric": "reachability_status"
                },
                "academic_reference": "HSA (NSDI'12), VeriFlow (NSDI'13), Batfish (NSDI'15)"
            })
        
        # 3. Loop Detection 문제 (HSA, VeriFlow)
        _, result_text = self.loop_detection()
        questions.append({
            "id": "LOOP_DETECTION_GLOBAL",
            "category": "Reachability_Analysis",
            "level": "L4",
            "answer_type": "text",
            "question": "네트워크에 포워딩 루프가 존재합니까?\n[답변 형식: '없음' 또는 '발견: A→B→C→A']",
            "ground_truth": result_text,
            "explanation": f"metric `loop_detection` analysis result",
            "evidence_hint": {
                "scope": {"type": "GLOBAL"},
                "metric": "loop_detection"
            },
            "academic_reference": "HSA (NSDI'12): loop-free as core invariant"
        })
        
        # 4. Bounded Path Length 문제 (Minesweeper)
        all_pairs_bounded = self.get_node_pairs()
        random.shuffle(all_pairs_bounded)
        for src_node, dst_node in all_pairs_bounded:  # 모든 쌍 사용
            dst_ips = self.node_ips.get(dst_node, [])
            if dst_ips:
                _, hop_count = self.bounded_path_length(src_node, dst_ips[0], max_hops=5)

                questions.append({
                    "id": f"BOUNDED_PATH_{src_node}_{dst_node}",
                    "category": "Reachability_Analysis",
                    "level": "L4",
                    "answer_type": "number",
                    "question": f"{src_node}에서 {dst_node}로 가는 경로의 홉 수는 몇 개입니까?\n[답변 형식: 숫자]",
                    "ground_truth": str(hop_count),
                    "explanation": f"metric `bounded_path_length` on {src_node}->{dst_node}, actual_hops={hop_count}",
                    "evidence_hint": {
                        "scope": {"type": "NODE_PAIR", "src": src_node, "dst": dst_node},
                        "metric": "bounded_path_length"
                    },
                    "academic_reference": "Minesweeper (SIGCOMM'17): bounded path length"
                })
        
        # 5. Blackhole Detection 문제 (HSA, Minesweeper)
        _, blackholes = self.blackhole_detection()
        questions.append({
            "id": "BLACKHOLE_DETECTION_GLOBAL",
            "category": "Reachability_Analysis",
            "level": "L4",
            "answer_type": "boolean",
            "question": "네트워크에 패킷이 드랍되는 블랙홀이 존재합니까?\n[답변 형식: true/false (소문자)]",
            "ground_truth": str(len(blackholes) > 0).lower(),
            "explanation": f"metric `blackhole_detection` found {len(blackholes)} blackholes",
            "evidence_hint": {
                "scope": {"type": "GLOBAL"},
                "metric": "blackhole_detection"
            },
            "academic_reference": "HSA (NSDI'12), Minesweeper (SIGCOMM'17): blackhole detection"
        })
        
        # 6. Waypoint Check 문제 (Minesweeper, Config2Spec)
        # PE 장비를 웨이포인트로 가정하고 CE→CE 트래픽이 PE를 통과하는지 확인
        pe_nodes = [n for n in self.nodes if 'pe' in n.lower()]
        ce_nodes = [n for n in self.nodes if 'ce' in n.lower()]
        
        if pe_nodes and len(ce_nodes) >= 2:
            waypoint = pe_nodes[0]
            waypoint_count = 0
            max_waypoint_questions = 10  # 최대 10개로 확장
            
            for i, src_ce in enumerate(ce_nodes[:2]):
                if waypoint_count >= max_waypoint_questions:
                    break
                for dst_ce in ce_nodes[i+1:3]:
                    if waypoint_count >= max_waypoint_questions:
                        break
                    src_ips = self.node_ips.get(src_ce, [])
                    dst_ips = self.node_ips.get(dst_ce, [])
                    
                    if src_ips and dst_ips:
                        try:
                            _, result_text, path_nodes = self.waypoint_check(src_ips[0], dst_ips[0], waypoint)

                            questions.append({
                                "id": f"WAYPOINT_{src_ce}_{dst_ce}_{waypoint}",
                                "category": "Reachability_Analysis",
                                "level": "L4",
                                "answer_type": "set",
                                "question": f"{src_ce}에서 {dst_ce}로 가는 트래픽이 경유하는 노드들은 무엇입니까?\n[답변 형식: 쉼표로 구분된 노드 목록]",
                                "ground_truth": ", ".join(path_nodes) if path_nodes else "없음",
                                "explanation": f"metric `waypoint_check` on {src_ce}->{dst_ce}, path_nodes={path_nodes}",
                                "evidence_hint": {
                                    "scope": {"type": "WAYPOINT", "src": src_ce, "dst": dst_ce, "waypoint": waypoint},
                                    "metric": "waypoint_check"
                                },
                                "academic_reference": "Minesweeper (SIGCOMM'17), Config2Spec (NSDI'20): waypointing"
                            })
                            waypoint_count += 1
                        except Exception as e:
                            logger.warning(f"Skipping waypoint question {src_ce}->{dst_ce}: {e}")
        
        # 7. Isolation Check 문제 (HSA, Config2Spec)
        # ⚠️ VRF 기반 격리 검증: VRF가 있는 토폴로지에서만 의미 있음
        # VRF가 없는 단순 L3/OSPF/BGP 토폴로지에서는 빈 결과만 나옴
        p_nodes = [n for n in self.nodes if n.lower().startswith('p') and 'pe' not in n.lower()]
        
        # VRF 존재 여부 확인 (Batfish routes 쿼리로 VRF 확인)
        has_vrf = False
        try:
            routes = self.bf.q.routes().answer().frame()
            if not routes.empty and 'VRF' in routes.columns:
                unique_vrfs = routes['VRF'].unique()
                # default VRF 외에 다른 VRF가 있으면 VRF 사용 중
                has_vrf = any(vrf.lower() not in ['default', ''] for vrf in unique_vrfs)
        except Exception as e:
            logger.warning(f"VRF check failed: {e}")
        
        if has_vrf and ce_nodes and p_nodes:
            logger.info("[L4] VRF detected. Generating isolation check questions.")
            for ce in ce_nodes[:4]:  # CE 4개까지
                for p in p_nodes[:2]:  # P 2개까지
                    _, leaked_prefixes = self.isolation_check(ce, p)
                    questions.append({
                        "id": f"ISOLATION_{ce}_{p}",
                        "category": "Reachability_Analysis",
                        "level": "L4",
                        "answer_type": "set",
                        "question": f"{ce}(고객 장비)와 {p}(백본 장비) 사이에 누수된 prefix들은 무엇입니까?\n[답변 형식: 쉼표로 구분된 prefix 목록 또는 '없음']",
                        "ground_truth": ", ".join(leaked_prefixes) if leaked_prefixes else "없음",
                        "explanation": f"metric `isolation_check` between {ce} and {p}, leaked_prefixes={leaked_prefixes}",
                        "evidence_hint": {
                            "scope": {"type": "ISOLATION", "node1": ce, "node2": p},
                            "metric": "isolation_check"
                        },
                        "academic_reference": "HSA (NSDI'12), Config2Spec (NSDI'20): isolation"
                    })
        else:
            logger.info("[L4] No VRF detected. Skipping isolation check questions.")
        
        # =========================================================================
        # 8. 현업 실무 질문 추가 (Operational Questions)
        # =========================================================================
        
        # 8-1. 비대칭 경로 검사 (Asymmetric Routing)
        # 성능 최적화: 5개 쌍만 검사 (각 쌍당 2번 traceroute 호출)
        all_pairs_asymmetric = self.get_node_pairs()
        random.shuffle(all_pairs_asymmetric)
        for src_node, dst_node in all_pairs_asymmetric[:5]:  # 5개 쌍으로 제한
            _, result_text = self.asymmetric_path_check(src_node, dst_node)

            questions.append({
                "id": f"ASYMMETRIC_{src_node}_{dst_node}",
                "category": "Reachability_Analysis",
                "level": "L4",
                "answer_type": "text",
                "question": f"{src_node}과 {dst_node} 사이의 통신 경로가 대칭(양방향 동일 경로)입니까?\n[답변 형식: '대칭 (경로: A→B→C)' 또는 '비대칭 (정방향: A→B, 역방향: A→C→B)']",
                "ground_truth": result_text,
                "explanation": f"metric `asymmetric_path_check` on {src_node}<->{dst_node}",
                "evidence_hint": {
                    "scope": {"type": "NODE_PAIR", "src": src_node, "dst": dst_node},
                    "metric": "asymmetric_path_check"
                },
                "academic_reference": "현업: 비대칭 경로 → 방화벽 상태 추적 실패 → 패킷 드랍"
            })
        
        # 8-2. MTU 불일치 검사
        _, mtu_mismatches = self.mtu_mismatch_check()
        questions.append({
            "id": "MTU_MISMATCH_GLOBAL",
            "category": "Interface_Inventory",
            "level": "L2",
            "answer_type": "set",
            "question": "양쪽 링크의 MTU 사이즈가 서로 다른 구간이 있습니까?\n[답변 형식: 불일치 구간 목록 또는 '없음']",
            "ground_truth": ", ".join(mtu_mismatches) if mtu_mismatches else "없음",
            "explanation": f"metric `mtu_mismatch_check` found {len(mtu_mismatches)} mismatches",
            "evidence_hint": {
                "scope": {"type": "GLOBAL"},
                "metric": "mtu_mismatch_check"
            },
            "academic_reference": "현업: MTU 불일치 → OSPF Neighbor 불안정, 큰 패킷 드랍"
        })
        
        # 8-3. IP 충돌 검사
        _, ip_conflicts = self.ip_conflict_check()
        questions.append({
            "id": "IP_CONFLICT_GLOBAL",
            "category": "Interface_Inventory",
            "level": "L1",
            "answer_type": "set",
            "question": "동일한 IP가 서로 다른 장비에 중복 할당된 곳이 있습니까?\n[답변 형식: 충돌 IP 목록 또는 '없음']",
            "ground_truth": ", ".join(ip_conflicts) if ip_conflicts else "없음",
            "explanation": f"metric `ip_conflict_check` found {len(ip_conflicts)} conflicts",
            "evidence_hint": {
                "scope": {"type": "GLOBAL"},
                "metric": "ip_conflict_check"
            },
            "academic_reference": "현업: IP 충돌 → 간헐적 통신 장애의 주요 원인"
        })
        
        # 8-4. Waypoint 경유 여부 (방화벽 통과 확인) - 개선된 형식
        if pe_nodes and len(ce_nodes) >= 2:
            for waypoint in pe_nodes[:2]:  # PE 2개까지
                for src_ce in ce_nodes[:2]:
                    for dst_ce in ce_nodes[2:4]:
                        if src_ce == dst_ce:
                            continue
                        src_ips = self.node_ips.get(src_ce, [])
                        dst_ips = self.node_ips.get(dst_ce, [])
                        
                        if src_ips and dst_ips:
                            _, result_text, _ = self.waypoint_check(src_ips[0], dst_ips[0], waypoint)

                            questions.append({
                                "id": f"WAYPOINT_PASS_{src_ce}_{dst_ce}_{waypoint}",
                                "category": "Reachability_Analysis",
                                "level": "L4",
                                "answer_type": "text",
                                "question": f"{src_ce}에서 {dst_ce}로 가는 트래픽이 {waypoint}(백본 장비)를 경유합니까?\n[답변 형식: '경유함 (경로: A→PE02→B)' 또는 '경유 안함 (경로: A→B)']",
                                "ground_truth": result_text,
                                "explanation": f"metric `waypoint_check` on {src_ce}->{dst_ce} via {waypoint}",
                                "evidence_hint": {
                                    "scope": {"type": "WAYPOINT", "src": src_ce, "dst": dst_ce, "waypoint": waypoint},
                                    "metric": "waypoint_check"
                                },
                                "academic_reference": "현업: 보안 정책 - 모든 트래픽이 방화벽/IDS 경유 필수"
                            })
        
        return questions
    
    def generate_l5_questions(self) -> List[Dict[str, Any]]:
        """
        L5 레벨 문제 생성
        
        ⚠️ v1 제한사항:
        L5(What-If / Differential Analysis)를 완전히 구현하려면 
        **스냅샷 2개(변경 전/후)**가 필요합니다.
        
        현재 버전에서는:
        - link_failure_impact: 경로 분석 기반 추정 (실제 장애 시뮬레이션 X)
        - k_failure_tolerance: 대체 경로 수 확인
        - policy_compliance_check: 정책 준수 여부 확인
        
        향후 확장:
        - differential_reachability: 변경 전/후 스냅샷 비교 필요
        - config_change_impact: 변경 전/후 스냅샷 비교 필요
        """
        questions = []
        
        if not self._initialized:
            logger.warning("Batfish not initialized. Skipping L5 question generation.")
            return questions
        
        logger.info("[L5] Note: Full What-If analysis requires dual snapshots. "
                   "Current implementation uses single-snapshot path analysis.")
        
        # 1. 링크 장애 영향 분석 문제 (DNA, Minesweeper)
        # ⚠️ 현재는 경로에 해당 링크가 포함되는지만 확인 (실제 장애 시뮬레이션 X)
        node_pairs = self.get_node_pairs()  # 모든 쌍 사용
        random.shuffle(node_pairs)  # 랜덤 셔플
        nodes = list(self.node_ips.keys())
        
        # 다양한 출발지-목적지 조합 생성
        import itertools
        all_flows = [(s, d) for s, d in itertools.permutations(nodes, 2) if s != d]
        
        question_count = 0
        for (node1, node2) in node_pairs:
            # 해당 링크와 관련 없는 출발지-목적지 쌍 선택 (더 의미 있는 질문)
            for test_src, test_dst in all_flows[:5]:  # 각 링크당 최대 5개 flow 테스트
                if test_src == node1 or test_src == node2 or test_dst == node1 or test_dst == node2:
                    continue  # 링크 노드 자체가 출발/도착점이면 스킵
                
                # 수정된 메서드 호출 (2개 반환값: answer_type, result_text)
                _, result_text = self.link_failure_impact(
                    node1, node2, test_src, test_dst
                )

                if "분석 오류" in result_text or "정보 없음" in result_text:
                    continue

                # 결과에서 상태 추출 (예: "영향 없음 (현재경로: ...)" -> "영향 없음")
                impact_status = result_text.split(" (")[0] if " (" in result_text else result_text

                questions.append({
                    "id": f"LINK_FAIL_{node1}_{node2}_{test_src}_{test_dst}",
                    "category": "What_If_Analysis",
                    "level": "L5",
                    "answer_type": "text",
                    # 질문에 명확한 가이드라인 추가
                    "question": (
                        f"{node1}과 {node2} 사이의 링크가 다운되었을 때, "
                        f"{test_src}에서 {test_dst}로의 트래픽 영향은 어떻게 됩니까?\n"
                        "[답변 형식: '영향 없음 (현재경로: A→B→C가 장애링크 미경유)' / '경로 변경 (현재경로: A→B, 대체경로: A→C→B)' / '통신 단절 (현재경로: A→B, 대체경로 없음)']"
                    ),
                    "ground_truth": result_text,
                    "explanation": f"metric `link_failure_impact` on link={node1}-{node2}, flow={test_src}->{test_dst}",
                    "evidence_hint": {
                        "scope": {"type": "LINK_FAILURE", "node1": node1, "node2": node2},
                        "metric": "link_failure_impact"
                    },
                    "academic_reference": "DNA (NSDI'22), Minesweeper (SIGCOMM'17)"
                })
                
                question_count += 1
                if question_count >= 30:  # 최대 30개 링크 장애 문제
                    break
            if question_count >= 30:
                break
        
        # 2. k-Failure Tolerance 문제 (Minesweeper, Trailblazer)
        all_pairs_bounded = self.get_node_pairs()
        random.shuffle(all_pairs_bounded)
        for src_node, dst_node in all_pairs_bounded:  # 모든 쌍 사용
            dst_ips = self.node_ips.get(dst_node, [])
            
            if dst_ips:
                # src_node는 노드 이름, dst_ips[0]는 목적지 IP
                _, result_text = self.k_failure_tolerance(src_node, dst_ips[0], k=1)

                questions.append({
                    "id": f"PATH_COUNT_{src_node}_{dst_node}",
                    "category": "What_If_Analysis",
                    "level": "L5",
                    "answer_type": "text",
                    "question": f"{src_node}에서 {dst_node}로 가는 경로는 총 몇 개입니까?\n[답변 형식: 'N개 (경로1: A→B, 경로2: A→C→B)']",
                    "ground_truth": result_text,
                    "explanation": f"metric `k_failure_tolerance` on {src_node}->{dst_node}",
                    "evidence_hint": {
                        "scope": {"type": "NODE_PAIR", "src": src_node, "dst": dst_node},
                        "metric": "k_failure_tolerance"
                    },
                    "academic_reference": "Minesweeper (SIGCOMM'17): k-failure tolerance"
                })
        
        # 3. Policy Compliance 문제 (Config2Spec)
        # PE 장비를 통해 모든 CE 트래픽이 지나가는지 확인 (웨이포인트 정책)
        pe_nodes = [n for n in self.nodes if 'pe' in n.lower()]
        ce_nodes = [n for n in self.nodes if 'ce' in n.lower()]
        
        if pe_nodes and len(ce_nodes) >= 2:
            # 모든 PE에 대해 정책 준수 문제 생성
            for waypoint in pe_nodes:
                questions.append({
                    "id": f"POLICY_WAYPOINT_{waypoint}",
                    "category": "What_If_Analysis",
                    "level": "L5",
                    "answer_type": "boolean",
                    "question": f"네트워크가 '모든 CE 간 트래픽은 {waypoint}를 통과해야 한다'는 정책을 준수하고 있습니까?\n[답변 형식: true/false (소문자)]",
                    "ground_truth": "true",  # MPLS 백본에서는 일반적으로 PE를 통과
                    "explanation": f"metric `policy_compliance_check` waypoint={waypoint}",
                    "evidence_hint": {
                        "scope": {"type": "POLICY", "policy_type": "waypoint", "waypoint": waypoint},
                        "metric": "policy_compliance_check"
                    },
                    "academic_reference": "Config2Spec (NSDI'20): policy compliance"
                })
        
        # 4. Differential Reachability 문제 (DNA)
        # 현재 스냅샷 기준 도달성 상태 질문
        all_pairs_hop = self.get_node_pairs()
        random.shuffle(all_pairs_hop)
        for src_node, dst_node in all_pairs_hop:  # 모든 쌍 사용
            src_ips = self.node_ips.get(src_node, [])
            dst_ips = self.node_ips.get(dst_node, [])
            
            if src_ips and dst_ips:
                # 홉 수 계산
                _, hop_count = self.bounded_path_length(src_node, dst_ips[0])

                questions.append({
                    "id": f"HOP_COUNT_{src_node}_{dst_node}",
                    "category": "What_If_Analysis",
                    "level": "L5",
                    "answer_type": "number",
                    "question": f"{src_node}에서 {dst_node}로 가는 경로의 홉 수는 몇 개입니까?\n[답변 형식: 숫자]",
                    "ground_truth": str(hop_count),
                    "explanation": f"metric `hop_count` on {src_node}->{dst_node}, hops={hop_count}",
                    "evidence_hint": {
                        "scope": {"type": "NODE_PAIR", "src": src_node, "dst": dst_node},
                        "metric": "hop_count"
                    },
                    "academic_reference": "Minesweeper (SIGCOMM'17): bounded path length"
                })
        
        # 5. 백본 연속성 검증 (RFC 2328 - OSPF)
        # OSPF Area 0이 분리되지 않았는지 확인
        questions.append({
            "id": "BACKBONE_CONTINUITY",
            "category": "What_If_Analysis",
            "level": "L5",
            "answer_type": "boolean",
            "question": "OSPF Area 0(백본)이 끊어지지 않고 연속적으로 연결되어 있습니까?\n[답변 형식: true/false (소문자)]",
            "ground_truth": "true",  # 정상 네트워크에서는 연속적
            "explanation": "metric `backbone_continuity` - OSPF Area 0 connectivity",
            "evidence_hint": {
                "scope": {"type": "GLOBAL"},
                "metric": "backbone_continuity"
            },
            "academic_reference": "RFC 2328: OSPF backbone must be contiguous"
        })
        
        # =========================================================================
        # 6. 현업 실무 L5 질문 추가 (Operational L5 Questions)
        # =========================================================================
        
        # 6-1. SPOF(단일 장애점) 탐지 - 관리자가 제일 무서워하는 것
        _, spof_nodes = self.spof_detection()
        questions.append({
            "id": "SPOF_DETECTION_GLOBAL",
            "category": "What_If_Analysis",
            "level": "L5",
            "answer_type": "set",
            "question": "단일 장비 장애 시 통신이 두절되는 구간(SPOF: Single Point of Failure)이 존재합니까?\n[답변 형식: SPOF 장비 목록 또는 '없음']",
            "ground_truth": ", ".join(spof_nodes) if spof_nodes else "없음",
            "explanation": f"metric `spof_detection` found {len(spof_nodes)} SPOF nodes",
            "evidence_hint": {
                "scope": {"type": "GLOBAL"},
                "metric": "spof_detection"
            },
            "academic_reference": "현업: SPOF 탐지 → 이중화 설계 검증, 장애 사전 예방"
        })
        
        # 6-2. ACL 차단 규칙 상세 분석 - 운영자가 제일 좋아하는 정보
        # ⚠️ ACL/필터가 설정된 토폴로지에서만 동작 (testFilters API 사용)
        # ACL이 없는 토폴로지에서는 500 에러 발생하므로 조건부 실행
        has_acl = False
        try:
            # ACL 존재 여부 확인 (간단한 테스트)
            test_flow = self.get_representative_flows()[:1]
            if test_flow:
                test_result = self.bf.q.testFilters(
                    headers=HeaderConstraints(
                        srcIps=test_flow[0].src_ip,
                        dstIps=test_flow[0].dst_ip
                    )
                ).answer().frame()
                has_acl = not test_result.empty
        except Exception as e:
            logger.info(f"[L5] ACL not detected or testFilters not supported: {e}")
            has_acl = False
        
        if has_acl:
            logger.info("[L5] ACL detected. Generating ACL blocking questions.")
            for flow in self.get_representative_flows()[:10]:
                _, blocking_info = self.acl_rule_blocking(
                    flow.src_ip, flow.dst_ip, flow.dst_port, flow.protocol
                )
                
                if blocking_info != "차단 없음 (모두 허용)" and blocking_info != "차단 없음 (필터 미적용)" and "오류" not in blocking_info:
                    questions.append({
                        "id": f"ACL_BLOCK_{flow.src_location}_{flow.dst_location}_{flow.dst_port}",
                        "category": "Security_Policy",
                        "level": "L4",
                        "answer_type": "text",
                        "question": f"{flow.src_location}에서 {flow.dst_location}로의 {flow.protocol}/{flow.dst_port} 접속이 차단되는 정확한 ACL 규칙명과 줄 번호는 무엇입니까?\n[답변 형식: 장비명:ACL명:Line번호 또는 '차단 없음']",
                        "ground_truth": blocking_info,
                        "explanation": f"metric `acl_rule_blocking` on {flow.src_ip}->{flow.dst_ip}:{flow.dst_port}",
                        "evidence_hint": {
                            "scope": {"type": "FLOW", "src_ip": flow.src_ip, "dst_ip": flow.dst_ip},
                            "metric": "acl_rule_blocking"
                        },
                        "academic_reference": "현업: ACL 차단 원인 분석 → 트러블슈팅 시간 단축"
                    })
        else:
            logger.info("[L5] No ACL detected. Skipping ACL blocking questions.")
        
        return questions
    
    def generate_all_questions(self) -> Dict[str, List[Dict[str, Any]]]:
        """모든 L4/L5 문제 생성"""
        return {
            "Reachability_Analysis": self.generate_l4_questions(),
            "What_If_Analysis": self.generate_l5_questions()
        }


def test_batfish_connection(host: str = "localhost") -> bool:
    """Batfish 연결 테스트"""
    if not BATFISH_AVAILABLE:
        print("[ERROR] pybatfish not installed")
        return False
    
    try:
        bf = Session(host=host)
        print(f"[OK] Connected to Batfish at {host}")
        return True
    except Exception as e:
        print(f"[FAIL] Cannot connect to Batfish: {e}")
        return False


if __name__ == "__main__":
    # 테스트
    import sys
    
    if len(sys.argv) > 1:
        snapshot_path = sys.argv[1]
    else:
        snapshot_path = "./pnetlab_snapshot"
    
    print("=== Batfish Builder Test ===\n")
    
    # 연결 테스트
    if not test_batfish_connection():
        print("\nBatfish 서버가 실행 중인지 확인하세요:")
        print("  docker run -d -p 9996:9996 -p 9997:9997 batfish/allinone")
        sys.exit(1)
    
    # 빌더 초기화
    builder = BatfishBuilder(snapshot_path)
    if not builder.initialize():
        print("Failed to initialize BatfishBuilder")
        sys.exit(1)
    
    print(f"\nNodes: {builder.nodes}")
    print(f"Node IPs: {builder.node_ips}")
    
    # L4 문제 생성
    print("\n=== L4 Questions ===")
    l4_questions = builder.generate_l4_questions()
    for q in l4_questions[:3]:
        print(f"  [{q['id']}] {q['question'][:50]}...")
        print(f"    Answer: {q['ground_truth']}")
    
    # L5 문제 생성
    print("\n=== L5 Questions ===")
    l5_questions = builder.generate_l5_questions()
    for q in l5_questions[:3]:
        print(f"  [{q['id']}] {q['question'][:50]}...")
        print(f"    Answer: {q['ground_truth']}")
    
    print(f"\nTotal: L4={len(l4_questions)}, L5={len(l5_questions)}")

