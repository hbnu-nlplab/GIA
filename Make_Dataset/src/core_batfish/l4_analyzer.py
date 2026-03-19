"""
L4 분석기 Mixin - 도달성 분석 메트릭

L4 Metrics (Reachability Analysis):
- traceroute_path: 네트워크 경로 추적
- reachability_status: 도달 가능 여부
- acl_blocking_point: ACL 차단 지점 분석
- loop_detection: 포워딩 루프 탐지
- blackhole_detection: 블랙홀 탐지
- waypoint_check: 웨이포인트 경유 여부
- bounded_path_length: 경로 홉 수 계산
- isolation_check: VRF 격리 검사
- asymmetric_path_check: 비대칭 경로 검사
- mtu_mismatch_check: MTU 불일치 검사
- ospf_compatibility_check: OSPF 네이버 호환성 검사 (Advanced)
- security_policy_bypass_check: 보안 정책 우회 탐지 (Advanced)
"""

import logging
from typing import Dict, List, Any

from .models import AnswerResult, build_evidence, DISPOSITION_PRIORITY, normalize_disposition

logger = logging.getLogger(__name__)

# Batfish 로드 (선택적)
try:
    from pybatfish.datamodel.flow import HeaderConstraints
except ImportError:
    HeaderConstraints = None


class L4AnalyzerMixin:
    """
    L4 도달성 분석 메트릭 Mixin
    
    이 Mixin은 BatfishBase를 상속한 클래스에서 사용해야 합니다.
    필요한 속성: bf, _initialized, nodes, node_ips, interfaces, snapshot_name
    """
    
    def _make_evidence(self, query_name: str, params: dict) -> dict:
        """BatfishBuilder 내부용 evidence 생성 헬퍼"""
        return build_evidence(query_name, params, getattr(self, 'snapshot_name', ''))
    
    # =========================================================================
    # 기본 L4 메트릭
    # =========================================================================
    
    def traceroute_path(self, src_location: str, dst_ip: str, target_name: str = "") -> AnswerResult:
        """
        L4: 네트워크 경로 추적
        Returns: AnswerResult(value=List[str], type="path")
        
        Note: VRF 환경에서는 startLocation을 노드 이름만 지정하면 첫 번째 VRF를 사용하여
        잘못된 라우팅 테이블을 참조할 수 있습니다. Loopback0을 명시하여 global routing table을
        사용하도록 합니다.
        """
        evidence = self._make_evidence("traceroute", {"startLocation": src_location, "dstIps": dst_ip})
        
        if not self._initialized:
            return AnswerResult("NOT_CONFIGURED", [], "path", evidence, "BATFISH_NOT_INITIALIZED")
        
        try:
            # 노드별 Loopback0 존재 여부를 고려해 안전하게 startLocation 보정
            # (Leaf처럼 Loopback0이 없는 장비에서 무조건 [Loopback0]을 붙이면 실패 가능)
            src_location = self._fix_start_location(src_location)
            
            result = self.bf.q.traceroute(
                startLocation=src_location,
                headers=HeaderConstraints(dstIps=dst_ip)
            ).answer(snapshot=self.snapshot_name).frame()

            if result.empty:
                return AnswerResult("OK", [], "path", evidence, "")
            
            # 경로 추출
            path = []
            traces = result['Traces'].iloc[0]
            if traces and len(traces) > 0:
                trace = traces[0]
                hops = getattr(trace, 'hops', []) if hasattr(trace, 'hops') else []
                
                # 디버깅: Trace disposition 확인
                disposition = getattr(trace, 'disposition', 'UNKNOWN')
                logger.debug(f"traceroute_path: src={src_location}, dst={dst_ip}, disposition={disposition}, hops={len(hops)}")
                
                for hop in hops:
                    node = getattr(hop, 'node', None)
                    if node:
                        node_name = getattr(node, 'hostname', str(node))
                        # 대소문자 무시하고 중복 제거
                        if node_name and node_name.lower() not in [n.lower() for n in path]:
                            path.append(node_name)
            
            # 목적지 노드 추가 로직
            if path:
                disposition = getattr(trace, 'disposition', 'UNKNOWN')
                if target_name and path[-1] != target_name:
                    if disposition in ['DELIVERED_TO_SUBNET', 'ACCEPTED', 'EXITS_NETWORK']:
                        path.append(target_name)
                
                return AnswerResult("OK", path, "path", evidence, "")
            
            return AnswerResult("OK", [], "path", evidence, "")
            
        except Exception as e:
            logger.warning(f"traceroute_path error: {e}")
            return AnswerResult("UNKNOWN", [], "path", evidence, "BATFISH_QUERY_ERROR")
    
    def reachability_status(self, 
                           src_ip: str, 
                           dst_ip: str,
                           dst_port: int = 0,
                           protocol: str = "TCP") -> AnswerResult:
        """
        L4: 도달 가능 여부 (경로 포함)
        Returns: AnswerResult(value={"reachable": bool, "path": List[str]}, type="l4_result")
        """
        params = {"srcIps": src_ip, "dstIps": dst_ip, "port": dst_port, "protocol": protocol}
        evidence = self._make_evidence("reachability", params)
        
        if not self._initialized:
            return AnswerResult("NOT_CONFIGURED", {"reachable": False, "path": []}, "l4_result", evidence, "BATFISH_NOT_INITIALIZED")
        
        try:
            # src_ip 노드 찾기
            src_node = None
            for node, ips in self.node_ips.items():
                if src_ip in ips:
                    src_node = node
                    break
            
            if not src_node:
                src_node = self.nodes[0] if self.nodes else None
            
            if not src_node:
                return AnswerResult("UNKNOWN", {"reachable": False, "path": []}, "l4_result", evidence, "NODE_NOT_FOUND")
            
            if protocol == "TCP" and dst_port > 0:
                headers = HeaderConstraints(srcIps=src_ip, dstIps=dst_ip, ipProtocols=["TCP"], dstPorts=[str(dst_port)])
            elif protocol == "ICMP":
                headers = HeaderConstraints(srcIps=src_ip, dstIps=dst_ip, ipProtocols=["ICMP"])
            else:
                headers = HeaderConstraints(srcIps=src_ip, dstIps=dst_ip)
            
            # VRF 문제 방지: [Loopback0] 추가
            src_node = self._fix_start_location(src_node)
            trace_result = self.bf.q.traceroute(startLocation=src_node, headers=headers).answer(snapshot=self.snapshot_name).frame()
            
            path = []
            is_reachable = False
            final_disposition = "UNKNOWN"
            failure_candidates = []  # (priority, disposition, path) 튜플 리스트
            
            if not trace_result.empty:
                traces = trace_result.iloc[0].get('Traces', [])
                for trace in traces:
                    hops = getattr(trace, 'hops', []) if hasattr(trace, 'hops') else []
                    current_path = []
                    for hop in hops:
                        node = getattr(hop, 'node', None)
                        if node:
                            node_name = getattr(node, 'hostname', str(node))
                            if node_name and node_name not in current_path:
                                current_path.append(node_name)
                    
                    disposition_str = str(getattr(trace, 'disposition', 'UNKNOWN'))
                    normalized_disposition = normalize_disposition(disposition_str)
                    
                    # Success Cases - 즉시 성공으로 반환
                    if normalized_disposition == "ACCEPTED":
                        is_reachable = True
                        path = current_path
                        final_disposition = "ACCEPTED"
                        break
                    
                    # Failure Cases - 우선순위와 함께 수집
                    priority = self.DISPOSITION_PRIORITY.get(normalized_disposition, 99)
                    failure_candidates.append((priority, normalized_disposition, current_path))
                
                # 성공하지 못한 경우, 가장 중요한 실패 원인 선택
                if not is_reachable and failure_candidates:
                    failure_candidates.sort(key=lambda x: x[0])  # 우선순위 오름차순 정렬
                    _, final_disposition, path = failure_candidates[0]

            # 정책 템플릿 계약: 실패 원인은 NO_ROUTE / ACL_DENY / EXTERNAL 중 하나로 제한
            if not is_reachable and final_disposition not in {"NO_ROUTE", "ACL_DENY", "EXTERNAL"}:
                final_disposition = "EXTERNAL"
            
            value = {"reachable": is_reachable, "path": path, "disposition": final_disposition}
            return AnswerResult("OK", value, "l4_result", evidence, "")
            
        except Exception as e:
            logger.warning(f"reachability_error: {e}")
            return AnswerResult("UNKNOWN", {"reachable": False, "path": []}, "l4_result", evidence, "BATFISH_QUERY_ERROR")
    
    def acl_blocking_point(self, 
                          src_ip: str, 
                          dst_ip: str,
                          dst_port: int = 80) -> AnswerResult:
        """
        L4: ACL 차단 지점 분석
        Returns: AnswerResult(value={"blocked": bool, "node": str, "reason": str}, type="acl_result")
        """
        evidence = self._make_evidence("acl_analysis", {"srcIps": src_ip, "dstIps": dst_ip, "dstPorts": dst_port})
        
        if not self._initialized:
            return AnswerResult("NOT_CONFIGURED", {"blocked": False, "node": "", "reason": ""}, "acl_result", evidence, "BATFISH_NOT_INITIALIZED")
        
        try:
            result = self.bf.q.reachability(
                headers=HeaderConstraints(
                    srcIps=src_ip,
                    dstIps=dst_ip,
                    dstPorts=[str(dst_port)],
                    ipProtocols=["TCP"]
                )
            ).answer(snapshot=self.snapshot_name).frame()

            if result.empty:
                return AnswerResult("OK", {"blocked": False, "node": "", "reason": "NO_PATH"}, "acl_result", evidence, "")
            
            for _, row in result.iterrows():
                if 'Disposition' in result.columns:
                    disposition = row.get('Disposition', '')
                    if 'DENIED' in str(disposition).upper():
                        traces = row.get('Traces', [])
                        blocking_node = "UNKNOWN"
                        if traces:
                            trace = traces[0] if traces else None
                            if trace:
                                hops = getattr(trace, 'hops', []) if hasattr(trace, 'hops') else []
                                if hops:
                                    last_hop = hops[-1]
                                    node = getattr(last_hop, 'node', None)
                                    if node:
                                        blocking_node = getattr(node, 'hostname', str(node))
                        
                        return AnswerResult("OK", {"blocked": True, "node": blocking_node, "reason": "ACL_DENY"}, "acl_result", evidence, "")
            
            return AnswerResult("OK", {"blocked": False, "node": "", "reason": "PERMITTED"}, "acl_result", evidence, "")
            
        except Exception as e:
            logger.warning(f"acl_blocking_point error: {e}")
            return AnswerResult("UNKNOWN", {"blocked": False, "node": "", "reason": ""}, "acl_result", evidence, "BATFISH_QUERY_ERROR")
    
    def loop_detection(self) -> AnswerResult:
        """
        L4: 포워딩 루프 탐지
        Returns: AnswerResult(value={"detected": bool, "loops": List[str]}, type="loop_result")
        """
        evidence = self._make_evidence("detectLoops", {})
        
        if not self._initialized:
            return AnswerResult("NOT_CONFIGURED", {"detected": False, "loops": []}, "loop_result", evidence, "BATFISH_NOT_INITIALIZED")

        try:
            result = self.bf.q.detectLoops().answer(snapshot=self.snapshot_name).frame()

            if result.empty:
                return AnswerResult("OK", {"detected": False, "loops": []}, "loop_result", evidence, "")

            loop_paths = []
            for _, row in result.iterrows():  
                loop_path = str(row.get('Loop', ''))
                if loop_path:
                    loop_paths.append(loop_path)
            
            return AnswerResult("OK", {"detected": True, "loops": loop_paths[:5]}, "loop_result", evidence, "")

        except Exception as e:
            logger.warning(f"loop_detection error: {e}")
            return AnswerResult("UNKNOWN", {"detected": False, "loops": []}, "loop_result", evidence, "BATFISH_QUERY_ERROR")
    
    def blackhole_detection(self, dst_prefix: str = "0.0.0.0/0") -> AnswerResult:
        """
        L4: 블랙홀 탐지 (패킷이 드랍되는 목적지)
        Returns: AnswerResult(value={"detected": bool, "blackholes": List[str]}, type="blackhole_result")
        """
        evidence = self._make_evidence("reachability", {"dstIps": dst_prefix})
        
        if not self._initialized:
            return AnswerResult("NOT_CONFIGURED", {"detected": False, "blackholes": []}, "blackhole_result", evidence, "BATFISH_NOT_INITIALIZED")
        
        try:
            result = self.bf.q.reachability(
                headers=HeaderConstraints(dstIps=dst_prefix)
            ).answer(snapshot=self.snapshot_name).frame()

            if result.empty:
                return AnswerResult("OK", {"detected": False, "blackholes": []}, "blackhole_result", evidence, "")
            
            blackholes = []
            
            if "Disposition" in result.columns:
                for _, row in result.iterrows():
                    disposition = str(row.get('Disposition', ''))
                    if any(d in disposition.upper() for d in ['DROP', 'NULL', 'NO_ROUTE', 'DENIED']):
                        dst = row.get('DstIp', '')
                        blackholes.append(f"{dst} ({disposition})")
            else:
                for _, row in result.iterrows():
                    trace_count = row.get('TraceCount', 0)
                    if trace_count == 0:
                        flow = row.get('Flow', {})
                        dst = getattr(flow, 'dstIp', '') if hasattr(flow, 'dstIp') else str(flow)
                        blackholes.append(f"{dst} (NO_TRACE)")
            
            detected = len(blackholes) > 0
            return AnswerResult("OK", {"detected": detected, "blackholes": list(set(blackholes))}, "blackhole_result", evidence, "")
            
        except Exception as e:
            logger.warning(f"blackhole_detection error: {e}")
            return AnswerResult("UNKNOWN", {"detected": False, "blackholes": []}, "blackhole_result", evidence, "BATFISH_QUERY_ERROR")
    
    def waypoint_check(self,
                      src_ip: str,
                      dst_ip: str,
                      waypoint_node: str) -> AnswerResult:
        """
        L4: 웨이포인트 경유 여부와 경로 정보
        Returns: AnswerResult(value={"passes_through": bool, "path": List[str]}, type="waypoint_result")
        """
        evidence = self._make_evidence("waypoint_check", {"srcIs": src_ip, "dstIps": dst_ip, "waypoint": waypoint_node})
        
        if not self._initialized:
            return AnswerResult("NOT_CONFIGURED", {"passes_through": False, "path": []}, "waypoint_result", evidence, "BATFISH_NOT_INITIALIZED")

        try:
            src_node = None
            for node, ips in self.node_ips.items():
                if src_ip in ips:
                    src_node = node
                    break

            if not src_node:
                src_node = self.nodes[0] if self.nodes else None
                
            if not src_node:
                 return AnswerResult("UNKNOWN", {"passes_through": False, "path": []}, "waypoint_result", evidence, "NODE_NOT_FOUND")

            # VRF 문제 방지: [Loopback0] 추가
            src_node = self._fix_start_location(src_node)
            
            result = self.bf.q.traceroute(
                startLocation=src_node,
                headers=HeaderConstraints(dstIps=dst_ip)
            ).answer(snapshot=self.snapshot_name).frame()

            if result.empty:
                return AnswerResult("OK", {"passes_through": False, "path": []}, "waypoint_result", evidence, "")

            path_nodes = []
            traces = result['Traces'].iloc[0]
            if traces:
                for trace in traces:
                    hops = getattr(trace, 'hops', []) if hasattr(trace, 'hops') else []
                    for hop in hops:
                        node = getattr(hop, 'node', None)
                        if node:
                            node_name = getattr(node, 'hostname', str(node)) if hasattr(node, 'hostname') else str(node)
                            if node_name not in path_nodes:
                                path_nodes.append(node_name)

            passes_waypoint = waypoint_node.lower() in [n.lower() for n in path_nodes]

            return AnswerResult("OK", {"passes_through": passes_waypoint, "path": path_nodes}, "waypoint_result", evidence, "")

        except Exception as e:
            logger.warning(f"waypoint_check error: {e}")
            return AnswerResult("UNKNOWN", {"passes_through": False, "path": []}, "waypoint_result", evidence, "BATFISH_QUERY_ERROR")
    
    def bounded_path_length(self,
                           src_location: str,
                           dst_ip: str,
                           max_hops: int = 5) -> AnswerResult:
        """
        L4: 경로 홉 수 계산
        Returns: AnswerResult(value={"hops": int}, type="hop_count")
        """
        evidence = build_evidence("traceroute", {"startLocation": src_location, "dstIps": dst_ip})
        
        if not self._initialized:
            return AnswerResult("NOT_CONFIGURED", {"hops": 0}, "hop_count", evidence, "BATFISH_NOT_INITIALIZED")
            
        try:
            # VRF 문제 방지: [Loopback0] 추가
            src_location = self._fix_start_location(src_location)
            
            result = self.bf.q.traceroute(
                startLocation=src_location,
                headers=HeaderConstraints(dstIps=dst_ip)
            ).answer(snapshot=self.snapshot_name).frame()

            if result.empty:
                return AnswerResult("OK", {"hops": 0}, "hop_count", evidence, "NO_ROUTE")

            traces = result['Traces'].iloc[0]
            if traces and len(traces) > 0:
                trace = traces[0]
                hops = getattr(trace, 'hops', []) if hasattr(trace, 'hops') else []
                hop_count = len(hops)
                return AnswerResult("OK", {"hops": hop_count}, "hop_count", evidence, "")

            return AnswerResult("OK", {"hops": 0}, "hop_count", evidence, "NO_TRACE")

        except Exception as e:
            logger.warning(f"bounded_path_length error: {e}")
            return AnswerResult("UNKNOWN", {"hops": 0}, "hop_count", evidence, "BATFISH_QUERY_ERROR")
    
    def isolation_check(self,
                       vrf1: str,
                       vrf2: str) -> AnswerResult:
        """
        L4: VRF/테넌트 격리 누수 prefix 목록 추출
        Returns: AnswerResult(value={"isolated": bool, "leaked_prefixes": List[str]}, type="isolation_result")
        """
        evidence = self._make_evidence("isolation_check", {"vrf1": vrf1, "vrf2": vrf2})
        
        if not self._initialized:
            return AnswerResult("NOT_CONFIGURED", {"isolated": True, "leaked_prefixes": []}, "isolation_result", evidence, "BATFISH_NOT_INITIALIZED")

        try:
            df_props = self.bf.q.interfaceProperties().answer(snapshot=self.snapshot_name).frame()
            vrf1_interfaces = df_props[df_props['VRF'] == vrf1]
            vrf2_interfaces = df_props[df_props['VRF'] == vrf2]

            if vrf1_interfaces.empty or vrf2_interfaces.empty:
                return AnswerResult("NOT_CONFIGURED", {"isolated": True, "leaked_prefixes": []}, "isolation_result", evidence, "VRF_NOT_FOUND")

            vrf1_ips = []
            for _, row in vrf1_interfaces.iterrows():
                if 'AllAddresses' in row and row['AllAddresses']:
                    for addr in row['AllAddresses']:
                        if '/' in addr:
                            ip = addr.split('/')[0]
                            vrf1_ips.append(ip)

            vrf2_ips = []
            for _, row in vrf2_interfaces.iterrows():
                if 'AllAddresses' in row and row['AllAddresses']:
                    for addr in row['AllAddresses']:
                        if '/' in addr:
                            ip = addr.split('/')[0]
                            vrf2_ips.append(ip)

            if not vrf1_ips or not vrf2_ips:
                return AnswerResult("OK", {"isolated": True, "leaked_prefixes": []}, "isolation_result", evidence, "NO_IPS_IN_VRF")

            leaked_prefixes = []
            vrf1_sample = vrf1_ips[:5]
            vrf2_sample = vrf2_ips[:5]

            for src_ip in vrf1_sample:
                for dst_ip in vrf2_sample:
                    try:
                        reach_result = self.bf.q.reachability(
                            headers=HeaderConstraints(srcIps=src_ip, dstIps=dst_ip)
                        ).answer(snapshot=self.snapshot_name).frame()

                        if not reach_result.empty:
                            if 'TraceCount' in reach_result.columns:
                                if any(reach_result['TraceCount'] > 0):
                                    prefix = f"{dst_ip}/32"
                                    if prefix not in leaked_prefixes:
                                        leaked_prefixes.append(prefix)
                            else:
                                prefix = f"{dst_ip}/32"
                                if prefix not in leaked_prefixes:
                                    leaked_prefixes.append(prefix)
                    except Exception:
                        continue

            return AnswerResult("OK", {"isolated": len(leaked_prefixes) == 0, "leaked_prefixes": leaked_prefixes}, "isolation_result", evidence, "")

        except Exception as e:
            logger.warning(f"isolation_check error: {e}")
            return AnswerResult("UNKNOWN", {"isolated": False, "leaked_prefixes": []}, "isolation_result", evidence, "BATFISH_QUERY_ERROR")
    
    def asymmetric_path_check(self,
                               node1: str,
                               node2: str) -> AnswerResult:
        """
        L4: 비대칭 경로(Asymmetric Routing) 검사
        Returns: AnswerResult(value={"symmetric": bool, "path_forward": List[str], "path_reverse": List[str]}, type="asymmetric_result")
        """
        evidence = self._make_evidence("asymmetric_path", {"node1": node1, "node2": node2})
        
        if not self._initialized:
             return AnswerResult("NOT_CONFIGURED", {"symmetric": True, "path_forward": [], "path_reverse": []}, "asymmetric_result", evidence, "BATFISH_NOT_INITIALIZED")
            
        try:
            node1_ips = self.node_ips.get(node1, [])
            node2_ips = self.node_ips.get(node2, [])

            if not node1_ips or not node2_ips:
                 return AnswerResult("UNKNOWN", {"symmetric": True, "path_forward": [], "path_reverse": []}, "asymmetric_result", evidence, "NO_IPS_FOR_NODE")

            # VRF 문제 방지: [Loopback0] 추가
            node1 = self._fix_start_location(node1)
            node2 = self._fix_start_location(node2)

            forward_result = self.bf.q.traceroute(
                startLocation=node1,
                headers=HeaderConstraints(dstIps=node2_ips[0])
            ).answer(snapshot=self.snapshot_name).frame()

            reverse_result = self.bf.q.traceroute(
                startLocation=node2,
                headers=HeaderConstraints(dstIps=node1_ips[0])
            ).answer(snapshot=self.snapshot_name).frame()

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

            reverse_nodes_reversed = list(reversed(reverse_nodes))
            is_symmetric = forward_nodes == reverse_nodes_reversed

            return AnswerResult("OK", {"symmetric": is_symmetric, "path_forward": forward_nodes, "path_reverse": reverse_nodes}, "asymmetric_result", evidence, "")

        except Exception as e:
            logger.warning(f"asymmetric_path_check error: {e}")
            return AnswerResult("UNKNOWN", {"symmetric": True, "path_forward": [], "path_reverse": []}, "asymmetric_result", evidence, "BATFISH_QUERY_ERROR")
    
    def mtu_mismatch_check(self) -> AnswerResult:
        """
        L1/L2: MTU 불일치 검사
        Returns: AnswerResult(value={"detected": bool, "mismatches": List[str]}, type="mtu_result")
        """
        evidence = build_evidence("interfaceProperties", {})
        
        if not self._initialized:
             return AnswerResult("NOT_CONFIGURED", {"detected": False, "mismatches": []}, "mtu_result", evidence, "BATFISH_NOT_INITIALIZED")
            
        try:
            interfaces = self.bf.q.interfaceProperties().answer(snapshot=self.snapshot_name).frame()
            if interfaces.empty:
                return AnswerResult("OK", {"detected": False, "mismatches": []}, "mtu_result", evidence, "")
            
            edges = self.bf.q.layer3Edges().answer(snapshot=self.snapshot_name).frame()
            mismatches = []
            
            if not edges.empty:
                for _, edge in edges.iterrows():
                    src_iface = edge.get('Interface', {})
                    dst_iface = edge.get('Remote_Interface', {})
                    src_hostname = getattr(src_iface, 'hostname', '') if hasattr(src_iface, 'hostname') else str(src_iface)
                    dst_hostname = getattr(dst_iface, 'hostname', '') if hasattr(dst_iface, 'hostname') else str(dst_iface)
                    
                    src_mtu, dst_mtu = None, None
                    
                    for _, iface in interfaces.iterrows():
                        iface_obj = iface.get('Interface', {})
                        iface_host = getattr(iface_obj, 'hostname', '')
                        iface_name = getattr(iface_obj, 'interface', '')
                        
                        s_name = getattr(src_iface, 'interface', '')
                        d_name = getattr(dst_iface, 'interface', '')
                        
                        if iface_host == src_hostname and iface_name == s_name:
                            src_mtu = iface.get('MTU', None)
                        if iface_host == dst_hostname and iface_name == d_name:
                            dst_mtu = iface.get('MTU', None)

                    if src_mtu and dst_mtu and src_mtu != dst_mtu:
                        mismatches.append(f"{src_hostname}:{src_mtu} <-> {dst_hostname}:{dst_mtu}")
            
            return AnswerResult("OK", {"detected": len(mismatches) > 0, "mismatches": mismatches}, "mtu_result", evidence, "")
            
        except Exception as e:
            logger.warning(f"mtu_mismatch_check error: {e}")
            return AnswerResult("UNKNOWN", {"detected": False, "mismatches": []}, "mtu_result", evidence, "BATFISH_QUERY_ERROR")
    
    # =========================================================================
    # 고급 L4 메트릭 (LLM 추론 요구)
    # =========================================================================
    
    def ospf_compatibility_check(self, node1: str, node2: str) -> AnswerResult:
        """
        L4 고급: OSPF 네이버 호환성 검사
        두 노드의 OSPF 설정을 비교하여 네이버 형성 불가 원인을 추론
        
        Returns: AnswerResult(value={"compatible": bool, "issues": List[str]}, type="ospf_compat_result")
        """
        evidence = self._make_evidence("ospfInterfaceConfiguration", {"node1": node1, "node2": node2})
        
        if not self._initialized:
            return AnswerResult("NOT_CONFIGURED", {"compatible": True, "issues": []}, "ospf_compat_result", evidence, "BATFISH_NOT_INITIALIZED")
        
        try:
            issues = []
            
            ospf_ifaces = self.bf.q.ospfInterfaceConfiguration(nodes=f"{node1}|{node2}").answer(snapshot=self.snapshot_name).frame()
            
            if ospf_ifaces.empty:
                return AnswerResult("NOT_CONFIGURED", {"compatible": True, "issues": ["No OSPF config"]}, "ospf_compat_result", evidence, "OSPF_NOT_CONFIGURED")
            
            n1_config = ospf_ifaces[ospf_ifaces['Interface'].apply(lambda x: getattr(x, 'hostname', '').lower() == node1.lower())]
            n2_config = ospf_ifaces[ospf_ifaces['Interface'].apply(lambda x: getattr(x, 'hostname', '').lower() == node2.lower())]
            
            if n1_config.empty or n2_config.empty:
                return AnswerResult("OK", {"compatible": True, "issues": ["Config not found for one node"]}, "ospf_compat_result", evidence, "")
            
            n1_areas = set(n1_config['OSPF_Area_Name'].dropna().unique())
            n2_areas = set(n2_config['OSPF_Area_Name'].dropna().unique())
            
            if n1_areas and n2_areas and not n1_areas.intersection(n2_areas):
                issues.append(f"area_mismatch: {node1}={n1_areas}, {node2}={n2_areas}")
            
            n1_hello = n1_config['OSPF_Hello_Interval'].iloc[0] if 'OSPF_Hello_Interval' in n1_config.columns and not n1_config['OSPF_Hello_Interval'].isna().all() else None
            n2_hello = n2_config['OSPF_Hello_Interval'].iloc[0] if 'OSPF_Hello_Interval' in n2_config.columns and not n2_config['OSPF_Hello_Interval'].isna().all() else None
            
            if n1_hello and n2_hello and n1_hello != n2_hello:
                issues.append(f"hello_interval_mismatch: {node1}={n1_hello}s, {node2}={n2_hello}s")
            
            n1_dead = n1_config['OSPF_Dead_Interval'].iloc[0] if 'OSPF_Dead_Interval' in n1_config.columns and not n1_config['OSPF_Dead_Interval'].isna().all() else None
            n2_dead = n2_config['OSPF_Dead_Interval'].iloc[0] if 'OSPF_Dead_Interval' in n2_config.columns and not n2_config['OSPF_Dead_Interval'].isna().all() else None
            
            if n1_dead and n2_dead and n1_dead != n2_dead:
                issues.append(f"dead_interval_mismatch: {node1}={n1_dead}s, {node2}={n2_dead}s")
            
            compatible = len(issues) == 0
            return AnswerResult("OK", {"compatible": compatible, "issues": issues}, "ospf_compat_result", evidence, "")
            
        except Exception as e:
            logger.warning(f"ospf_compatibility_check error: {e}")
            return AnswerResult("UNKNOWN", {"compatible": True, "issues": []}, "ospf_compat_result", evidence, "BATFISH_QUERY_ERROR")
    
    def security_policy_bypass_check(self, src_node: str, dst_node: str, required_waypoint: str) -> AnswerResult:
        """
        L4 고급: 보안 정책(Waypoint) 우회 경로 탐지
        src→dst 경로가 required_waypoint를 거치지 않고 도달 가능한지 확인
        
        Returns: AnswerResult(value={"bypass_exists": bool, "bypass_path": List[str]}, type="security_bypass_result")
        """
        evidence = self._make_evidence("traceroute", {"src": src_node, "dst": dst_node, "waypoint": required_waypoint})
        
        if not self._initialized:
            return AnswerResult("NOT_CONFIGURED", {"bypass_exists": False, "bypass_path": []}, "security_bypass_result", evidence, "BATFISH_NOT_INITIALIZED")
        
        try:
            dst_ips = self.node_ips.get(dst_node, [])
            if not dst_ips:
                return AnswerResult("NOT_CONFIGURED", {"bypass_exists": False, "bypass_path": []}, "security_bypass_result", evidence, "")
            
            # VRF 문제 방지: [Loopback0] 추가
            src_node = self._fix_start_location(src_node)
            
            traceroute = self.bf.q.traceroute(
                startLocation=src_node,
                headers=HeaderConstraints(dstIps=dst_ips[0])
            ).answer(snapshot=self.snapshot_name).frame()
            
            if traceroute.empty:
                return AnswerResult("OK", {"bypass_exists": False, "bypass_path": []}, "security_bypass_result", evidence, "")
            
            traces = traceroute['Traces'].iloc[0]
            bypass_paths = []
            
            for trace in traces:
                disposition = getattr(trace, 'disposition', '')
                if disposition != 'ACCEPTED':
                    continue
                    
                hops = getattr(trace, 'hops', [])
                path_nodes = []
                passes_waypoint = False
                
                for hop in hops:
                    node = getattr(hop, 'node', None)
                    if node:
                        node_name = getattr(node, 'hostname', str(node))
                        path_nodes.append(node_name)
                        if node_name.lower() == required_waypoint.lower():
                            passes_waypoint = True
                
                if not passes_waypoint and path_nodes:
                    bypass_paths.append(path_nodes)
            
            bypass_exists = len(bypass_paths) > 0
            bypass_path = bypass_paths[0] if bypass_paths else []
            
            return AnswerResult("OK", {"bypass_exists": bypass_exists, "bypass_path": bypass_path}, "security_bypass_result", evidence, "")
            
        except Exception as e:
            logger.warning(f"security_policy_bypass_check error: {e}")
            return AnswerResult("UNKNOWN", {"bypass_exists": False, "bypass_path": []}, "security_bypass_result", evidence, "BATFISH_QUERY_ERROR")
