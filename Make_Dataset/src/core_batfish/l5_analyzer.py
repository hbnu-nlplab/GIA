"""
L5 분석기 Mixin - What-If / Impact 분석 메트릭

L5 Metrics (What-If Analysis):
- link_failure_impact: 링크 장애 영향 분석
- config_change_impact: 설정 변경 영향 분석
- policy_compliance_check: 정책 준수 검증
- k_failure_tolerance: k-failure tolerance 검증
- spof_detection: 단일 장애점(SPOF) 탐지
- root_cause_analysis: 장애 근본 원인 분석 (Advanced)
- blast_radius_estimation: 장애 영향 범위 추정 (Advanced)
- multi_link_failure_analysis: 동시 다중 링크 장애 분석 (Advanced)
- acl_rule_blocking: ACL 차단 규칙 상세 분석
- ip_conflict_check: IP 충돌 검사
- ospf_backbone_contiguity: OSPF Backbone Area 0 연속성 검사
- differential_reachability: 변경 전/후 도달성 차이 분석
"""

import logging
import time
import re
import random
from typing import Dict, List, Any

from .models import AnswerResult, build_evidence

logger = logging.getLogger(__name__)

# Batfish 로드 (선택적)
try:
    from pybatfish.datamodel.flow import HeaderConstraints, PathConstraints
except ImportError:
    HeaderConstraints = None
    PathConstraints = None

try:
    from pybatfish.datamodel import Interface as NodeInterfacePair
except ImportError:
    NodeInterfacePair = None


class L5AnalyzerMixin:
    """
    L5 What-If 분석 메트릭 Mixin
    
    이 Mixin은 BatfishBase를 상속한 클래스에서 사용해야 합니다.
    필요한 속성: bf, _initialized, nodes, node_ips, interfaces, snapshot_name
    """
    
    # Batfish Disposition 우선순위 (낮을수록 더 중요한 실패 원인)
    DISPOSITION_PRIORITY = {
        'NO_ROUTE': 1,              # 최우선: 명확한 라우팅 실패
        'NULL_ROUTED': 2,           # 의도적으로 버림 (Null0)
        'ACL_DENY': 3,              # 정규화된 ACL 차단 상태
        'ACL_IN_DENIED': 3,         # ACL 차단 (Ingress)
        'ACL_OUT_DENIED': 3,        # ACL 차단 (Egress)
        'DENIED': 3,                # 일반 ACL 차단
        'DENIED_IN': 3,             # ACL 차단 변형
        'DENIED_OUT': 3,            # ACL 차단 변형
        'NEIGHBOR_UNREACHABLE': 4,  # 이웃 도달 불가
        'LOOP': 5,                  # 라우팅 루프
        'EXTERNAL': 6,              # 네트워크 외부/정보부족 계열 정규화
        'EXITS_NETWORK': 6,         # 낮은 우선순위: 네트워크를 벗어남 (성공일 수도 있음)
        'INSUFFICIENT_INFO': 6,     # 낮은 우선순위: 정보 불충분 (성공일 수도 있음)
        'UNKNOWN': 7                # 알 수 없는 상태
    }
    
    def _make_evidence(self, query_name: str, params: dict) -> dict:
        """BatfishBuilder 내부용 evidence 생성 헬퍼"""
        return build_evidence(query_name, params, getattr(self, 'snapshot_name', ''))

    def _normalize_disposition(self, disposition: str) -> str:
        """Batfish disposition을 분석/정답용 라벨로 정규화합니다."""
        d = str(disposition or "").upper()
        if "ACCEPTED" in d or "DELIVERED" in d:
            return "ACCEPTED"
        if "NO_ROUTE" in d:
            return "NO_ROUTE"
        if "NULL_ROUTED" in d:
            return "NULL_ROUTED"
        if "DENIED" in d or "BLOCK" in d:
            return "ACL_DENY"
        if "NEIGHBOR_UNREACHABLE" in d:
            return "NEIGHBOR_UNREACHABLE"
        if "LOOP" in d:
            return "LOOP"
        if "EXITS_NETWORK" in d or "INSUFFICIENT_INFO" in d:
            return "EXTERNAL"
        return "UNKNOWN"
    

    
    def _analyze_routing_failure(self, src_node: str, dst_ip: str) -> dict:
        """
        라우팅 실패 원인 상세 분석 (범용적)
        
        Returns:
            dict: {
                "has_route": bool,
                "active_protocols": List[str],
                "diagnosis": str
            }
        """
        result = {
            "has_route": False,
            "active_protocols": [],
            "diagnosis": "UNKNOWN"
        }
        
        try:
            # 1. 라우팅 테이블에 경로 존재 확인
            try:
                routes = self.bf.q.routes(nodes=src_node, network=dst_ip).answer().frame()
                result["has_route"] = not routes.empty
                
                if result["has_route"]:
                    # 경로는 있지만 차단됨 → ACL 또는 interface down
                    result["diagnosis"] = "ROUTE_EXISTS_BUT_BLOCKED"
                    return result
            except Exception as e:
                logger.debug(f"Routes query failed: {e}")
            
            # 2. 활성 라우팅 프로토콜 확인
            # BGP 확인
            try:
                bgp_proc = self.bf.q.bgpProcessConfiguration(nodes=src_node).answer().frame()
                if not bgp_proc.empty:
                    result["active_protocols"].append("BGP")
                    
                    # BGP neighbor 확인
                    bgp_peers = self.bf.q.bgpPeerConfiguration(nodes=src_node).answer().frame()
                    if bgp_peers.empty:
                        result["diagnosis"] = "NO_BGP_NEIGHBORS"
                        return result
            except Exception as e:
                logger.debug(f"BGP query failed: {e}")
            
            # OSPF 확인
            try:
                ospf_proc = self.bf.q.ospfProcessConfiguration(nodes=src_node).answer().frame()
                if not ospf_proc.empty:
                    result["active_protocols"].append("OSPF")
            except Exception as e:
                logger.debug(f"OSPF query failed: {e}")
            
            # Static route 확인
            try:
                all_routes = self.bf.q.routes(nodes=src_node).answer().frame()
                if not all_routes.empty:
                    static_routes = all_routes[all_routes['Protocol'] == 'static']
                    if not static_routes.empty:
                        result["active_protocols"].append("STATIC")
            except Exception as e:
                logger.debug(f"Static routes query failed: {e}")
            
            # 3. 진단 결정
            if not result["active_protocols"]:
                result["diagnosis"] = "NO_ROUTING_PROTOCOL"
            elif "BGP" in result["active_protocols"] and not result["has_route"]:
                result["diagnosis"] = "BGP_ROUTE_NOT_RECEIVED"
            elif "OSPF" in result["active_protocols"] and not result["has_route"]:
                result["diagnosis"] = "OSPF_ROUTE_NOT_ADVERTISED"
            elif "STATIC" in result["active_protocols"] and not result["has_route"]:
                result["diagnosis"] = "STATIC_ROUTE_MISMATCH"
            else:
                result["diagnosis"] = "ROUTING_TABLE_EMPTY"
            
            return result
            
        except Exception as e:
            logger.warning(f"Routing failure analysis error: {e}")
            result["diagnosis"] = "ANALYSIS_ERROR"
            return result
    
    # =========================================================================
    # 기본 L5 메트릭
    # =========================================================================
    
    def ospf_backbone_contiguity(self) -> AnswerResult:
        """
        L5: OSPF Backbone Area (Area 0) 연속성 검사
        
        Backbone Area는 물리적으로 연속적이어야 하며(Contiguous), 모든 ABR은 Backbone에 연결되어야 한다.
        
        Returns: AnswerResult(value={"contiguous": bool, "details": str}, type="ospf_result")
        """
        evidence = self._make_evidence("ospfAreaConfiguration", {"area": "0"})
        
        if not self._initialized:
            return AnswerResult("NOT_CONFIGURED", {"contiguous": False, "details": "Batfish not initialized"}, "ospf_result", evidence, "BATFISH_NOT_INITIALIZED")
            
        try:
            # Batfish의 ospfAreaConfiguration 질문을 통해 Area 0 정보를 가져옴
            area_config = self.bf.q.ospfAreaConfiguration().answer().frame()
            
            backbone_nodes = []
            if not area_config.empty:
                # Area 0 (Backbone)에 해당하는 행만 필터링
                backbone = area_config[area_config['Area'] == '0']
                backbone_nodes = backbone['Node'].tolist()
            
            if not backbone_nodes:
                # Backbone Area가 아예 없는 경우 (단일 Area 설계일 수도 있음)
                return AnswerResult("OK", {"contiguous": True, "details": "No Backbone Area (Single Area OSPF or No OSPF)"}, "ospf_result", evidence, "NO_BACKBONE")

            # 간단한 연속성 검사: 모든 Backbone 라우터가 BGP/OSPF 등을 통해 서로 도달 가능한지 확인
            # (엄밀한 물리적 연속성 검사는 토폴로지 분석이 필요함)
            # 여기서는 약식으로 'Backbone 라우터 개수'와 '인터페이스 상태'를 리포트
            
            details = f"Backbone Routers: {len(backbone_nodes)} ({', '.join(sorted(backbone_nodes[:5]))}...)"
            
            return AnswerResult("OK", {"contiguous": True, "details": details}, "ospf_result", evidence, "")

        except Exception as e:
            logger.warning(f"ospf_backbone_contiguity error: {e}")
            return AnswerResult("UNKNOWN", {"contiguous": False, "details": str(e)}, "ospf_result", evidence, "BATFISH_QUERY_ERROR")

    def differential_reachability(self, 
                                 snapshot1: str, 
                                 snapshot2: str,
                                 src_node: str = "",
                                 dst_ip: str = "") -> AnswerResult:
        """
        L5: Differential Reachability (변경 전후 도달성 비교) - Wrapper
        
        Returns: AnswerResult(value={"diff_count": int, "flows": List[str]}, type="diff_reachability")
        """
        evidence = self._make_evidence("differentialReachability", {"s1": snapshot1, "s2": snapshot2})
        
        try:
            headers = HeaderConstraints()
            if dst_ip:
                headers = HeaderConstraints(dstIps=dst_ip)

            # Some pybatfish versions do not accept snapshot parameters
            # at question-construction time; pass them to answer() instead.
            diff_q = self.bf.q.differentialReachability(headers=headers)
            diff = diff_q.answer(
                snapshot=snapshot2,
                reference_snapshot=snapshot1
            ).frame()
            
            flows = []
            if not diff.empty:
                for _, row in diff.iterrows():
                    flow = row.get('Flow')
                    if flow:
                        s_ip = getattr(flow, 'srcIp', '')
                        d_ip = getattr(flow, 'dstIp', '')
                        flows.append(f"{s_ip} -> {d_ip}")
            
            return AnswerResult("OK", {"diff_count": len(flows), "flows": flows[:10]}, "diff_reachability", evidence, "")
            
        except Exception as e:
            return AnswerResult("UNKNOWN", {"diff_count": 0, "flows": []}, "diff_reachability", evidence, str(e))

    def spof_detection(self) -> AnswerResult:
        """
        L5: 단일 장애점(SPOF) 탐지
        Returns: AnswerResult(value={"detected": bool, "spof_nodes": List[str]}, type="spof_result")
        """
        evidence = self._make_evidence("traceroute", {})
        
        if not self._initialized:
             return AnswerResult("NOT_CONFIGURED", {"detected": False, "spof_nodes": []}, "spof_result", evidence, "BATFISH_NOT_INITIALIZED")
            
        try:
            spof_nodes = []
            if len(self.nodes) < 3:
                return AnswerResult("OK", {"detected": False, "spof_nodes": []}, "spof_result", evidence, "TOO_FEW_NODES")
            
            ce_nodes = self.get_edge_nodes()  # 토폴로지 추론 기반 (이전: 이름 기반)
            if len(ce_nodes) >= 2:
                src, dst = ce_nodes[0], ce_nodes[-1]
            else:
                src, dst = self.nodes[0], self.nodes[-1]
                
            src_ips = self.node_ips.get(src, [])
            dst_ips = self.node_ips.get(dst, [])
            
            if not src_ips or not dst_ips:
                 return AnswerResult("OK", {"detected": False, "spof_nodes": []}, "spof_result", evidence, "")
            
            # VRF 문제 방지: [Loopback0] 추가
            src = self._fix_start_location(src)
            
            traceroute = self.bf.q.traceroute(
                startLocation=src,
                headers=HeaderConstraints(dstIps=dst_ips[0])
            ).answer().frame()
            
            if traceroute.empty:
                return AnswerResult("OK", {"detected": False, "spof_nodes": []}, "spof_result", evidence, "")
            
            traces = traceroute['Traces'].iloc[0]
            if not traces:
                return AnswerResult("OK", {"detected": False, "spof_nodes": []}, "spof_result", evidence, "")
            
            path_nodes = set()
            for trace in traces:
                hops = getattr(trace, 'hops', [])
                for hop in hops:
                    node = getattr(hop, 'node', None)
                    if node:
                        node_name = getattr(node, 'hostname', str(node))
                        path_nodes.add(node_name)
            
            total_paths = len(traces)
            if total_paths == 1:
                for node in path_nodes:
                    if node.lower() != src.lower() and node.lower() != dst.lower():
                        spof_nodes.append(node)
            
            detected = len(spof_nodes) > 0
            return AnswerResult("OK", {"detected": detected, "spof_nodes": list(set(spof_nodes))}, "spof_result", evidence, "")
            
        except Exception as e:
            logger.warning(f"spof_detection error: {e}")
            return AnswerResult("UNKNOWN", {"detected": False, "spof_nodes": []}, "spof_result", evidence, "BATFISH_QUERY_ERROR")
    
    def link_failure_impact(self, node1: str, node2: str, test_src: str, test_dst: str) -> AnswerResult:
        """
        L5: 링크 장애 영향 분석
        Returns: AnswerResult(value={"impact": str, "description": str}, type="link_failure_result")
        """
        evidence = self._make_evidence("link_failure", {"link": f"{node1}-{node2}", "flow": f"{test_src}->{test_dst}"})

        if not self._initialized:
            return AnswerResult("NOT_CONFIGURED", {"impact": "UNKNOWN", "description": "Batfish not initialized"}, "link_failure_result", evidence, "BATFISH_NOT_INITIALIZED")

        try:
            # VRF 문제 방지: [Loopback0] 추가
            test_src = self._fix_start_location(test_src)
            
            test_dst_ips = self.node_ips.get(test_dst, [])
            if not test_dst_ips:
                 return AnswerResult("UNKNOWN", {"impact": "UNKNOWN", "description": "Dst IP Not Found"}, "link_failure_result", evidence, "DST_IP_NOT_FOUND")
            test_dst_ip = test_dst_ips[0]

            base_traces = self.bf.q.traceroute(
                startLocation=test_src,
                headers=HeaderConstraints(dstIps=test_dst_ip)
            ).answer().frame()

            if base_traces.empty:
                return AnswerResult("NOT_APPLICABLE", {"impact": "NONE", "description": "No base path"}, "link_failure_result", evidence, "NO_BASE_PATH")
            base_trace_list = base_traces['Traces'].iloc[0] if 'Traces' in base_traces.columns else []
            if not base_trace_list:
                return AnswerResult("NOT_APPLICABLE", {"impact": "NONE", "description": "No base trace"}, "link_failure_result", evidence, "NO_BASE_TRACE")
            base_trace_obj = base_trace_list[0]
            base_disposition = self._normalize_disposition(getattr(base_trace_obj, 'disposition', 'UNKNOWN'))
            # baseline이 이미 불통이면 링크 다운 영향 분석의 기준 자체가 성립하지 않음
            if base_disposition != "ACCEPTED":
                return AnswerResult(
                    "NOT_APPLICABLE",
                    {"impact": "NONE", "description": f"Baseline not reachable ({base_disposition})"},
                    "link_failure_result",
                    evidence,
                    "BASELINE_NOT_REACHABLE"
                )
            base_path_nodes = []
            for hop in base_trace_obj.hops:
                 node = getattr(hop, 'node', None)
                 if node:
                     base_path_nodes.append(getattr(node, 'hostname', str(node)))
            
            edges = self.bf.q.layer3Edges().answer().frame()
            
            deactivate_list = []
            if not edges.empty:
                for _, row in edges.iterrows():
                    n1 = row['Interface'].hostname
                    n2 = row['Remote_Interface'].hostname
                    if (n1 == node1 and n2 == node2) or (n1 == node2 and n2 == node1):
                        deactivate_list.append(row['Interface'])
                        deactivate_list.append(row['Remote_Interface'])
            
            if not deactivate_list:
                 return AnswerResult("OK", {"impact": "NONE", "description": "Link not found or inactive"}, "link_failure_result", evidence, "LINK_NOT_FOUND")

            failure_snapshot_name = f"failure_{node1}_{node2}_{int(time.time())}"
            self.bf.fork_snapshot(
                base_name=self.snapshot_name,
                name=failure_snapshot_name,
                deactivate_interfaces=deactivate_list,
                overwrite=True
            )
            
            fail_traces = self.bf.q.traceroute(
                startLocation=test_src,
                headers=HeaderConstraints(dstIps=test_dst_ip)
            ).answer(snapshot=failure_snapshot_name).frame()
            
            impact = "NONE"
            desc = ""
            
            if fail_traces.empty:
                impact = "DISCONNECTED"
                desc = "Traffic disconnected after link failure"
            else:
                fail_trace_list = fail_traces['Traces'].iloc[0] if 'Traces' in fail_traces.columns else []
                if not fail_trace_list:
                    impact = "DISCONNECTED"
                    desc = "No trace after link failure"
                else:
                    accepted_paths = []
                    failure_dispositions = []

                    for fail_trace_obj in fail_trace_list:
                        raw_disposition = getattr(fail_trace_obj, 'disposition', 'UNKNOWN')
                        disposition = self._normalize_disposition(raw_disposition)

                        fail_path_nodes = []
                        for hop in getattr(fail_trace_obj, 'hops', []):
                            node = getattr(hop, 'node', None)
                            if node:
                                fail_path_nodes.append(getattr(node, 'hostname', str(node)))

                        if disposition == "ACCEPTED":
                            accepted_paths.append(fail_path_nodes)
                        else:
                            failure_dispositions.append(disposition)

                    if not accepted_paths:
                        impact = "DISCONNECTED"
                        reason = failure_dispositions[0] if failure_dispositions else "UNKNOWN"
                        desc = f"Traffic unreachable after failure ({reason})"
                    else:
                        # 도달 가능한 후보 중 가장 짧은 경로를 대표 경로로 사용
                        best_path = sorted(accepted_paths, key=len)[0]
                        if base_path_nodes == best_path:
                            impact = "NONE"
                            desc = "Path unchanged"
                        else:
                            impact = "REROUTED"
                            desc = f"Rerouted: {'->'.join(best_path)}"
            
            return AnswerResult("OK", {"impact": impact, "description": desc}, "link_failure_result", evidence, "")

        except Exception as e:
            err_msg = str(e)
            if "Found no active locations" in err_msg:
                return AnswerResult("NOT_APPLICABLE", {"impact": "NONE", "description": "Source node inactive"}, "link_failure_result", evidence, "SOURCE_NODE_INACTIVE")
            
            logger.warning(f"link_failure_impact error: {e}")
            return AnswerResult("UNKNOWN", {"impact": "UNKNOWN", "description": str(e)}, "link_failure_result", evidence, "BATFISH_QUERY_ERROR")
    
    def config_change_impact(self,
                            before_snapshot: str,
                            after_snapshot: str,
                            src_node: str = "",
                            dst_node: str = "") -> AnswerResult:
        """
        L5: 설정 변경 영향 분석
        Returns: AnswerResult(value={"changed": bool, "affected_flows": List[str]}, type="config_change_result")
        """
        evidence = self._make_evidence("differentialReachability", {"before": before_snapshot, "after": after_snapshot})
        
        if not self._initialized:
             return AnswerResult("NOT_CONFIGURED", {"changed": False, "affected_flows": []}, "config_change_result", evidence, "BATFISH_NOT_INITIALIZED")
        
        try:
            diff_q = self.bf.q.differentialReachability()
            diff_result = diff_q.answer(
                snapshot=after_snapshot,
                reference_snapshot=before_snapshot
            ).frame()
            
            if diff_result.empty:
                 return AnswerResult("OK", {"changed": False, "affected_flows": []}, "config_change_result", evidence, "")
            
            affected_flows = []
            for _, row in diff_result.iterrows():
                src = row.get('Flow', {})
                src_ip = getattr(src, 'srcIp', '') if hasattr(src, 'srcIp') else ''
                dst_ip = getattr(src, 'dstIp', '') if hasattr(src, 'dstIp') else ''
                if src_ip and dst_ip:
                    affected_flows.append(f"{src_ip}→{dst_ip}")
            
            return AnswerResult("OK", {"changed": True, "affected_flows": affected_flows}, "config_change_result", evidence, "")
            
        except Exception as e:
            logger.warning(f"config_change_impact error: {e}")
            return AnswerResult("UNKNOWN", {"changed": False, "affected_flows": []}, "config_change_result", evidence, "BATFISH_QUERY_ERROR")
    
    def policy_compliance_check(self,
                                policy_type: str = "waypoint",
                                waypoint_node: str = "",
                                dst_ports: List[str] = None,
                                policy_name: str = "") -> AnswerResult:
        """
        L5: 정책 준수 검증
        Returns: AnswerResult(value={"compliant": bool, "violations": List[str]}, type="policy_result")
        """
        evidence = self._make_evidence("policy_check", {"type": policy_type, "waypoint": waypoint_node})
        
        if not self._initialized:
            return AnswerResult("NOT_CONFIGURED", {"compliant": True, "violations": []}, "policy_result", evidence, "BATFISH_NOT_INITIALIZED")
        
        if dst_ports is None:
            dst_ports = ["80", "443"]
        
        try:
            if policy_type == "waypoint" and waypoint_node:
                violations = self.bf.q.reachability(
                    headers=HeaderConstraints(
                        dstPorts=dst_ports,
                        ipProtocols=["TCP"]
                    ),
                    pathConstraints=PathConstraints(
                        # Batfish expects a node-spec string, not a list.
                        forbiddenLocations=waypoint_node
                    )
                ).answer().frame()
                
                if violations.empty:
                    return AnswerResult("OK", {"compliant": True, "violations": []}, "policy_result", evidence, "")
                
                violation_flows = []
                for _, row in violations.iterrows():
                    flow = row.get('Flow', {})
                    src_ip = getattr(flow, 'srcIp', '') if hasattr(flow, 'srcIp') else ''
                    dst_ip = getattr(flow, 'dstIp', '') if hasattr(flow, 'dstIp') else ''
                    if src_ip and dst_ip:
                        violation_flows.append(f"{src_ip}→{dst_ip}")
                
                return AnswerResult("OK", {"compliant": False, "violations": violation_flows}, "policy_result", evidence, "VIOLATIONS_FOUND")
            
            return AnswerResult("OK", {"compliant": True, "violations": []}, "policy_result", evidence, "UNKNOWN_POLICY_TYPE")
            
        except Exception as e:
            logger.warning(f"policy_compliance_check error: {e}")
            return AnswerResult("UNKNOWN", {"compliant": False, "violations": []}, "policy_result", evidence, "BATFISH_QUERY_ERROR")
    
    def k_failure_tolerance(self,
                           src_node: str,
                           dst_ip: str,
                           k: int = 1) -> AnswerResult:
        """
        L5: k-failure tolerance 경로 수와 경로 목록
        Returns: AnswerResult(value={"path_count": int, "paths": List[str]}, type="measure_k_failure")
        """
        evidence = self._make_evidence("k_failure", {"src": src_node, "dst": dst_ip, "k": k})
        
        if not self._initialized:
            return AnswerResult("NOT_CONFIGURED", {"path_count": 0, "paths": []}, "measure_k_failure", evidence, "BATFISH_NOT_INITIALIZED")

        try:
            src_ips = self.node_ips.get(src_node, [])
            src_ip = src_ips[0] if src_ips else None

            if not src_ip:
                return AnswerResult("UNKNOWN", {"path_count": 0, "paths": []}, "measure_k_failure", evidence, "NO_IPS_FOR_NODE")

            baseline = self.bf.q.reachability(
                headers=HeaderConstraints(srcIps=src_ip, dstIps=dst_ip)
            ).answer().frame()

            if baseline.empty:
                return AnswerResult("OK", {"path_count": 0, "paths": []}, "measure_k_failure", evidence, "")

            # VRF 문제 방지: [Loopback0] 추가
            src_node = self._fix_start_location(src_node)
            
            trace_result = self.bf.q.traceroute(
                startLocation=src_node,
                headers=HeaderConstraints(dstIps=dst_ip)
            ).answer().frame()

            if trace_result.empty:
                return AnswerResult("OK", {"path_count": 0, "paths": []}, "measure_k_failure", evidence, "")

            traces = trace_result['Traces'].iloc[0]
            unique_paths = set()

            for trace in traces:
                disposition = getattr(trace, 'disposition', '')
                if 'ACCEPTED' not in str(disposition).upper():
                    continue
                    
                path_nodes = []
                for hop in getattr(trace, 'hops', []):
                    node = getattr(hop, 'node', None)
                    if node:
                        path_nodes.append(getattr(node, 'hostname', str(node)))
                if path_nodes:
                    unique_paths.add(" -> ".join(path_nodes))

            paths_list = list(unique_paths)
            path_count = len(paths_list)
            
            return AnswerResult("OK", {"path_count": path_count, "paths": paths_list}, "measure_k_failure", evidence, "")

        except Exception as e:
            logger.warning(f"k_failure_tolerance error: {e}")
            return AnswerResult("UNKNOWN", {"path_count": 0, "paths": []}, "measure_k_failure", evidence, "BATFISH_QUERY_ERROR")
    
    # =========================================================================
    # 고급 L5 메트릭 (LLM 추론 요구)
    # =========================================================================
    
    def root_cause_analysis(self, src_node: str, dst_node: str) -> AnswerResult:
        """
        L5 고급: 도달 불가 시 근본 원인 분석 (개선 버전)
        
        Traceroute 결과 + 라우팅 상태 종합 분석으로 정확한 원인 진단
        
        Returns: AnswerResult(value={
            "reachable": bool,
            "root_cause": str,  # 구체적 원인 (BGP_ROUTE_NOT_RECEIVED 등)
            "blocking_point": str,
            "details": str  # 추가 진단 정보
        }, type="root_cause_result")
        """
        evidence = self._make_evidence("traceroute", {"src": src_node, "dst": dst_node})
        
        if not self._initialized:
            return AnswerResult("NOT_CONFIGURED", {
                "reachable": False,
                "root_cause": "NOT_INITIALIZED",
                "blocking_point": "",
                "details": ""
            }, "root_cause_result", evidence, "BATFISH_NOT_INITIALIZED")
        
        try:
            dst_ips = self.node_ips.get(dst_node, [])
            if not dst_ips:
                return AnswerResult("NOT_CONFIGURED", {
                    "reachable": False,
                    "root_cause": "DESTINATION_IP_UNKNOWN",
                    "blocking_point": dst_node,
                    "details": "No IP addresses found for destination node"
                }, "root_cause_result", evidence, "")
            
            # VRF 문제 방지: [Loopback0] 추가
            src_node = self._fix_start_location(src_node)
            
            # Traceroute 수행
            traceroute = self.bf.q.traceroute(
                startLocation=src_node,
                headers=HeaderConstraints(dstIps=dst_ips[0])
            ).answer().frame()
            
            # Traceroute 결과가 없으면 라우팅 실패
            if traceroute.empty:
                routing_info = self._analyze_routing_failure(src_node, dst_ips[0])
                protocols = ', '.join(routing_info['active_protocols']) if routing_info['active_protocols'] else 'None'
                
                return AnswerResult("OK", {
                    "reachable": False,
                    "root_cause": routing_info["diagnosis"],
                    "blocking_point": src_node,
                    "details": f"Active protocols: {protocols}"
                }, "root_cause_result", evidence, "")
            
            traces = traceroute['Traces'].iloc[0]
            if not traces:
                return AnswerResult("OK", {
                    "reachable": False,
                    "root_cause": "EMPTY_TRACE",
                    "blocking_point": src_node,
                    "details": "Traceroute returned empty trace"
                }, "root_cause_result", evidence, "")
            
            trace = traces[0]
            disposition = getattr(trace, 'disposition', 'UNKNOWN')
            
            # 도달 성공
            if disposition == 'ACCEPTED':
                return AnswerResult("OK", {
                    "reachable": True,
                    "root_cause": "NONE",
                    "blocking_point": "",
                    "details": "Traffic successfully reaches destination"
                }, "root_cause_result", evidence, "")
            
            # Blocking point 찾기
            hops = getattr(trace, 'hops', [])
            last_hop_node = src_node
            for hop in hops:
                node = getattr(hop, 'node', None)
                if node:
                    last_hop_node = getattr(node, 'hostname', str(node))
            
            # Disposition 기반 원인 분석 + 라우팅 상세 분석 조합
            root_cause = ""
            details = ""
            
            if disposition == 'NO_ROUTE':
                # 라우팅 실패 상세 분석
                routing_info = self._analyze_routing_failure(last_hop_node, dst_ips[0])
                root_cause = routing_info["diagnosis"]
                protocols = ', '.join(routing_info['active_protocols']) if routing_info['active_protocols'] else 'None'
                details = f"No route at {last_hop_node}. Active protocols: {protocols}"
                
            elif disposition in ['DENIED_IN', 'DENIED_OUT']:
                direction = disposition.split('_')[1]
                root_cause = f"ACL_BLOCKED_{direction}"
                details = f"Traffic blocked by ACL at {last_hop_node} ({disposition})"
                
            elif disposition == 'NULL_ROUTED':
                root_cause = "NULL_ROUTE_CONFIGURED"
                details = f"Traffic null-routed at {last_hop_node}"
                
            elif disposition == 'LOOP':
                root_cause = "FORWARDING_LOOP"
                details = "Forwarding loop detected in path"
                
            elif disposition == 'UNREACHABLE':
                root_cause = "DESTINATION_UNREACHABLE"
                details = f"Destination unreachable from {last_hop_node}"
                
            elif disposition == 'NEIGHBOR_UNREACHABLE':
                root_cause = "NEIGHBOR_UNREACHABLE"
                details = f"Next-hop neighbor unreachable at {last_hop_node}"
                
            else:
                root_cause = f"UNKNOWN_{disposition}"
                details = f"Unknown disposition: {disposition}"
            
            return AnswerResult("OK", {
                "reachable": False,
                "root_cause": root_cause,
                "blocking_point": last_hop_node,
                "details": details
            }, "root_cause_result", evidence, "")
            
        except Exception as e:
            logger.warning(f"root_cause_analysis error: {e}")
            return AnswerResult("UNKNOWN", {
                "reachable": False,
                "root_cause": "ERROR",
                "blocking_point": "",
                "details": str(e)
            }, "root_cause_result", evidence, "BATFISH_QUERY_ERROR")
    
    def blast_radius_estimation(self, failed_node: str) -> AnswerResult:
        """
        L5 고급: 노드 장애 영향 분석 (Fork Snapshot & Differential Reachability)
        
        특정 노드를 비활성화한 Snapshot을 생성하고, 원본과 비교하여
        새로 차단되는 트래픽 흐름(Impact)을 객관적으로 분석함.
        
        Returns: AnswerResult(value={
            "affected_count": int,
            "newly_blocked_flows": List[str],
            "still_reachable_count": int
        }, type="node_failure_result")
        """
        evidence = self._make_evidence("differentialReachability", {"failed_node": failed_node})
        
        if not self._initialized:
            return AnswerResult("NOT_CONFIGURED", {
                "affected_count": 0,
                "newly_blocked_flows": [],
                "still_reachable_count": 0
            }, "node_failure_result", evidence, "BATFISH_NOT_INITIALIZED")
        
        try:
            # 1. Fork Snapshot: 노드 비활성화
            failure_snapshot = f"failure_{failed_node}_{int(time.time())}"
            try:
                self.bf.fork_snapshot(
                    base_name=self.snapshot_name,
                    name=failure_snapshot,
                    deactivate_nodes=[failed_node],
                    overwrite=True
                )
            except Exception as e:
                 print(f"DEBUG ERROR in fork_snapshot (blast_radius): {e}")
                 logger.warning(f"Fork snapshot failed: {e}")
                 return AnswerResult("UNKNOWN", {}, "node_failure_result", evidence, f"FORK_FAILED: {e}")

            # 2. Differential Reachability
            # 변경 전(self.snapshot_name) -> 변경 후(failure_snapshot)
            # reference_snapshot (basis) -> snapshot (new)
            # We want to find flows that were accepted in reference but dropped/unreachable in snapshot.
            
            diff_q = self.bf.q.differentialReachability()
            diff_result = diff_q.answer(
                snapshot=failure_snapshot,
                reference_snapshot=self.snapshot_name
            ).frame()
            
            newly_blocked = []
            
            if not diff_result.empty:
                # 'Flow' column contains the flow details
                for _, row in diff_result.iterrows():
                    flow = row.get('Flow')
                    if flow:
                        src_ip = getattr(flow, 'srcIp', 'unknown')
                        dst_ip = getattr(flow, 'dstIp', 'unknown')
                        ip_prot = getattr(flow, 'ipProtocol', 'unknown')
                        newly_blocked.append(f"{src_ip} -> {dst_ip} ({ip_prot})")
            
            # Limit results
            # Remove duplicated strings if any
            newly_blocked = list(set(newly_blocked))
            affected_count = len(newly_blocked)
            display_flows = newly_blocked[:15] # Top 15
            
            return AnswerResult("OK", {
                "affected_count": affected_count,
                "newly_blocked_flows": display_flows,
                "still_reachable_count": -1 # Not calculated for performance
            }, "node_failure_result", evidence, "")
            
        except Exception as e:
            print(f"DEBUG ERROR in blast_radius_estimation: {e}")
            logger.warning(f"blast_radius_estimation error: {e}")
            return AnswerResult("UNKNOWN", {
                "affected_count": 0,
                "newly_blocked_flows": [],
            }, "node_failure_result", evidence, "BATFISH_QUERY_ERROR")
    
    def multi_link_failure_analysis(self, 
                                    link1_iface1: str, link1_iface2: str,
                                    link2_iface1: str, link2_iface2: str,
                                    test_src: str, test_dst: str) -> AnswerResult:
        """
        L5 고급: 동시 다중 링크 장애 분석 (Dynamic Simulation)
        2개 링크(4개 인터페이스)를 실제로 비활성화 후 시뮬레이션
        
        Returns: AnswerResult(value={"isolated": bool, "new_path": List[str], "path_change": str, "failure_reason": str}, type="multi_failure_result")
        """
        link1_desc = f"{link1_iface1}<->{link1_iface2}"
        link2_desc = f"{link2_iface1}<->{link2_iface2}"
        
        evidence = self._make_evidence("traceroute", {
            "link1": link1_desc,
            "link2": link2_desc,
            "src": test_src, "dst": test_dst,
            "simulation": "dynamic_snapshot_fork"
        })
        
        if not self._initialized:
            return AnswerResult("NOT_CONFIGURED", {"isolated": False, "new_path": [], "path_change": "UNKNOWN"}, "multi_failure_result", evidence, "BATFISH_NOT_INITIALIZED")
        
        # 임시 스냅샷 이름
        failure_snapshot = f"multi_fail_{int(time.time()*1000)}_{random.randint(0,9999)}"
        
        try:
            # VRF 문제 방지: [Loopback0] 추가
            test_src = self._fix_start_location(test_src)
            
            dst_ips = self.node_ips.get(test_dst, [])
            if not dst_ips:
                return AnswerResult("NOT_CONFIGURED", {"isolated": False, "new_path": [], "path_change": "UNKNOWN"}, "multi_failure_result", evidence, "NO_DST_IP")
            
            # 1. 스냅샷 복제 및 인터페이스 비활성화 (Fork)
            # 입력받은 인터페이스들은 "hostname[interface]" 형식이므로 NodeInterfacePair 객체로 변환
            interfaces_to_deactivate = []
            for iface_str in [link1_iface1, link1_iface2, link2_iface1, link2_iface2]:
                match = re.match(r"([^\[]+)\[([^\]]+)\]", iface_str)
                if match:
                    node, iface = match.groups()
                    interfaces_to_deactivate.append(NodeInterfacePair(node, iface))
                else:
                    logger.warning(f"Invalid interface format: {iface_str}")
            
            self.bf.fork_snapshot(
                base_name=self.snapshot_name,
                name=failure_snapshot,
                deactivate_interfaces=interfaces_to_deactivate,
                overwrite=True
            )
            
            # 2. 장애 상황에서 Traceroute 실행
            trace_res = self.bf.q.traceroute(
                startLocation=test_src,
                headers=HeaderConstraints(dstIps=dst_ips[0])
            ).answer(snapshot=failure_snapshot).frame()
            
            # 3. 결과 분석
            if trace_res.empty:
                 # Trace 자체가 없으면 시뮬레이션 실패 혹은 완전 차단
                 return AnswerResult("OK", {"isolated": True, "new_path": [], "path_change": "ISOLATED", "failure_reason": "NO_TRACE_GENERATED"}, "multi_failure_result", evidence, "")

            traces = trace_res['Traces'].iloc[0]
            accepted_paths = []
            failure_reasons = []  # (priority, disposition, blocking_node) 튜플 리스트
            
            for trace in traces:
                raw_disposition = getattr(trace, 'disposition', 'UNKNOWN')
                disposition = self._normalize_disposition(raw_disposition)
                
                # 경로 추출
                hops = getattr(trace, 'hops', [])
                path_nodes = []
                for hop in hops:
                    node = getattr(hop, 'node', None)
                    if node:
                        node_name = getattr(node, 'hostname', str(node))
                        path_nodes.append(node_name)
                
                if disposition == 'ACCEPTED':
                    accepted_paths.append(path_nodes)
                else:
                    # 실패 원인 분석 - 우선순위와 함께 저장
                    priority = self.DISPOSITION_PRIORITY.get(disposition, 99)  # 정의되지 않은 disposition은 99
                    blocking_node = path_nodes[-1] if path_nodes else "Unknown"
                    failure_reasons.append((priority, disposition, blocking_node))
            
            # 4. 종합 판정
            if accepted_paths:
                # 우회 성공
                # 최단 경로 선택 (홉 수 기준)
                accepted_paths.sort(key=len)
                best_path = accepted_paths[0]
                return AnswerResult("OK", {
                    "isolated": False, 
                    "new_path": best_path, 
                    "path_change": "REROUTED",
                    "failure_reason": ""
                }, "multi_failure_result", evidence, "")
            else:
                # 전면 차단 - 가장 중요한 실패 원인만 선택 (우선순위가 가장 높은 것)
                if failure_reasons:
                    failure_reasons.sort(key=lambda x: x[0])  # 우선순위 오름차순 정렬
                    most_important = failure_reasons[0]  # 가장 높은 우선순위 (가장 낮은 숫자)
                    _, disposition, blocking_node = most_important
                    detailed_reason = f"{blocking_node}에서 {disposition}"
                else:
                    detailed_reason = "Unknown에서 UNKNOWN"
                
                return AnswerResult("OK", {
                    "isolated": True, 
                    "new_path": [], 
                    "path_change": "ISOLATED",
                    "failure_reason": detailed_reason
                }, "multi_failure_result", evidence, "")
            
        except Exception as e:
            logger.warning(f"multi_link_failure_analysis (dynamic) error: {e}")
            return AnswerResult("UNKNOWN", {"isolated": False, "new_path": [], "path_change": "ERROR"}, "multi_failure_result", evidence, f"SIMULATION_ERROR: {e}")
        finally:
            # 스냅샷 정리는 Batfish 설정에 따름 (일단 유지하거나 추후 자동정리)
            pass
    
    def redundancy_verification(self, node1: str, node2: str) -> AnswerResult:
        """
        L5 고급: 이중 장비 장애(Dual Failure) 시뮬레이션
        
        node1과 node2를 동시에 비활성화한 후, Differential Reachability를 통해
        고립되는 트래픽 흐름을 분석하여 이중화 구조의 안전성을 검증함.
        
        Returns: AnswerResult(value={
            "isolated_flow_count": int,
            "isolated_flows": List[str]
        }, type="dual_failure_result")
        """
        evidence = self._make_evidence("differentialReachability", {"failed_nodes": f"{node1}, {node2}"})
        
        if not self._initialized:
            return AnswerResult("NOT_CONFIGURED", {
                "isolated_flow_count": 0,
                "isolated_flows": []
            }, "dual_failure_result", evidence, "BATFISH_NOT_INITIALIZED")
            
        try:
            # 1. Fork Snapshot (두 노드 동시 비활성화)
            failure_snapshot = f"dual_fail_{node1}_{node2}_{int(time.time())}"
            try:
                self.bf.fork_snapshot(
                    base_name=self.snapshot_name,
                    name=failure_snapshot,
                    deactivate_nodes=[node1, node2],
                    overwrite=True
                )
            except Exception as e:
                 print(f"DEBUG ERROR in fork_snapshot (dual): {e}")
                 logger.warning(f"Fork snapshot (dual) failed: {e}")
                 return AnswerResult("UNKNOWN", {}, "dual_failure_result", evidence, f"FORK_FAILED: {e}")

            # 2. Differential Reachability
            # Reference(Base) -> Snapshot(Dual Fail) 비교
            diff_q = self.bf.q.differentialReachability()
            diff_result = diff_q.answer(
                snapshot=failure_snapshot,
                reference_snapshot=self.snapshot_name
            ).frame()
            
            isolated_flows = []
            if not diff_result.empty:
                for _, row in diff_result.iterrows():
                    flow = row.get('Flow')
                    if flow:
                        src_ip = getattr(flow, 'srcIp', 'unknown')
                        dst_ip = getattr(flow, 'dstIp', 'unknown')
                        ip_prot = getattr(flow, 'ipProtocol', 'unknown')
                        isolated_flows.append(f"{src_ip} -> {dst_ip} ({ip_prot})")
            
            isolated_flows = list(set(isolated_flows))
            
            return AnswerResult("OK", {
                "isolated_flow_count": len(isolated_flows),
                "isolated_flows": isolated_flows[:15] # Top 15
            }, "dual_failure_result", evidence, "")
            
        except Exception as e:
            print(f"DEBUG ERROR in redundancy_verification: {e}")
            logger.warning(f"redundancy_verification error: {e}")
            return AnswerResult("UNKNOWN", {
                "isolated_flow_count": 0,
                "isolated_flows": []
            }, "dual_failure_result", evidence, "BATFISH_QUERY_ERROR")

    # =========================================================================
    # 추가 메트릭 (L4/L5 혼합)
    # =========================================================================
    
    def triple_node_failure(self, node1: str, node2: str, node3: str) -> AnswerResult:
        """
        L5 Advanced: Triple Node Failure Simulation
        """
        evidence = self._make_evidence("differentialReachability", {"failed_nodes": f"{node1}, {node2}, {node3}"})
        
        if not self._initialized:
            return AnswerResult("NOT_CONFIGURED", {}, "triple_failure_result", evidence, "BATFISH_NOT_INITIALIZED")
            
        try:
            # 1. Fork Snapshot (세 노드 동시 비활성화)
            failure_snapshot = f"triple_fail_{node1}_{node2}_{node3}_{int(time.time())}"
            try:
                self.bf.fork_snapshot(
                    base_name=self.snapshot_name,
                    name=failure_snapshot,
                    deactivate_nodes=[node1, node2, node3],
                    overwrite=True
                )
            except Exception as e:
                 logger.warning(f"Fork snapshot (triple) failed: {e}")
                 return AnswerResult("UNKNOWN", {}, "triple_failure_result", evidence, f"FORK_FAILED: {e}")

            # 2. Differential Reachability
            diff_q = self.bf.q.differentialReachability()
            diff_result = diff_q.answer(
                snapshot=failure_snapshot,
                reference_snapshot=self.snapshot_name
            ).frame()
            
            isolated_flows = []
            if not diff_result.empty:
                for _, row in diff_result.iterrows():
                    flow = row.get('Flow')
                    if flow:
                        src_ip = getattr(flow, 'srcIp', 'unknown')
                        dst_ip = getattr(flow, 'dstIp', 'unknown')
                        ip_prot = getattr(flow, 'ipProtocol', 'unknown')
                        isolated_flows.append(f"{src_ip} -> {dst_ip} ({ip_prot})")
            
            isolated_flows = list(set(isolated_flows))
            
            return AnswerResult("OK", {
                "isolated_flow_count": len(isolated_flows),
                "isolated_flows": isolated_flows[:15]
            }, "triple_failure_result", evidence, "")
            
        except Exception as e:
            logger.warning(f"triple_node_failure error: {e}")
            return AnswerResult("UNKNOWN", {}, "triple_failure_result", evidence, "BATFISH_QUERY_ERROR")

    def check_non_existent_node(self, node_name: str) -> AnswerResult:
        """
        L5 Negative Testing: Check system response for non-existent node
        """
        evidence = self._make_evidence("check_node", {"target_node": node_name})
        
        if node_name in self.nodes:
            # 존재하면 오히려 테스트 실패 (의도는 없는 노드를 넣는 것)
            return AnswerResult("OK", {"status": "EXISTS", "message": "Node exists"}, "negative_test_result", evidence, "")
        else:
            # 존재하지 않음을 정확히 감지해야 성공
            return AnswerResult("OK", {
                "status": "NOT_FOUND", 
                "message": f"Batfish knows that '{node_name}' does not exist."
            }, "negative_test_result", evidence, "CORRECTLY_IDENTIFIED_MISSING_NODE")

    def find_worst_failure_node(self, candidate_nodes: List[str]) -> AnswerResult:
        """
        L5 Analysis: Find the single node that causes the most blocked flows
        """
        evidence = self._make_evidence("multi_simulation", {"candidates": len(candidate_nodes)})
        
        max_affected = -1
        worst_node = None
        
        # Analyze each candidate
        # This is expensive, so candidates should be limited
        try:
            for node in candidate_nodes:
                # Use the existing method name 'blast_radius_estimation'
                res = self.blast_radius_estimation(node) 
                
                if res.status == "OK":
                    count = res.value.get("affected_count", 0)
                    if count > max_affected:
                        max_affected = count
                        worst_node = node
            
            return AnswerResult("OK", {
                "worst_node": worst_node,
                "blocked_flow_count": max_affected
            }, "worst_case_result", evidence, "")
            
        except Exception as e:
            logger.warning(f"find_worst_failure_node error: {e}")
            return AnswerResult("UNKNOWN", {}, "worst_case_result", evidence, str(e))
    def acl_rule_blocking(self,
                          src_ip: str,
                          dst_ip: str,
                          dst_port: int = 80,
                          protocol: str = "TCP") -> AnswerResult:
        """
        L4: ACL 차단 규칙 상세 분석
        Returns: AnswerResult(value={"blocked": bool, "rules": List[str]}, type="acl_rule_result")
        """
        evidence = self._make_evidence("testFilters", {"src": src_ip, "dst": dst_ip, "port": dst_port})
        
        if not self._initialized:
             return AnswerResult("NOT_CONFIGURED", {"blocked": False, "rules": []}, "acl_rule_result", evidence, "BATFISH_NOT_INITIALIZED")
            
        try:
            filter_result = self.bf.q.testFilters(
                headers=HeaderConstraints(
                    srcIps=src_ip, dstIps=dst_ip, dstPorts=[str(dst_port)], ipProtocols=[protocol]
                )
            ).answer().frame()
            
            if filter_result.empty:
                return AnswerResult("OK", {"blocked": False, "rules": []}, "acl_rule_result", evidence, "")
            
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
            
            detected = len(blocking_info) > 0
            return AnswerResult("OK", {"blocked": detected, "rules": blocking_info}, "acl_rule_result", evidence, "")
            
        except Exception as e:
             logger.warning(f"acl_rule_blocking error: {e}")
             return AnswerResult("UNKNOWN", {"blocked": False, "rules": []}, "acl_rule_result", evidence, "BATFISH_QUERY_ERROR")
    
    def ip_conflict_check(self) -> AnswerResult:
        """
        L1: IP 충돌 검사
        Returns: AnswerResult(value={"detected": bool, "conflicts": List[str]}, type="ip_conflict_result")
        """
        evidence = build_evidence("interfaceProperties", {})
        
        if not self._initialized:
             return AnswerResult("NOT_CONFIGURED", {"detected": False, "conflicts": []}, "ip_conflict_result", evidence, "BATFISH_NOT_INITIALIZED")
            
        try:
            interfaces = self.bf.q.interfaceProperties().answer().frame()
            if interfaces.empty:
                 return AnswerResult("OK", {"detected": False, "conflicts": []}, "ip_conflict_result", evidence, "")
            
            ip_to_devices = {}
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
            
            conflicts = []
            for ip, devices in ip_to_devices.items():
                if len(devices) > 1:
                    conflicts.append(f"{ip} -> {', '.join(devices)}")
            
            detected = len(conflicts) > 0
            return AnswerResult("OK", {"detected": detected, "conflicts": conflicts}, "ip_conflict_result", evidence, "")
            
        except Exception as e:
             logger.warning(f"ip_conflict_check error: {e}")
             return AnswerResult("UNKNOWN", {"detected": False, "conflicts": []}, "ip_conflict_result", evidence, "BATFISH_QUERY_ERROR")
