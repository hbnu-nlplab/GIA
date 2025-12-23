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
"""

import logging
import time
from typing import Dict, List, Any

from .models import AnswerResult, build_evidence

logger = logging.getLogger(__name__)

# Batfish 로드 (선택적)
try:
    from pybatfish.datamodel.flow import HeaderConstraints, PathConstraints
except ImportError:
    HeaderConstraints = None
    PathConstraints = None


class L5AnalyzerMixin:
    """
    L5 What-If 분석 메트릭 Mixin
    
    이 Mixin은 BatfishBase를 상속한 클래스에서 사용해야 합니다.
    필요한 속성: bf, _initialized, nodes, node_ips, interfaces, snapshot_name
    """
    
    def _make_evidence(self, query_name: str, params: dict) -> dict:
        """BatfishBuilder 내부용 evidence 생성 헬퍼"""
        return build_evidence(query_name, params, getattr(self, 'snapshot_name', ''))
    

    
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
            
            ce_nodes = [n for n in self.nodes if 'ce' in n.lower()]
            if len(ce_nodes) >= 2:
                src, dst = ce_nodes[0], ce_nodes[-1]
            else:
                src, dst = self.nodes[0], self.nodes[-1]
                
            src_ips = self.node_ips.get(src, [])
            dst_ips = self.node_ips.get(dst, [])
            
            if not src_ips or not dst_ips:
                 return AnswerResult("OK", {"detected": False, "spof_nodes": []}, "spof_result", evidence, "")
            
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

            base_trace_obj = base_traces['Traces'].iloc[0][0]
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
                base_name=self.bf.snapshot,
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
                fail_trace_obj = fail_traces['Traces'].iloc[0][0]
                fail_path_nodes = []
                for hop in fail_trace_obj.hops:
                     node = getattr(hop, 'node', None)
                     if node:
                         fail_path_nodes.append(getattr(node, 'hostname', str(node)))
                
                if base_path_nodes == fail_path_nodes:
                     impact = "NONE"
                     desc = "Path unchanged"
                else:
                     impact = "REROUTED"
                     desc = f"Rerouted: {'->'.join(fail_path_nodes)}"
            
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
            diff_result = self.bf.q.differentialReachability(
                snapshot=after_snapshot,
                reference_snapshot=before_snapshot
            ).answer().frame()
            
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
                        forbiddenLocations=[waypoint_node]
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
    
    def multi_link_failure_analysis(self, link1_node1: str, link1_node2: str, link2_node1: str, link2_node2: str, test_src: str, test_dst: str) -> AnswerResult:
        """
        L5 고급: 동시 다중 링크 장애 분석
        2개 링크가 동시에 다운될 경우 test_src→test_dst 경로 변화 분석
        
        Returns: AnswerResult(value={"isolated": bool, "new_path": List[str], "path_change": str}, type="multi_failure_result")
        """
        evidence = self._make_evidence("traceroute", {
            "link1": f"{link1_node1}-{link1_node2}",
            "link2": f"{link2_node1}-{link2_node2}",
            "src": test_src, "dst": test_dst
        })
        
        if not self._initialized:
            return AnswerResult("NOT_CONFIGURED", {"isolated": False, "new_path": [], "path_change": "UNKNOWN"}, "multi_failure_result", evidence, "BATFISH_NOT_INITIALIZED")
        
        try:
            dst_ips = self.node_ips.get(test_dst, [])
            if not dst_ips:
                return AnswerResult("NOT_CONFIGURED", {"isolated": False, "new_path": [], "path_change": "UNKNOWN"}, "multi_failure_result", evidence, "")
            
            traceroute = self.bf.q.traceroute(
                startLocation=test_src,
                headers=HeaderConstraints(dstIps=dst_ips[0])
            ).answer().frame()
            
            if traceroute.empty:
                return AnswerResult("OK", {"isolated": True, "new_path": [], "path_change": "NO_BASELINE_PATH"}, "multi_failure_result", evidence, "")
            
            traces = traceroute['Traces'].iloc[0]
            
            current_paths = []
            for trace in traces:
                disposition = getattr(trace, 'disposition', '')
                if disposition != 'ACCEPTED':
                    continue
                    
                hops = getattr(trace, 'hops', [])
                path_nodes = []
                uses_failed_links = False
                
                for i, hop in enumerate(hops):
                    node = getattr(hop, 'node', None)
                    if node:
                        node_name = getattr(node, 'hostname', str(node))
                        path_nodes.append(node_name)
                        
                        if i > 0:
                            prev_node = path_nodes[-2]
                            curr_node = node_name
                            if (prev_node.lower() in [link1_node1.lower(), link1_node2.lower()] and 
                                curr_node.lower() in [link1_node1.lower(), link1_node2.lower()]):
                                uses_failed_links = True
                            if (prev_node.lower() in [link2_node1.lower(), link2_node2.lower()] and 
                                curr_node.lower() in [link2_node1.lower(), link2_node2.lower()]):
                                uses_failed_links = True
                
                if not uses_failed_links and path_nodes:
                    current_paths.append(path_nodes)
            
            if current_paths:
                return AnswerResult("OK", {"isolated": False, "new_path": current_paths[0], "path_change": "ALTERNATE_PATH_AVAILABLE"}, "multi_failure_result", evidence, "")
            else:
                return AnswerResult("OK", {"isolated": True, "new_path": [], "path_change": "ISOLATED"}, "multi_failure_result", evidence, "")
            
        except Exception as e:
            logger.warning(f"multi_link_failure_analysis error: {e}")
            return AnswerResult("UNKNOWN", {"isolated": False, "new_path": [], "path_change": "ERROR"}, "multi_failure_result", evidence, "BATFISH_QUERY_ERROR")
    
        """
        L4: ACL 차단 규칙 상세 분석
        Returns: AnswerResult(value={"blocked": bool, "rules": List[str]}, type="acl_rule_result")
        """
        # ... logic ...
        pass # The previous code ended abruptly in the view, but assumed acl_rule_blocking exists below.
        # Actually I need to insert the NEW method before the end of the class or in a suitable place. 
        # I will insert it after multi_link_failure_analysis.

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
    
    def acl_rule_blocking(self, src_ip, dst_ip, dst_port, protocol="tcp"):
         # ... (existing content, simplified for brevity in replacement) ...
         pass 

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
