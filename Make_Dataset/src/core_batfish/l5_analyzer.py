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
        L5 고급: 도달 불가 시 근본 원인 분석
        traceroute 결과를 분석하여 차단/실패 원인 추론
        
        Returns: AnswerResult(value={"reachable": bool, "root_cause": str, "blocking_point": str}, type="root_cause_result")
        """
        evidence = self._make_evidence("traceroute", {"src": src_node, "dst": dst_node})
        
        if not self._initialized:
            return AnswerResult("NOT_CONFIGURED", {"reachable": False, "root_cause": "NOT_INITIALIZED", "blocking_point": ""}, "root_cause_result", evidence, "BATFISH_NOT_INITIALIZED")
        
        try:
            dst_ips = self.node_ips.get(dst_node, [])
            if not dst_ips:
                return AnswerResult("NOT_CONFIGURED", {"reachable": False, "root_cause": "NO_DST_IP", "blocking_point": ""}, "root_cause_result", evidence, "")
            
            traceroute = self.bf.q.traceroute(
                startLocation=src_node,
                headers=HeaderConstraints(dstIps=dst_ips[0])
            ).answer().frame()
            
            if traceroute.empty:
                return AnswerResult("OK", {"reachable": False, "root_cause": "NO_ROUTE", "blocking_point": src_node}, "root_cause_result", evidence, "")
            
            traces = traceroute['Traces'].iloc[0]
            if not traces:
                return AnswerResult("OK", {"reachable": False, "root_cause": "EMPTY_TRACE", "blocking_point": src_node}, "root_cause_result", evidence, "")
            
            trace = traces[0]
            disposition = getattr(trace, 'disposition', 'UNKNOWN')
            
            if disposition == 'ACCEPTED':
                return AnswerResult("OK", {"reachable": True, "root_cause": "NONE", "blocking_point": ""}, "root_cause_result", evidence, "")
            
            hops = getattr(trace, 'hops', [])
            last_hop_node = ""
            for hop in hops:
                node = getattr(hop, 'node', None)
                if node:
                    last_hop_node = getattr(node, 'hostname', str(node))
            
            root_cause_map = {
                'DENIED_IN': 'ACL_BLOCKED_INBOUND',
                'DENIED_OUT': 'ACL_BLOCKED_OUTBOUND',
                'NO_ROUTE': 'ROUTING_FAILURE',
                'NULL_ROUTED': 'NULL_ROUTE_CONFIGURED',
                'LOOP': 'FORWARDING_LOOP',
                'UNREACHABLE': 'DESTINATION_UNREACHABLE'
            }
            
            root_cause = root_cause_map.get(disposition, f'UNKNOWN_{disposition}')
            
            return AnswerResult("OK", {"reachable": False, "root_cause": root_cause, "blocking_point": last_hop_node}, "root_cause_result", evidence, "")
            
        except Exception as e:
            logger.warning(f"root_cause_analysis error: {e}")
            return AnswerResult("UNKNOWN", {"reachable": False, "root_cause": "ERROR", "blocking_point": ""}, "root_cause_result", evidence, "BATFISH_QUERY_ERROR")
    
    def blast_radius_estimation(self, failed_node: str) -> AnswerResult:
        """
        L5 고급: 노드 장애 시 영향 범위(Blast Radius) 추정
        특정 노드가 다운될 경우 영향받는 다른 노드들을 분석
        
        Returns: AnswerResult(value={"affected_nodes": List[str], "affected_count": int, "severity": str}, type="blast_radius_result")
        """
        evidence = self._make_evidence("layer3Edges", {"failed_node": failed_node})
        
        if not self._initialized:
            return AnswerResult("NOT_CONFIGURED", {"affected_nodes": [], "affected_count": 0, "severity": "UNKNOWN"}, "blast_radius_result", evidence, "BATFISH_NOT_INITIALIZED")
        
        try:
            edges = self.bf.q.layer3Edges(nodes=failed_node).answer().frame()
            
            directly_connected = set()
            if not edges.empty:
                for _, edge in edges.iterrows():
                    remote_iface = edge.get('Remote_Interface', {})
                    remote_node = getattr(remote_iface, 'hostname', '') if hasattr(remote_iface, 'hostname') else ''
                    if remote_node and remote_node.lower() != failed_node.lower():
                        directly_connected.add(remote_node)
            
            affected_nodes = list(directly_connected)
            affected_count = len(affected_nodes)
            
            total_nodes = len(self.nodes)
            impact_ratio = affected_count / total_nodes if total_nodes > 0 else 0
            
            if impact_ratio >= 0.5:
                severity = "CRITICAL"
            elif impact_ratio >= 0.25:
                severity = "HIGH"
            elif impact_ratio >= 0.1:
                severity = "MEDIUM"
            else:
                severity = "LOW"
            
            return AnswerResult("OK", {"affected_nodes": affected_nodes, "affected_count": affected_count, "severity": severity}, "blast_radius_result", evidence, "")
            
        except Exception as e:
            logger.warning(f"blast_radius_estimation error: {e}")
            return AnswerResult("UNKNOWN", {"affected_nodes": [], "affected_count": 0, "severity": "UNKNOWN"}, "blast_radius_result", evidence, "BATFISH_QUERY_ERROR")
    
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
    
    # =========================================================================
    # 추가 메트릭 (L4/L5 혼합)
    # =========================================================================
    
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
