"""
L6 분석기 Mixin - Diagnostic Troubleshooting (진단형 문제)

L6 Metrics (Diagnostic Analysis):
- generate_diagnostic_qa_link: 링크 장애 진단 문제 생성
- generate_diagnostic_qa_node: 노드 장애 진단 문제 생성 (예정)

이 모듈은 "가상 장애 주입(Fault Injection)"을 통해 고장난 네트워크 상태(Broken Snapshot)를 만들고,
에이전트에게 "증상(Symptom)"을 제시하여 "원인(Root Cause)"을 맞추게 하는 역추론(Inverse Reasoning) 문제를 생성합니다.
"""

import logging
import time
import random
import re
from typing import Dict, List, Any, Optional, Tuple

from .models import AnswerResult, build_evidence

logger = logging.getLogger(__name__)

# Batfish 로드 (선택적)
try:
    from pybatfish.datamodel.flow import HeaderConstraints
    from pybatfish.datamodel import Interface
except ImportError:
    HeaderConstraints = None
    Interface = None

    NodeInterfacePair = None


class L6AnalyzerMixin:
    """
    L6 Diagnostic 분석 메트릭 Mixin
    
    이 Mixin은 BatfishBase, L4AnalyzerMixin, L5AnalyzerMixin을 상속한 클래스에서 사용해야 합니다.
    필요한 속성: bf, _initialized, nodes, node_ips, snapshot_name
    """

    def _get_template(self, metric: str, default: str) -> str:
        """Template 가져오기 (BatfishBuilder에 정의된 메서드 활용)"""
        if hasattr(self, 'metrics_metadata') and metric in self.metrics_metadata:
            return self.metrics_metadata[metric].get("template", default)
        return default

    def _inject_fault_interface_down(self, snapshot_name: str, interfaces: List[Any]) -> bool:
        """
        Helper: 특정 인터페이스들을 Deactivate하는 Fault Snapshot 생성
        """
        try:
            self.bf.fork_snapshot(
                base_name=self.snapshot_name,
                name=snapshot_name,
                deactivate_interfaces=interfaces,
                overwrite=True
            )
            return True
        except Exception as e:
            logger.warning(f"L6 Fault Injection Failed ({snapshot_name}): {e}")
            return False

    def generate_diagnostic_qa_link(self, count: int = 10) -> List[Dict[str, Any]]:
        """
        L6: 링크 장애 진단 문제 생성
        
        1. 정상 상태에서 통신 가능한 Flow 선정
        2. 해당 Flow가 지나는 링크 중 하나를 Random 선택하여 Down (Fault Injection)
        3. 장애 상태에서 통신 불능(Unreachable) 확인 (Symptom Verification)
        4. 문제 생성: "A->B 통신 실패. 원인 진단하시오."
        """
        questions = []
        if not self._initialized:
            return questions

        # 1. 대상 Flow 선정 (Edge 장비 위주)
        candidates = self.nodes if len(self.nodes) >= 2 else []


        qa_count = 0
        tried_links = set()

        # Random Pair Sampling
        test_pairs = []
        for _ in range(count * 3): # 3배수 후보 선정
            src = random.choice(candidates)
            dst = random.choice(candidates)
            if src != dst:
                test_pairs.append((src, dst))
        
        # 중복 제거
        test_pairs = list(set(test_pairs))
        
        logger.info(f"[L6_LINK] Candidates: {len(candidates)}, Pairs: {len(test_pairs)}")

        for src_node, dst_node in test_pairs:
            logger.debug(f"[L6_LINK] Processing {src_node} -> {dst_node}")
            if qa_count >= count:
                break

            src_ips = self.node_ips.get(src_node, [])
            dst_ips = self.node_ips.get(dst_node, [])
            if not src_ips or not dst_ips:
                continue
            
            dst_ip = dst_ips[0]

            # 2. 정상 경로 확인 (Baseline)
            try:
                # VRF 보정
                src_loc = self._fix_start_location(src_node)
                
                tr_base = self.bf.q.traceroute(
                    startLocation=src_loc,
                    headers=HeaderConstraints(dstIps=dst_ip)
                ).answer().frame()

                if tr_base.empty:
                    logger.debug(f"[L6_LINK] Baseline empty for {src_node}->{dst_node}")
                    continue
                
                trace = tr_base['Traces'].iloc[0][0]
                disp = getattr(trace, 'disposition', '')
                if disp != 'ACCEPTED':
                    logger.debug(f"[L6_LINK] Baseline failed ({disp}) for {src_node}->{dst_node}")
                    continue # 원래 안 되는 경로는 패스

                # Ensure src_node is included (Traceroute hops sometimes omit the source)
                # But more importantly, we need Node and Exit Interface pairs
                path_hops = []
                for hop in getattr(trace, 'hops', []):
                    node = getattr(hop, 'node', None)
                    hostname = getattr(node, 'hostname', str(node))
                    if hasattr(node, 'name'): hostname = node.name # Backup
                    
                    exit_intf = None
                    for step in getattr(hop, 'steps', []):
                        detail = getattr(step, 'detail', None)
                        if detail:
                            exit_intf = getattr(detail, 'outputInterface', None)
                            if not exit_intf and isinstance(detail, dict):
                                exit_intf = detail.get('outputInterface')
                        
                        if exit_intf:
                            break 

                                # Sometimes it's in receivingInterface for EnterInterface? 
                                # No, we want outgoing for link failure.
                    
                    if hostname and exit_intf:
                        path_hops.append((hostname, exit_intf))

                logger.debug(f"[L6_LINK] Path hops for {src_node}->{dst_node}: {path_hops}")
                
                if not path_hops:
                    logger.debug(f"[L6_LINK] No valid exit interfaces for {src_node}->{dst_node}. Hops: {len(hops)}")
                    continue


                # Select a random hop to fail
                target_hop = random.choice(path_hops)
                u_name, intf_u = target_hop
                
                # 3. Fault Injection (Snapshot Forking)
                # Snapshot name cannot contain slashes ('/')
                safe_intf = intf_u.replace('/', '_')
                fault_snapshot = f"diag_link_{u_name}_{safe_intf}_{int(time.time()*1000)}"
                
                # Use explicit Interface objects for robustness
                # Pybatfish Interface uses hostname and interface
                target_iface = Interface(hostname=u_name, interface=intf_u)
                logger.info(f"[L6_LINK] Injecting fault: {target_iface}")
                success = self._inject_fault_interface_down(fault_snapshot, [target_iface])


                
                if not success:
                    continue

                # Store who we failed for ground truth
                # u_name is node, intf_u is interface name (str)
                v_name = "Unknown" # In interface-based failure, we just know the outgoing end
                target_link = (u_name, intf_u)


                # 4. Symptom Verification (With Fault)
                # 동일한 경로가 끊겼는지 확인
                tr_fail = self.bf.q.traceroute(
                    startLocation=src_loc,
                    headers=HeaderConstraints(dstIps=dst_ip)
                ).answer(snapshot=fault_snapshot).frame()
                
                is_broken = False
                fail_disposition = "UNKNOWN"
                
                if tr_fail.empty:
                    is_broken = True
                    fail_disposition = "NO_ROUTE"
                else:
                    fail_trace = tr_fail['Traces'].iloc[0][0]
                    fail_disposition = getattr(fail_trace, 'disposition', 'UNKNOWN')
                    if fail_disposition != 'ACCEPTED':
                        is_broken = True
                
                logger.info(f"[L6_LINK] Fault verification: {u_name}[{intf_u}] DOWN -> Disposition: {fail_disposition} (Broken: {is_broken})")


                
                # 5. 문제 생성 (증상이 확인된 경우만)
                if is_broken:
                    metric = "diagnostic_link_failure"
                    # 질문 템플릿: 증상(Symptom) 제시
                    template = self._get_template(metric, 
                        "**네트워크 장애 신고**: 사용자 '{src}'에서 목적지 '{dst}'(IP: {dst_ip})로의 통신이 갑자기 중단되었습니다.\n"
                        "현재 상태에서 Traceroute 결과는 '{disposition}'입니다.\n\n"
                        "**질문**: 이 장애의 근본 원인(Root Cause)이 되는 링크(장비 A - 장비 B)를 진단하십시오.\n"
                        "[답변 형식: '장비A - 장비B' (예: Core1 - Spine2)]")
                    
                    q_text = template.format(
                        src=src_node, 
                        dst=dst_node, 
                        dst_ip=dst_ip,
                        disposition=fail_disposition
                    )
                    
                    # 정답 포맷
                    ground_truth = f"{u_name} - {v_name}"
                    
                    questions.append({
                        "id": f"DIAG_LINK_{u_name}_{v_name}",
                        "category": "Diagnostic_Troubleshooting",
                        "level": "L6",
                        "answer_type": "text",
                        "question": q_text,
                        "ground_truth": ground_truth,
                        "explanation": f"Injected Fault: Interface {intf_u} on {u_name} set to administrative down.",

                        "evidence_hint": {
                            "scope": {"type": "DIAGNOSTIC_LINK", "src": src_node, "dst": dst_node},
                            "injected_fault": {"type": "LINK_DOWN", "link": ground_truth},
                            "symptom": fail_disposition
                        },
                        "academic_reference": "NIKA (SIGCOMM'25): Fault Injection Benchmark"
                    })
                    qa_count += 1
                
                # Cleanup (Optional: snapshots list grows, maybe delete?)
                # self.bf.delete_snapshot(fault_snapshot) # pybatfish might not support explicit delete easily in all versions/backends
                
            except Exception as e:
                logger.warning(f"Error generating diagnostic qa for {src_node}-{dst_node}: {e}")
                continue

        return questions

    # =========================================================================
    # L6-2: Node Failure Diagnostic (노드 장애 진단)
    # =========================================================================
    def _inject_fault_node_down(self, snapshot_name: str, node: str) -> bool:
        """Helper: 특정 노드를 Deactivate하는 Fault Snapshot 생성"""
        try:
            self.bf.fork_snapshot(
                base_name=self.snapshot_name,
                name=snapshot_name,
                deactivate_nodes=[node],
                overwrite=True
            )
            return True
        except Exception as e:
            logger.warning(f"L6 Node Fault Injection Failed ({snapshot_name}): {e}")
            return False

    def generate_diagnostic_qa_node(self, count: int = 10) -> List[Dict[str, Any]]:
        """
        L6: 노드(장비) 장애 진단 문제 생성
        
        1. 정상 상태에서 통신 가능한 Flow 선정
        2. 해당 Flow가 지나는 중간 노드 중 하나를 Down (Fault Injection)
        3. 장애 상태에서 통신 불능 확인 (Symptom Verification)
        4. 문제 생성: "A->B 통신 실패. 다운된 장비를 진단하시오."
        """
        questions = []
        if not self._initialized:
            return questions

        candidates = self.nodes if len(self.nodes) >= 3 else []
        if not candidates:
            return questions

        qa_count = 0
        tried_nodes = set()

        test_pairs = []
        for _ in range(count * 3):
            src = random.choice(candidates)
            dst = random.choice(candidates)
            if src != dst:
                test_pairs.append((src, dst))
        test_pairs = list(set(test_pairs))

        for src_node, dst_node in test_pairs:
            logger.debug(f"[L6_NODE] Processing {src_node} -> {dst_node}")
            if qa_count >= count:
                break

            dst_ips = self.node_ips.get(dst_node, [])
            if not dst_ips:
                continue
            dst_ip = dst_ips[0]

            try:
                src_loc = self._fix_start_location(src_node)
                tr_base = self.bf.q.traceroute(
                    startLocation=src_loc,
                    headers=HeaderConstraints(dstIps=dst_ip)
                ).answer().frame()

                if tr_base.empty:
                    logger.debug(f"[L6_NODE] Baseline empty for {src_node}->{dst_node}")
                    continue
                
                trace = tr_base['Traces'].iloc[0][0]
                disp = getattr(trace, 'disposition', '')
                if disp != 'ACCEPTED':
                    logger.debug(f"[L6_NODE] Baseline failed ({disp}) for {src_node}->{dst_node}")
                    continue

                # 경로상 노드 추출 (출발지/목적지 제외)
                hops = getattr(trace, 'hops', [])
                path_nodes = []
                for hop in hops:
                    n = getattr(hop, 'node', None)
                    if n:
                        hostname = getattr(n, 'hostname', str(n))
                        # 확실하게 제외 (Strict exclusion)
                        if hostname != src_node and hostname != dst_node:
                            path_nodes.append(hostname)

                if not path_nodes:
                    logger.debug(f"[L6_NODE] No intermediate nodes for {src_node}->{dst_node}")
                    continue
                
                logger.debug(f"[L6_NODE] Path nodes for {src_node}->{dst_node}: {path_nodes}")

                # 경로 중간 노드 선택
                target_node = random.choice(path_nodes)
                
                # Double check to prevent selecting source node
                logger.info(f"[L6_NODE_DEBUG] Checking: target={repr(target_node)} vs src={repr(src_node)}")
                if target_node == src_node:
                    logger.debug(f"[L6_NODE] Skipping: target({target_node}) == src({src_node})")
                    continue
                    
                if target_node in tried_nodes:
                    continue
                tried_nodes.add(target_node)

                # Fault Injection
                fault_snapshot = f"diag_node_{target_node}_{int(time.time()*1000)}"
                success = self._inject_fault_node_down(fault_snapshot, target_node)
                if not success:
                    continue

                # Symptom Verification
                tr_fail = self.bf.q.traceroute(
                    startLocation=src_loc,
                    headers=HeaderConstraints(dstIps=dst_ip)
                ).answer(snapshot=fault_snapshot).frame()

                is_broken = False
                fail_disposition = "UNKNOWN"
                if tr_fail.empty:
                    is_broken = True
                    fail_disposition = "NO_ROUTE"
                else:
                    fail_trace = tr_fail['Traces'].iloc[0][0]
                    fail_disposition = getattr(fail_trace, 'disposition', 'UNKNOWN')
                    if fail_disposition != 'ACCEPTED':
                        is_broken = True

                if is_broken:
                    metric = "diagnostic_node_failure"
                    template = self._get_template(metric,
                        "**네트워크 장애 신고**: 사용자 '{src}'에서 목적지 '{dst}'(IP: {dst_ip})로의 통신이 갑자기 중단되었습니다.\n"
                        "현재 상태에서 Traceroute 결과는 '{disposition}'입니다.\n\n"
                        "**질문**: 이 장애의 근본 원인(Root Cause)이 되는 다운된 장비(Node)를 진단하십시오.\n"
                        "[답변 형식: '장비명' (예: Core1)]")
                    
                    q_text = template.format(
                        src=src_node, dst=dst_node, dst_ip=dst_ip, disposition=fail_disposition
                    )
                    
                    questions.append({
                        "id": f"DIAG_NODE_{target_node}",
                        "category": "Diagnostic_Troubleshooting",
                        "level": "L6",
                        "answer_type": "text",
                        "question": q_text,
                        "ground_truth": target_node,
                        "explanation": f"Injected Fault: Node {target_node} set to deactivated.",
                        "evidence_hint": {
                            "scope": {"type": "DIAGNOSTIC_NODE", "src": src_node, "dst": dst_node},
                            "injected_fault": {"type": "NODE_DOWN", "node": target_node},
                            "symptom": fail_disposition
                        },
                        "academic_reference": "NIKA (SIGCOMM'25): Fault Injection Benchmark"
                    })
                    qa_count += 1

            except Exception as e:
                logger.warning(f"Error generating node diagnostic qa: {e}")
                continue

        return questions

    # =========================================================================
    # L6-3: BGP Session Misconfiguration Diagnostic (BGP 세션 오류 진단)
    # =========================================================================
    def generate_diagnostic_qa_bgp_mismatch(self, count: int = 10) -> List[Dict[str, Any]]:
        """
        L6: BGP 세션 호환성 문제 진단
        
        Batfish의 bgpSessionCompatibility 쿼리를 활용하여
        설정상 호환되지 않는 BGP 세션(ASN 불일치, 인증 불일치 등)을 찾아 문제로 출제
        """
        questions = []
        if not self._initialized:
            return questions

        try:
            # Batfish BGP Session Compatibility 분석
            bgp_compat = self.bf.q.bgpSessionCompatibility().answer().frame()
            
            if bgp_compat.empty:
                return questions
            
            # 호환되지 않는 세션 필터링
            incompatible = bgp_compat[bgp_compat['Configured_Status'] != 'UNIQUE_MATCH']
            
            if incompatible.empty:
                return questions

            qa_count = 0
            for _, row in incompatible.iterrows():
                if qa_count >= count:
                    break
                
                node = row.get('Node', 'Unknown')
                remote_node = row.get('Remote_Node', 'Unknown')
                local_ip = row.get('Local_IP', 'N/A')
                remote_ip = row.get('Remote_IP', 'N/A')
                status = row.get('Configured_Status', 'UNKNOWN')
                local_as = row.get('Local_AS', 'N/A')
                remote_as = row.get('Remote_AS', 'N/A')

                metric = "diagnostic_bgp_mismatch"
                template = self._get_template(metric,
                    "**BGP 세션 장애 신고**: '{node}'와 '{remote_node}' 사이의 BGP 세션이 Established 상태가 되지 않습니다.\n"
                    "로컬 IP: {local_ip}, 원격 IP: {remote_ip}\n"
                    "현재 상태: {status}\n\n"
                    "**질문**: BGP 세션이 성립되지 않는 원인을 진단하십시오.\n"
                    "[답변 형식: 'ASN 불일치', '인증 불일치', 'Peer IP 누락' 중 하나]")

                q_text = template.format(
                    node=node, remote_node=remote_node,
                    local_ip=local_ip, remote_ip=remote_ip,
                    status=status
                )

                # 정답 추론
                ground_truth = "설정 오류"
                if 'NO_REMOTE_AS' in status or 'LOCAL_IP_UNKNOWN' in status:
                    ground_truth = "Peer IP 누락"
                elif 'NO_MATCH' in status:
                    ground_truth = "ASN 불일치"
                elif 'AUTH' in status.upper():
                    ground_truth = "인증 불일치"

                questions.append({
                    "id": f"DIAG_BGP_{node}_{remote_node}",
                    "category": "Diagnostic_Troubleshooting",
                    "level": "L6",
                    "answer_type": "text",
                    "question": q_text,
                    "ground_truth": ground_truth,
                    "explanation": f"BGP Session Status: {status}, Local AS: {local_as}, Remote AS: {remote_as}",
                    "evidence_hint": {
                        "scope": {"type": "DIAGNOSTIC_BGP", "node": node, "remote_node": remote_node},
                        "session_status": status,
                        "local_as": str(local_as),
                        "remote_as": str(remote_as)
                    },
                    "academic_reference": "NIKA (SIGCOMM'25): BGP Misconfiguration"
                })
                qa_count += 1

        except Exception as e:
            logger.warning(f"Error generating BGP diagnostic qa: {e}")

        return questions

    # =========================================================================
    # L6-4: OSPF Area Misconfiguration Diagnostic (OSPF Area 불일치 진단)
    # =========================================================================
    def generate_diagnostic_qa_ospf_mismatch(self, count: int = 10) -> List[Dict[str, Any]]:
        """
        L6: OSPF 세션 호환성 문제 진단
        
        Batfish의 ospfSessionCompatibility 쿼리를 활용하여
        설정상 호환되지 않는 OSPF 세션(Area 불일치, Hello/Dead 타이머 불일치 등)을 찾아 문제로 출제
        """
        questions = []
        if not self._initialized:
            return questions

        try:
            # Batfish OSPF Session Compatibility 분석
            ospf_compat = self.bf.q.ospfSessionCompatibility().answer().frame()
            
            if ospf_compat.empty:
                return questions
            
            # 호환되지 않는 세션 필터링
            incompatible = ospf_compat[ospf_compat['Session_Status'] != 'ESTABLISHED']
            
            if incompatible.empty:
                return questions

            qa_count = 0
            for _, row in incompatible.iterrows():
                if qa_count >= count:
                    break
                
                intf = row.get('Interface', {})
                remote_intf = row.get('Remote_Interface', {})
                node = getattr(intf, 'hostname', str(intf)) if hasattr(intf, 'hostname') else str(intf)
                remote_node = getattr(remote_intf, 'hostname', str(remote_intf)) if hasattr(remote_intf, 'hostname') else str(remote_intf)
                status = row.get('Session_Status', 'UNKNOWN')

                metric = "diagnostic_ospf_mismatch"
                template = self._get_template(metric,
                    "**OSPF 인접 관계 장애 신고**: '{node}'와 '{remote_node}' 사이의 OSPF 인접 관계(Adjacency)가 형성되지 않습니다.\n"
                    "현재 상태: {status}\n\n"
                    "**질문**: OSPF 인접 관계가 성립되지 않는 원인을 진단하십시오.\n"
                    "[답변 형식: 'Area 불일치', 'Hello/Dead 타이머 불일치', 'Network Type 불일치' 중 하나]")

                q_text = template.format(node=node, remote_node=remote_node, status=status)

                # 정답 추론 (Batfish 상태 기반)
                ground_truth = "설정 오류"
                status_upper = status.upper()
                if 'AREA' in status_upper:
                    ground_truth = "Area 불일치"
                elif 'TIMER' in status_upper or 'HELLO' in status_upper or 'DEAD' in status_upper:
                    ground_truth = "Hello/Dead 타이머 불일치"
                elif 'NETWORK_TYPE' in status_upper:
                    ground_truth = "Network Type 불일치"

                questions.append({
                    "id": f"DIAG_OSPF_{node}_{remote_node}",
                    "category": "Diagnostic_Troubleshooting",
                    "level": "L6",
                    "answer_type": "text",
                    "question": q_text,
                    "ground_truth": ground_truth,
                    "explanation": f"OSPF Session Status: {status}",
                    "evidence_hint": {
                        "scope": {"type": "DIAGNOSTIC_OSPF", "node": node, "remote_node": remote_node},
                        "session_status": status
                    },
                    "academic_reference": "NIKA (SIGCOMM'25): OSPF Misconfiguration"
                })
                qa_count += 1

        except Exception as e:
            logger.warning(f"Error generating OSPF diagnostic qa: {e}")

        return questions

    # =========================================================================
    # L6-5: ACL Block Diagnostic (ACL 차단 진단)
    # =========================================================================
    def generate_diagnostic_qa_acl_block(self, count: int = 10) -> List[Dict[str, Any]]:
        """
        L6: ACL 차단 진단 문제 생성
        
        Batfish의 searchFilters 쿼리를 활용하여
        특정 트래픽이 어떤 ACL 규칙에 의해 차단되는지 분석하고 문제 출제
        """
        questions = []
        if not self._initialized:
            return questions

        try:
            # 모든 노드에서 ACL 테스트
            # 대표적인 포트: SSH(22), HTTP(80), HTTPS(443), ICMP
            test_ports = [
                (22, 'tcp', 'SSH'),
                (80, 'tcp', 'HTTP'),
                (443, 'tcp', 'HTTPS')
            ]

            qa_count = 0
            for port, proto, service_name in test_ports:
                if qa_count >= count:
                    break

                try:
                    # ACL 검색: 해당 포트가 차단되는 케이스 찾기
                    filters = self.bf.q.searchFilters(
                        headers=HeaderConstraints(
                            dstPorts=str(port),
                            ipProtocols=[proto.upper()]
                        ),
                        action='deny'
                    ).answer().frame()

                    if filters.empty:
                        continue

                    for _, row in filters.iterrows():
                        if qa_count >= count:
                            break

                        node = row.get('Node', 'Unknown')
                        filter_name = row.get('Filter_Name', 'Unknown')
                        flow = row.get('Flow', {})

                        metric = "diagnostic_acl_block"
                        template = self._get_template(metric,
                            "**서비스 접속 장애 신고**: '{node}' 장비에서 {service}({port}/{proto}) 서비스 접근이 거부됩니다.\n\n"
                            "**질문**: 해당 트래픽을 차단하는 ACL(Access Control List) 이름을 찾으십시오.\n"
                            "[답변 형식: 'ACL 이름' (예: BLOCK_SSH_IN)]")

                        q_text = template.format(
                            node=node, service=service_name, port=port, proto=proto.upper()
                        )

                        questions.append({
                            "id": f"DIAG_ACL_{node}_{service_name}",
                            "category": "Diagnostic_Troubleshooting",
                            "level": "L6",
                            "answer_type": "text",
                            "question": q_text,
                            "ground_truth": filter_name,
                            "explanation": f"Filter {filter_name} on {node} denies {proto.upper()}/{port}",
                            "evidence_hint": {
                                "scope": {"type": "DIAGNOSTIC_ACL", "node": node},
                                "blocked_service": service_name,
                                "filter_name": filter_name
                            },
                            "academic_reference": "NIKA (SIGCOMM'25): ACL Misconfiguration"
                        })
                        qa_count += 1

                except Exception as e:
                    logger.debug(f"ACL search for port {port} failed: {e}")
                    continue

        except Exception as e:
            logger.warning(f"Error generating ACL diagnostic qa: {e}")

        return questions
