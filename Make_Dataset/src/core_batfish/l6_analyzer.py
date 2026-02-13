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

    def _safe_text(self, value: Any, default: str = "Unknown") -> str:
        """None/NaN/공백을 안전한 문자열로 정규화"""
        if value is None:
            return default
        text = str(value).strip()
        if not text or text.lower() == "nan":
            return default
        return text

    def _slug(self, value: Any) -> str:
        """ID/스냅샷 이름에 안전한 slug 생성"""
        text = self._safe_text(value, default="unknown")
        return re.sub(r"[^a-zA-Z0-9_.-]+", "_", text).strip("_") or "unknown"

    def _make_question_id(self, prefix: str, *parts: Any) -> str:
        """충돌을 줄인 question id 생성기"""
        head = "_".join([self._slug(prefix)] + [self._slug(p) for p in parts if p is not None])
        return f"{head}_{int(time.time()*1000)}_{random.randint(1000, 9999)}"

    def _hop_hostname(self, hop: Any) -> str:
        """Batfish hop 객체에서 hostname 추출"""
        node = getattr(hop, 'node', None)
        if node is None:
            return "Unknown"
        hostname = getattr(node, 'hostname', None)
        if hostname:
            return self._safe_text(hostname)
        name = getattr(node, 'name', None)
        if name:
            return self._safe_text(name)
        return self._safe_text(node)

    def _same_node(self, a: Any, b: Any) -> bool:
        """노드명 비교 (대소문자/공백 차이 무시)"""
        return self._safe_text(a).lower() == self._safe_text(b).lower()

    def _traceroute_frame(self, src_node: str, dst_ip: str, snapshot: Optional[str] = None):
        """
        traceroute를 안전하게 실행.
        1) _fix_start_location(node) 시도
        2) 실패 시 node 자체로 재시도
        """
        last_error = None
        candidates = [self._fix_start_location(src_node), src_node]
        tried = set()
        for start_loc in candidates:
            if start_loc in tried:
                continue
            tried.add(start_loc)
            try:
                q = self.bf.q.traceroute(
                    startLocation=start_loc,
                    headers=HeaderConstraints(dstIps=dst_ip)
                )
                if snapshot:
                    return q.answer(snapshot=snapshot).frame()
                return q.answer().frame()
            except Exception as e:
                last_error = e
                logger.debug(f"L6 traceroute retry: start={start_loc}, dst={dst_ip}, snapshot={snapshot}, error={e}")

        raise last_error if last_error else RuntimeError("Traceroute failed with unknown error")

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
        if not self._initialized or HeaderConstraints is None or Interface is None:
            return questions

        # 1. 대상 Flow 선정 (Edge 장비 위주)
        candidates = self.nodes if len(self.nodes) >= 2 else []
        if not candidates:
            return questions

        qa_count = 0
        tried_fault_targets = set()

        # Random Pair Sampling
        test_pairs = []
        for _ in range(count * 3):  # 3배수 후보 선정
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
                tr_base = self._traceroute_frame(src_node=src_node, dst_ip=dst_ip)

                if tr_base.empty:
                    logger.debug(f"[L6_LINK] Baseline empty for {src_node}->{dst_node}")
                    continue
                
                trace = tr_base['Traces'].iloc[0][0]
                disp = getattr(trace, 'disposition', '')
                if disp != 'ACCEPTED':
                    logger.debug(f"[L6_LINK] Baseline failed ({disp}) for {src_node}->{dst_node}")
                    continue  # 원래 안 되는 경로는 패스

                # outgoing interface + 다음 hop node를 함께 추출
                hops = list(getattr(trace, 'hops', []))
                path_hops = []
                for idx, hop in enumerate(hops):
                    hostname = self._hop_hostname(hop)
                    exit_intf = None
                    for step in getattr(hop, 'steps', []):
                        detail = getattr(step, 'detail', None)
                        if detail:
                            exit_intf = getattr(detail, 'outputInterface', None)
                            if not exit_intf and isinstance(detail, dict):
                                exit_intf = detail.get('outputInterface')

                        if exit_intf:
                            break

                    if hostname and exit_intf:
                        next_hop_name = self._safe_text(dst_node)
                        if idx + 1 < len(hops):
                            next_hop_name = self._hop_hostname(hops[idx + 1])
                        path_hops.append((hostname, str(exit_intf), next_hop_name))

                logger.debug(f"[L6_LINK] Path hops for {src_node}->{dst_node}: {path_hops}")

                if not path_hops:
                    logger.debug(f"[L6_LINK] No valid exit interfaces for {src_node}->{dst_node}. Hops: {len(hops)}")
                    continue

                # Select a random hop to fail
                target_hop = random.choice(path_hops)
                u_name, intf_u, v_name = target_hop
                fault_key = (u_name, intf_u, v_name)
                if fault_key in tried_fault_targets:
                    continue
                tried_fault_targets.add(fault_key)

                # 3. Fault Injection (Snapshot Forking)
                # Snapshot name cannot contain slashes ('/')
                safe_intf = self._slug(intf_u)
                fault_snapshot = f"diag_link_{self._slug(u_name)}_{safe_intf}_{int(time.time()*1000)}"

                # Use explicit Interface objects for robustness
                # Pybatfish Interface uses hostname and interface
                target_iface = Interface(hostname=u_name, interface=intf_u)
                logger.info(f"[L6_LINK] Injecting fault: {target_iface}")
                success = self._inject_fault_interface_down(fault_snapshot, [target_iface])

                if not success:
                    continue

                # 4. Symptom Verification (With Fault)
                # 동일한 경로가 끊겼는지 확인
                tr_fail = self._traceroute_frame(src_node=src_node, dst_ip=dst_ip, snapshot=fault_snapshot)

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
                        "id": self._make_question_id("DIAG_LINK", src_node, dst_node, u_name, v_name, intf_u),
                        "category": "Diagnostic_Troubleshooting",
                        "level": "L6",
                        "answer_type": "text",
                        "question": q_text,
                        "ground_truth": ground_truth,
                        "explanation": f"Injected Fault: Interface {intf_u} on {u_name} set to administrative down.",
                        "evidence_hint": {
                            "scope": {"type": "DIAGNOSTIC_LINK", "src": src_node, "dst": dst_node},
                            "injected_fault": {
                                "type": "LINK_DOWN",
                                "link": ground_truth,
                                "node": u_name,
                                "interface": intf_u
                            },
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
        if not self._initialized or HeaderConstraints is None:
            return questions

        candidates = self.nodes if len(self.nodes) >= 3 else []
        if not candidates:
            return questions

        qa_count = 0
        tried_fault_targets = set()

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
                tr_base = self._traceroute_frame(src_node=src_node, dst_ip=dst_ip)

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
                    hostname = self._hop_hostname(hop)
                    if not self._same_node(hostname, src_node) and not self._same_node(hostname, dst_node):
                        path_nodes.append(hostname)

                if not path_nodes:
                    logger.debug(f"[L6_NODE] No intermediate nodes for {src_node}->{dst_node}")
                    continue
                
                logger.debug(f"[L6_NODE] Path nodes for {src_node}->{dst_node}: {path_nodes}")

                # 경로 중간 노드 선택
                target_node = self._safe_text(random.choice(path_nodes))
                
                # Double check to prevent selecting source node
                logger.info(f"[L6_NODE_DEBUG] Checking: target={repr(target_node)} vs src={repr(src_node)}")
                if self._same_node(target_node, src_node):
                    logger.debug(f"[L6_NODE] Skipping: target({target_node}) == src({src_node})")
                    continue
                    
                fault_key = (src_node, dst_node, target_node)
                if fault_key in tried_fault_targets:
                    continue
                tried_fault_targets.add(fault_key)

                # Fault Injection
                fault_snapshot = f"diag_node_{self._slug(target_node)}_{int(time.time()*1000)}"
                success = self._inject_fault_node_down(fault_snapshot, target_node)
                if not success:
                    continue

                # Symptom Verification
                tr_fail = self._traceroute_frame(src_node=src_node, dst_ip=dst_ip, snapshot=fault_snapshot)

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
                        "id": self._make_question_id("DIAG_NODE", src_node, dst_node, target_node),
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
            seen_sessions = set()
            for _, row in incompatible.iterrows():
                if qa_count >= count:
                    break

                node = self._safe_text(row.get('Node', 'Unknown'))
                remote_node = self._safe_text(row.get('Remote_Node', 'Unknown'))
                local_ip = self._safe_text(row.get('Local_IP', 'N/A'), default="N/A")
                remote_ip = self._safe_text(row.get('Remote_IP', 'N/A'), default="N/A")
                status = self._safe_text(row.get('Configured_Status', 'UNKNOWN'))
                local_as = self._safe_text(row.get('Local_AS', 'N/A'), default="N/A")
                remote_as = self._safe_text(row.get('Remote_AS', 'N/A'), default="N/A")
                session_key = (node, remote_node, local_ip, remote_ip, status)
                if session_key in seen_sessions:
                    continue
                seen_sessions.add(session_key)

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
                    "id": self._make_question_id("DIAG_BGP", node, remote_node, local_ip, remote_ip),
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
            seen_pairs = set()
            for _, row in incompatible.iterrows():
                if qa_count >= count:
                    break

                intf = row.get('Interface', {})
                remote_intf = row.get('Remote_Interface', {})
                node = self._safe_text(getattr(intf, 'hostname', str(intf)) if hasattr(intf, 'hostname') else str(intf))
                remote_node = self._safe_text(getattr(remote_intf, 'hostname', str(remote_intf)) if hasattr(remote_intf, 'hostname') else str(remote_intf))
                status = self._safe_text(row.get('Session_Status', 'UNKNOWN'))
                pair_key = (node, remote_node, status)
                if pair_key in seen_pairs:
                    continue
                seen_pairs.add(pair_key)

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
                    "id": self._make_question_id("DIAG_OSPF", node, remote_node),
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
        if not self._initialized or HeaderConstraints is None:
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
            seen_acl = set()
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

                        node = self._safe_text(row.get('Node', 'Unknown'))
                        filter_name = self._safe_text(row.get('Filter_Name', 'Unknown'))
                        dedup_key = (node, service_name, port, filter_name)
                        if dedup_key in seen_acl:
                            continue
                        seen_acl.add(dedup_key)

                        metric = "diagnostic_acl_block"
                        template = self._get_template(metric,
                            "**서비스 접속 장애 신고**: '{node}' 장비에서 {service}({port}/{proto}) 서비스 접근이 거부됩니다.\n\n"
                            "**질문**: 해당 트래픽을 차단하는 ACL(Access Control List) 이름을 찾으십시오.\n"
                            "[답변 형식: 'ACL 이름' (예: BLOCK_SSH_IN)]")

                        q_text = template.format(
                            node=node, service=service_name, port=port, proto=proto.upper()
                        )

                        questions.append({
                            "id": self._make_question_id("DIAG_ACL", node, service_name, port, filter_name),
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
