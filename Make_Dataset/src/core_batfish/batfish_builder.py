"""
Batfish 기반 L4/L5 문제 생성기 (통합 Facade)

이 파일은 리팩토링된 모듈들을 통합하는 Facade 클래스입니다.
실제 구현은 다음 파일들에 분리되어 있습니다:

- models.py: 데이터 클래스 (AnswerResult, FlowSpec 등)
- batfish_base.py: BatfishBase 클래스 (초기화, 스냅샷 관리)
- l4_analyzer.py: L4AnalyzerMixin (도달성 분석 메트릭)
- l5_analyzer.py: L5AnalyzerMixin (What-If 분석 메트릭)

=== 학술적 근거 (Golden 6 Papers) ===

1. HSA (Header Space Analysis) - NSDI 2012
2. VeriFlow - NSDI 2013
3. Batfish - NSDI 2015
4. Minesweeper - SIGCOMM 2017
5. Config2Spec - NSDI 2020
6. DNA (Differential Network Analysis) - NSDI 2022
"""

import os
import json
import logging
import random
import re
import time
from typing import Dict, List, Any, Optional, Tuple, Set
from itertools import combinations
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

# 리팩토링된 모듈 임포트
from .models import (
    AnswerResult, FlowSpec, L4Result, L5Result,
    CanonicalizationError, CONFIGURED_RULES, UNKNOWN_REASONS,
    build_evidence, canonicalize, _build_evidence, _canonicalize
)
from .batfish_base import BatfishBase, BATFISH_AVAILABLE
from .l4_analyzer import L4AnalyzerMixin
from .l5_analyzer import L5AnalyzerMixin
from .l6_analyzer import L6AnalyzerMixin
from .ko_josa import fix_josa

# Batfish 로드 (선택적)
try:
    from pybatfish.client.session import Session
    from pybatfish.datamodel.flow import HeaderConstraints, PathConstraints
except ImportError:
    Session = None
    HeaderConstraints = None
    PathConstraints = None

logger = logging.getLogger(__name__)


class BatfishBuilder(BatfishBase, L4AnalyzerMixin, L5AnalyzerMixin, L6AnalyzerMixin):
    """
    Batfish 기반 L4/L5 문제 생성기
    
    Multiple Inheritance (Mixin 패턴)를 사용하여 기능을 모듈화:
    - BatfishBase: 초기화, 스냅샷 관리, 기본 쿼리
    - L4AnalyzerMixin: 도달성 분석 (Traceroute, ACL, Loop 등)
    - L5AnalyzerMixin: What-If 분석 (Link Failure, RCA 등)
    - L6AnalyzerMixin: Diagnostic 분석 (Fault Injection, 역추론)
    """

    def __init__(
        self,
        network_name: str,
        snapshot_path: str,
        policies_path: str = None,
        batfish_host: str = "localhost",
        question_lang: str = "ko",
    ):
        # Fix: Pass arguments by keyword to avoid mismatch with BatfishBase signature
        super().__init__(snapshot_path=snapshot_path, network_name=network_name, batfish_host=batfish_host)
        self.question_lang = str(question_lang or "ko").strip().lower()
        if self.question_lang not in {"ko", "en"}:
            raise ValueError(f"Unsupported question_lang: {self.question_lang}")
        
        self.metrics_metadata = {}
        if policies_path:
            try:
                policy_text = Path(policies_path).read_text(encoding="utf-8")
                policy_data = json.loads(policy_text)
                self.metrics_metadata = policy_data.get("metrics_metadata", {})
            except Exception as e:
                logger.error(f"Failed to load policies from {policies_path}: {e}")

    def _get_template(self, metric: str, default: str) -> str:
        """Get localized template from metadata or return default."""
        if metric in self.metrics_metadata:
            if self.question_lang == "en":
                template_en = str(self.metrics_metadata[metric].get("template_en", "")).strip()
                if not template_en:
                    raise ValueError(
                        f"Metric '{metric}' is missing template_en for question_lang=en"
                    )
                return template_en
            return self.metrics_metadata[metric].get("template", default)
        return default

    def _format_question(self, template: str, **kwargs) -> str:
        """템플릿에 변수를 치환하고, 한국어인 경우 조사를 교정합니다."""
        q_text = template.format(**kwargs)
        if self.question_lang == "ko":
            q_text = fix_josa(q_text)
        return q_text

    # =========================================================================
    # 문제 생성 메서드
    # =========================================================================
    
    def generate_l4_questions(self, seed: int = 42) -> List[Dict[str, Any]]:
        """L4 레벨 문제 생성"""
        questions = []
        random.seed(seed)  # 재현성 보장
        
        if not self._initialized:
            logger.warning("Batfish not initialized. Skipping L4 question generation.")
            return questions
        
        # 1. Traceroute 문제
        all_pairs = self.get_node_pairs()
        random.shuffle(all_pairs)
        for src_node, dst_node in all_pairs:
            dst_ips = self.node_ips.get(dst_node, [])
            if dst_ips:
                tr_result = self.traceroute_path(src_node, dst_ips[0], target_name=dst_node)
                path_str = " → ".join(tr_result.value) if tr_result.status == "OK" and tr_result.value else "경로 없음"
                # 템플릿 호환성을 위해 src_ip/src_node 둘 다 제공
                src_ip_for_q = self.node_ips.get(src_node, [src_node])[0]
                
                metric = "traceroute_path"
                template = self._get_template(metric, "{src_node}에서 {dst_node}({dst_ip})로 가는 패킷의 네트워크 경로를 알려주세요.\n[답변 형식: 화살표(→)로 구분된 장비 목록]")
                q_text = self._format_question(template, src_ip=src_ip_for_q, dst_ip=dst_ips[0], src_node=src_node, dst_node=dst_node)

                questions.append({
                    "id": f"TRACEROUTE_{src_node}_{dst_node}",
                    "category": "Reachability_Analysis",
                    "level": "L4",
                    "answer_type": "text",
                    "question": q_text,
                    "ground_truth": path_str,
                    "explanation": f"metric `{metric}` on src={src_node}, dst={dst_ips[0]}",
                    "evidence_hint": {
                        "scope": {"type": "NODE_PAIR", "src": src_node, "dst": dst_node},
                        "metric": metric
                    }
                })
        
        # 2. Reachability 문제
        all_flows = self.get_representative_flows()
        random.shuffle(all_flows)  # Shuffle flows for diversity
        
        for flow in all_flows[:30]:  # Limit to 30 diverse flows
            res = self.reachability_status(flow.src_ip, flow.dst_ip, flow.dst_port, flow.protocol)
            
            if res.status != "OK":
                continue
                
            reachable = res.value.get("reachable", False)
            path_list = res.value.get("path", [])
            disposition = res.value.get("disposition", "UNKNOWN")
            
            path_str = " → ".join(path_list) if path_list else "없음"
            
            # Formulate the answer with the mapped disposition
            if reachable:
                result_text = f"경로: {path_str}, 도달: 가능"
            else:
                result_text = f"경로: {path_str}, 도달: 불가 (원인: {disposition})"
            
            metric = "reachability_status"
            # Updated template with explicit classification options for LLM evaluation
            template = self._get_template(metric, "{src_ip}에서 {dst_ip}({dst_port}/{protocol})로의 트래픽 경로와 도달 여부를 알려주세요.\n[답변 형식: '경로: A → B → C, 도달: 가능' 또는 '경로: ..., 도달: 불가 (원인: NO_ROUTE, ACL_DENY, EXTERNAL 중 택1)']")
            q_text = self._format_question(template, src_ip=flow.src_ip, dst_ip=flow.dst_ip, dst_port=flow.dst_port, protocol=flow.protocol, src_location=flow.src_location, dst_location=flow.dst_location)

            questions.append({
                "id": f"REACH_{flow.src_location}_{flow.dst_location}_{flow.protocol}",
                "category": "Reachability_Analysis",
                "level": "L4",
                "answer_type": "text",
                "question": q_text,
                "ground_truth": result_text,
                "explanation": f"metric `{metric}` on src={flow.src_ip}, dst={flow.dst_ip}",
                "evidence_hint": {
                    "scope": {"type": "FLOW", "src_ip": flow.src_ip, "dst_ip": flow.dst_ip},
                    "metric": metric
                },
                "academic_reference": "HSA (NSDI'12), VeriFlow (NSDI'13), Batfish (NSDI'15)"
            })
        
        # 3. Loop Detection
        loop_res = self.loop_detection()
        if loop_res.status == "OK":
            has_loop = loop_res.value.get("detected", False)
            loops = loop_res.value.get("loops", [])
            
            result_text = f"발견: {loops[0] if loops else 'Loop detected'}" if has_loop else "없음"
            
            metric = "loop_detection"
            template = self._get_template(metric, "네트워크에 포워딩 루프가 존재합니까?\n[답변 형식: '없음' 또는 '발견: A→B→C→A']")
            
            questions.append({
                "id": "LOOP_DETECTION_GLOBAL",
                "category": "Reachability_Analysis",
                "level": "L4",
                "answer_type": "text",
                "question": template,
                "ground_truth": result_text,
                "explanation": "metric `loop_detection` analysis result",
                "evidence_hint": {"scope": {"type": "GLOBAL"}, "metric": metric},
                "academic_reference": "HSA (NSDI'12): loop-free as core invariant"
            })
        
        # 3.5 ACL Blocking Point Analysis
        acl_flows = self.get_representative_flows()
        random.shuffle(acl_flows)
        acl_q_count = 0
        
        for flow in acl_flows[:30]:
            # Use acl_blocking_point analysis
            # Ensure port is valid (default 80 if 0/None)
            port = flow.dst_port if flow.dst_port else 80
            
            res = self.acl_blocking_point(flow.src_ip, flow.dst_ip, port)
            if res.status == "OK":
                blocked = res.value.get("blocked", False)
                blocking_node = res.value.get("node", "")
                reason = res.value.get("reason", "")
                
                if blocked:
                    result_text = f"차단됨 (장비: {blocking_node}, 원인: {reason})"
                else:
                    result_text = "허용됨"
                
                metric = "acl_blocking_point"
                template = self._get_template(metric, "{src_ip}에서 {dst_ip}({dst_port}/TCP)로의 트래픽이 ACL에 의해 차단됩니까? 차단된다면 어느 장비입니까?\\n[답변 형식: '허용됨' 또는 '차단됨 (장비: 장비명, 원인: 사유)']")
                q_text = self._format_question(template, src_ip=flow.src_ip, dst_ip=flow.dst_ip, dst_port=port)
                
                questions.append({
                    "id": f"ACL_BLOCKING_{flow.src_location}_{flow.dst_location}",
                    "category": "Security_Analysis",
                    "level": "L4",
                    "answer_type": "text",
                    "question": q_text,
                    "ground_truth": result_text,
                    "explanation": f"metric `{metric}` analysis",
                    "evidence_hint": {"scope": {"type": "FLOW", "src_ip": flow.src_ip, "dst_ip": flow.dst_ip}, "metric": metric},
                    "academic_reference": "ACL Reachability Analysis"
                })
                acl_q_count += 1
                if acl_q_count >= 10:
                    break

        # 4. Bounded Path Length
        all_pairs_bounded = self.get_node_pairs()
        random.shuffle(all_pairs_bounded)
        for src_node, dst_node in all_pairs_bounded:
            dst_ips = self.node_ips.get(dst_node, [])
            if dst_ips:
                bound_res = self.bounded_path_length(src_node, dst_ips[0], max_hops=5)
                if bound_res.status == "OK":
                    hop_count = bound_res.value.get("hops", -1)
                    
                    metric = "bounded_path_length"
                    template = self._get_template(metric, "{src_host}에서 {dst_ip}로 가는 경로의 홉 수는 몇 개입니까?\n[답변 형식: 숫자]")
                    q_text = self._format_question(template, src_host=src_node, dst_ip=dst_ips[0], src_node=src_node, dst_node=dst_node)

                    questions.append({
                        "id": f"BOUNDED_PATH_{src_node}_{dst_node}",
                        "category": "Reachability_Analysis",
                        "level": "L4",
                        "answer_type": "number",
                        "question": q_text,
                        "ground_truth": str(hop_count),
                        "explanation": f"metric `{metric}` on {src_node}->{dst_node}",
                        "evidence_hint": {"scope": {"type": "NODE_PAIR", "src": src_node, "dst": dst_node}, "metric": metric},
                        "academic_reference": "Minesweeper (SIGCOMM'17): bounded path length"
                    })
        
        # 5. Blackhole Detection - Now returns destination list instead of boolean
        bh_res = self.blackhole_detection()
        if bh_res.status == "OK":
            blackholes = bh_res.value.get("blackholes", [])
            
            metric = "blackhole_destination_list"
            template = self._get_template(metric, "네트워크에서 블랙홀이 발생하는 목적지 prefix 목록을 알려주세요.\n[답변 형식: prefix 목록 (예: [\"10.0.0.0/8\"]) 또는 빈 목록 []]")
            
            questions.append({
                "id": "BLACKHOLE_DETECTION_GLOBAL",
                "category": "Reachability_Analysis",
                "level": "L4",
                "answer_type": "set",
                "question": template,
                "ground_truth": blackholes if blackholes else [],
                "explanation": f"metric `{metric}` found {len(blackholes)} blackholes",
                "evidence_hint": {"scope": {"type": "GLOBAL"}, "metric": metric},
                "academic_reference": "HSA (NSDI'12), Minesweeper (SIGCOMM'17): blackhole detection"
            })
        
        # 6. Waypoint Traversal Path
        spine_or_pe = self.get_transit_nodes()  # 토폴로지 추론 기반 (이전: 이름 기반)
        if len(self.nodes) >= 3 and spine_or_pe:
            waypoint_count = 0
            for waypoint in spine_or_pe[:5]:
                test_pairs = [(self.nodes[0], self.nodes[-1])]
                for src_node, dst_node in test_pairs:
                    src_ips = self.node_ips.get(src_node, [])
                    dst_ips = self.node_ips.get(dst_node, [])
                    if src_ips and dst_ips:
                        wp_res = self.waypoint_check(src_ips[0], dst_ips[0], waypoint)
                        if wp_res.status == "OK":
                            passes = wp_res.value.get("passes_through", False)
                            path = wp_res.value.get("path", [])
                            path_str = " → ".join(path) if path else "경로 정보 없음"
                            ground_truth = path_str if passes else "경유하지 않음"
                            
                            metric = "waypoint_traversal_path"
                            template = self._get_template(metric, f"{{src_ip}}에서 {{dst_ip}}로의 트래픽이 {{waypoint}} 장비를 경유하는 경로를 알려주세요.\\n[답변 형식: 'A → B → C' 또는 '경유하지 않음']")
                            q_text = self._format_question(template, src_ip=src_ips[0], dst_ip=dst_ips[0], waypoint=waypoint)
                            
                            questions.append({
                                "id": f"WAYPOINT_{src_node}_{dst_node}_{waypoint}",
                                "category": "Reachability_Analysis",
                                "level": "L4",
                                "answer_type": "text",
                                "question": q_text,
                                "ground_truth": ground_truth,
                                "explanation": f"metric `{metric}` for waypoint {waypoint}",
                                "evidence_hint": {"scope": {"type": "WAYPOINT", "src": src_ips[0], "dst": dst_ips[0], "waypoint": waypoint}, "metric": metric},
                                "academic_reference": "Waypoint enforcement verification"
                            })
                            waypoint_count += 1
                if waypoint_count >= 10:
                    break
        
        # 7. VRF Isolation - Leaked Prefixes List
        try:
            # Query VRFs from Batfish
            vrf_query = self.bf.q.nodeProperties(properties="VRFs").answer().frame()
            vrf_names = set()
            if not vrf_query.empty and 'VRFs' in vrf_query.columns:
                for vrfs_list in vrf_query['VRFs']:
                    if vrfs_list:
                        vrf_names.update(vrfs_list)
            
            vrf_list = sorted(vrf_names)
            if len(vrf_list) >= 2:
                for i, vrf1 in enumerate(vrf_list[:3]):
                    for vrf2 in vrf_list[i+1:4]:
                        iso_res = self.isolation_check(vrf1, vrf2)
                        if iso_res.status == "OK":
                            leaked = iso_res.value.get("leaked_prefixes", [])
                            
                            metric = "leaked_prefixes_list"
                            template = self._get_template(metric, f"{{vrf1}}과 {{vrf2}} VRF 사이에 누수된 prefix 목록을 알려주세요.\\n[답변 형식: prefix 리스트 또는 빈 리스트 []]")
                            q_text = self._format_question(template, vrf1=vrf1, vrf2=vrf2)
                            
                            questions.append({
                                "id": f"ISOLATION_{vrf1}_{vrf2}",
                                "category": "Security_Analysis",
                                "level": "L4",
                                "answer_type": "set",
                                "question": q_text,
                                "ground_truth": leaked if leaked else [],
                                "explanation": f"metric `{metric}` between {vrf1} and {vrf2}",
                                "evidence_hint": {"scope": {"type": "VRF_PAIR", "vrf1": vrf1, "vrf2": vrf2}, "metric": metric},
                                "academic_reference": "VRF isolation verification"
                            })
        except Exception as e:
            logger.warning(f"VRF isolation check failed: {e}")
        
        # 8. Asymmetric Path Comparison
        node_pairs = self.get_node_pairs()
        random.shuffle(node_pairs)  # seed는 generate_l4_questions()에서 고정
        asym_count = 0
        for node1, node2 in node_pairs[:15]:
            asym_res = self.asymmetric_path_check(node1, node2)
            if asym_res.status == "OK":
                symmetric = asym_res.value.get("symmetric", True)
                fwd_path = asym_res.value.get("path_forward", [])
                rev_path = asym_res.value.get("path_reverse", [])
                
                fwd_str = " → ".join(fwd_path) if fwd_path else "경로 없음"
                rev_str = " → ".join(rev_path) if rev_path else "경로 없음"
                ground_truth = f"Forward: {fwd_str}, Reverse: {rev_str}"
                
                metric = "asymmetric_path_comparison"
                template = self._get_template(metric, f"{{host1}}과 {{host2}} 사이의 Forward 경로와 Reverse 경로를 비교해주세요.\\n[답변 형식: 'Forward: A→B, Reverse: B→A']")
                q_text = self._format_question(template, host1=node1, host2=node2)
                
                questions.append({
                    "id": f"ASYMMETRIC_{node1}_{node2}",
                    "category": "Routing_Analysis",
                    "level": "L4",
                    "answer_type": "text",
                    "question": q_text,
                    "ground_truth": ground_truth,
                    "explanation": f"metric `{metric}` for {node1}-{node2}",
                    "evidence_hint": {"scope": {"type": "NODE_PAIR", "node1": node1, "node2": node2}, "metric": metric},
                    "academic_reference": "Asymmetric routing detection"
                })
                asym_count += 1
                if asym_count >= 10:
                    break
        
        # 9. Advanced: OSPF Compatibility Check
        ospf_pairs = self.get_node_pairs()
        random.shuffle(ospf_pairs)
        ospf_q_count = 0
        for node1, node2 in ospf_pairs[:30]:
            compat_res = self.ospf_compatibility_check(node1, node2)
            if compat_res.status == "OK":
                issues = compat_res.value.get("issues", [])
                metric = "ospf_compatibility_check"
                template = self._get_template(metric, "{node1}과 {node2} 사이에 OSPF 네이버가 형성되지 않는 경우, 가능한 원인들을 분석하세요.\n[답변 형식: JSON {{\"issues\": [...]}}]")
                q_text = self._format_question(template, node1=node1, node2=node2)

                # 정책 계약(최상위 키=issues)에 맞춘 정답 구조
                # 주의: dict로 유지해야 main_batfish에서 JSON 문자열로 1회만 직렬화됩니다.
                ground_truth = {"issues": issues}
                questions.append({
                    "id": f"OSPF_COMPAT_{node1}_{node2}",
                    "category": "Routing_Consistency",
                    "level": "L4",
                    "answer_type": "json",
                    "question": q_text,
                    "ground_truth": ground_truth,
                    "explanation": f"metric `{metric}` on {node1}-{node2}",
                    "evidence_hint": {"scope": {"type": "NODE_PAIR", "node1": node1, "node2": node2}, "metric": metric},
                    "academic_reference": "RFC 2328, 현업: OSPF 트러블슈팅"
                })
                ospf_q_count += 1
                if ospf_q_count >= 15:
                    break
        
        # 7. Advanced: Security Policy Bypass Check
        spine_nodes = self.get_transit_nodes()  # 토폴로지 추론 기반 (이전: 이름 기반)
        leaf_nodes = self.get_edge_nodes()        # 토폴로지 추론 기반 (이전: 이름 기반)
        
        if spine_nodes and len(leaf_nodes) >= 2:
            bypass_q_count = 0
            for required_wp in spine_nodes[:2]:
                for src_leaf in leaf_nodes[:4]:
                    # leaf 수가 적어도 src!=dst 조건만 만족하면 생성되도록 보정
                    dst_candidates = [n for n in leaf_nodes if n != src_leaf][:4]
                    for dst_leaf in dst_candidates:
                        if src_leaf == dst_leaf:
                            continue
                        bypass_res = self.security_policy_bypass_check(src_leaf, dst_leaf, required_wp)
                        if bypass_res.status == "OK":
                            bypass_exists = bypass_res.value.get("bypass_exists", False)
                            bypass_path = bypass_res.value.get("bypass_path", [])
                            
                            # Clear text answer with explicit format guidance
                            if bypass_exists:
                                path_str = " → ".join(bypass_path) if bypass_path else "직접 경로"
                                gt_text = f"우회 경로 존재 (경로: {path_str})"
                            else:
                                gt_text = "우회 경로 없음 (정책 준수)"
                            
                            metric = "security_policy_bypass_check"
                            template = self._get_template(metric, "보안 정책상 '{src}'에서 '{dst}'로 가는 모든 트래픽은 반드시 '{waypoint}' 장비를 경유해야 합니다. 현재 구성에서 이 정책을 우회하는 경로가 존재합니까? [답변 형식: '우회 경로 존재 (경로: A→B→C)' 또는 '우회 경로 없음 (정책 준수)']")
                            q_text = self._format_question(template, src=src_leaf, dst=dst_leaf, waypoint=required_wp)
                            
                            questions.append({
                                "id": f"SEC_BYPASS_{src_leaf}_{dst_leaf}_{required_wp}",
                                "category": "Security_Policy",
                                "level": "L4",
                                "answer_type": "text",
                                "question": q_text,
                                "ground_truth": gt_text,
                                "explanation": f"metric `{metric}` waypoint={required_wp}",
                                "evidence_hint": {"scope": {"type": "SECURITY_POLICY", "src": src_leaf, "dst": dst_leaf, "waypoint": required_wp}, "metric": metric},
                                "academic_reference": "Config2Spec (NSDI'20)"
                            })
                            bypass_q_count += 1
                            if bypass_q_count >= 20:
                                break
                    if bypass_q_count >= 20:
                        break
                if bypass_q_count >= 20:
                    break
        
        return questions
    
    def generate_l5_questions(self, seed: int = 42) -> List[Dict[str, Any]]:
        """L5 레벨 문제 생성"""
        questions = []
        random.seed(seed)  # 재현성 보장
        
        if not self._initialized:
            logger.warning("Batfish not initialized. Skipping L5 question generation.")
            return questions
        
        # 1. Link Failure Impact
        edges = self.get_layer3_edges()
        ce_nodes = self.get_edge_nodes()            # 토폴로지 추론 기반 (이전: 이름 기반)
        pe_nodes = self.get_provider_edge_nodes()    # 토폴로지 추론 기반 (이전: 이름 기반)
        
        if edges and len(ce_nodes) >= 2:
            link_count = 0
            for edge in edges[:80]:
                if link_count >= 80:
                    break
                node1, node2 = edge["node1"], edge["node2"]
                src = ce_nodes[0]
                dst = ce_nodes[-1] if len(ce_nodes) > 1 else ce_nodes[0]
                
                link_res = self.link_failure_impact(node1, node2, src, dst)
                if link_res.status in ["OK", "NOT_APPLICABLE"]:
                    impact = link_res.value.get("impact", "NONE")
                    
                    metric = "link_failure_impact"
                    template = self._get_template(metric, "'{link}' 링크가 다운될 경우, '{src}→{dst}' 트래픽에 어떤 영향이 발생합니까?\n[답변 형식: 'NONE', 'REROUTED', 'DISCONNECTED']")
                    q_text = self._format_question(template, link=f"{node1}-{node2}", src=src, dst=dst)

                    questions.append({
                        "id": f"LINK_FAILURE_{node1}_{node2}",
                        "category": "What_If_Analysis",
                        "level": "L5",
                        "answer_type": "text",
                        "question": q_text,
                        # 정책 템플릿 계약: enum 값만 반환
                        "ground_truth": impact,
                        "explanation": f"metric `{metric}` on {node1}-{node2}->({src}->{dst})",
                        "evidence_hint": {"scope": {"type": "LINK_FAILURE", "link": f"{node1}-{node2}"}, "metric": metric},
                        "academic_reference": "DNA (NSDI'22), Minesweeper (SIGCOMM'17)"
                    })
                    link_count += 1
        
        # 2. SPOF Detection
        spof_res = self.spof_detection()
        if spof_res.status == "OK":
            spof_nodes = spof_res.value.get("spof_nodes", [])
            
            metric = "spof_detection"
            template = self._get_template(metric, "단일 장비 장애 시 통신이 두절되는 구간(SPOF: Single Point of Failure)이 존재합니까?\n[답변 형식: SPOF 장비 목록 (예: [\"p1\", \"pe1\"]) 또는 빈 목록 []]")

            questions.append({
                "id": "SPOF_DETECTION_GLOBAL",
                "category": "What_If_Analysis",
                "level": "L5",
                "answer_type": "set_str",
                "question": template,
                "ground_truth": spof_nodes if spof_nodes else [],
                "explanation": f"metric `{metric}` found {len(spof_nodes)} SPOF nodes",
                "evidence_hint": {"scope": {"type": "GLOBAL"}, "metric": metric},
                "academic_reference": "현업: SPOF 탐지 → 이중화 설계 검증"
            })
        
        # 3. OSPF Backbone Area 0 Routers List
        backbone_res = self.ospf_backbone_contiguity()
        if backbone_res.status == "OK":
            details = backbone_res.value.get("details", "")
            # Extract router names from details string "Backbone Routers: N (r1, r2, r3...)"
            import re
            match = re.search(r'Backbone Routers: \d+ \(([^)]+)\)', details)
            if match:
                routers_str = match.group(1)
                # Remove "..." if present and split
                routers_str = routers_str.replace("...", "").strip()
                backbone_routers = [r.strip() for r in routers_str.split(',') if r.strip()]
            else:
                backbone_routers = []
            
            metric = "ospf_area0_routers"
            template = self._get_template(metric, "OSPF Area 0(Backbone Area)에 참여하는 라우터 목록을 알려주세요.\\n[답변 형식: 라우터 목록 또는 빈 리스트 []]")
            
            questions.append({
                "id": "OSPF_AREA0_ROUTERS_GLOBAL",
                "category": "What_If_Analysis",
                "level": "L5",
                "answer_type": "set",
                "question": template,
                "ground_truth": backbone_routers if backbone_routers else [],
                "explanation": f"metric `{metric}` found {len(backbone_routers)} backbone routers",
                "evidence_hint": {"scope": {"type": "GLOBAL"}, "metric": metric},
                "academic_reference": "OSPF Area 0 verification"
            })
        
        # 4. K-Failure Tolerance - Redundant Paths List
        # Sample a few source-destination pairs and analyze their path redundancy
        test_pairs = []
        ce_or_leaf = self.get_edge_nodes()  # 토폴로지 추론 기반 (이전: 이름 기반)
        if len(ce_or_leaf) >= 2:
            test_pairs = [(ce_or_leaf[0], ce_or_leaf[-1])]
        elif len(self.nodes) >= 2:
            test_pairs = [(self.nodes[0], self.nodes[-1])]
        
        for src_node, dst_node in test_pairs[:5]:
            src_ips = self.node_ips.get(src_node, [])
            dst_ips = self.node_ips.get(dst_node, [])
            
            if src_ips and dst_ips:
                # Analyze redundancy by checking traceroutes
                try:
                    # VRF 문제 방지: [Loopback0] 추가
                    src_node_fixed = self._fix_start_location(src_node)
                    
                    traces_result = self.bf.q.traceroute(
                        startLocation=src_node_fixed,
                        headers=HeaderConstraints(dstIps=dst_ips[0])
                    ).answer().frame()
                    
                    redundant_paths = []
                    if not traces_result.empty:
                        traces = traces_result['Traces'].iloc[0]
                        if traces:
                            for trace in traces[:3]:  # Limit to first 3 paths
                                path_nodes = []
                                hops = getattr(trace, 'hops', []) if hasattr(trace, 'hops') else []
                                for hop in hops:
                                    node = getattr(hop, 'node', None)
                                    if node:
                                        node_name = getattr(node, 'hostname', str(node)) if hasattr(node, 'hostname') else str(node)
                                        if node_name not in path_nodes:
                                            path_nodes.append(node_name)
                                if path_nodes:
                                    path_str = " → ".join(path_nodes)
                                    if path_str not in redundant_paths:
                                        redundant_paths.append(path_str)
                    
                    metric = "redundant_paths_list"
                    template = self._get_template(metric, f"{{src_node}}에서 {{dst_node}}로의 중복 경로(redundant paths) 목록을 알려주세요.\\n[답변 형식: ['경로1', '경로2'] 형식의 경로 리스트]")
                    # 정책/기본 템플릿 모두 안전하게 채우기 위해 키를 중복 제공
                    q_text = self._format_question(template, src_host=src_node, dst_ip=dst_ips[0], src_node=src_node, dst_node=dst_node)
                    
                    questions.append({
                        "id": f"K_FAILURE_{src_node}_{dst_node}",
                        "category": "What_If_Analysis",
                        "level": "L5",
                        "answer_type": "set",
                        "question": q_text,
                        "ground_truth": redundant_paths if redundant_paths else [],
                        "explanation": f"metric `{metric}` found {len(redundant_paths)} redundant paths",
                        "evidence_hint": {"scope": {"type": "NODE_PAIR", "src": src_node, "dst": dst_node}, "metric": metric},
                        "academic_reference": "Minesweeper (SIGCOMM'17): k-failure tolerance"
                    })
                except Exception as e:
                    logger.warning(f"Redundant path analysis failed for {src_node}-{dst_node}: {e}")
        
        # 5. Advanced: Root Cause Analysis
        all_pairs_rca = self.get_node_pairs()
        random.shuffle(all_pairs_rca)
        rca_q_count = 0
        for src_node, dst_node in all_pairs_rca[:80]:
            rca_res = self.root_cause_analysis(src_node, dst_node)
            if rca_res.status == "OK":
                reachable = rca_res.value.get("reachable", True)
                blocking_point = rca_res.value.get("blocking_point", "")
                
                if not reachable and blocking_point:
                    metric = "root_cause_analysis"
                    template = self._get_template(metric, "{src_node}에서 {dst_node}로의 통신이 실패할 때, 어느 장비에서 차단됩니까? [답변 형식: 장비명]")
                    q_text = self._format_question(template, src_node=src_node, dst_node=dst_node)

                    questions.append({
                        "id": f"ROOT_CAUSE_{src_node}_{dst_node}",
                        "category": "What_If_Analysis",
                        "level": "L5",
                        "answer_type": "text",
                        "question": q_text,
                        "ground_truth": blocking_point,
                        "explanation": f"metric `{metric}` on {src_node}->{dst_node}",
                        "evidence_hint": {"scope": {"type": "NODE_PAIR", "src": src_node, "dst": dst_node}, "metric": metric},
                        "academic_reference": "현업: 장애 근본 원인 분석"
                    })
                    rca_q_count += 1
                    if rca_q_count >= 50:
                        break
        
        # 4. Advanced: Node Failure Impact Analysis (Objective)
        for node in self.nodes[:10]:
            br_res = self.blast_radius_estimation(node)
            if br_res.status == "OK":
                affected_count = br_res.value.get("affected_count", 0)

                metric = "node_failure_impact"
                template = self._get_template(metric, "'{node}' 장비가 다운되면 몇 개의 트래픽 흐름이 새로 차단됩니까? [답변 형식: 숫자]")
                q_text = self._format_question(template, host=node, node=node)

                questions.append({
                    "id": f"NODE_FAILURE_{node}",
                    "category": "What_If_Analysis",
                    "level": "L5",
                    "answer_type": "number",
                    "question": q_text,
                    "ground_truth": str(affected_count),
                    "explanation": f"metric `{metric}` on {node}",
                    "evidence_hint": {"scope": {"type": "NODE", "node": node}, "metric": metric},
                    "academic_reference": "현업: 장애 영향 범위 사전 분석 (Objective)"
                })

        # 5. Advanced: Redundancy Verification (Dual Failure)
        # Find potential HA pairs (same prefix, sequential numbers)
        node_groups = {}
        for node in self.nodes:
            match = re.match(r"([a-zA-Z\-_]+)(\d+)", node)
            if match:
                prefix, num = match.groups()
                if prefix not in node_groups:
                    node_groups[prefix] = []
                node_groups[prefix].append((int(num), node))
        
        redundancy_metric = "redundancy_verification"
        for prefix, items in node_groups.items():
            if len(items) >= 2:
                items.sort()
                for i in range(0, len(items)-1, 2):
                    n1 = items[i][1]
                    n2 = items[i+1][1]
                    
                    if items[i+1][0] == items[i][0] + 1: 
                        res = self.redundancy_verification(n1, n2)
                        
                        if res.status == "OK":
                            isolated_count = res.value.get("isolated_flow_count", 0)
                            
                            # 간결한 정답 포맷
                            if isolated_count == 0:
                                gt_text = "없음"
                            else:
                                gt_text = f"{isolated_count}개"
                            
                            tmpl = self._get_template(redundancy_metric, "'{node1}'과 '{node2}'가 동시에 다운되면 고립되는 흐름이 있습니까? 몇 개입니까? [답변 형식: '없음' 또는 'N개']")
                            q_text_red = self._format_question(tmpl, node1=n1, node2=n2)
                            
                            questions.append({
                                "id": f"DUAL_FAILURE_{n1}_{n2}",
                                "category": "What_If_Analysis",
                                "level": "L5",
                                "answer_type": "text",
                                "question": q_text_red,
                                "ground_truth": gt_text,
                                "explanation": f"metric `{redundancy_metric}` on {n1}, {n2}",
                                "evidence_hint": {"scope": {"type": "NODE_PAIR", "src": n1, "dst": n2}, "metric": redundancy_metric},
                                "academic_reference": "현업: 이중화(HA) 구조 검증"
                            })

        # 6. Advanced: Triple Node Failure (Extreme Resilience)
        triple_metric = "triple_node_failure"
        if len(self.nodes) >= 3:
            triplet = None
            for prefix, items in node_groups.items():
                 if len(items) >= 3:
                     items.sort()
                     triplet = [items[0][1], items[1][1], items[2][1]]
                     break
            
            if not triplet and len(self.nodes) >= 3:
                triplet = self.nodes[:3]

            if triplet:
                n1, n2, n3 = triplet
                res_triple = self.triple_node_failure(n1, n2, n3)
                if res_triple.status == "OK":
                    iso_cnt = res_triple.value.get("isolated_flow_count", 0)
                    
                    # 간결한 텍스트 정답
                    if iso_cnt == 0:
                        gt_triple = "예, 완전 분리"
                    else:
                        gt_triple = f"아니오, {iso_cnt}개 흐름만 영향"

                    tmpl_triple = self._get_template(triple_metric, "'{node1}', '{node2}', '{node3}'가 동시에 다운되면 네트워크가 완전히 분리됩니까? [답변 형식: '예, 완전 분리' 또는 '아니오, N개 흐름만 영향']")
                    q_text_triple = self._format_question(tmpl_triple, node1=n1, node2=n2, node3=n3)
                    
                    questions.append({
                        "id": f"TRIPLE_FAILURE_{n1}_{n2}_{n3}",
                        "category": "What_If_Analysis",
                        "level": "L5",
                        "answer_type": "text",
                        "question": q_text_triple,
                        "ground_truth": gt_triple,
                        "explanation": f"metric `{triple_metric}` on {n1}, {n2}, {n3}",
                        "evidence_hint": {"scope": {"type": "NODE_TRIPLET", "nodes": [n1, n2, n3]}, "metric": triple_metric},
                        "academic_reference": "극한 장애 시나리오 (DR Testing)"
                    })

        # 7. Advanced: Worst Case Failure Analysis (SPOF Search)
        worst_metric = "worst_case_failure_analysis"
        candidates = self.nodes[:10]
        res_worst = self.find_worst_failure_node(candidates)
        if res_worst.status == "OK":
            w_node = res_worst.value.get("worst_node", "NONE")
            b_count = res_worst.value.get("blocked_flow_count", 0)
            
            # 간결한 텍스트 정답: "장비명 (N개)"
            gt_worst = f"{w_node} ({b_count}개)"
            
            tmpl_worst = self._get_template(worst_metric, "단일 장비 장애 시 가장 큰 영향을 주는 장비는? [답변 형식: '장비명 (N개)']")
            
            questions.append({
                "id": "WORST_CASE_FAILURE",
                "category": "What_If_Analysis",
                "level": "L5",
                "answer_type": "text",
                "question": tmpl_worst,
                "ground_truth": gt_worst,
                "explanation": f"metric `{worst_metric}` analyzed {len(candidates)} nodes",
                "evidence_hint": {"scope": {"type": "GLOBAL"}, "metric": worst_metric},
                "academic_reference": "Critical Node Identification"
            })

        # 8. Negative Testing: Non-existent Node Check (고난도 버전)
        neg_metric = "non_existent_node_check"
        fake_node = "non_existent_router_999"
        
        # 존재하지 않는 장비이므로 영향은 0
        tmpl_neg = self._get_template(neg_metric, "'{fake_node}' 장비가 다운되면 몇 개의 트래픽 흐름이 차단됩니까? [답변 형식: 숫자]")
        q_text_neg = self._format_question(tmpl_neg, host=fake_node, fake_node=fake_node)
        
        questions.append({
            "id": "NEGATIVE_TEST_FAKE_NODE",
            "category": "What_If_Analysis",
            "level": "L5",
            "answer_type": "number",
            "question": q_text_neg,
            "ground_truth": "0",
            "explanation": f"Negative test for `{neg_metric}` - node does not exist, so impact is 0",
            "evidence_hint": {"scope": {"type": "FAKE_NODE", "node": fake_node}, "metric": neg_metric},
            "academic_reference": "AI Hallucination Check"
        })

        # 8.5 Policy SSOT 누락 메트릭 보완: Config/Diff/Compliance
        # 정책 파일에 존재하지만 생성 경로가 없던 메트릭을 최소 1건씩 생성
        analysis_src = ""
        analysis_dst = ""
        edge_nodes_for_analysis = self.get_edge_nodes()
        if len(edge_nodes_for_analysis) >= 2:
            analysis_src, analysis_dst = edge_nodes_for_analysis[0], edge_nodes_for_analysis[-1]
        elif len(self.nodes) >= 2:
            analysis_src, analysis_dst = self.nodes[0], self.nodes[-1]

        # 변경 스냅샷 준비:
        # 가능하면 baseline에 작은 변화(노드 1개 비활성화)를 만들어 baseline 대비 비교 수행
        # 실패 시 baseline vs baseline으로 안전하게 fallback
        changed_snapshot = self.snapshot_name
        change_desc = "baseline_vs_baseline"
        if self.nodes:
            exclude_nodes = {analysis_src, analysis_dst}
            candidate_nodes: List[str] = []
            for n in (self.get_transit_nodes() + self.nodes):
                if n and n not in exclude_nodes and n not in candidate_nodes:
                    candidate_nodes.append(n)

            if candidate_nodes:
                failure_node = candidate_nodes[0]
                changed_snapshot = f"cfg_change_{failure_node}_{int(time.time())}"
                try:
                    self.bf.fork_snapshot(
                        base_name=self.snapshot_name,
                        name=changed_snapshot,
                        deactivate_nodes=[failure_node],
                        overwrite=True
                    )
                    change_desc = f"node_down:{failure_node}"
                except Exception as e:
                    logger.warning(f"config/diff snapshot fork failed, fallback baseline: {e}")
                    changed_snapshot = self.snapshot_name
                    change_desc = "baseline_vs_baseline"

        # (A) config_change_impact
        if analysis_src and analysis_dst:
            cfg_metric = "config_change_impact"
            cfg_template = self._get_template(
                cfg_metric,
                "설정 변경 후 {src}에서 {dst}까지의 경로/도달성 변경 여부를 알려주세요. [답변 형식: 'NO_CHANGE' 또는 'CHANGED (N건: 흐름1, 흐름2, ...)']"
            )
            cfg_q = self._format_question(cfg_template, src=analysis_src, dst=analysis_dst)
            cfg_res = self.config_change_impact(self.snapshot_name, changed_snapshot, analysis_src, analysis_dst)
            if cfg_res.status == "OK":
                changed = cfg_res.value.get("changed", False)
                affected = cfg_res.value.get("affected_flows", [])
                if not changed:
                    cfg_gt = "NO_CHANGE"
                else:
                    preview = ", ".join(affected[:3]) if affected else "-"
                    cfg_gt = f"CHANGED ({len(affected)}건: {preview})"
                questions.append({
                    "id": "CONFIG_CHANGE_BASELINE",
                    "category": "What_If_Analysis",
                    "level": "L5",
                    "answer_type": "text",
                    "question": cfg_q,
                    "ground_truth": cfg_gt,
                    "explanation": f"metric `{cfg_metric}` scenario={change_desc}",
                    "evidence_hint": {"scope": {"type": "SNAPSHOT_DIFF", "src": analysis_src, "dst": analysis_dst}, "metric": cfg_metric},
                    "academic_reference": "Differential Analysis"
                })

        # (B) differential_reachability
        dst_ips_for_analysis = self.node_ips.get(analysis_dst, []) if analysis_dst else []
        if analysis_src and analysis_dst and dst_ips_for_analysis:
            diff_metric = "differential_reachability"
            diff_template = self._get_template(
                diff_metric,
                "변경 전후 {src}에서 {dst}로의 도달성에 차이가 있습니까? [답변 형식: 'NO_DIFF' 또는 'DIFF (N건: 흐름1, 흐름2, ...)']"
            )
            diff_q = self._format_question(diff_template, src=analysis_src, dst=analysis_dst)
            diff_res = self.differential_reachability(
                snapshot1=self.snapshot_name,
                snapshot2=changed_snapshot,
                src_node=analysis_src,
                dst_ip=dst_ips_for_analysis[0]
            )
            if diff_res.status == "OK":
                diff_count = diff_res.value.get("diff_count", 0)
                flows = diff_res.value.get("flows", [])
                if diff_count == 0:
                    diff_gt = "NO_DIFF"
                else:
                    preview = ", ".join(flows[:3]) if flows else "-"
                    diff_gt = f"DIFF ({diff_count}건: {preview})"
                questions.append({
                    "id": "DIFF_REACH_BASELINE",
                    "category": "What_If_Analysis",
                    "level": "L5",
                    "answer_type": "text",
                    "question": diff_q,
                    "ground_truth": diff_gt,
                    "explanation": f"metric `{diff_metric}` scenario={change_desc}",
                    "evidence_hint": {"scope": {"type": "SNAPSHOT_DIFF", "src": analysis_src, "dst": analysis_dst}, "metric": diff_metric},
                    "academic_reference": "DNA (NSDI'22)"
                })

        # (C) policy_compliance_check
        transit_nodes = self.get_transit_nodes()
        if transit_nodes:
            waypoint = transit_nodes[0]
            policy_metric = "policy_compliance_check"
            policy_name = f"MANDATORY_WAYPOINT_{waypoint}"
            policy_template = self._get_template(
                policy_metric,
                "'{policy_name}' 정책 준수 여부와 위반 사례를 알려주세요. [답변 형식: 'COMPLIANT' 또는 'VIOLATION: 흐름1, 흐름2, ...']"
            )
            policy_q = self._format_question(policy_template, policy_name=policy_name)
            policy_res = self.policy_compliance_check(
                policy_type="waypoint",
                waypoint_node=waypoint,
                policy_name=policy_name
            )
            if policy_res.status == "OK":
                compliant = policy_res.value.get("compliant", True)
                violations = policy_res.value.get("violations", [])
                if compliant:
                    policy_gt = "COMPLIANT"
                else:
                    preview = ", ".join(violations[:3]) if violations else "-"
                    policy_gt = f"VIOLATION: {preview}"
                questions.append({
                    "id": f"POLICY_COMPLIANCE_{waypoint}",
                    "category": "What_If_Analysis",
                    "level": "L5",
                    "answer_type": "text",
                    "question": policy_q,
                    "ground_truth": policy_gt,
                    "explanation": f"metric `{policy_metric}` with waypoint {waypoint}",
                    "evidence_hint": {"scope": {"type": "POLICY", "policy_name": policy_name}, "metric": policy_metric},
                    "academic_reference": "Policy Compliance Verification"
                })
        
        # 9. Advanced: Multi-Link Failure Analysis (descriptive text version)
        if len(edges) >= 4:
            valid_edge_pairs = []
            for edge1, edge2 in combinations(edges[:30], 2):
                n1_1, n1_2 = edge1["node1"], edge1["node2"]
                n2_1, n2_2 = edge2["node1"], edge2["node2"]
                unique_nodes = {n1_1.lower(), n1_2.lower(), n2_1.lower(), n2_2.lower()}
                if len(unique_nodes) == 4:
                    valid_edge_pairs.append((edge1, edge2))
            
            random.shuffle(valid_edge_pairs)
            
            mlf_q_count = 0
            for (edge1, edge2) in valid_edge_pairs[:50]:
                link_nodes = {edge1['node1'].lower(), edge1['node2'].lower(), 
                             edge2['node1'].lower(), edge2['node2'].lower()}
                test_candidates = [n for n in self.nodes if n.lower() not in link_nodes]
                
                if len(test_candidates) >= 2:
                    test_src = test_candidates[0]
                    test_dst = test_candidates[-1]
                    
                    # Pass interface names ("hostname[interface]") for True Simulation
                    mlf_res = self.multi_link_failure_analysis(
                        edge1['interface1'], edge1['interface2'],
                        edge2['interface1'], edge2['interface2'],
                        test_src, test_dst
                    )
                    
                    if mlf_res.status == "OK":
                        isolated = mlf_res.value.get("isolated", False)
                        new_path = mlf_res.value.get("new_path", [])
                        failure_reason = mlf_res.value.get("failure_reason", "")
                        
                        # Clear text answer with explicit format guidance
                        if isolated:
                            failure_detail = failure_reason if failure_reason else "알 수 없음"
                            gt_text = f"불가능 (원인: {failure_detail})"
                        else:
                            path_str = " → ".join(new_path) if new_path else "대체경로 존재"
                            gt_text = f"가능 (대체경로: {path_str})"
                        
                        metric = "multi_link_failure_reachability"
                        template = self._get_template(metric, "(시나리오) '{link1}' 링크와 '{link2}' 링크가 동시에 다운되었습니다. 이 상황에서 '{test_src}'에서 '{test_dst}'로의 트래픽 전달이 가능합니까? [답변 형식: '가능 (대체경로: A→B→C)' 또는 '불가능 (원인: 장비명에서 사유)']")
                        q_text = self._format_question(template, link1=f"{edge1['node1']}-{edge1['node2']}", link2=f"{edge2['node1']}-{edge2['node2']}", test_src=test_src, test_dst=test_dst)

                        questions.append({
                            "id": f"MULTI_FAIL_{edge1['node1']}_{edge1['node2']}_{edge2['node1']}_{edge2['node2']}",
                            "category": "What_If_Analysis",
                            "level": "L5",
                            "answer_type": "text",
                            "question": q_text,
                            "ground_truth": gt_text,
                            "explanation": f"metric `{metric}` result: {gt_text}",
                            "evidence_hint": {"scope": {"type": "MULTI_LINK_FAILURE", "link1": f"{edge1['node1']}-{edge1['node2']}", "link2": f"{edge2['node1']}-{edge2['node2']}"}, "metric": metric},
                            "academic_reference": "Minesweeper (SIGCOMM'17): k-failure tolerance"
                        })
                        mlf_q_count += 1
                        if mlf_q_count >= 50:
                            break
        
        return questions
    
    def generate_l6_questions(self) -> List[Dict[str, Any]]:
        """L6 레벨 진단형(Diagnostic) 문제 생성
        
        5가지 진단 유형을 모두 호출하여 문제 생성:
        1. Link Failure Diagnostic (링크 장애)
        2. Node Failure Diagnostic (노드 장애)
        3. BGP Mismatch Diagnostic (BGP 세션 호환성)
        4. OSPF Mismatch Diagnostic (OSPF 인접 호환성)
        5. ACL Block Diagnostic (ACL 차단)
        """
        questions = []
        
        if not self._initialized:
            logger.warning("Batfish not initialized. Skipping L6 question generation.")
            return questions
            
        logger.info("Generating L6 Diagnostic QA...")
        
        # 1. Link Failure Diagnostic
        try:
            link_questions = self.generate_diagnostic_qa_link(count=20)
            questions.extend(link_questions)
            logger.info(f"  - Link Failure: {len(link_questions)} questions")
        except Exception as e:
            logger.error(f"L6 Link Failure QA generation failed: {e}")
        
        # 2. Node Failure Diagnostic
        try:
            node_questions = self.generate_diagnostic_qa_node(count=10)
            questions.extend(node_questions)
            logger.info(f"  - Node Failure: {len(node_questions)} questions")
        except Exception as e:
            logger.error(f"L6 Node Failure QA generation failed: {e}")
        
        # 3. BGP Mismatch Diagnostic
        try:
            bgp_questions = self.generate_diagnostic_qa_bgp_mismatch(count=10)
            questions.extend(bgp_questions)
            logger.info(f"  - BGP Mismatch: {len(bgp_questions)} questions")
        except Exception as e:
            logger.error(f"L6 BGP Mismatch QA generation failed: {e}")
        
        # 4. OSPF Mismatch Diagnostic
        try:
            ospf_questions = self.generate_diagnostic_qa_ospf_mismatch(count=10)
            questions.extend(ospf_questions)
            logger.info(f"  - OSPF Mismatch: {len(ospf_questions)} questions")
        except Exception as e:
            logger.error(f"L6 OSPF Mismatch QA generation failed: {e}")
        
        # 5. ACL Block Diagnostic
        try:
            acl_questions = self.generate_diagnostic_qa_acl_block(count=10)
            questions.extend(acl_questions)
            logger.info(f"  - ACL Block: {len(acl_questions)} questions")
        except Exception as e:
            logger.error(f"L6 ACL Block QA generation failed: {e}")
            
        logger.info(f"Generated {len(questions)} L6 Diagnostic questions total.")
        return questions
    
    def generate_all_questions(self, include_l6: bool = False) -> Dict[str, List[Dict[str, Any]]]:
        """L4/L5 문제를 생성하고, 필요 시 L6를 추가 생성한다."""
        result = {
            "Reachability_Analysis": self.generate_l4_questions(),
            "What_If_Analysis": self.generate_l5_questions(),
        }
        if include_l6:
            result["Diagnostic_Troubleshooting"] = self.generate_l6_questions()
        return result


# =========================================================================
# 하위 호환성을 위한 re-export
# =========================================================================

# models.py에서
__all__ = [
    'BatfishBuilder',
    'AnswerResult',
    'FlowSpec',
    'L4Result',
    'L5Result',
    'CanonicalizationError',
    'CONFIGURED_RULES',
    'UNKNOWN_REASONS',
    'build_evidence',
    'canonicalize',
    '_build_evidence',
    '_canonicalize',
    'BATFISH_AVAILABLE'
]
