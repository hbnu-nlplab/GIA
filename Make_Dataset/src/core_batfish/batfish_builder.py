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

# Batfish 로드 (선택적)
try:
    from pybatfish.client.session import Session
    from pybatfish.datamodel.flow import HeaderConstraints, PathConstraints
except ImportError:
    Session = None
    HeaderConstraints = None
    PathConstraints = None

logger = logging.getLogger(__name__)


class BatfishBuilder(BatfishBase, L4AnalyzerMixin, L5AnalyzerMixin):
    """
    Batfish 기반 L4/L5 문제 생성기
    
    Multiple Inheritance (Mixin 패턴)를 사용하여 기능을 모듈화:
    - BatfishBase: 초기화, 스냅샷 관리, 기본 쿼리
    - L4AnalyzerMixin: 도달성 분석 (Traceroute, ACL, Loop 등)
    - L5AnalyzerMixin: What-If 분석 (Link Failure, RCA 등)
    """

    def __init__(self, network_name: str, snapshot_path: str, policies_path: str = None):
        # Fix: Pass arguments by keyword to avoid mismatch with BatfishBase signature
        # BatfishBase.__init__(snapshot_path, batfish_host="localhost", network_name="...")
        super().__init__(snapshot_path=snapshot_path, network_name=network_name)
        
        self.metrics_metadata = {}
        if policies_path:
            try:
                policy_text = Path(policies_path).read_text(encoding="utf-8")
                policy_data = json.loads(policy_text)
                self.metrics_metadata = policy_data.get("metrics_metadata", {})
            except Exception as e:
                logger.error(f"Failed to load policies from {policies_path}: {e}")

    def _get_template(self, metric: str, default: str) -> str:
        """Get template from metadata or return default."""
        if metric in self.metrics_metadata:
            return self.metrics_metadata[metric].get("template", default)
        return default
    
    # =========================================================================
    # 문제 생성 메서드
    # =========================================================================
    
    def generate_l4_questions(self) -> List[Dict[str, Any]]:
        """L4 레벨 문제 생성"""
        questions = []
        
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
                
                metric = "traceroute_path"
                template = self._get_template(metric, "{src_node}에서 {dst_node}({dst_ip})로 가는 패킷의 네트워크 경로를 알려주세요.\n[답변 형식: 화살표(→)로 구분된 장비 목록]")
                q_text = template.format(src_ip=src_node, dst_ip=dst_ips[0], src_node=src_node, dst_node=dst_node)

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
        for flow in self.get_representative_flows()[:30]:
            res = self.reachability_status(flow.src_ip, flow.dst_ip, flow.dst_port, flow.protocol)
            
            if res.status != "OK":
                continue
                
            reachable = res.value.get("reachable", False)
            path_list = res.value.get("path", [])
            path_str = " → ".join(path_list) if path_list else "없음"
            result_text = f"경로: {path_str}, 도달: {'가능' if reachable else '불가'}"
            
            port_desc = f":{flow.dst_port}" if flow.dst_port else ""
            
            metric = "reachability_status"
            template = self._get_template(metric, "{src_ip}에서 {dst_ip}({dst_port}/{protocol})로의 트래픽 경로와 도달 여부를 알려주세요.\n[답변 형식: '경로: A → B → C, 도달: 가능' 또는 '경로: 없음, 도달: 불가']")
            q_text = template.format(src_ip=flow.src_ip, dst_ip=flow.dst_ip, dst_port=flow.dst_port, protocol=flow.protocol, src_location=flow.src_location, dst_location=flow.dst_location)

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
                    q_text = template.format(src_host=src_node, dst_ip=dst_ips[0], src_node=src_node, dst_node=dst_node)

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
        
        # 5. Blackhole Detection
        bh_res = self.blackhole_detection()
        if bh_res.status == "OK":
            blackholes = bh_res.value.get("blackholes", [])
            
            metric = "blackhole_detection"
            template = self._get_template(metric, "네트워크에 패킷이 드랍되는 블랙홀이 존재합니까?\n[답변 형식: true/false]")
            
            questions.append({
                "id": "BLACKHOLE_DETECTION_GLOBAL",
                "category": "Reachability_Analysis",
                "level": "L4",
                "answer_type": "boolean",
                "question": template,
                "ground_truth": str(len(blackholes) > 0).lower(),
                "explanation": f"metric `{metric}` found {len(blackholes)} blackholes",
                "evidence_hint": {"scope": {"type": "GLOBAL"}, "metric": metric},
                "academic_reference": "HSA (NSDI'12), Minesweeper (SIGCOMM'17): blackhole detection"
            })
        
        # 6. Advanced: OSPF Compatibility Check
        ospf_pairs = self.get_node_pairs()
        random.shuffle(ospf_pairs)
        ospf_q_count = 0
        for node1, node2 in ospf_pairs[:30]:
            compat_res = self.ospf_compatibility_check(node1, node2)
            if compat_res.status == "OK":
                issues = compat_res.value.get("issues", [])
                compatible = compat_res.value.get("compatible", True)
                
                if issues:
                    metric = "ospf_compatibility_check"
                    template = self._get_template(metric, "{node1}과 {node2} 사이에 OSPF 네이버가 형성되지 않는 경우, 가능한 원인들을 분석하세요.\n[답변 형식: JSON {{\"issues\": [...]}}]")
                    q_text = template.format(node1=node1, node2=node2)

                    questions.append({
                        "id": f"OSPF_COMPAT_{node1}_{node2}",
                        "category": "Routing_Consistency",
                        "level": "L4",
                        "answer_type": "json",
                        "question": q_text,
                        "ground_truth": f'{{"issues": {issues}, "compatible": {str(compatible).lower()}}}',
                        "explanation": f"metric `{metric}` on {node1}-{node2}",
                        "evidence_hint": {"scope": {"type": "NODE_PAIR", "node1": node1, "node2": node2}, "metric": metric},
                        "academic_reference": "RFC 2328, 현업: OSPF 트러블슈팅"
                    })
                    ospf_q_count += 1
                    if ospf_q_count >= 15:
                        break
        
        # 7. Advanced: Security Policy Bypass Check
        spine_nodes = [n for n in self.nodes if 'spine' in n.lower() or 'pe' in n.lower()]
        leaf_nodes = [n for n in self.nodes if 'leaf' in n.lower() or 'ce' in n.lower()]
        
        if spine_nodes and len(leaf_nodes) >= 2:
            bypass_q_count = 0
            for required_wp in spine_nodes[:2]:
                for src_leaf in leaf_nodes[:3]:
                    for dst_leaf in leaf_nodes[3:6]:
                        if src_leaf == dst_leaf:
                            continue
                        bypass_res = self.security_policy_bypass_check(src_leaf, dst_leaf, required_wp)
                        if bypass_res.status == "OK":
                            bypass_exists = bypass_res.value.get("bypass_exists", False)
                            bypass_path = bypass_res.value.get("bypass_path", [])
                            
                            path_str = " → ".join(bypass_path) if bypass_path else "없음"
                            result_text = f"우회 경로 존재: {path_str}" if bypass_exists else "우회 경로 없음 (정책 준수)"
                            
                            metric = "security_policy_bypass_check"
                            template = self._get_template(metric, "'{src}→{dst}' 트래픽이 보안 장비 '{waypoint}'를 거치지 않고 도달 가능한 우회 경로가 있습니까?\n[답변 형식: '우회 경로 존재: ...' 또는 '우회 경로 없음']")
                            q_text = template.format(src=src_leaf, dst=dst_leaf, waypoint=required_wp)
                            
                            questions.append({
                                "id": f"SEC_BYPASS_{src_leaf}_{dst_leaf}_{required_wp}",
                                "category": "Security_Policy",
                                "level": "L4",
                                "answer_type": "text",
                                "question": q_text,
                                "ground_truth": result_text,
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
    
    def generate_l5_questions(self) -> List[Dict[str, Any]]:
        """L5 레벨 문제 생성"""
        questions = []
        
        if not self._initialized:
            logger.warning("Batfish not initialized. Skipping L5 question generation.")
            return questions
        
        # 1. Link Failure Impact
        edges = self.get_layer3_edges()
        ce_nodes = [n for n in self.nodes if 'ce' in n.lower()]
        pe_nodes = [n for n in self.nodes if 'pe' in n.lower()]
        
        if edges and len(ce_nodes) >= 2:
            link_count = 0
            for edge in edges[:50]:
                if link_count >= 50:
                    break
                node1, node2 = edge["node1"], edge["node2"]
                src = ce_nodes[0]
                dst = ce_nodes[-1] if len(ce_nodes) > 1 else ce_nodes[0]
                
                link_res = self.link_failure_impact(node1, node2, src, dst)
                if link_res.status == "OK":
                    impact = link_res.value.get("impact", "NONE")
                    desc = link_res.value.get("description", "")
                    
                    metric = "link_failure_impact"
                    template = self._get_template(metric, "'{link}' 링크가 다운될 경우, '{src}→{dst}' 트래픽에 어떤 영향이 발생합니까?\n[답변 형식: 'NONE', 'REROUTED', 'DISCONNECTED']")
                    q_text = template.format(link=f"{node1}-{node2}", src=src, dst=dst)

                    questions.append({
                        "id": f"LINK_FAILURE_{node1}_{node2}",
                        "category": "What_If_Analysis",
                        "level": "L5",
                        "answer_type": "text",
                        "question": q_text,
                        "ground_truth": f"{impact}:{desc}" if desc else impact,
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
            template = self._get_template(metric, "단일 장비 장애 시 통신이 두절되는 구간(SPOF: Single Point of Failure)이 존재합니까?\n[답변 형식: SPOF 장비 목록 또는 '없음']")

            questions.append({
                "id": "SPOF_DETECTION_GLOBAL",
                "category": "What_If_Analysis",
                "level": "L5",
                "answer_type": "set",
                "question": template,
                "ground_truth": ", ".join(spof_nodes) if spof_nodes else "없음",
                "explanation": f"metric `{metric}` found {len(spof_nodes)} SPOF nodes",
                "evidence_hint": {"scope": {"type": "GLOBAL"}, "metric": metric},
                "academic_reference": "현업: SPOF 탐지 → 이중화 설계 검증"
            })
        
        # 3. Advanced: Root Cause Analysis
        all_pairs_rca = self.get_node_pairs()
        random.shuffle(all_pairs_rca)
        rca_q_count = 0
        for src_node, dst_node in all_pairs_rca[:50]:
            rca_res = self.root_cause_analysis(src_node, dst_node)
            if rca_res.status == "OK":
                reachable = rca_res.value.get("reachable", True)
                root_cause = rca_res.value.get("root_cause", "NONE")
                blocking_point = rca_res.value.get("blocking_point", "")
                
                if not reachable and root_cause != "NONE":
                    metric = "root_cause_analysis"
                    template = self._get_template(metric, "{src_node}에서 {dst_node}로의 통신이 실패합니다. 근본 원인과 차단 지점을 분석하세요.\n[답변 형식: JSON {{\"root_cause\": \"...\", \"blocking_point\": \"노드명\"}}]")
                    q_text = template.format(src_node=src_node, dst_node=dst_node)

                    questions.append({
                        "id": f"ROOT_CAUSE_{src_node}_{dst_node}",
                        "category": "What_If_Analysis",
                        "level": "L5",
                        "answer_type": "json",
                        "question": q_text,
                        "ground_truth": f'{{"root_cause": "{root_cause}", "blocking_point": "{blocking_point}"}}',
                        "explanation": f"metric `{metric}` on {src_node}->{dst_node}",
                        "evidence_hint": {"scope": {"type": "NODE_PAIR", "src": src_node, "dst": dst_node}, "metric": metric},
                        "academic_reference": "현업: 장애 근본 원인 분석"
                    })
                    rca_q_count += 1
                    if rca_q_count >= 30:
                        break
        
        # 4. Advanced: Blast Radius Estimation
        for node in self.nodes[:10]:
            br_res = self.blast_radius_estimation(node)
            if br_res.status == "OK":
                affected_nodes = br_res.value.get("affected_nodes", [])
                affected_count = br_res.value.get("affected_count", 0)
                severity = br_res.value.get("severity", "UNKNOWN")
                
                metric = "blast_radius_estimation"
                template = self._get_template(metric, "'{node}' 장비가 다운될 경우, 직접 영향을 받는 노드들과 심각도를 추정하세요.\n[답변 형식: JSON {{\"affected_nodes\": [...], \"severity\": \"...\"}}]")
                q_text = template.format(node=node)

                questions.append({
                    "id": f"BLAST_RADIUS_{node}",
                    "category": "What_If_Analysis",
                    "level": "L5",
                    "answer_type": "json",
                    "question": q_text,
                    "ground_truth": f'{{"affected_nodes": {affected_nodes}, "affected_count": {affected_count}, "severity": "{severity}"}}',
                    "explanation": f"metric `{metric}` on {node}",
                    "evidence_hint": {"scope": {"type": "NODE", "node": node}, "metric": metric},
                    "academic_reference": "현업: 장애 영향 범위 사전 분석"
                })
        
        # 5. Advanced: Multi-Link Failure Analysis
        if len(edges) >= 4:
            edge_pairs = list(combinations(edges[:10], 2))
            random.shuffle(edge_pairs)
            
            mlf_q_count = 0
            for (edge1, edge2) in edge_pairs[:20]:  # 20개 조합 제한
                link_nodes = {edge1['node1'].lower(), edge1['node2'].lower(), edge2['node1'].lower(), edge2['node2'].lower()}
                test_candidates = [n for n in self.nodes if n.lower() not in link_nodes]
                
                if len(test_candidates) >= 2:
                    test_src = test_candidates[0]
                    test_dst = test_candidates[-1]
                    
                    mlf_res = self.multi_link_failure_analysis(
                        edge1['node1'], edge1['node2'],
                        edge2['node1'], edge2['node2'],
                        test_src, test_dst
                    )
                    
                    if mlf_res.status == "OK":
                        isolated = mlf_res.value.get("isolated", False)
                        new_path = mlf_res.value.get("new_path", [])
                        
                        path_str = " → ".join(new_path) if new_path else "없음"
                        result_text = "고립됨 (대체 경로 없음)" if isolated else f"대체 경로: {path_str}"
                        
                        metric = "multi_link_failure_analysis"
                        template = self._get_template(metric, "'{link1}' 링크와 '{link2}' 링크가 동시에 다운될 경우, {test_src}에서 {test_dst}로의 통신이 가능합니까?\n[답변 형식: '고립됨' 또는 '대체 경로: ...']")
                        q_text = template.format(link1=f"{edge1['node1']}-{edge1['node2']}", link2=f"{edge2['node1']}-{edge2['node2']}", test_src=test_src, test_dst=test_dst)

                        questions.append({
                            "id": f"MULTI_FAIL_{edge1['node1']}_{edge1['node2']}_{edge2['node1']}_{edge2['node2']}",
                            "category": "What_If_Analysis",
                            "level": "L5",
                            "answer_type": "text",
                            "question": q_text,
                            "ground_truth": result_text,
                            "explanation": f"metric `{metric}`",
                            "evidence_hint": {"scope": {"type": "MULTI_LINK_FAILURE", "link1": f"{edge1['node1']}-{edge1['node2']}", "link2": f"{edge2['node1']}-{edge2['node2']}"}, "metric": "multi_link_failure_analysis"},
                            "academic_reference": "Minesweeper (SIGCOMM'17): k-failure tolerance"
                        })
                        mlf_q_count += 1
                        if mlf_q_count >= 20:
                            break
        
        return questions
    
    def generate_all_questions(self) -> Dict[str, List[Dict[str, Any]]]:
        """모든 L4/L5 문제 생성"""
        return {
            "Reachability_Analysis": self.generate_l4_questions(),
            "What_If_Analysis": self.generate_l5_questions()
        }


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
