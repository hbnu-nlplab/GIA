"""
현재 시스템에서 개선된 파이프라인으로의 마이그레이션 가이드
단계별 통합 및 점진적 개선 방법
"""

from __future__ import annotations
from typing import Dict, Any, List, Optional
import os
import json
from pathlib import Path
import logging

# 기존 시스템 import (문제 해결 필요)
from generators.llm_explorer import LLMExplorer
from generators.rule_based_generator import RuleBasedGenerator, RuleBasedGeneratorConfig
from inspectors.question_reviewer import heuristic_filter, llm_reviewer
from utils.llm_adapter import generate_hypothesis_llm, parse_intent_llm

# 새로운 시스템 import
from enhanced_llm_generator import EnhancedLLMQuestionGenerator, QuestionComplexity
from evaluation_system import ComprehensiveEvaluator, AnswerType


class LegacySystemFixer:
    """기존 시스템의 문제점 수정"""
    
    def __init__(self):
        self.logger = self._setup_logger()
    
    def fix_llm_explorer_stability(self) -> Dict[str, Any]:
        """LLM Explorer의 안정성 문제 해결"""
        
        fixes = {
            "coerce_hypothesis_list": self._fix_coerce_function(),
            "intent_parsing": self._fix_intent_parsing(),
            "error_handling": self._add_robust_error_handling(),
            "fallback_mechanisms": self._add_fallback_mechanisms()
        }
        
        return fixes
    
    def _fix_coerce_function(self) -> str:
        """_coerce_hypothesis_list 함수 개선"""
        return """
def _coerce_hypothesis_list_improved(raw: Any) -> List[Dict[str, Any]]:
    '''개선된 가설 리스트 변환 - 더 안정적인 파싱'''
    
    if not raw:
        return []
    
    # 1) 기본 타입 체크 및 변환
    items = []
    try:
        if isinstance(raw, str):
            # JSON 문자열 파싱 시도
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, list):
                    items = parsed
                elif isinstance(parsed, dict):
                    # 'questions', 'hypotheses', 'items' 등의 키 확인
                    for key in ['questions', 'hypotheses', 'items', 'data']:
                        if key in parsed and isinstance(parsed[key], list):
                            items = parsed[key]
                            break
                    else:
                        items = [parsed]  # 단일 객체를 리스트로 감싸기
            except json.JSONDecodeError:
                # JSON이 아닌 일반 텍스트 - 단일 질문으로 처리
                items = [{"question": raw.strip(), "reasoning_steps": "legacy_text_input"}]
                
        elif isinstance(raw, list):
            items = raw
            
        elif isinstance(raw, dict):
            # 중첩된 구조에서 리스트 찾기
            if "question" in raw:
                items = [raw]
            else:
                for key in ['questions', 'hypotheses', 'items', 'data']:
                    if key in raw and isinstance(raw[key], list):
                        items = raw[key]
                        break
                else:
                    # 깊이 2까지 탐색
                    for v in raw.values():
                        if isinstance(v, dict):
                            for vv in v.values():
                                if isinstance(vv, list):
                                    items = vv
                                    break
                        if items:
                            break
                    
        else:
            return []
            
    except Exception as e:
        logging.warning(f"Raw parsing failed: {e}, attempting recovery...")
        return []
    
    # 2) 아이템 정규화 - 더 관대한 접근
    normalized = []
    for idx, item in enumerate(items):
        try:
            if isinstance(item, str):
                if len(item.strip()) >= 10:  # 최소 길이 체크
                    normalized.append({
                        "question": item.strip(),
                        "hypothesis_type": "ImpactAnalysis",
                        "intent_hint": {"metric": "", "scope": {}},
                        "expected_condition": "",
                        "reasoning_steps": "string_input_conversion",
                        "cited_values": {}
                    })
                continue
                
            if not isinstance(item, dict):
                continue
                
            # 필수 필드 확인 및 보정
            question = ""
            for q_key in ['question', 'text', 'query', 'prompt']:
                if q_key in item and isinstance(item[q_key], str):
                    question = item[q_key].strip()
                    break
            
            if len(question) < 10:  # 너무 짧은 질문 제외
                continue
                
            # 표준화된 객체 생성
            normalized_item = {
                "question": question,
                "hypothesis_type": item.get("hypothesis_type") or item.get("type") or "ImpactAnalysis",
                "intent_hint": self._normalize_intent_hint(item.get("intent_hint") or item.get("hint")),
                "expected_condition": item.get("expected_condition") or item.get("condition") or "",
                "reasoning_steps": item.get("reasoning_steps") or item.get("reasoning") or item.get("rationale") or "",
                "cited_values": item.get("cited_values") or item.get("values") or {}
            }
            
            normalized.append(normalized_item)
            
        except Exception as e:
            logging.warning(f"Item normalization failed for index {idx}: {e}")
            continue
    
    return normalized

def _normalize_intent_hint(hint: Any) -> Dict[str, Any]:
    '''Intent hint 정규화'''
    if not isinstance(hint, dict):
        return {"metric": "", "scope": {}}
    
    return {
        "metric": hint.get("metric") or hint.get("suggested_metric") or "",
        "scope": hint.get("scope") or hint.get("suggested_scope") or {}
    }
"""
    
    def _fix_intent_parsing(self) -> str:
        """Intent 파싱 개선"""
        return """
def parse_intent_llm_improved(question: str, metrics: List[str], **kwargs) -> Dict[str, Any]:
    '''개선된 의도 파싱 - 더 안정적인 매핑'''
    
    # 1) 기본 휴리스틱 매핑 (LLM 실패시 폴백)
    fallback_intent = _create_heuristic_intent(question, metrics)
    
    # 2) 환경변수로 LLM 사용 여부 제어
    if os.environ.get("GIA_USE_INTENT_LLM") != "1":
        return fallback_intent
    
    # 3) LLM 호출 (안전한 래퍼)
    try:
        llm_intent = _call_intent_llm_safe(question, metrics, **kwargs)
        
        # 4) LLM 결과 검증 및 보정
        validated_intent = _validate_and_merge_intent(llm_intent, fallback_intent, metrics)
        return validated_intent
        
    except Exception as e:
        logging.warning(f"LLM intent parsing failed: {e}, using heuristic fallback")
        return fallback_intent

def _create_heuristic_intent(question: str, metrics: List[str]) -> Dict[str, Any]:
    '''휴리스틱 기반 의도 생성'''
    q_lower = question.lower()
    
    # 키워드 기반 메트릭 매핑 (개선된 버전)
    metric_keywords = {
        'ssh': ['ssh_missing_count', 'ssh_enabled_devices', 'ssh_all_enabled_bool'],
        'bgp': ['ibgp_missing_pairs_count', 'ibgp_fullmesh_ok', 'neighbor_list_ibgp', 'bgp_neighbor_count'],
        'vrf': ['vrf_without_rt_count', 'vrf_rd_map', 'vrf_rt_list_per_device', 'vrf_names_set'],
        'l2vpn': ['l2vpn_unidir_count', 'l2vpn_mismatch_count', 'l2vpn_pairs'],
        'ospf': ['ospf_area0_if_count', 'ospf_proc_ids', 'ospf_area_set'],
        'interface': ['interface_count', 'interface_ip_map', 'interface_vlan_set'],
        'security': ['ssh_missing_count', 'aaa_present_bool'],
        'system': ['system_hostname_text', 'system_version_text', 'system_user_count']
    }
    
    selected_metric = ""
    for keyword, candidates in metric_keywords.items():
        if keyword in q_lower:
            for candidate in candidates:
                if candidate in metrics:
                    selected_metric = candidate
                    break
            if selected_metric:
                break
    
    if not selected_metric and metrics:
        selected_metric = metrics[0]  # 기본값
    
    # 스코프 추출 (정규표현식 기반)
    scope = {"type": "GLOBAL"}
    
    import re
    # AS 번호
    as_match = re.search(r'AS\s*(\d+)', question, re.IGNORECASE)
    if as_match:
        scope = {"type": "AS", "asn": as_match.group(1)}
    
    # 호스트명 (패턴 개선)
    host_patterns = [
        r'\b([A-Za-z]+\d+[A-Za-z]*)\b',  # Router1, PE01 등
        r'\b(PE|CE|P|RR)[-_]?(\d+)\b',   # PE-01, CE_02 등
        r'장비\s+([A-Za-z0-9_-]+)',      # "장비 Router1"
    ]
    
    for pattern in host_patterns:
        host_match = re.search(pattern, question, re.IGNORECASE)
        if host_match:
            hostname = host_match.group(1) if len(host_match.groups()) == 1 else f"{host_match.group(1)}{host_match.group(2)}"
            scope = {"type": "DEVICE", "host": hostname}
            break
    
    # VRF 이름
    vrf_match = re.search(r'vrf\s+([A-Za-z0-9_-]+)', question, re.IGNORECASE)
    if vrf_match:
        if scope.get("type") == "DEVICE":
            scope["vrf"] = vrf_match.group(1)
            scope["type"] = "DEVICE_VRF"
        else:
            scope = {"type": "VRF", "vrf": vrf_match.group(1)}
    
    return {
        "metric": selected_metric,
        "scope": scope,
        "aggregation": _infer_aggregation(selected_metric),
        "placeholders": _extract_placeholders(scope)
    }

def _infer_aggregation(metric: str) -> str:
    '''메트릭에서 집계 타입 추론'''
    if metric.endswith('_count') or metric.endswith('_numeric'):
        return "numeric"
    elif metric.endswith('_bool') or metric.endswith('_ok'):
        return "boolean"
    elif metric.endswith('_map'):
        return "map"
    elif metric.endswith('_set') or metric.endswith('_list'):
        return "set"
    else:
        return "text"

def _extract_placeholders(scope: Dict[str, Any]) -> List[str]:
    '''스코프에서 플레이스홀더 추출'''
    placeholders = []
    if "host" in scope:
        placeholders.append("host")
    if "asn" in scope:
        placeholders.append("asn")
    if "vrf" in scope:
        placeholders.append("vrf")
    if "if" in scope:
        placeholders.append("if")
    return placeholders
"""
    
    def _add_robust_error_handling(self) -> str:
        """강화된 에러 핸들링"""
        return """
import functools
import time
from typing import Callable, Any

def with_retry_and_fallback(retries: int = 3, fallback_value: Any = None):
    '''재시도 및 폴백 데코레이터'''
    def decorator(func: Callable):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    logging.warning(f"Attempt {attempt + 1} failed for {func.__name__}: {e}")
                    
                    if attempt < retries - 1:
                        # 지수 백오프
                        delay = min(2 ** attempt, 10)
                        time.sleep(delay)
            
            logging.error(f"All attempts failed for {func.__name__}: {last_exception}")
            
            if fallback_value is not None:
                return fallback_value
            else:
                raise last_exception
        
        return wrapper
    return decorator

# 사용 예시
@with_retry_and_fallback(retries=3, fallback_value=[])
def generate_hypothesis_llm_safe(context, policies, **kwargs):
    '''안전한 가설 생성'''
    return generate_hypothesis_llm(context, policies, **kwargs)

@with_retry_and_fallback(retries=2, fallback_value={"metric": "", "scope": {}})  
def parse_intent_llm_safe(question, metrics, **kwargs):
    '''안전한 의도 파싱'''
    return parse_intent_llm(question, metrics, **kwargs)
"""
    
    def _add_fallback_mechanisms(self) -> str:
        """폴백 메커니즘 추가"""
        return """
class LLMExplorerImproved(LLMExplorer):
    '''개선된 LLM Explorer - 안정적인 폴백 메커니즘'''
    
    def from_llm(self, facts: Dict[str, Any], policies: Any, n_hypotheses: int = 5) -> List[Dict[str, Any]]:
        '''메인 LLM 탐색 함수 - 개선된 버전'''
        
        # 1) 기본 설정
        metrics = list_available_metrics()
        focused_ctx = make_grounding(facts) if isinstance(facts, (dict, list)) else facts
        
        # 2) 3단계 폴백 전략
        hypotheses = []
        
        # 2-1) 1차: 기존 LLM 방식 시도
        try:
            raw = generate_hypothesis_llm_safe(focused_ctx, policies, n_hypotheses=n_hypotheses, builder_metrics=metrics)
            hypotheses = _coerce_hypothesis_list_improved(raw)
            
            if len(hypotheses) >= n_hypotheses // 2:  # 최소 절반 이상 성공
                self.logger.info(f"LLM 1차 성공: {len(hypotheses)}개 가설 생성")
            else:
                raise ValueError(f"Insufficient hypotheses generated: {len(hypotheses)}")
                
        except Exception as e:
            self.logger.warning(f"LLM 1차 실패: {e}, 2차 시도...")
            
            # 2-2) 2차: 템플릿 기반 LLM 시도
            try:
                hypotheses = self._generate_template_based_hypotheses(focused_ctx, n_hypotheses, metrics)
                self.logger.info(f"템플릿 기반 2차 성공: {len(hypotheses)}개 가설 생성")
                
            except Exception as e2:
                self.logger.warning(f"LLM 2차 실패: {e2}, 3차 폴백...")
                
                # 2-3) 3차: 완전 휴리스틱 폴백
                hypotheses = self._generate_heuristic_hypotheses(focused_ctx, n_hypotheses, metrics)
                self.logger.info(f"휴리스틱 3차 폴백: {len(hypotheses)}개 가설 생성")
        
        # 3) 품질 필터링 (개선된 버전)
        filtered_hypotheses = self._apply_improved_filtering(hypotheses, focused_ctx)
        
        # 4) Intent 변환 (안전한 버전)
        translated = self._safe_intent_translation(filtered_hypotheses, metrics)
        
        return translated
    
    def _generate_template_based_hypotheses(self, context: Dict[str, Any], n: int, metrics: List[str]) -> List[Dict[str, Any]]:
        '''템플릿 기반 가설 생성 (2차 폴백)'''
        
        templates = [
            "SSH 설정이 {condition}된 장비가 보안 정책을 준수하는가?",
            "AS {asn}의 BGP 피어링에서 {condition} 문제가 있는가?", 
            "VRF 설정에서 route-target이 {condition} 경우가 있는가?",
            "L2VPN 회선에서 {condition} 상태인 세션이 있는가?",
            "OSPF 설정에서 {condition} 인터페이스가 있는가?"
        ]
        
        conditions = ["누락", "불일치", "오류", "비정상", "미설정"]
        as_numbers = list(context.get("as_groups", {}).keys())
        
        hypotheses = []
        for template in templates:
            for condition in conditions:
                if "{asn}" in template and as_numbers:
                    for asn in as_numbers[:2]:  # 최대 2개 AS
                        question = template.format(condition=condition, asn=asn)
                        hypotheses.append(self._create_hypothesis_from_template(question, metrics))
                else:
                    question = template.format(condition=condition, asn="")
                    hypotheses.append(self._create_hypothesis_from_template(question, metrics))
                
                if len(hypotheses) >= n:
                    break
            if len(hypotheses) >= n:
                break
        
        return hypotheses[:n]
    
    def _generate_heuristic_hypotheses(self, context: Dict[str, Any], n: int, metrics: List[str]) -> List[Dict[str, Any]]:
        '''완전 휴리스틱 가설 생성 (3차 폴백)'''
        
        # 컨텍스트 기반 문제 상황 식별
        anomalies = context.get("anomalies", {})
        as_groups = context.get("as_groups", {})
        
        hypotheses = []
        
        # SSH 문제
        ssh_missing = anomalies.get("ssh_missing_devices", [])
        if ssh_missing:
            hypotheses.append({
                "question": f"SSH가 설정되지 않은 {len(ssh_missing)}대 장비가 보안 취약점을 야기하는가?",
                "hypothesis_type": "SecurityRisk",
                "intent_hint": {"metric": "ssh_missing_count", "scope": {}},
                "expected_condition": "ssh_missing_count == 0",
                "reasoning_steps": "heuristic: ssh anomaly detected",
                "cited_values": {"ssh_missing_count": len(ssh_missing)}
            })
        
        # BGP 문제  
        for asn, meta in as_groups.items():
            missing_pairs = meta.get("ibgp_missing_pairs_count", 0)
            if missing_pairs > 0:
                hypotheses.append({
                    "question": f"AS {asn}에서 iBGP 피어 {missing_pairs}쌍 누락이 라우팅 수렴성에 영향을 주는가?",
                    "hypothesis_type": "RoutingStability", 
                    "intent_hint": {"metric": "ibgp_missing_pairs_count", "scope": {"asn": asn}},
                    "expected_condition": "ibgp_missing_pairs_count == 0",
                    "reasoning_steps": "heuristic: bgp anomaly detected",
                    "cited_values": {"asn": asn, "missing_pairs": missing_pairs}
                })
            
            if len(hypotheses) >= n:
                break
        
        # 기본 질문들로 채우기
        basic_questions = [
            ("모든 장비에서 SSH 접근이 가능한가?", "ssh_all_enabled_bool"),
            ("BGP 피어링이 완전한 풀메시 구조인가?", "ibgp_fullmesh_ok"),
            ("VRF 설정에 route-target이 누락된 경우가 있는가?", "vrf_without_rt_count"),
            ("L2VPN 회선에서 단방향 연결된 세션이 있는가?", "l2vpn_unidir_count"),
            ("시스템 정보가 모든 장비에서 정상 조회되는가?", "system_hostname_text")
        ]
        
        for question, metric in basic_questions:
            if len(hypotheses) >= n:
                break
            hypotheses.append({
                "question": question,
                "hypothesis_type": "SystemCheck",
                "intent_hint": {"metric": metric, "scope": {}},
                "expected_condition": f"{metric} != null",
                "reasoning_steps": "heuristic: basic system check",
                "cited_values": {}
            })
        
        return hypotheses[:n]
    
    def _create_hypothesis_from_template(self, question: str, metrics: List[str]) -> Dict[str, Any]:
        '''템플릿에서 가설 객체 생성'''
        # 질문에서 적절한 메트릭 추론
        q_lower = question.lower()
        
        if "ssh" in q_lower:
            metric = "ssh_missing_count" if "ssh_missing_count" in metrics else "ssh_enabled_devices"
        elif "bgp" in q_lower:
            metric = "ibgp_missing_pairs_count" if "ibgp_missing_pairs_count" in metrics else "neighbor_list_ibgp"
        elif "vrf" in q_lower:
            metric = "vrf_without_rt_count" if "vrf_without_rt_count" in metrics else "vrf_rd_map"
        elif "l2vpn" in q_lower:
            metric = "l2vpn_unidir_count" if "l2vpn_unidir_count" in metrics else "l2vpn_pairs"
        elif "ospf" in q_lower:
            metric = "ospf_area0_if_count" if "ospf_area0_if_count" in metrics else "ospf_proc_ids"
        else:
            metric = metrics[0] if metrics else ""
        
        return {
            "question": question,
            "hypothesis_type": "TemplateGenerated",
            "intent_hint": {"metric": metric, "scope": {}},
            "expected_condition": f"{metric} meets_policy",
            "reasoning_steps": "template-based generation",
            "cited_values": {}
        }
    
    def _apply_improved_filtering(self, hypotheses: List[Dict[str, Any]], context: Dict[str, Any]) -> List[Dict[str, Any]]:
        '''개선된 품질 필터링'''
        
        if not hypotheses:
            return []
        
        # 1차: 휴리스틱 필터
        heuristic_passed = heuristic_filter(hypotheses)
        
        # 2차: 길이 및 복잡도 필터
        quality_passed = []
        for h in heuristic_passed:
            question = h.get("question", "")
            
            # 기본 품질 체크
            if len(question.strip()) < 15 or len(question) > 200:
                continue
            
            # 의미있는 키워드 포함 여부
            meaningful_keywords = ["개수", "수", "있는가", "되어있는가", "일치", "누락", "오류", "정상"]
            if not any(kw in question for kw in meaningful_keywords):
                continue
            
            quality_passed.append(h)
        
        # 3차: LLM 리뷰 (선택적)
        if os.environ.get("GIA_ENABLE_LLM_REVIEW") == "1" and len(quality_passed) > 3:
            try:
                llm_passed = llm_reviewer(quality_passed, context, score_threshold=8)
                return llm_passed if llm_passed else quality_passed
            except:
                return quality_passed
        
        return quality_passed
    
    def _safe_intent_translation(self, hypotheses: List[Dict[str, Any]], metrics: List[str]) -> List[Dict[str, Any]]:
        '''안전한 Intent 번역'''
        translated = []
        
        for h in hypotheses:
            try:
                question = h.get("question", "")
                if not question:
                    continue
                
                # 안전한 Intent 파싱
                intent = parse_intent_llm_safe(
                    question, 
                    metrics,
                    hint_metric=h.get("intent_hint", {}).get("metric"),
                    hint_scope=h.get("intent_hint", {}).get("scope"),
                    cited_values=h.get("cited_values")
                )
                
                # Intent 검증 및 보정
                if not intent.get("metric") or intent["metric"] not in metrics:
                    intent["metric"] = self._find_fallback_metric(question, metrics)
                
                if not isinstance(intent.get("scope"), dict):
                    intent["scope"] = {}
                
                translated.append({
                    "origin": "improved_llm_explorer",
                    "hypothesis": h,
                    "intent": intent
                })
                
            except Exception as e:
                self.logger.warning(f"Intent 번역 실패: {e}, 항목 스킵")
                continue
        
        return translated
    
    def _find_fallback_metric(self, question: str, metrics: List[str]) -> str:
        '''폴백 메트릭 찾기'''
        q_lower = question.lower()
        
        # 우선순위 기반 매핑
        priority_mappings = [
            (["ssh", "보안"], ["ssh_missing_count", "ssh_enabled_devices", "ssh_all_enabled_bool"]),
            (["bgp", "피어"], ["ibgp_missing_pairs_count", "neighbor_list_ibgp", "ibgp_fullmesh_ok"]),
            (["vrf", "route-target"], ["vrf_without_rt_count", "vrf_rd_map", "vrf_rt_list_per_device"]),
            (["l2vpn", "회선"], ["l2vpn_unidir_count", "l2vpn_pairs", "l2vpn_mismatch_count"]),
            (["ospf"], ["ospf_area0_if_count", "ospf_proc_ids"]),
            (["시스템", "장비"], ["system_hostname_text", "system_version_text"])
        ]
        
        for keywords, candidates in priority_mappings:
            if any(kw in q_lower for kw in keywords):
                for candidate in candidates:
                    if candidate in metrics:
                        return candidate
        
        # 최종 폴백
        return metrics[0] if metrics else "system_hostname_text"
    
    def _setup_logger(self):
        logger = logging.getLogger("ImprovedLLMExplorer")
        logger.setLevel(logging.INFO)
        return logger
"""
    
    def _setup_logger(self):
        logger = logging.getLogger("LegacySystemFixer")
        logger.setLevel(logging.INFO)
        return logger


class EnhancedDatasetConfigurator:
    """교수님 요구사항 반영한 데이터셋 설정"""
    
    def create_incount_variants(self, base_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """incount 확장 - 다양한 케이스 생성"""
        
        variants = []
        
        # 기본 케이스
        base_case = base_config.copy()
        base_case["case_name"] = "standard"
        base_case["description"] = "표준 네트워크 설정"
        variants.append(base_case)
        
        # 장애 시나리오 케이스들
        failure_cases = [
            {
                "case_name": "bgp_peer_failure",
                "description": "BGP 피어 일부 장애 상황",
                "simulation_conditions": [
                    {"target": "Router1", "component": "bgp_peer:10.0.0.2", "state": "down"},
                    {"target": "Router2", "component": "bgp_peer:10.0.0.1", "state": "down"}
                ],
                "expected_impact": "routing_convergence_delay"
            },
            {
                "case_name": "interface_failure", 
                "description": "핵심 인터페이스 장애",
                "simulation_conditions": [
                    {"target": "PE01", "component": "interface:GigabitEthernet0/0/0/0", "state": "down"},
                    {"target": "PE02", "component": "interface:GigabitEthernet0/0/0/1", "state": "down"}
                ],
                "expected_impact": "service_disruption"
            },
            {
                "case_name": "partial_ssh_failure",
                "description": "일부 장비 SSH 접근 불가",
                "simulation_conditions": [
                    {"target": "CE01", "component": "ssh_service", "state": "disabled"},
                    {"target": "CE02", "component": "ssh_service", "state": "disabled"}
                ],
                "expected_impact": "management_access_limited"
            }
        ]
        
        for failure_case in failure_cases:
            case_config = base_config.copy()
            case_config.update(failure_case)
            variants.append(case_config)
        
        # 확장 시나리오 케이스들
        expansion_cases = [
            {
                "case_name": "network_expansion",
                "description": "새로운 PE 라우터 추가 시나리오",
                "additional_devices": [
                    {
                        "hostname": "PE03",
                        "type": "PE",
                        "bgp_as": "65001",
                        "interfaces": ["GigabitEthernet0/0/0/0", "GigabitEthernet0/0/0/1"],
                        "vrfs": ["CUSTOMER_A", "CUSTOMER_B"]
                    }
                ],
                "expected_impact": "configuration_validation_needed"
            },
            {
                "case_name": "customer_onboarding",
                "description": "신규 고객 L3VPN 서비스 개통",
                "new_services": [
                    {
                        "service_type": "l3vpn",
                        "customer": "CUSTOMER_C", 
                        "vrf_name": "CUSTOMER_C_VRF",
                        "rd": "65001:103",
                        "rt_import": ["65001:103"],
                        "rt_export": ["65001:103"]
                    }
                ],
                "expected_impact": "service_provisioning_validation"
            }
        ]
        
        for expansion_case in expansion_cases:
            case_config = base_config.copy()
            case_config.update(expansion_case)
            variants.append(case_config)
        
        return variants
    
    def create_evaluation_profiles(self) -> List[Dict[str, Any]]:
        """다양한 평가 프로필 생성"""
        
        profiles = [
            {
                "profile_name": "comprehensive",
                "description": "종합 평가 - 모든 메트릭 사용",
                "metrics": ["exact_match", "f1_score", "bert_score", "bleu_score", "rouge_score"],
                "short_answer_weight": 0.4,
                "long_answer_weight": 0.6,
                "thresholds": {
                    "exact_match": 0.8,
                    "f1_score": 0.7,
                    "overall_score": 0.75
                }
            },
            {
                "profile_name": "precision_focused",
                "description": "정확성 중심 평가",
                "metrics": ["exact_match", "f1_score"],
                "short_answer_weight": 0.7,
                "long_answer_weight": 0.3,
                "thresholds": {
                    "exact_match": 0.9,
                    "f1_score": 0.85,
                    "overall_score": 0.85
                }
            },
            {
                "profile_name": "fluency_focused",
                "description": "유창성 중심 평가 (Long Answer)",
                "metrics": ["bert_score", "bleu_score", "rouge_score"],
                "short_answer_weight": 0.2,
                "long_answer_weight": 0.8,
                "thresholds": {
                    "bert_score": 0.7,
                    "bleu_score": 0.3,
                    "rouge_score": 0.5
                }
            },
            {
                "profile_name": "network_domain",
                "description": "네트워크 도메인 특화 평가",
                "metrics": ["exact_match", "f1_score", "entity_f1"],
                "short_answer_weight": 0.5,
                "long_answer_weight": 0.5,
                "entity_types": ["ip_addresses", "as_numbers", "interfaces"],
                "thresholds": {
                    "exact_match": 0.75,
                    "entity_f1": 0.8,
                    "overall_score": 0.7
                }
            }
        ]
        
        return profiles


class StepByStepMigrationPlan:
    """단계별 마이그레이션 계획"""
    
    def __init__(self):
        self.steps = [
            {
                "step": 1,
                "title": "기존 시스템 문제 해결",
                "description": "현재 LLM Explorer 안정화",
                "actions": [
                    "LLMExplorer.from_llm() 메서드 안정화",
                    "_coerce_hypothesis_list() 함수 개선",
                    "에러 핸들링 및 폴백 메커니즘 추가",
                    "Intent 파싱 로직 보완"
                ],
                "estimated_time": "1-2일",
                "success_criteria": [
                    "LLM 호출 실패율 < 10%",
                    "가설 생성 개수 >= 목표치의 80%",
                    "Intent 파싱 성공률 > 90%"
                ]
            },
            {
                "step": 2,
                "title": "Enhanced LLM Generator 통합",
                "description": "새로운 복합 질문 생성 시스템 적용",
                "actions": [
                    "EnhancedLLMQuestionGenerator 모듈 통합",
                    "기존 LLMExplorer와 병행 운영",
                    "복잡도별, 페르소나별 질문 생성 테스트",
                    "생성 품질 비교 평가"
                ],
                "estimated_time": "2-3일",
                "success_criteria": [
                    "Enhanced 질문 생성 성공률 > 80%",
                    "복잡도 3-4 수준 질문 비율 > 40%",
                    "다양한 페르소나 관점 반영"
                ]
            },
            {
                "step": 3,
                "title": "평가 시스템 구축",
                "description": "Multi-Modal 평가 시스템 구현",
                "actions": [
                    "ComprehensiveEvaluator 구현",
                    "EM, F1, BERT-Score, BLEU, ROUGE 메트릭 통합",
                    "Short/Long Answer 자동 분류",
                    "네트워크 도메인 특화 평가 로직 추가"
                ],
                "estimated_time": "3-4일", 
                "success_criteria": [
                    "모든 평가 메트릭 정상 동작",
                    "Answer Type 분류 정확도 > 95%",
                    "네트워크 엔티티 인식률 > 85%"
                ]
            },
            {
                "step": 4,
                "title": "통합 파이프라인 구축",
                "description": "전체 시스템 통합 및 최적화",
                "actions": [
                    "NetworkConfigDatasetGenerator 구현",
                    "단계별 파이프라인 검증",
                    "중간 결과 저장 및 복구 기능",
                    "설정 기반 유연한 실행"
                ],
                "estimated_time": "2-3일",
                "success_criteria": [
                    "End-to-End 파이프라인 정상 동작",
                    "각 단계별 성공률 > 85%",
                    "최종 데이터셋 품질 검증 통과"
                ]
            },
            {
                "step": 5,
                "title": "케이스 확장 및 검증",
                "description": "incount 확장 및 다양한 시나리오 적용",
                "actions": [
                    "다양한 장애/확장 시나리오 케이스 생성",
                    "각 케이스별 데이터셋 생성 및 검증",
                    "평가 프로필별 성능 분석",
                    "최종 논문용 데이터셋 완성"
                ],
                "estimated_time": "3-5일",
                "success_criteria": [
                    "최소 5개 이상 케이스 시나리오",
                    "케이스별 100개 이상 고품질 질문",
                    "논문 기준 성능 달성"
                ]
            }
        ]
    
    def get_immediate_actions(self) -> List[str]:
        """즉시 시작할 수 있는 액션들"""
        return [
            "1. 현재 코드의 LLMExplorer.from_llm() 메서드에 try-except 추가",
            "2. _coerce_hypothesis_list() 함수를 개선된 버전으로 교체",
            "3. 환경변수로 LLM 사용 여부 제어 (GIA_USE_INTENT_LLM=0으로 시작)",
            "4. 기본 휴리스틱 폴백 로직 구현",
            "5. 간단한 로깅 시스템 추가하여 디버깅 정보 수집"
        ]
    
    def get_parallel_tasks(self) -> Dict[str, List[str]]:
        """병렬로 진행할 수 있는 작업들"""
        return {
            "코드_개선": [
                "기존 LLM Explorer 안정화",
                "Enhanced Generator 개발",
                "평가 시스템 구현"
            ],
            "데이터_준비": [
                "XML 데이터 검증 및 정리",
                "Policy 파일 확장",
                "시나리오 케이스 설계"
            ],
            "평가_설계": [
                "평가 메트릭 검증",
                "벤치마크 기준 설정",
                "논문용 실험 설계"
            ]
        }


def create_quick_start_guide() -> str:
    """빠른 시작 가이드"""
    return """
# 네트워크 설정 데이터셋 생성 파이프라인 - 빠른 시작 가이드

## 즉시 개선 (30분 내)

### 1. 기존 LLMExplorer 안정화
```python
# generators/llm_explorer.py 수정
def from_llm(self, facts, policies, n_hypotheses=5):
    try:
        # 기존 로직
        raw = generate_hypothesis_llm(...)
        hypos_raw = _coerce_hypothesis_list(raw)
    except Exception as e:
        print(f"[FALLBACK] LLM 실패: {e}")
        # 안전한 폴백
        hypos_raw = self._create_fallback_hypotheses(facts, n_hypotheses)
    
    return self._process_hypotheses(hypos_raw)

def _create_fallback_hypotheses(self, facts, n):
    # 간단한 휴리스틱 기반 가설 생성
    return [
        {"question": "SSH가 모든 장비에 설정되어 있는가?", ...},
        {"question": "BGP 피어링이 정상적으로 구성되어 있는가?", ...},
        # ... 더 많은 기본 질문들
    ]
```

### 2. 환경변수 제어 추가
```bash
export GIA_USE_INTENT_LLM=0  # LLM 의도 파싱 비활성화
export GIA_ENABLE_LLM_REVIEW=0  # LLM 리뷰 비활성화
export OPENAI_API_KEY=your_key  # LLM 사용시에만 필요
```

### 3. 기본 실행 테스트
```python
from integrated_pipeline import NetworkConfigDatasetGenerator, PipelineConfig

config = PipelineConfig(
    xml_data_dir="XML_Data",
    policies_path="policies/policies.json", 
    target_categories=["BGP_Consistency", "Security_Policy"],
    basic_questions_per_category=3,
    enhanced_questions_per_category=2  # 작게 시작
)

generator = NetworkConfigDatasetGenerator(config)
dataset = generator.generate_complete_dataset()
```

## 1주일 개선 계획

### Day 1-2: 안정화
- LLM Explorer 에러 처리 개선
- 폴백 메커니즘 구현
- 기본 데이터셋 생성 검증

### Day 3-4: 심화 질문 생성
- Enhanced LLM Generator 통합
- 복잡도별 질문 생성 테스트
- 페르소나 기반 질문 검증

### Day 5-6: 평가 시스템
- Multi-Modal 평가 구현
- Short/Long Answer 분류
- 네트워크 도메인 특화 메트릭

### Day 7: 통합 및 검증
- 전체 파이프라인 통합
- 케이스별 데이터셋 생성
- 품질 검증 및 최적화

## 성공 지표

### 즉시 (1일 내)
- [x] 파이프라인이 에러 없이 실행됨
- [x] 기본 질문 50개 이상 생성
- [x] Rule-based 질문 100% 성공률

### 단기 (1주일 내)  
- [ ] Enhanced 질문 50개 이상 생성
- [ ] 복잡도 3-4 수준 질문 20개 이상
- [ ] 평가 메트릭 정상 동작

### 중기 (2주일 내)
- [ ] 5개 이상 시나리오 케이스
- [ ] 총 500개 이상 고품질 질문
- [ ] 논문용 실험 데이터 완성
"""


if __name__ == "__main__":
    # 마이그레이션 플랜 출력
    plan = StepByStepMigrationPlan()
    
    print("=== 즉시 시작 가능한 개선 작업 ===")
    for action in plan.get_immediate_actions():
        print(f"• {action}")
    
    print("\n=== 병렬 진행 가능한 작업들 ===")
    for category, tasks in plan.get_parallel_tasks().items():
        print(f"\n{category}:")
        for task in tasks:
            print(f"  - {task}")
    
    print("\n=== 빠른 시작 가이드 ===")
    print(create_quick_start_guide())
