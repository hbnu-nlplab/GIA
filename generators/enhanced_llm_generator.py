"""
Enhanced LLM Question Generator for Complex Network Analysis
복합 추론, 페르소나 기반, 시나리오 기반 질문 생성
"""

from __future__ import annotations
from typing import Dict, Any, List, Optional
import json
from dataclasses import dataclass
from enum import Enum

from utils.llm_adapter import _call_llm_json
from utils.builder_core import BuilderCore, list_available_metrics


class QuestionComplexity(Enum):
    BASIC = "basic"           # 단순 팩트 추출
    ANALYTICAL = "analytical" # 분석적 추론
    SYNTHETIC = "synthetic"   # 복합 정보 종합
    DIAGNOSTIC = "diagnostic" # 문제 진단
    SCENARIO = "scenario"     # 시나리오 기반


class PersonaType(Enum):
    NETWORK_ENGINEER = "network_engineer"
    SECURITY_AUDITOR = "security_auditor"
    NOC_OPERATOR = "noc_operator"
    ARCHITECT = "network_architect"
    TROUBLESHOOTER = "troubleshooter"


@dataclass
class QuestionTemplate:
    complexity: QuestionComplexity
    persona: PersonaType
    scenario: str
    prompt_template: str
    expected_metrics: List[str]
    answer_type: str  # "short" or "long"


class EnhancedLLMQuestionGenerator:
    def __init__(self):
        self.templates = self._initialize_templates()
    
    def _initialize_templates(self) -> List[QuestionTemplate]:
        """복합성과 페르소나를 고려한 질문 템플릿 초기화"""
        return [
            # 분석적 추론 - 네트워크 엔지니어
            QuestionTemplate(
                complexity=QuestionComplexity.ANALYTICAL,
                persona=PersonaType.NETWORK_ENGINEER,
                scenario="BGP 경로 수렴 분석",
                prompt_template="""
네트워크 엔지니어 관점에서, 주어진 BGP 설정을 분석하여 다음과 같은 복합적 질문을 생성하세요:

1. **경로 수렴성 분석**: iBGP 풀메시 누락이 경로 수렴에 미치는 영향
2. **장애 영향도 평가**: 특정 피어 장애시 전체 네트워크에 미치는 파급효과
3. **설정 일관성 검증**: AS 내 라우터들의 BGP 설정 일관성 문제점

각 질문은 다음 형식으로 생성하세요:
- 분석적 추론이 필요한 질문
- 여러 메트릭을 종합한 판단 요구
- 실무적 문제 해결 관점
""",
                expected_metrics=["ibgp_missing_pairs", "ibgp_under_peered_count", "neighbor_list_ibgp"],
                answer_type="long"
            ),
            
            # 진단적 - 보안 감사자
            QuestionTemplate(
                complexity=QuestionComplexity.DIAGNOSTIC,
                persona=PersonaType.SECURITY_AUDITOR,
                scenario="보안 취약점 진단",
                prompt_template="""
보안 감사자 관점에서, 네트워크 보안 설정을 종합적으로 분석하는 질문을 생성하세요:

1. **보안 정책 준수성**: SSH, AAA 설정의 일관성과 표준 준수 여부
2. **취약점 우선순위**: 발견된 보안 문제의 위험도 평가
3. **규정 준수 검증**: 보안 정책 위반 사항의 비즈니스 영향도

질문 특성:
- 보안 위험도 평가 필요
- 규정 준수 관점 포함
- 개선 권고사항 도출 가능
""",
                expected_metrics=["ssh_missing_count", "aaa_present_bool", "ssh_all_enabled_bool"],
                answer_type="long"
            ),
            
            # 복합 종합 - NOC 운영자
            QuestionTemplate(
                complexity=QuestionComplexity.SYNTHETIC,
                persona=PersonaType.NOC_OPERATOR,
                scenario="서비스 영향도 분석",
                prompt_template="""
NOC 운영자 관점에서, 서비스 가용성과 관련된 복합적 상황 분석 질문을 생성하세요:

1. **서비스 영향도 매트릭스**: L2VPN/L3VPN 서비스의 장애 파급 범위
2. **우선순위 복구 계획**: 여러 문제 동시 발생시 복구 우선순위
3. **예방적 모니터링**: 잠재적 서비스 위험 요소 식별

질문 요구사항:
- 다중 서비스 계층 고려
- 비즈니스 영향도 포함
- 운영 관점의 실용성
""",
                expected_metrics=["l2vpn_unidir_count", "l2vpn_mismatch_count", "vrf_without_rt_count"],
                answer_type="long"
            ),
            
            # 시나리오 기반 - 트러블슈터
            QuestionTemplate(
                complexity=QuestionComplexity.SCENARIO,
                persona=PersonaType.TROUBLESHOOTER,
                scenario="장애 상황 대응",
                prompt_template="""
네트워크 트러블슈터 관점에서, 실제 장애 상황을 가정한 문제 해결 질문을 생성하세요:

장애 시나리오 예시:
- "고객사 A의 L3VPN 서비스가 간헐적으로 끊어진다는 보고"
- "새로운 PE 라우터 추가 후 BGP 경로 이상"
- "보안 점검 후 일부 장비 접속 불가"

질문 형태:
1. **근본 원인 분석**: 증상으로부터 원인 추적
2. **영향 범위 파악**: 동일 문제로 영향받을 수 있는 다른 서비스
3. **해결 방안 검증**: 제안한 해결책의 부작용 검토

각 질문은 실제 장애 대응 경험이 반영되어야 함
""",
                expected_metrics=["vrf_rd_map", "ospf_area0_if_count", "neighbor_list_ebgp"],
                answer_type="long"
            )
        ]
    
    def generate_enhanced_questions(
        self, 
        network_facts: Dict[str, Any], 
        target_complexities: List[QuestionComplexity] = None,
        questions_per_template: int = 2
    ) -> List[Dict[str, Any]]:
        """향상된 LLM 질문 생성"""
        
        if target_complexities is None:
            target_complexities = [QuestionComplexity.ANALYTICAL, QuestionComplexity.SYNTHETIC]
        
        # 네트워크 현황 분석
        context = self._analyze_network_context(network_facts)
        
        generated_questions = []
        
        for template in self.templates:
            if template.complexity not in target_complexities:
                continue
                
            questions = self._generate_from_template(
                template, context, questions_per_template
            )
            generated_questions.extend(questions)
        
        return generated_questions
    
    def _analyze_network_context(self, facts: Dict[str, Any]) -> Dict[str, Any]:
        """네트워크 현황 분석 및 컨텍스트 생성"""
        builder = BuilderCore(facts.get("devices", []))
        pre = builder._precompute()
        
        # 중요한 네트워크 메트릭 추출
        context = {
            "device_count": len(builder.devices),
            "as_groups": builder._as_groups(),
            "anomalies": {
                "bgp_missing_pairs": len(pre.get("bgp_missing_pairs_by_as", {})),
                "ssh_missing_count": len(pre.get("ssh_missing", [])),
                "vrf_without_rt": len(pre.get("vrf_without_rt_pairs", [])),
                "l2vpn_issues": len(pre.get("l2vpn_unidir", [])) + len(pre.get("l2vpn_mismatch", []))
            },
            "technologies": self._identify_technologies(builder.devices),
            "complexity_indicators": self._assess_network_complexity(builder.devices)
        }
        
        return context
    
    def _identify_technologies(self, devices: List[Dict[str, Any]]) -> Dict[str, bool]:
        """네트워크에서 사용되는 기술 식별"""
        tech = {
            "bgp": False,
            "ospf": False,
            "l2vpn": False,
            "l3vpn": False,
            "mpls": False
        }
        
        for device in devices:
            if device.get("routing", {}).get("bgp"):
                tech["bgp"] = True
            if device.get("routing", {}).get("ospf"):
                tech["ospf"] = True
            if device.get("services", {}).get("l2vpn"):
                tech["l2vpn"] = True
            if device.get("services", {}).get("vrf"):
                tech["l3vpn"] = True
                
        return tech
    
    def _assess_network_complexity(self, devices: List[Dict[str, Any]]) -> Dict[str, Any]:
        """네트워크 복잡도 평가"""
        
        total_bgp_peers = 0
        total_vrfs = 0
        total_l2vpns = 0
        
        for device in devices:
            bgp = device.get("routing", {}).get("bgp", {})
            total_bgp_peers += len(bgp.get("neighbors", []))
            total_vrfs += len(device.get("services", {}).get("vrf", []))
            total_l2vpns += len(device.get("services", {}).get("l2vpn", []))
        
        return {
            "avg_bgp_peers_per_device": total_bgp_peers / max(len(devices), 1),
            "total_vrfs": total_vrfs,
            "total_l2vpns": total_l2vpns,
            "complexity_score": self._calculate_complexity_score(
                len(devices), total_bgp_peers, total_vrfs, total_l2vpns
            )
        }
    
    def _calculate_complexity_score(self, devices: int, bgp_peers: int, vrfs: int, l2vpns: int) -> str:
        """네트워크 복잡도 점수 계산"""
        score = devices * 0.3 + bgp_peers * 0.2 + vrfs * 0.3 + l2vpns * 0.2
        
        if score < 10:
            return "simple"
        elif score < 30:
            return "moderate"
        else:
            return "complex"
    
    def _generate_from_template(
        self, 
        template: QuestionTemplate, 
        context: Dict[str, Any],
        count: int
    ) -> List[Dict[str, Any]]:
        """템플릿 기반 질문 생성"""
        
        schema = {
            "title": "EnhancedNetworkQuestions",
            "type": "object",
            "properties": {
                "questions": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "question": {"type": "string"},
                            "reasoning_requirement": {"type": "string"},
                            "expected_analysis_depth": {"type": "string", "enum": ["surface", "detailed", "comprehensive"]},
                            "metrics_involved": {"type": "array", "items": {"type": "string"}},
                            "scenario_context": {"type": "string"},
                            "answer_structure": {"type": "string"}
                        },
                        "required": ["question", "reasoning_requirement", "expected_analysis_depth"],
                        "additionalProperties": False
                    },
                    "maxItems": count
                }
            },
            "required": ["questions"],
            "additionalProperties": False
        }
        
        system_prompt = f"""
당신은 {template.persona.value} 역할의 네트워크 전문가입니다.
복잡도: {template.complexity.value}
시나리오: {template.scenario}

주어진 네트워크 현황을 바탕으로 {template.answer_type} 답변이 필요한 전문적 질문을 생성하세요.
**규칙: 모든 질문과 설명은 반드시 한국어로 작성해야 합니다.**
"""
        
        user_prompt = f"""
{template.prompt_template}

네트워크 현황:
- 장비 수: {context['device_count']}
- AS 그룹: {list(context['as_groups'].keys())}
- 발견된 이상징후: {context['anomalies']}
- 네트워크 복잡도: {context['complexity_indicators']['complexity_score']}
- 사용 기술: {[k for k, v in context['technologies'].items() if v]}

생성할 질문 수: {count}

각 질문은 다음을 포함해야 합니다:
1. 복합적 분석이 필요한 내용
2. 실무 경험과 전문 지식 요구
3. 단순한 팩트 조회를 넘어선 추론
4. {template.answer_type} 형태의 상세한 답변 필요성

**엄격한 규칙: 모든 응답은 반드시 한국어로만 작성해주십시오.**
"""
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
        
        try:
            data = _call_llm_json(
                messages, schema, temperature=0.7,
                model="gpt-4o", max_output_tokens=2000,
                use_responses_api=False
            )
            
            questions = []
            if isinstance(data, dict) and "questions" in data:
                for idx, q_data in enumerate(data["questions"]):
                    question_obj = {
                        "question": q_data["question"],
                        "complexity": template.complexity.value,
                        "persona": template.persona.value,
                        "scenario": template.scenario,
                        "answer_type": template.answer_type,
                        "reasoning_requirement": q_data.get("reasoning_requirement", ""),
                        "expected_analysis_depth": q_data.get("expected_analysis_depth", "detailed"),
                        "metrics_involved": q_data.get("metrics_involved", template.expected_metrics),
                        "test_id": f"ENHANCED-{template.complexity.value.upper()}-{idx+1:03d}",
                        # 심화 파이프라인 구분을 위해 카테고리와 난이도 정보를 추가한다
                        "category": "advanced",
                        "level": 4 if template.complexity in [QuestionComplexity.SYNTHETIC, QuestionComplexity.SCENARIO] else 3,
                        # level과 동일한 값을 가지는 answer_difficulty 필드를 명시적으로 포함한다
                        "answer_difficulty": 4 if template.complexity in [QuestionComplexity.SYNTHETIC, QuestionComplexity.SCENARIO] else 3
                    }
                    questions.append(question_obj)
            
            return questions
            
        except Exception as e:
            print(f"[Enhanced Generator] Failed for {template.scenario}: {e}")
            return []


class QuestionQualityAssessor:
    """생성된 질문의 품질을 다면적으로 평가"""
    
    def assess_question_quality(self, questions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """질문 품질 다면 평가"""
        
        schema = {
            "title": "QuestionQualityAssessment",
            "type": "object",
            "properties": {
                "assessments": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "question_index": {"type": "integer"},
                            "complexity_score": {"type": "integer", "minimum": 1, "maximum": 5},
                            "clarity_score": {"type": "integer", "minimum": 1, "maximum": 5},
                            "practicality_score": {"type": "integer", "minimum": 1, "maximum": 5},
                            "reasoning_depth": {"type": "string", "enum": ["shallow", "moderate", "deep"]},
                            "is_approved": {"type": "boolean"},
                            "improvement_suggestions": {"type": "string"},
                            "estimated_answer_length": {"type": "string", "enum": ["short", "medium", "long"]}
                        },
                        "required": ["question_index", "complexity_score", "clarity_score", "practicality_score", "is_approved"],
                        "additionalProperties": False
                    }
                }
            },
            "required": ["assessments"],
            "additionalProperties": False
        }
        
        system_prompt = """
네트워크 테스트 질문 품질 평가 전문가입니다.
다음 기준으로 각 질문을 평가하세요:

1. 복잡도 (1-5): 단순 조회(1) ~ 복합 분석(5)
2. 명확성 (1-5): 모호함(1) ~ 매우 명확(5)  
3. 실용성 (1-5): 이론적(1) ~ 실무적(5)
4. 추론 깊이: shallow/moderate/deep
5. 승인 여부: 전체 점수 12점 이상 승인

연구용 데이터셋 생성이 목적이므로 높은 기준을 적용하세요.
"""
        
        questions_text = []
        for i, q in enumerate(questions):
            questions_text.append(f"[{i}] {q.get('question', '')}")
        
        user_prompt = f"""
평가할 질문들:
{chr(10).join(questions_text)}

각 질문을 위 기준으로 평가해주세요.
"""
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
        
        try:
            data = _call_llm_json(
                messages, schema, temperature=0.1,
                model="gpt-4o-mini", max_output_tokens=1500,
                use_responses_api=False
            )
            
            if isinstance(data, dict) and "assessments" in data:
                return data["assessments"]
            
        except Exception as e:
            print(f"[Quality Assessor] Failed: {e}")
        
        # 폴백: 모든 질문 통과
        return [{"question_index": i, "complexity_score": 3, "clarity_score": 3, 
                "practicality_score": 3, "is_approved": True} for i in range(len(questions))]
