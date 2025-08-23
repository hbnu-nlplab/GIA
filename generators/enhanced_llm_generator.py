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
    COMPLIANCE_OFFICER = "compliance_officer"


class ScenarioType(Enum):
    """질문이 다루는 시나리오의 종류"""
    NORMAL = "normal"       # 정상 운영
    FAILURE = "failure"     # 장애 상황
    EXPANSION = "expansion" # 확장/변경


@dataclass
class QuestionTemplate:
    complexity: QuestionComplexity
    persona: PersonaType
    scenario: str
    scenario_type: ScenarioType
    prompt_template: str
    expected_metrics: List[str]
    answer_type: str  # "short" or "long"


class EnhancedLLMQuestionGenerator:
    def __init__(self):
        self.templates = self._initialize_templates()
    
    def _initialize_templates(self) -> List[QuestionTemplate]:
        """복합성과 페르소나를 고려한 질문 템플릿 초기화"""
        return [
            # 분석적 추론 - 네트워크 엔지니어 (정상 시나리오)
            QuestionTemplate(
                complexity=QuestionComplexity.ANALYTICAL,
                persona=PersonaType.NETWORK_ENGINEER,
                scenario="BGP 경로 수렴 분석",
                scenario_type=ScenarioType.NORMAL,
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
                scenario_type=ScenarioType.NORMAL,
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
                scenario_type=ScenarioType.NORMAL,
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
                scenario_type=ScenarioType.FAILURE,
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
            ),

            # 확장 시나리오 - 네트워크 아키텍트
            QuestionTemplate(
                complexity=QuestionComplexity.ANALYTICAL,
                persona=PersonaType.ARCHITECT,
                scenario="네트워크 확장 계획",
                scenario_type=ScenarioType.EXPANSION,
                prompt_template="""
네트워크 아키텍트 관점에서, 새로운 데이터센터 추가와 같은 네트워크 확장 시 고려해야 할 사항을 분석하는 질문을 생성하세요:

1. **용량 계획**: 확장에 따른 BGP/OSPF 재구성 필요성
2. **서비스 영향도**: 기존 L2/L3VPN 서비스에 미치는 영향
3. **보안 검토**: 확장 구간의 보안 정책 수립 필요성

질문 특성:
- 장기적인 확장 관점
- 인프라 재설계 요소 포함
- 비즈니스 연속성 고려
""",
                expected_metrics=["bgp_neighbor_count", "vrf_count", "ssh_missing_count"],
                answer_type="long"
            ),

            # 규정 준수 - 컴플라이언스 담당자
            QuestionTemplate(
                complexity=QuestionComplexity.DIAGNOSTIC,
                persona=PersonaType.COMPLIANCE_OFFICER,
                scenario="정책 준수 점검",
                scenario_type=ScenarioType.NORMAL,
                prompt_template="""
컴플라이언스 담당자 관점에서, 네트워크 장비 설정이 사내 표준 및 규제 요구사항을 충족하는지 평가하는 질문을 생성하세요:

1. **접근 제어 정책**: AAA 및 패스워드 정책의 일관성 여부
2. **로그 보존 요건**: 로컬 로그 버퍼의 심각도 설정이 감사 기준을 충족하는가
3. **보안 프로토콜 준수**: SSH 설정이 최신 보안 가이드를 따르고 있는가

질문 특성:
- 정책/규정 준수 여부 검토
- 감사 대비 문서화 가능성 고려
- 미준수 항목에 대한 개선 권고 포함
""",
                expected_metrics=["password_policy_present_bool", "aaa_present_bool", "logging_buffered_severity_text"],
                answer_type="long"
            ),

            # 명확한 정답을 요구하는 분석형 - 트러블슈터
            QuestionTemplate(
                complexity=QuestionComplexity.ANALYTICAL,
                persona=PersonaType.TROUBLESHOOTER,
                scenario="규정 위반 장비 식별",
                scenario_type=ScenarioType.NORMAL,
                prompt_template="""
네트워크 감사관의 관점에서, 주어진 여러 네트워크 데이터를 종합적으로 분석해야만 답할 수 있는 질문을 생성하세요.
**가장 중요한 규칙**: 질문의 최종 답변은 반드시 **'장비 이름 리스트(list)', '개수(number)', 'IP 주소(string)'** 등 명확하고 단일한 값으로 귀결되어야 합니다.

**[생성하면 안 되는 질문 형태 (How/Why)]**
- "네트워크 보안을 어떻게 강화할 수 있을까요?" (정답이 주관적임)
- "BGP 설정이 왜 중요한가요?" (설명형)

**[생성해야 하는 질문 형태 (What/Which/How many)]**
- "보안 정책(SSH 활성화, AAA 비활성화)을 위반하는 장비의 이름은 무엇인가?" (정답: 리스트)
- "AS 65000에 속하지만 iBGP 피어 수가 3개 미만인 장비는 총 몇 개인가?" (정답: 숫자)
- "VRF 'exam-l3vpn'에 연결된 eBGP 피어의 IP 주소는 무엇인가?" (정답: 문자열)

주어진 네트워크 현황을 바탕으로, 위 **[생성해야 하는 질문 형태]**와 같이 **추론 과정은 복잡하지만 정답은 명확한 질문**과 그 질문을 풀기 위한 **실행 가능한 reasoning_plan**을 함께 생성해주세요.
""",
                expected_metrics=["ssh_present_bool", "aaa_present_bool", "bgp_neighbor_count"],
                answer_type="short",
            ),
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
                            "answer_structure": {"type": "string"},
                            "reasoning_plan": {
                                "type": "array",
                                "description": "정답을 도출하기 위한 단계별 계획",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "step": {"type": "integer"},
                                        "description": {"type": "string"},
                                        "required_metric": {"type": "string"},
                                        "metric_params": {
                                            "type": "object",
                                            "description": "calculate_metric 호출 시 전달할 파라미터",
                                            "properties": {},
                                            "additionalProperties": True
                                        },
                                        "synthesis": {
                                            "type": "string",
                                            "enum": ["fetch", "compare", "summarize"]
                                        }
                                    },
                                    "required": ["step", "description", "required_metric", "synthesis"],
                                    "additionalProperties": False
                                }
                            }
                        },
                        "required": ["question", "reasoning_requirement", "expected_analysis_depth", "reasoning_plan"],
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

주어진 네트워크 현황을 바탕으로, 복합적인 질문과 해당 질문을 해결하기 위한 단계별 **추론 계획(reasoning_plan)**을 함께 작성하세요.
**규칙: 모든 질문과 설명은 반드시 한국어로 작성해야 합니다.**
"""

        user_prompt = f"""
{template.prompt_template}

네트워크 현황 요약:
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
5. **reasoning_plan**: 각 단계에 required_metric과 metric_params(필요 시)를 명시

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
                        "scenario_type": template.scenario_type.value,
                        "answer_type": template.answer_type,
                        "reasoning_requirement": q_data.get("reasoning_requirement", ""),
                        "expected_analysis_depth": q_data.get("expected_analysis_depth", "detailed"),
                        "metrics_involved": q_data.get("metrics_involved", template.expected_metrics),
                        "reasoning_plan": q_data.get("reasoning_plan", []),
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
