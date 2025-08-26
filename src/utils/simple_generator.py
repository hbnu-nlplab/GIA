# -*- coding: utf-8 -*-
"""
Simplified Network Question Generator
- Rule-based 기본 생성 + LLM 보강
- 단순화된 스키마
- 통합된 검토 Agent
"""

from __future__ import annotations
from typing import Dict, Any, List, Optional
import json
from dataclasses import dataclass

from utils.config_manager import get_settings
from .llm_adapter import _call_llm_json


settings = get_settings()


@dataclass
class SimpleQuestion:
    """단순화된 질문 스키마"""
    question: str
    expected_answer: str
    category: str
    test_id: str
    answer_type: str = "text"  # text, numeric, boolean, list
    level: int = 2
    source_files: List[str] = None
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "question": self.question,
            "expected_answer": self.expected_answer,
            "category": self.category,
            "test_id": self.test_id,
            "answer_type": self.answer_type,
            "level": self.level,
            "notes": self.notes
        }
        if self.source_files:
            result["source_files"] = self.source_files
        return result


class RuleBasedQuestionGenerator:
    """규칙 기반 질문 생성기"""
    
    def __init__(self):
        self.templates = {
            "BGP_Consistency": [
                ("AS {asn}의 iBGP 피어 수는?", "neighbor_count"),
                ("{host} 장비의 BGP Local-AS 번호는?", "local_as"),
                ("AS {asn}에서 iBGP 피어 누락이 있는가?", "missing_pairs_check"),
            ],
            "VRF_Consistency": [
                ("{host}의 VRF 개수는?", "vrf_count"),
                ("Route-Target이 없는 VRF가 있는가?", "vrf_without_rt_check"),
                ("{host}의 VRF {vrf} route-target 목록은?", "vrf_rt_list"),
            ],
            "Security_Policy": [
                ("SSH가 비활성화된 장비 수는?", "ssh_missing_count"),
                ("{host} 장비에서 SSH가 활성화되어 있는가?", "ssh_enabled_check"),
                ("모든 장비에 SSH가 설정되어 있는가?", "ssh_all_enabled_check"),
            ],
            "L2VPN_Consistency": [
                ("L2VPN 단방향 세션 수는?", "l2vpn_unidir_count"),
                ("PW-ID 불일치 L2VPN 회선이 있는가?", "l2vpn_mismatch_check"),
                ("구성된 L2VPN 회선 수는?", "l2vpn_total_count"),
            ],
            "OSPF_Consistency": [
                ("{host}의 OSPF 프로세스 ID는?", "ospf_process_id"),
                ("{host}의 OSPF Area 0 인터페이스 수는?", "ospf_area0_if_count"),
                ("모든 PE 라우터가 OSPF에 참여하고 있는가?", "ospf_participation_check"),
            ]
        }

    def generate(self, network_facts: Dict[str, Any], categories: List[str]) -> List[SimpleQuestion]:
        """규칙 기반 질문 생성"""
        questions = []
        
        for category in categories:
            if category not in self.templates:
                continue
                
            templates = self.templates[category]
            category_questions = self._generate_for_category(
                network_facts, category, templates
            )
            questions.extend(category_questions)
        
        return questions

    def _generate_for_category(
        self, 
        facts: Dict[str, Any], 
        category: str, 
        templates: List[tuple]
    ) -> List[SimpleQuestion]:
        """카테고리별 질문 생성"""
        questions = []
        devices = facts.get("devices", [])
        
        for idx, (template, metric_type) in enumerate(templates):
            test_id = f"{category.upper()}-RULE-{idx+1:03d}"
            
            if "{host}" in template or "{asn}" in template or "{vrf}" in template:
                # 장비별 질문
                for device in devices[:3]:  # 최대 3개 장비
                    host = device.get("system", {}).get("hostname", "unknown")
                    
                    # 템플릿 변수 준비
                    format_vars = {
                        "host": host,
                        "asn": device.get("bgp", {}).get("as_number", "unknown"),
                        "vrf": "default"  # 기본값
                    }
                    
                    # VRF가 있는 경우 첫 번째 VRF 사용
                    vrfs = device.get("vrfs", {})
                    if vrfs:
                        format_vars["vrf"] = list(vrfs.keys())[0]
                    
                    try:
                        question = template.format(**format_vars)
                        answer = self._calculate_answer(device, metric_type)
                    except KeyError as e:
                        print(f"[WARNING] Template format error: {e}, skipping question")
                        continue
                    
                    questions.append(SimpleQuestion(
                        question=question,
                        expected_answer=str(answer),
                        category=category,
                        test_id=f"{test_id}-{host}",
                        answer_type=self._get_answer_type(metric_type),
                        source_files=[device.get("file", "")],
                        notes=f"Rule-based generation for {host}"
                    ))
            
            elif "{asn}" in template:
                # AS별 질문
                as_numbers = self._extract_as_numbers(facts)
                for asn in as_numbers[:2]:  # 최대 2개 AS
                    question = template.format(asn=asn)
                    answer = self._calculate_as_answer(facts, asn, metric_type)
                    
                    questions.append(SimpleQuestion(
                        question=question,
                        expected_answer=str(answer),
                        category=category,
                        test_id=f"{test_id}-AS{asn}",
                        answer_type=self._get_answer_type(metric_type),
                        notes=f"Rule-based generation for AS {asn}"
                    ))
            
            else:
                # 전체 네트워크 질문
                answer = self._calculate_global_answer(facts, metric_type)
                
                questions.append(SimpleQuestion(
                    question=template,
                    expected_answer=str(answer),
                    category=category,
                    test_id=test_id,
                    answer_type=self._get_answer_type(metric_type),
                    notes="Rule-based global question"
                ))
        
        return questions

    def _calculate_answer(self, device: Dict[str, Any], metric_type: str) -> Any:
        """장비별 답변 계산"""
        if metric_type == "neighbor_count":
            neighbors = device.get("routing", {}).get("bgp", {}).get("neighbors", [])
            return len(neighbors)
        elif metric_type == "local_as":
            return device.get("routing", {}).get("bgp", {}).get("local_as", "unknown")
        elif metric_type == "vrf_count":
            vrfs = device.get("services", {}).get("vrf", [])
            return len(vrfs)
        elif metric_type == "ssh_enabled_check":
            ssh_present = device.get("security", {}).get("ssh", {}).get("present", False)
            return "yes" if ssh_present else "no"
        elif metric_type == "ospf_process_id":
            ospf = device.get("routing", {}).get("ospf", {})
            return ospf.get("process_id", "not_configured")
        elif metric_type == "ospf_area0_if_count":
            # 간단화: OSPF 설정이 있으면 1, 없으면 0
            ospf = device.get("routing", {}).get("ospf", {})
            return 1 if ospf else 0
        else:
            return "unknown"

    def _calculate_as_answer(self, facts: Dict[str, Any], asn: str, metric_type: str) -> Any:
        """AS별 답변 계산"""
        devices = facts.get("devices", [])
        as_devices = [d for d in devices if d.get("routing", {}).get("bgp", {}).get("local_as") == asn]
        
        if metric_type == "missing_pairs_check":
            # 간단화: 장비 수가 2개 이상이면 iBGP 피어링 확인
            if len(as_devices) >= 2:
                return "possible"  # 실제로는 더 복잡한 계산 필요
            else:
                return "no"
        else:
            return len(as_devices)

    def _calculate_global_answer(self, facts: Dict[str, Any], metric_type: str) -> Any:
        """전체 네트워크 답변 계산"""
        devices = facts.get("devices", [])
        
        if metric_type == "ssh_missing_count":
            missing = 0
            for device in devices:
                ssh_present = device.get("security", {}).get("ssh", {}).get("present", False)
                if not ssh_present:
                    missing += 1
            return missing
        elif metric_type == "ssh_all_enabled_check":
            all_enabled = all(
                device.get("security", {}).get("ssh", {}).get("present", False)
                for device in devices
            )
            return "yes" if all_enabled else "no"
        elif metric_type == "l2vpn_unidir_count":
            # 간단화: L2VPN 설정 개수 반환
            total = 0
            for device in devices:
                l2vpns = device.get("services", {}).get("l2vpn", [])
                total += len(l2vpns)
            return total // 2  # 단방향으로 가정
        elif metric_type == "l2vpn_mismatch_check":
            return "no"  # 간단화
        elif metric_type == "l2vpn_total_count":
            total = 0
            for device in devices:
                l2vpns = device.get("services", {}).get("l2vpn", [])
                total += len(l2vpns)
            return total
        elif metric_type == "ospf_participation_check":
            pe_devices = [d for d in devices if "sample" in d.get("file", "").lower()]
            participating = sum(1 for d in pe_devices if d.get("routing", {}).get("ospf"))
            return "yes" if participating == len(pe_devices) else "no"
        else:
            return 0

    def _extract_as_numbers(self, facts: Dict[str, Any]) -> List[str]:
        """AS 번호 추출"""
        as_numbers = set()
        for device in facts.get("devices", []):
            local_as = device.get("routing", {}).get("bgp", {}).get("local_as")
            if local_as:
                as_numbers.add(str(local_as))
        return list(as_numbers)

    def _get_answer_type(self, metric_type: str) -> str:
        """답변 타입 결정"""
        if metric_type.endswith("_count"):
            return "numeric"
        elif metric_type.endswith("_check"):
            return "boolean"
        elif metric_type.endswith("_list"):
            return "list"
        else:
            return "text"


class LLMQuestionEnhancer:
    """LLM 기반 질문 보강"""
    
    def enhance_questions(
        self, 
        base_questions: List[SimpleQuestion], 
        network_facts: Dict[str, Any],
        enhancement_count: int = 2
    ) -> List[SimpleQuestion]:
        """기본 질문을 LLM으로 보강"""
        if not settings.api.api_key:
            print("[LLM Enhancer] OPENAI_API_KEY not set, skipping enhancement")
            return []
        
        enhanced = []
        
        # 카테고리별로 그룹화
        by_category = {}
        for q in base_questions:
            by_category.setdefault(q.category, []).append(q)
        
        for category, questions in by_category.items():
            enhanced_for_category = self._enhance_category(
                category, questions[:3], network_facts, enhancement_count
            )
            enhanced.extend(enhanced_for_category)
        
        return enhanced

    def _enhance_category(
        self,
        category: str,
        sample_questions: List[SimpleQuestion],
        network_facts: Dict[str, Any],
        count: int
    ) -> List[SimpleQuestion]:
        """카테고리별 LLM 보강"""
        
        schema = {
            "title": "EnhancedQuestions",
            "type": "object",
            "properties": {
                "questions": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "question": {"type": "string"},
                            "expected_answer": {"type": "string"},
                            "answer_type": {"type": "string", "enum": ["text", "numeric", "boolean", "list"]},
                            "notes": {"type": "string"}
                        },
                        "required": ["question", "expected_answer", "answer_type"],
                        "additionalProperties": False
                    },
                    "maxItems": count
                }
            },
            "required": ["questions"],
            "additionalProperties": False
        }

        # 샘플 질문들 요약
        sample_summary = []
        for q in sample_questions:
            sample_summary.append({
                "question": q.question,
                "expected_answer": q.expected_answer,
                "answer_type": q.answer_type
            })

        system_msg = f"""당신은 네트워크 테스트 질문 생성 전문가입니다.
주어진 {category} 카테고리의 샘플 질문들을 참고하여, 유사하지만 다른 관점의 새로운 질문을 생성하세요.

규칙:
1. 기존 질문과 중복되지 않게 하세요
2. 네트워크 현황 데이터를 기반으로 답변 가능한 질문만 생성하세요  
3. 질문은 한국어로, 명확하고 구체적으로 작성하세요
4. expected_answer는 실제 계산 가능한 값으로 설정하세요

응답은 JSON 형식으로 제공해주세요."""

        user_msg = json.dumps({
            "category": category,
            "sample_questions": sample_summary,
            "network_summary": self._summarize_network(network_facts),
            "target_count": count
        }, ensure_ascii=False, indent=2)

        messages = [
            {"role": "system", "content": system_msg},
            {"role": "user", "content": user_msg}
        ]

        try:
            data = _call_llm_json(
                messages, schema, temperature=0.7,
                model=settings.models.question_generation, max_output_tokens=1200,
                use_responses_api=False
            )
            
            print(f"[DEBUG] LLM response data for {category}: {data}")
            
            enhanced_questions = []
            if isinstance(data, dict):
                # 여러 가능한 키 이름 확인
                questions_data = data.get("questions") or data.get("new_questions") or []
                print(f"[DEBUG] Found {len(questions_data)} questions in response")
                
                for idx, q_data in enumerate(questions_data):
                    enhanced_question = SimpleQuestion(
                        question=q_data["question"],
                        expected_answer=q_data["expected_answer"],
                        category=category,
                        test_id=f"{category.upper()}-LLM-{idx+1:03d}",
                        answer_type=q_data.get("answer_type", "text"),
                        level=2,
                        notes=f"LLM enhanced: {q_data.get('notes', '')}"
                    )
                    print(f"[DEBUG] Created LLM question: {enhanced_question.test_id} - {enhanced_question.question}")
                    enhanced_questions.append(enhanced_question)
            else:
                print(f"[DEBUG] No questions found in LLM response. Data type: {type(data)}, keys: {list(data.keys()) if isinstance(data, dict) else 'N/A'}")
            
            print(f"[LLM Enhancer] Generated {len(enhanced_questions)} questions for {category}")
            return enhanced_questions
            
        except Exception as e:
            print(f"[LLM Enhancer] Failed for {category}: {e}")
            return []

    def _summarize_network(self, facts: Dict[str, Any]) -> Dict[str, Any]:
        """네트워크 현황 요약"""
        devices = facts.get("devices", [])
        device_count = len(devices)
        
        # AS 번호 추출
        as_numbers = set()
        ssh_enabled = 0
        ospf_enabled = 0
        
        for device in devices:
            # AS 번호
            local_as = device.get("routing", {}).get("bgp", {}).get("local_as")
            if local_as:
                as_numbers.add(str(local_as))
            
            # SSH 상태
            if device.get("security", {}).get("ssh", {}).get("present"):
                ssh_enabled += 1
            
            # OSPF 상태  
            if device.get("routing", {}).get("ospf"):
                ospf_enabled += 1
        
        return {
            "device_count": device_count,
            "as_numbers": list(as_numbers),
            "ssh_enabled_count": ssh_enabled,
            "ospf_enabled_count": ospf_enabled
        }


class QuestionReviewer:
    """질문 검토 Agent"""
    
    def review_questions(self, questions: List[SimpleQuestion]) -> List[SimpleQuestion]:
        """질문들을 검토하고 필터링"""
        if not questions:
            return []
        
        # 1단계: 휴리스틱 검토
        heuristic_passed = self._heuristic_review(questions)
        print(f"[Reviewer] Heuristic: {len(heuristic_passed)}/{len(questions)} passed")
        
        # 2단계: LLM 검토 (임시 비활성화)
        # TODO: LLM 검토 로직 안정화 후 재활성화
        if False and settings.api.api_key and len(heuristic_passed) > 0:
            llm_passed = self._llm_review(heuristic_passed)
            print(f"[Reviewer] LLM: {len(llm_passed)}/{len(heuristic_passed)} passed")
            return llm_passed
        else:
            return heuristic_passed

    def _heuristic_review(self, questions: List[SimpleQuestion]) -> List[SimpleQuestion]:
        """휴리스틱 기반 검토"""
        passed = []
        
        for q in questions:
            # 기본 품질 체크
            if len(q.question.strip()) < 10:
                continue
            if len(q.question) > 200:
                continue
            if not q.expected_answer.strip():
                continue
            
            # 금지 패턴 체크
            question_lower = q.question.lower()
            forbidden_patterns = [
                "어떻게", "무엇을", "왜", "설명하시오", "방법은"
            ]
            
            if any(pattern in question_lower for pattern in forbidden_patterns):
                continue
            
            # 필수 패턴 체크 (측정 가능한 질문)
            required_patterns = [
                "개수", "수는", "있는가", "되어 있는가", "몇", "목록", "번호"
            ]
            
            if any(pattern in question_lower for pattern in required_patterns):
                passed.append(q)
        
        return passed

    def _llm_review(self, questions: List[SimpleQuestion]) -> List[SimpleQuestion]:
        """LLM 기반 검토"""
        if len(questions) > 10:
            # 너무 많으면 샘플링
            questions = questions[:10]
        
        schema = {
            "title": "QuestionReview",
            "type": "object",
            "properties": {
                "reviews": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "index": {"type": "integer"},
                            "score": {"type": "integer", "minimum": 0, "maximum": 10},
                            "is_approved": {"type": "boolean"},
                            "reason": {"type": "string"}
                        },
                        "required": ["index", "score", "is_approved"],
                        "additionalProperties": False
                    }
                }
            },
            "required": ["reviews"],
            "additionalProperties": False
        }

        questions_data = []
        for i, q in enumerate(questions):
            questions_data.append({
                "index": i,
                "question": q.question,
                "expected_answer": q.expected_answer,
                "category": q.category
            })

        system_msg = """네트워크 테스트 질문 품질 평가자입니다.
각 질문을 다음 기준으로 평가하세요:

평가 기준:
1. 명확성 (3점): 질문이 명확하고 이해하기 쉬운가?
2. 측정가능성 (3점): 답변이 객관적으로 측정/확인 가능한가?
3. 실용성 (2점): 네트워크 운영/진단에 실제 도움이 되는가?
4. 정확성 (2점): 예상 답변이 질문과 일치하는가?

총 10점 만점, 7점 이상만 승인하세요. 응답은 JSON 형식으로 제공해주세요."""

        user_msg = json.dumps({
            "questions": questions_data
        }, ensure_ascii=False, indent=2)

        messages = [
            {"role": "system", "content": system_msg},
            {"role": "user", "content": user_msg}
        ]

        try:
            data = _call_llm_json(
                messages, schema, temperature=0.1,
                model=settings.models.hypothesis_review, max_output_tokens=1500,
                use_responses_api=False
            )
            
            approved_indices = set()
            if isinstance(data, dict):
                # 여러 가능한 키 이름 확인
                reviews_data = data.get("reviews") or data.get("evaluations") or []
                print(f"[DEBUG] Found {len(reviews_data)} reviews in response")
                print(f"[DEBUG] Sample review: {reviews_data[0] if reviews_data else 'None'}")
                
                for review in reviews_data:
                    score = review.get("score", 0) or review.get("total_score", 0)
                    approved = review.get("is_approved", False) 
                    index = review.get("index", -1)
                    
                    # total_score가 없으면 개별 점수들을 합산
                    if score == 0 and any(k in review for k in ["clarity", "measurability", "practicality", "accuracy"]):
                        score = (review.get("clarity", 0) + 
                                review.get("measurability", 0) + 
                                review.get("practicality", 0) + 
                                review.get("accuracy", 0))
                    
                    if approved or score >= 5:  # 기준: 5점 이상
                        approved_indices.add(index)
                        print(f"[DEBUG] Approved question {index} with score {score}, approved={approved}")
                    else:
                        print(f"[DEBUG] Rejected question {index} with score {score}, approved={approved}")
            else:
                print(f"[DEBUG] Invalid review response format. Data type: {type(data)}")
            
            print(f"[DEBUG] Total approved indices: {approved_indices}")
            return [q for i, q in enumerate(questions) if i in approved_indices]
            
        except Exception as e:
            print(f"[Reviewer] LLM review failed: {e}")
            return questions  # LLM 실패시 원본 반환


class SimpleNetworkQuestionGenerator:
    """통합된 단순화 질문 생성기"""
    
    def __init__(self):
        self.rule_generator = RuleBasedQuestionGenerator()
        self.llm_enhancer = LLMQuestionEnhancer()
        self.reviewer = QuestionReviewer()
    
    def generate(
        self, 
        network_facts: Dict[str, Any], 
        categories: List[str],
        enhance_with_llm: bool = True,
        llm_enhancement_count: int = 2
    ) -> Dict[str, List[Dict[str, Any]]]:
        """질문 생성 메인 함수"""
        
        print(f"[SimpleGen] Starting generation for {categories}")
        
        # 1단계: Rule-based 기본 생성
        rule_questions = self.rule_generator.generate(network_facts, categories)
        print(f"[SimpleGen] Rule-based generated: {len(rule_questions)} questions")
        
        # 2단계: LLM 보강 (선택적)
        enhanced_questions = []
        if enhance_with_llm and rule_questions:
            enhanced_questions = self.llm_enhancer.enhance_questions(
                rule_questions, network_facts, llm_enhancement_count
            )
            print(f"[SimpleGen] LLM enhanced: {len(enhanced_questions)} questions")
        
        # 3단계: 통합 및 검토
        all_questions = rule_questions + enhanced_questions
        reviewed_questions = self.reviewer.review_questions(all_questions)
        print(f"[SimpleGen] After review: {len(reviewed_questions)} questions")
        
        # 4단계: 카테고리별 그룹화
        result = {}
        for question in reviewed_questions:
            category = question.category
            if category not in result:
                result[category] = []
            result[category].append(question.to_dict())
        
        return result
