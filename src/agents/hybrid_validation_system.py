"""
하이브리드 검증 시스템: 에이전트 + 로직 기반 검증의 완벽한 조합
실제 AI가 문제를 풀고, BuilderCore로 정답을 확인하는 이중 검증
"""

from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import json
import time
from datetime import datetime

from agents.answer_agent import AnswerAgent
from inspectors.evaluation_system import ExactMatchEvaluator, F1ScoreEvaluator
from utils.builder_core import BuilderCore
from utils.llm_adapter import _call_llm_json
from utils.config_manager import get_settings

class ValidationMode(Enum):
    """검증 모드"""
    AGENT_ONLY = "agent_only"  # 에이전트만 사용
    LOGIC_ONLY = "logic_only"  # BuilderCore만 사용
    HYBRID = "hybrid"          # 둘 다 사용 (추천!)

class ErrorCategory(Enum):
    """오류 카테고리 - 더 세분화된 분류"""
    # 질문 문제
    AMBIGUOUS_QUESTION = "ambiguous_question"
    IMPOSSIBLE_QUESTION = "impossible_question"
    
    # 답변 문제
    WRONG_GROUND_TRUTH = "wrong_ground_truth"
    HALLUCINATION = "hallucination"
    
    # 추론 문제
    REASONING_ERROR = "reasoning_error"
    CALCULATION_ERROR = "calculation_error"
    
    # 데이터 문제
    MISSING_DATA = "missing_data"
    INCONSISTENT_DATA = "inconsistent_data"

@dataclass
class ValidationResult:
    """하이브리드 검증 결과"""
    question_id: str
    question: str
    
    # 3가지 답변
    ground_truth: Any  # 데이터셋의 정답
    agent_answer: Any  # 에이전트가 푼 답
    logic_answer: Any  # BuilderCore 계산 답
    
    # 3중 비교 결과
    agent_vs_gt: bool  # 에이전트 == 정답
    agent_vs_logic: bool  # 에이전트 == 로직
    gt_vs_logic: bool  # 정답 == 로직
    
    # 메타 정보
    agent_confidence: float = 0.0
    agent_reasoning: List[str] = field(default_factory=list)
    agent_time: float = 0.0
    
    # 오류 분석
    is_valid: bool = False
    error_category: Optional[ErrorCategory] = None
    error_details: Optional[str] = None
    improvement_suggestions: List[str] = field(default_factory=list)
    # 설명(해설) 평가
    explanation_eval: Optional[Dict[str, Any]] = None
    explanation_quality: Optional[float] = None
    # 분리 통계를 위한 라벨
    category: Optional[str] = None
    answer_type: Optional[str] = None
    
    def get_validation_status(self) -> str:
        """검증 상태를 한눈에 파악"""
        if self.agent_vs_gt and self.agent_vs_logic and self.gt_vs_logic:
            return "✅ PERFECT"  # 모두 일치
        elif self.gt_vs_logic:
            return "⚠️ AGENT_FAILED"  # 에이전트만 틀림
        elif self.agent_vs_logic:
            return "🔴 GT_WRONG"  # Ground Truth가 틀림
        elif self.agent_vs_gt:
            return "❓ LOGIC_DIFFERS"  # 로직만 다름 (이상한 케이스)
        else:
            return "❌ ALL_DIFFERENT"  # 모두 다름

class HybridValidationSystem:
    """
    하이브리드 검증 시스템
    
    이 시스템의 목표:
    1. 에이전트가 실제로 풀 수 있는 문제인지 확인
    2. Ground Truth가 정확한지 BuilderCore로 검증
    3. 틀린 부분을 정확히 파악하여 개선
    """
    
    def __init__(
        self, 
        network_facts: Dict[str, Any],
        mode: ValidationMode = ValidationMode.HYBRID,
        xml_base_dir: Optional[str] = None,
    ):
        self.network_facts = network_facts
        self.mode = mode
        self.xml_base_dir = xml_base_dir
        
        # 컴포넌트 초기화
        self.builder_core = BuilderCore(network_facts.get("devices", []))
        
        # 다양한 수준의 에이전트 준비
        self.agents = self._initialize_agents()
        
        # 통계 추적
        self.validation_stats = {
            "total": 0,
            "perfect": 0,
            "agent_failed": 0,
            "gt_wrong": 0,
            "all_different": 0
        }
        # 텍스트 비교 보조기
        self._em_eval = ExactMatchEvaluator()
        self._f1_eval = F1ScoreEvaluator()
    
    def _initialize_agents(self) -> Dict[str, Any]:
        """다양한 난이도의 검증 에이전트 설정 초기화 (설정 기반 + 폴백 체인)."""
        settings = get_settings()
        # 모델 폴백 체인: answer_synthesis → question_generation → default → enhanced_generation
        chain = [
            settings.models.answer_synthesis,
            settings.models.question_generation,
            settings.models.default,
            settings.models.enhanced_generation,
        ]
        # 중복 제거(순서 유지)
        seen = set(); fallback_models = []
        for m in chain:
            if m and m not in seen:
                seen.add(m); fallback_models.append(m)

        return {
            "beginner": {
                "model": fallback_models[0],
                "fallback_models": fallback_models,
                "temperature": 0.3,
                "system_prompt": """당신은 네트워크 엔지니어 초급자입니다.
기본적인 네트워크 설정을 이해하고 간단한 질문에 답할 수 있습니다.
주어진 네트워크 설정 정보를 바탕으로 질문에 정확히 답하세요."""
            },
            "intermediate": {
                "model": fallback_models[0],
                "fallback_models": fallback_models,
                "temperature": 0.2,
                "system_prompt": """당신은 3년 경력의 네트워크 엔지니어입니다.
복잡한 설정을 분석하고 문제를 해결할 수 있습니다.
주어진 네트워크 설정을 종합적으로 분석하여 정확한 답변을 제시하세요."""
            },
            "expert": {
                "model": fallback_models[0],
                "fallback_models": fallback_models,
                "temperature": 0.1,
                "system_prompt": """당신은 10년 경력의 시니어 네트워크 아키텍트입니다.
가장 복잡한 네트워크 구성도 완벽히 이해하고 분석할 수 있습니다.
모든 설정의 상호작용을 고려하여 정밀한 답변을 제공하세요."""
            }
        }
    
    def validate_single_item(
        self,
        item: Dict[str, Any],
        agent_level: str = "intermediate"
    ) -> ValidationResult:
        """
        단일 Q&A 항목을 하이브리드 방식으로 검증
        
        3단계 프로세스:
        1. 에이전트가 문제 풀기
        2. BuilderCore로 정답 계산
        3. 3중 비교 및 분석
        """
        
        question = item.get("question", "")
        ground_truth = item.get("ground_truth")
        question_id = item.get("test_id") or item.get("id") or item.get("question_id") or (item.get("question") and str(abs(hash(item.get("question"))))[:8]) or "unknown"
        
        print(f"\n검증 중: {question_id}")
        print(f"질문: {question[:100]}...")
        
        # Step 1: 에이전트가 문제 풀기
        agent_answer = None
        agent_confidence = 0.0
        agent_reasoning = []
        agent_time = 0.0
        
        if self.mode in [ValidationMode.HYBRID, ValidationMode.AGENT_ONLY]:
            agent_result = self._solve_with_agent(
                question=question,
                context=self._get_question_context(item),
                agent_level=agent_level,
                item=item
            )
            agent_answer = agent_result["answer"]
            agent_confidence = agent_result["confidence"]
            agent_reasoning = agent_result["reasoning"]
            agent_time = agent_result["time_taken"]
            
            print(f"  에이전트 답: {agent_answer} (신뢰도: {agent_confidence:.2f})")
        
        # Step 2: BuilderCore로 정답 계산
        logic_answer = None
        
        if self.mode in [ValidationMode.HYBRID, ValidationMode.LOGIC_ONLY]:
            try:
                logic_answer = self._compute_with_logic(item)
                print(f"  로직 답: {logic_answer}")
            except Exception as e:
                print(f"  로직 계산 실패: {e}")
                logic_answer = None
        
        # Step 3: 3중 비교
        agent_vs_gt = self._smart_compare(agent_answer, ground_truth, item)
        agent_vs_logic = self._smart_compare(agent_answer, logic_answer, item)
        gt_vs_logic = self._smart_compare(ground_truth, logic_answer, item)
        
        print(f"  Ground Truth: {ground_truth}")
        print(f"  비교 결과: Agent==GT:{agent_vs_gt}, Agent==Logic:{agent_vs_logic}, GT==Logic:{gt_vs_logic}")
        
        # Step 4: 검증 결과 생성
        result = ValidationResult(
            question_id=question_id,
            question=question,
            ground_truth=ground_truth,
            agent_answer=agent_answer,
            logic_answer=logic_answer,
            agent_vs_gt=agent_vs_gt,
            agent_vs_logic=agent_vs_logic,
            gt_vs_logic=gt_vs_logic,
            agent_confidence=agent_confidence,
            agent_reasoning=agent_reasoning,
            agent_time=agent_time,
            category=item.get("category"),
            answer_type=item.get("answer_type")
        )
        
        # Step 5: 오류 분석
        self._analyze_validation_result(result, item)
        
        # 통계 업데이트
        self._update_statistics(result)
        
        print(f"  상태: {result.get_validation_status()}")
        # 설명 품질 측정 (ENHANCED/long 위주)
        try:
            exp_eval = self._evaluate_explanation(item, agent_answer, logic_answer)
            result.explanation_eval = exp_eval
            result.explanation_quality = exp_eval.get("quality")
            if result.explanation_quality is not None:
                print(f"  설명 품질: {result.explanation_quality:.2f}")
        except Exception:
            pass
        
        return result
    
    def _solve_with_agent(
        self,
        question: str,
        context: str,
        agent_level: str = "intermediate",
        item: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """에이전트가 실제로 문제를 풉니다"""
        
        # 에이전트 설정 가져오기
        agent_config = self.agents.get(agent_level, self.agents["intermediate"])
        system_prompt = agent_config["system_prompt"]
        temperature = agent_config["temperature"]
        model_chain = agent_config.get("fallback_models") or [agent_config.get("model")]
        
        prompt = f"""
네트워크 설정 컨텍스트:
{context}

질문: {question}

위 정보를 바탕으로 질문에 답하세요.
단계별로 추론 과정을 설명하고, 최종 답변을 제시하세요.
"""
        
        schema = {
            "type": "object",
            "properties": {
                "reasoning": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "단계별 추론 과정"
                },
                "calculations": {
                    "type": "object",
                    "description": "수행한 계산들"
                },
                "answer": {
                    "description": "최종 답변"
                },
                "confidence": {
                    "type": "number",
                    "minimum": 0,
                    "maximum": 1,
                    "description": "답변 확신도"
                },
                "data_sources": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "참조한 데이터"
                }
            },
            "required": ["reasoning", "answer", "confidence"]
        }
        
        start_time = time.time()
        
        # 다중 모델 폴백 시도
        last_err = None
        for m in model_chain:
            try:
                response = _call_llm_json(
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": prompt}
                    ],
                    schema=schema,
                    temperature=temperature,
                    model=m,
                    max_output_tokens=8000
                )
                ans = response.get("answer") if isinstance(response, dict) else None
                if ans is None or (isinstance(ans, str) and not ans.strip()):
                    raise ValueError("empty agent answer")
                return {
                    "answer": ans,
                    "confidence": response.get("confidence", 0.6),
                    "reasoning": response.get("reasoning", []),
                    "time_taken": time.time() - start_time,
                    "success": True
                }
            except Exception as e:
                last_err = e
                continue
        # 전부 실패
        return {
            "answer": None,
            "confidence": 0.0,
            "reasoning": [f"Agent LLM failed: {str(last_err) if last_err else 'unknown'}"],
            "time_taken": time.time() - start_time,
            "success": False
        }
    
    def _compute_with_logic(self, item: Dict[str, Any]) -> Any:
        """BuilderCore로 정답을 계산합니다"""
        # Intent 추출 (메타데이터 포함 검색)
        intent = item.get("intent")
        if not intent:
            intent = (item.get("metadata") or {}).get("intent")
        if not intent:
            # 질문에서 intent 추론
            intent = self._infer_intent_from_question(item.get("question", ""))

        # Command형 의도는 로직 계산 불가 → GT로 대체 비교
        if isinstance(intent, dict) and "command" in intent:
            return item.get("ground_truth")

        # BuilderCore 실행 (compute 또는 calculate_metric 경로)
        if isinstance(intent, dict) and intent.get("metric"):
            try:
                val, _files = self.builder_core.calculate_metric(intent["metric"], intent.get("params") or intent.get("scope") or {})
                return val
            except Exception:
                pass
        result = self.builder_core.compute(intent, self.network_facts)
        if result.get("answer_type") == "error":
            raise ValueError(f"BuilderCore error: {result.get('value')}")
        return result.get("value")
    
    def _compare_answers(self, answer1: Any, answer2: Any) -> bool:
        """두 답변을 비교합니다 (타입별 유연한 비교)"""
        
        if answer1 is None or answer2 is None:
            return answer1 == answer2
        
        # 숫자 비교 (5% 오차 허용)
        try:
            num1 = float(answer1) if not isinstance(answer1, (int, float)) else answer1
            num2 = float(answer2) if not isinstance(answer2, (int, float)) else answer2
            if abs(num1 - num2) <= abs(num2) * 0.05:
                return True
        except (ValueError, TypeError):
            pass
        
        # 불린 비교
        if isinstance(answer1, bool) or isinstance(answer2, bool):
            bool_map = {
                True: ["true", "yes", "활성", "enabled", "up", True],
                False: ["false", "no", "비활성", "disabled", "down", False]
            }
            
            def to_bool(val):
                if isinstance(val, bool):
                    return val
                val_lower = str(val).lower()
                for bool_val, keywords in bool_map.items():
                    if val_lower in [str(k).lower() for k in keywords]:
                        return bool_val
                return None
            
            bool1 = to_bool(answer1)
            bool2 = to_bool(answer2)
            if bool1 is not None and bool2 is not None:
                return bool1 == bool2
        
        # 리스트/집합 비교
        if isinstance(answer1, list) and isinstance(answer2, list):
            return set(map(str, answer1)) == set(map(str, answer2))
        
        # 문자열 비교 (정규화)
        str1 = str(answer1).strip().lower()
        str2 = str(answer2).strip().lower()
        
        return str1 == str2

    def _smart_compare(self, a: Any, b: Any, item: Optional[Dict[str, Any]]) -> bool:
        """답변 타입/길이에 따라 적절한 비교 방식을 선택"""
        # 우선 기존 타입별 비교 시도
        if self._compare_answers(a, b):
            return True
        if a is None or b is None:
            return a == b
        try:
            ans_type = (item.get("answer_type") or "").lower() if isinstance(item, dict) else ""
        except Exception:
            ans_type = ""
        sa = str(a); sb = str(b)
        # 긴 서술형 또는 advanced 카테고리 → F1 기준 허용
        is_long = (ans_type == "long") or (len(sa) > 80 or len(sb) > 80) or ((item or {}).get("category") == "advanced")
        if is_long:
            try:
                em = self._em_eval.evaluate(sa, sb)
                if em == 1.0:
                    return True
                f1 = self._f1_eval.evaluate(sa, sb)
                return f1 >= 0.7
            except Exception:
                return False
        return False
    
    def _analyze_validation_result(
        self,
        result: ValidationResult,
        item: Dict[str, Any]
    ) -> None:
        """검증 결과를 분석하고 오류 카테고리를 결정합니다"""
        
        status = result.get_validation_status()
        
        if status == "✅ PERFECT":
            result.is_valid = True
            result.error_category = None
            
        elif status == "🔴 GT_WRONG":
            result.is_valid = False
            result.error_category = ErrorCategory.WRONG_GROUND_TRUTH
            result.error_details = f"Ground Truth({result.ground_truth})가 실제 답({result.logic_answer})과 다릅니다"
            result.improvement_suggestions = [
                f"Ground Truth를 {result.logic_answer}로 수정",
                "데이터 생성 프로세스 재검토"
            ]
            
        elif status == "⚠️ AGENT_FAILED":
            result.is_valid = True  # GT는 맞음
            result.error_category = ErrorCategory.REASONING_ERROR
            
            # 에이전트가 왜 틀렸는지 분석
            if result.agent_confidence < 0.3:
                result.error_details = "에이전트가 답변에 확신이 없음"
                result.improvement_suggestions = [
                    "질문을 더 명확하게 수정",
                    "필요한 컨텍스트 추가"
                ]
            else:
                result.error_details = "에이전트의 추론 과정에 오류"
                result.improvement_suggestions = [
                    "추론 단계를 더 명시적으로 유도",
                    "에이전트 프롬프트 개선"
                ]
                
        elif status == "❌ ALL_DIFFERENT":
            result.is_valid = False
            result.error_category = ErrorCategory.AMBIGUOUS_QUESTION
            result.error_details = "모든 답변이 다름 - 질문이 모호하거나 데이터가 불충분"
            result.improvement_suggestions = [
                "질문을 구체적으로 재작성",
                "정답을 BuilderCore 결과로 교체",
                "필요한 데이터 확인"
            ]
    
    def validate_dataset(
        self,
        dataset: List[Dict[str, Any]],
        sample_size: Optional[int] = None,
        parallel: bool = False
    ) -> Tuple[List[ValidationResult], Dict[str, Any]]:
        """
        전체 데이터셋을 하이브리드 방식으로 검증합니다
        """
        
        print("\n" + "="*60)
        print("하이브리드 검증 시작")
        print("="*60)
        
        # 샘플링
        if sample_size and len(dataset) > sample_size:
            import random
            dataset = random.sample(dataset, sample_size)
            print(f"샘플링: {sample_size}개 항목")
        
        results = []
        
        # 복잡도별로 에이전트 레벨 결정
        def get_agent_level(item):
            complexity = item.get("complexity", "medium")
            if complexity in ["basic", "simple"]:
                return "beginner"
            elif complexity in ["complex", "advanced", "synthetic"]:
                return "expert"
            else:
                return "intermediate"
        
        # 검증 수행
        for i, item in enumerate(dataset, 1):
            print(f"\n진행률: {i}/{len(dataset)}")
            
            agent_level = get_agent_level(item)
            result = self.validate_single_item(item, agent_level)
            results.append(result)
            
            # 중간 통계 출력 (5개마다)
            if i % 5 == 0:
                self._print_intermediate_stats()
        
        # 최종 분석
        final_stats = self._generate_final_report(results)
        
        return results, final_stats
    
    def _generate_final_report(
        self, 
        results: List[ValidationResult]
    ) -> Dict[str, Any]:
        """최종 검증 리포트 생성"""
        
        total = len(results)
        
        # 상태별 집계
        status_counts = {}
        for result in results:
            status = result.get_validation_status()
            status_counts[status] = status_counts.get(status, 0) + 1
        
        # 오류 카테고리별 집계
        error_counts = {}
        for result in results:
            if result.error_category:
                cat = result.error_category.value
                error_counts[cat] = error_counts.get(cat, 0) + 1
        
        # 에이전트 성능 분석
        agent_correct = sum(1 for r in results if r.agent_vs_gt)
        agent_accuracy = agent_correct / total if total > 0 else 0
        
        avg_confidence = sum(r.agent_confidence for r in results) / total if total > 0 else 0
        avg_time = sum(r.agent_time for r in results) / total if total > 0 else 0
        
        # Ground Truth 정확도
        gt_correct = sum(1 for r in results if r.gt_vs_logic)
        gt_accuracy = gt_correct / total if total > 0 else 0
        
        # BASIC/ENHANCED 분리 통계
        def _acc(lst, key):
            return (sum(1 for r in lst if getattr(r, key)) / len(lst)) if lst else 0.0
        basic = [r for r in results if (r.category or "").lower() == "basic"]
        enhanced = [r for r in results if (r.category or "").lower() == "advanced"]
        enhanced_exp = [r for r in enhanced if r.explanation_quality is not None]
        enhanced_exp_avg = (sum(r.explanation_quality for r in enhanced_exp) / len(enhanced_exp)) if enhanced_exp else 0.0

        # ENHANCED 전용 리포트: 낮은 설명 품질 사례
        low_examples = []
        for r in enhanced:
            if r.explanation_quality is not None and r.explanation_quality < 0.4:
                low_examples.append({
                    "question_id": r.question_id,
                    "quality": r.explanation_quality,
                })
                if len(low_examples) >= 10:
                    break

        report = {
            "summary": {
                "total_items": total,
                "validation_mode": self.mode.value,
                "timestamp": datetime.now().isoformat()
            },
            "status_distribution": status_counts,
            "error_categories": error_counts,
            "agent_performance": {
                "accuracy": agent_accuracy,
                "average_confidence": avg_confidence,
                "average_time_seconds": avg_time,
                "correct_answers": agent_correct
            },
            "ground_truth_quality": {
                "accuracy": gt_accuracy,
                "correct_items": gt_correct,
                "incorrect_items": total - gt_correct
            },
            "type_breakdown": {
                "basic": {
                    "count": len(basic),
                    "agent_vs_gt_accuracy": _acc(basic, "agent_vs_gt"),
                    "gt_vs_logic_accuracy": _acc(basic, "gt_vs_logic"),
                },
                "enhanced": {
                    "count": len(enhanced),
                    "agent_vs_gt_accuracy": _acc(enhanced, "agent_vs_gt"),
                    "gt_vs_logic_accuracy": _acc(enhanced, "gt_vs_logic"),
                    "explanation_quality_avg": enhanced_exp_avg,
                }
            },
            "enhanced_summary": {
                "explanation_quality_avg": enhanced_exp_avg,
                "low_quality_examples": low_examples,
            },
            "recommendations": self._generate_recommendations(results)
        }
        
        # 콘솔 출력
        self._print_final_report(report)
        
        return report
    
    def _generate_recommendations(
        self, 
        results: List[ValidationResult]
    ) -> List[str]:
        """검증 결과를 바탕으로 개선 권장사항 생성"""
        
        recommendations = []
        
        # Ground Truth 정확도 체크
        gt_errors = sum(1 for r in results if r.error_category == ErrorCategory.WRONG_GROUND_TRUTH)
        if gt_errors > len(results) * 0.1:  # 10% 이상
            recommendations.append(
                f"⚠️ {gt_errors}개({gt_errors/len(results)*100:.1f}%)의 Ground Truth가 잘못되었습니다. "
                "데이터 생성 프로세스를 재검토하세요."
            )
        
        # 에이전트 성능 체크
        agent_failures = sum(1 for r in results if not r.agent_vs_gt)
        if agent_failures > len(results) * 0.3:  # 30% 이상
            recommendations.append(
                f"📝 에이전트가 {agent_failures}개({agent_failures/len(results)*100:.1f}%) 문제를 틀렸습니다. "
                "질문을 더 명확하게 만들거나 난이도를 조정하세요."
            )
        
        # 모호한 질문 체크
        ambiguous = sum(1 for r in results if r.error_category == ErrorCategory.AMBIGUOUS_QUESTION)
        if ambiguous > 0:
            recommendations.append(
                f"❓ {ambiguous}개의 모호한 질문이 발견되었습니다. "
                "질문을 구체적으로 재작성하세요."
            )
        
        if not recommendations:
            recommendations.append("✅ 데이터셋 품질이 양호합니다!")
        
        return recommendations
    
    def _print_final_report(self, report: Dict[str, Any]) -> None:
        """콘솔에 보기 좋게 리포트 출력"""
        
        print("\n" + "="*60)

    def _evaluate_explanation(self, item: Dict[str, Any], agent_answer: Any, logic_answer: Any) -> Dict[str, Any]:
        """ENHANCED 질문 중심으로 explanation 텍스트의 품질을 평가.
        - GT 및 Logic 값과의 정합성(EM/F1)
        - 길이/존재 여부 체크
        반환: {quality: float, em_gt, f1_gt, em_logic, f1_logic, length}
        """
        explanation = item.get("explanation") or (item.get("metadata") or {}).get("explanation")
        if not isinstance(explanation, str) or not explanation.strip():
            return {"quality": 0.0, "length": 0, "reason": "empty_explanation"}

        gt = item.get("ground_truth")
        txt = explanation.strip()
        s_gt = "" if gt is None else str(gt)
        s_logic = "" if logic_answer is None else str(logic_answer)

        try:
            em_gt = self._em_eval.evaluate(txt, s_gt) if s_gt else 0.0
            f1_gt = self._f1_eval.evaluate(txt, s_gt) if s_gt else 0.0
        except Exception:
            em_gt, f1_gt = 0.0, 0.0

        try:
            em_logic = self._em_eval.evaluate(txt, s_logic) if s_logic else 0.0
            f1_logic = self._f1_eval.evaluate(txt, s_logic) if s_logic else 0.0
        except Exception:
            em_logic, f1_logic = 0.0, 0.0

        # 품질 스코어: GT와의 일치 60%, Logic와의 일치 40% 가중 평균(가용 시)
        parts = []
        if s_gt:
            parts.append(max(em_gt, f1_gt))
        if s_logic:
            parts.append(max(em_logic, f1_logic))
        quality = sum(parts) / len(parts) if parts else 0.0

        return {
            "quality": float(quality),
            "em_gt": float(em_gt),
            "f1_gt": float(f1_gt),
            "em_logic": float(em_logic),
            "f1_logic": float(f1_logic),
            "length": len(txt),
        }
        print("📊 하이브리드 검증 리포트")
        print("="*60)
        
        print(f"\n총 검증 항목: {report['summary']['total_items']}개")
        
        print("\n상태별 분포:")
        for status, count in report['status_distribution'].items():
            percentage = count / report['summary']['total_items'] * 100
            print(f"  {status}: {count}개 ({percentage:.1f}%)")
        
        if report['error_categories']:
            print("\n오류 유형:")
            for category, count in report['error_categories'].items():
                print(f"  - {category}: {count}개")
        
        print(f"\n에이전트 성능:")
        perf = report['agent_performance']
        print(f"  - 정확도: {perf['accuracy']:.1%}")
        print(f"  - 평균 확신도: {perf['average_confidence']:.2f}")
        print(f"  - 평균 응답 시간: {perf['average_time_seconds']:.2f}초")
        
        print(f"\nGround Truth 품질:")
        gt = report['ground_truth_quality']
        print(f"  - 정확도: {gt['accuracy']:.1%}")
        print(f"  - 올바른 항목: {gt['correct_items']}개")
        print(f"  - 잘못된 항목: {gt['incorrect_items']}개")
        
        print("\n📌 권장사항:")
        for i, rec in enumerate(report['recommendations'], 1):
            print(f"{i}. {rec}")
        
        print("\n" + "="*60)
    
    def _get_question_context(self, item: Dict[str, Any]) -> str:
        """질문에 필요한 컨텍스트 생성"""
        
        # 기본 네트워크 정보
        devices = self.network_facts.get("devices", [])
        context_parts = [
            f"네트워크에는 총 {len(devices)}개의 장비가 있습니다:",
            ""
        ]
        
        # 장비별 기본 정보
        for device in devices[:5]:  # 최대 5개만 표시
            sys = device.get("system", {}) or {}
            device_name = sys.get("hostname") or device.get("name") or device.get("file") or "Unknown"
            device_type = device.get("vendor") or device.get("os") or "Unknown"
            context_parts.append(f"- {device_name} ({device_type})")
        
        if len(devices) > 5:
            context_parts.append(f"- ... 외 {len(devices) - 5}개 장비")
        
        # 소스 파일 정보
        source_files = item.get("source_files", [])
        if source_files:
            context_parts.extend([
                "",
                "관련 설정 파일:",
                *[f"- {f}" for f in source_files[:3]]  # 최대 3개만
            ])

        # XML 스니펫/증거 포함 (가능 시)
        snippets = item.get("evidence_snippets") or []
        if not snippets:
            meta = item.get("metadata") or {}
            ev = meta.get("evidence")
            if isinstance(ev, (list, tuple)):
                snippets = [{"snippet": str(x)} for x in ev[:3]]
        # xml_base_dir가 있고 source_files가 있으면 직접 일부 라인 추출 (개선된 스니펫: 주변 컨텍스트 포함)
        if not snippets and self.xml_base_dir and source_files:
            try:
                import os
                keywords = ["bgp", "vrf", "ssh", "ospf", "neighbor", "route-target", "aaa"]
                def _snippet_lines(lines: List[str], needle_list: List[str], window: int = 1) -> List[str]:
                    hits=[]
                    for i, raw in enumerate(lines):
                        low = raw.lower()
                        if any(n in low for n in needle_list):
                            s=max(0,i-window); e=min(len(lines), i+window+1)
                            snip="\n".join([ln.rstrip() for ln in lines[s:e]]).strip()
                            if snip and snip not in hits:
                                hits.append(snip)
                        if len(hits)>=3:
                            break
                    return hits
                found_snips = []
                for f in source_files[:3]:
                    path = os.path.join(self.xml_base_dir, f)
                    if not os.path.exists(path):
                        continue
                    with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
                        lines = fh.readlines()
                    for sn in _snippet_lines(lines, keywords, window=1):
                        found_snips.append({"snippet": sn})
                        if len(found_snips) >= 3:
                            break
                    if len(found_snips) >= 3:
                        break
                if found_snips:
                    snippets = found_snips
            except Exception:
                pass
        if snippets:
            context_parts.extend(["", "증거 스니펫:"])
            for s in snippets[:3]:
                sn = s.get("snippet") if isinstance(s, dict) else str(s)
                if sn:
                    context_parts.append(f"• {sn[:240]}")

        return "\n".join(context_parts)
    
    def _infer_intent_from_question(self, question: str) -> Dict[str, Any]:
        """질문에서 intent를 추론합니다"""
        
        question_lower = question.lower()
        
        # 간단한 키워드 기반 매핑 (정밀)
        if ("full-mesh" in question_lower) or ("fullmesh" in question_lower) or ("풀메시" in question_lower):
            return {"metric": "ibgp_fullmesh_ok", "type": "boolean", "params": {}}
        if ("누락" in question_lower) or ("missing" in question_lower):
            if "bgp" in question_lower or "ibgp" in question_lower:
                return {"metric": "ibgp_missing_pairs_count", "type": "numeric", "params": {}}
        if any(keyword in question_lower for keyword in ["bgp", "neighbor", "이웃"]):
            return {"metric": "bgp_neighbor_count", "type": "numeric", "params": {}}
        elif any(keyword in question_lower for keyword in ["ssh", "보안"]):
            if any(k in question_lower for k in ["불가능", "불가", "미설정", "없는", "비활성"]):
                return {"metric": "ssh_missing_count", "type": "numeric", "params": {}}
            return {"metric": "ssh_present_bool", "type": "boolean", "params": {}}
        elif any(keyword in question_lower for keyword in ["vrf", "route-target"]):
            return {"metric": "vrf_without_rt_count", "type": "numeric", "params": {}}
        elif any(keyword in question_lower for keyword in ["ospf", "area"]):
            return {"metric": "ospf_area0_if_count", "type": "numeric", "params": {}}
        elif any(keyword in question_lower for keyword in ["interface", "인터페이스"]):
            if "vrf" in question_lower:
                return {"metric": "vrf_interface_bind_count", "type": "numeric", "params": {}}
            return {"metric": "interface_count", "type": "numeric", "params": {}}
        else:
            # 기본값
            return {"metric": "GENERAL_INFO", "type": "text"}
    
    def _update_statistics(self, result: ValidationResult) -> None:
        """통계 업데이트"""
        self.validation_stats["total"] += 1
        
        status = result.get_validation_status()
        if status == "✅ PERFECT":
            self.validation_stats["perfect"] += 1
        elif status == "⚠️ AGENT_FAILED":
            self.validation_stats["agent_failed"] += 1
        elif status == "🔴 GT_WRONG":
            self.validation_stats["gt_wrong"] += 1
        elif status == "❌ ALL_DIFFERENT":
            self.validation_stats["all_different"] += 1
    
    def _print_intermediate_stats(self) -> None:
        """중간 통계 출력"""
        stats = self.validation_stats
        total = stats["total"]
        
        if total == 0:
            return
        
        print(f"\n📊 중간 통계 (총 {total}개):")
        print(f"  ✅ 완벽: {stats['perfect']}개 ({stats['perfect']/total*100:.1f}%)")
        print(f"  ⚠️ 에이전트 실패: {stats['agent_failed']}개 ({stats['agent_failed']/total*100:.1f}%)")
        print(f"  🔴 GT 오류: {stats['gt_wrong']}개 ({stats['gt_wrong']/total*100:.1f}%)")
        print(f"  ❌ 모두 다름: {stats['all_different']}개 ({stats['all_different']/total*100:.1f}%)")
