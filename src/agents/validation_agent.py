# src/agents/validation_agent.py

from __future__ import annotations
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import logging

# --- 현재 프로젝트의 모듈 임포트 ---
# utils.builder_core는 네트워크 사실로부터 정답을 계산하는 핵심 로직을 담고 있습니다.
from utils.builder_core import BuilderCore 
# inspectors.intent_inspector는 다양한 데이터 타입의 답변을 비교하는 로직을 제공합니다.
from inspectors.intent_inspector import IntentInspector 

# 로거 설정
logger = logging.getLogger(__name__)

class ErrorType(Enum):
    """검증 과정에서 발견된 오류의 유형을 분류합니다."""
    METRIC_ERROR = "metric_error"          # BuilderCore에서 정답 계산 중 발생한 오류
    WRONG_VALUE = "wrong_value"            # 정답과 값이 일치하지 않음
    HALLUCINATION = "hallucination"        # LLM이 사실이 아닌 내용을 생성함 (WRONG_VALUE의 하위 분류)
    AMBIGUOUS_QUESTION = "ambiguous_question" # 질문의 의도나 대상(scope)이 모호함
    FORMAT_ERROR = "format_error"          # 답변의 데이터 타입이 기대와 다름 (예: list여야 하는데 str)

@dataclass
class ValidationResult:
    """각 질문에 대한 검증 결과를 저장하는 데이터 구조체입니다."""
    original_item: Dict[str, Any] # 피드백 루프에서 원본 질문 정보를 사용하기 위해 추가
    is_correct: bool
    generated_answer: Any
    actual_answer: Any
    error_type: Optional[ErrorType] = None
    error_details: Optional[str] = None

class ValidationAgent:
    """데이터셋의 모든 질문을 직접 풀어보고, 생성된 답변과 비교하여 검증하는 에이전트입니다."""
    
    def __init__(self, network_facts: Dict[str, Any]):
        self.network_facts = network_facts
        self.builder_core = BuilderCore(network_facts.get("devices", []))
        self.intent_inspector = IntentInspector()
        
    def validate_dataset(self, dataset: List[Dict[str, Any]]) -> Tuple[List[ValidationResult], Dict[str, Any]]:
        """데이터셋 전체를 검증하고, 정확도 및 오류 유형 통계를 반환합니다."""
        validation_results = []
        error_counts = {e.value: 0 for e in ErrorType}
        correct_count = 0
        
        for item in dataset:
            result = self._validate_single_item(item)
            validation_results.append(result)
            if result.is_correct:
                correct_count += 1
            else:
                if result.error_type:
                    error_counts[result.error_type.value] += 1
        
        total = len(dataset)
        stats = {
            "total_items": total,
            "correct": correct_count,
            "incorrect": total - correct_count,
            "accuracy": (correct_count / total) if total > 0 else 0,
            "error_types": error_counts
        }
        return validation_results, stats
    
    def _validate_single_item(self, item: Dict[str, Any]) -> ValidationResult:
        """단일 질문-답변 쌍을 검증합니다."""
        question = item.get("question", "")
        generated_answer = item.get("ground_truth")
        
        try:
            actual_answer, _ = self._compute_actual_answer(item)
            is_correct = self.intent_inspector.compare_answers(generated_answer, actual_answer)
            
            if is_correct:
                return ValidationResult(original_item=item, is_correct=True, generated_answer=generated_answer, actual_answer=actual_answer)
            else:
                error_type, details = self._analyze_error(generated_answer, actual_answer)
                return ValidationResult(original_item=item, is_correct=False, generated_answer=generated_answer, actual_answer=actual_answer, error_type=error_type, error_details=details)
                
        except Exception as e:
            logger.warning(f"ID {item.get('id')} 검증 중 오류 발생: {e}")
            return ValidationResult(original_item=item, is_correct=False, generated_answer=generated_answer, actual_answer=None, error_type=ErrorType.METRIC_ERROR, error_details=str(e))

    def _compute_actual_answer(self, item: Dict[str, Any]) -> Tuple[Any, List[str]]:
        """BuilderCore를 사용해 '실제 정답'을 계산합니다."""
        intent = (item.get("metadata", {}) or {}).get("intent")
        if not intent or not intent.get("metric"):
            raise ValueError(f"ID {item.get('id')}에 대한 유효한 intent 또는 metric을 찾을 수 없습니다.")
            
        metric = intent.get("metric")
        params = intent.get("params") or intent.get("scope") or {}
        
        value, files = self.builder_core.calculate_metric(metric, params)
        return value, files

    def _analyze_error(self, generated: Any, actual: Any) -> Tuple[ErrorType, str]:
        """두 답변을 비교하여 오류 유형을 분석합니다."""
        # 이 부분은 향후 LLM을 이용해 더 정교하게 분석할 수 있습니다.
        # 현재는 값 비교를 통해 WRONG_VALUE로 단순화합니다.
        details = f"생성된 값: '{str(generated)[:150]}', 실제 값: '{str(actual)[:150]}'"
        return ErrorType.WRONG_VALUE, details