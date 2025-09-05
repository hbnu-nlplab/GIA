from __future__ import annotations
from typing import Dict, Any, List, Optional, Tuple
import logging
from dataclasses import dataclass, field, asdict

from agents.validation_agent import ValidationResult, ErrorType
# utils.llm_adapter와 utils.builder_core 임포트를 추가합니다.
from utils.llm_adapter import _call_llm_json, get_settings
from utils.builder_core import BuilderCore

logger = logging.getLogger(__name__)

@dataclass
class RegenerationRequest:
    """재생성 요청 데이터"""
    original_item: Dict[str, Any]
    validation_result: ValidationResult

class FeedbackLoop:
    """피드백 기반 질문/답변 재생성 시스템"""
    
    def __init__(self, network_facts: Dict[str, Any]):
        """
        클래스 생성 시 network_facts를 인수로 받아 초기화합니다.
        """
        self.network_facts = network_facts
        self.builder_core = BuilderCore(network_facts.get("devices", []))
        
    def regenerate_failed_items(
        self, 
        validation_results: List[ValidationResult],
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """검증에 실패한 모든 항목에 대해 교정을 시도합니다."""
        
        # ValidationResult에 원본 item이 포함되어 있다고 가정
        failed_requests = [
            RegenerationRequest(
                original_item=res.original_item,
                validation_result=res
            ) for res in validation_results if not res.is_correct
        ]
        
        if not failed_requests:
            return [], {"message": "모든 항목이 검증을 통과했습니다.", "regenerated_and_corrected": 0}
        
        logger.info(f"자동 교정 대상: {len(failed_requests)}개 항목")
        
        regenerated_items = []
        for req in failed_requests:
            new_item = self._regenerate_by_error_type(req)
            if new_item:
                regenerated_items.append(new_item)

        stats = {
            "total_failed": len(failed_requests),
            "regenerated_and_corrected": len(regenerated_items)
        }
        return regenerated_items, stats

    def _regenerate_by_error_type(self, req: RegenerationRequest) -> Optional[Dict[str, Any]]:
        """오류 유형에 따라 다른 교정 전략을 적용합니다."""
        error_type = req.validation_result.error_type
        
        if error_type == ErrorType.WRONG_VALUE or error_type == ErrorType.HALLUCINATION:
            return self._fix_answer(req)
        
        # 추후 다른 오류 유형에 대한 처리 추가 가능
        else:
            logger.warning(f"'{error_type.value if error_type else 'N/A'}' 유형에 대한 자동 수정 전략이 없어 건너뜁니다: ID {req.original_item.get('id')}")
            return None
            
    def _fix_answer(self, req: RegenerationRequest) -> Dict[str, Any]:
        """답변을 실제 계산된 값(actual_answer)으로 교정합니다."""
        fixed_item = req.original_item.copy()
        
        original_answer = req.validation_result.generated_answer
        correct_answer = req.validation_result.actual_answer
        
        fixed_item["ground_truth"] = correct_answer
        
        if "metadata" not in fixed_item:
            fixed_item["metadata"] = {}
        fixed_item["metadata"]["correction_log"] = {
            "status": "CORRECTED",
            "error_type": req.validation_result.error_type.value if req.validation_result.error_type else "unknown",
            "original_answer": str(original_answer),
            "corrected_answer": str(correct_answer),
            "correction_method": "Replaced with BuilderCore computed value"
        }
        logger.info(f"ID {fixed_item.get('id')}의 답변을 교정했습니다.")
        return fixed_item