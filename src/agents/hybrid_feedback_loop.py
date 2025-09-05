"""
하이브리드 피드백 루프: 검증 결과를 바탕으로 데이터셋 개선
에이전트와 로직 검증 결과를 모두 활용하여 최적의 개선안 도출
"""

from typing import Dict, Any, List, Tuple, Optional
from dataclasses import dataclass
import json

from agents.hybrid_validation_system import ValidationResult, ErrorCategory
from utils.llm_adapter import _call_llm_json
from utils.builder_core import BuilderCore

@dataclass
class ImprovementAction:
    """개선 액션"""
    action_type: str  # "fix_answer", "clarify_question", "add_context", "remove"
    original_item: Dict[str, Any]
    improved_item: Optional[Dict[str, Any]]
    reason: str
    confidence: float

class HybridFeedbackLoop:
    """
    하이브리드 검증 결과를 바탕으로 데이터셋을 개선하는 시스템
    """
    
    def __init__(self, network_facts: Dict[str, Any]):
        self.network_facts = network_facts
        self.builder_core = BuilderCore(network_facts.get("devices", []))
        self.improvement_stats = {
            "fixed_answers": 0,
            "clarified_questions": 0,
            "added_context": 0,
            "removed_items": 0
        }
    
    def improve_dataset(
        self,
        validation_results: List[ValidationResult],
        original_dataset: List[Dict[str, Any]]
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        검증 결과를 바탕으로 데이터셋을 개선합니다
        
        개선 전략:
        1. GT_WRONG → 정답을 BuilderCore 값으로 수정
        2. AGENT_FAILED → 질문을 더 명확하게
        3. ALL_DIFFERENT → 전면 재검토
        4. PERFECT → 그대로 유지
        """
        
        print("\n" + "="*60)
        print("🔧 하이브리드 피드백 루프 시작")
        print("="*60)
        
        # 원본 데이터셋 인덱스 구축 (id / test_id 모두 지원)
        try:
            self._original_map = {}
            for it in original_dataset:
                key = it.get("test_id") or it.get("id")
                if key:
                    self._original_map[str(key)] = it
        except Exception:
            self._original_map = {}

        # 결과를 상태별로 분류
        categorized = self._categorize_results(validation_results)
        
        # 개선 액션 생성
        improvement_actions = []
        
        # 1. Ground Truth가 틀린 경우 - 즉시 수정
        if categorized["gt_wrong"]:
            print(f"\n수정 중: {len(categorized['gt_wrong'])}개의 잘못된 정답")
            actions = self._fix_wrong_ground_truths(categorized["gt_wrong"])
            improvement_actions.extend(actions)
        
        # 2. 에이전트만 틀린 경우 - 질문 개선
        if categorized["agent_failed"]:
            print(f"\n개선 중: {len(categorized['agent_failed'])}개의 어려운 질문")
            actions = self._improve_difficult_questions(categorized["agent_failed"])
            improvement_actions.extend(actions)
        
        # 3. 모두 다른 경우 - 전면 재검토
        if categorized["all_different"]:
            print(f"\n재검토 중: {len(categorized['all_different'])}개의 문제 항목")
            actions = self._handle_problematic_items(categorized["all_different"])
            improvement_actions.extend(actions)
        
        # 개선된 데이터셋 생성
        improved_dataset = self._apply_improvements(
            original_dataset,
            improvement_actions
        )
        
        # 개선 통계 (계속)
        improvement_report = {
           "total_improvements": len(improvement_actions),
           "improvement_stats": self.improvement_stats,
           "success_rate": self._calculate_improvement_success_rate(improvement_actions),
           "actions_by_type": self._count_actions_by_type(improvement_actions)
       }
       
        self._print_improvement_report(improvement_report)
       
        return improved_dataset, improvement_report

    def _find_original_item(self, question_id: str) -> Optional[Dict[str, Any]]:
        """검증 결과의 question_id로 원본 항목을 조회"""
        if not hasattr(self, "_original_map"):
            return None
        return self._original_map.get(str(question_id))

    def _mark_for_removal(self, result: ValidationResult) -> Optional[ImprovementAction]:
        """재생성 불가 항목을 제거 대상으로 표시"""
        original_item = self._find_original_item(result.question_id)
        if not original_item:
            return None
        action = ImprovementAction(
            action_type="remove",
            original_item=original_item,
            improved_item=None,
            reason="모호/불가해 항목 제거",
            confidence=0.6,
        )
        self.improvement_stats["removed_items"] += 1
        return action
   
    def _categorize_results(
       self,
       validation_results: List[ValidationResult]
   ) -> Dict[str, List[ValidationResult]]:
       """검증 결과를 상태별로 분류"""
       
       categorized = {
           "perfect": [],
           "gt_wrong": [],
           "agent_failed": [],
           "all_different": [],
           "other": []
       }
       
       for result in validation_results:
           status = result.get_validation_status()
           if status == "✅ PERFECT":
               categorized["perfect"].append(result)
           elif status == "🔴 GT_WRONG":
               categorized["gt_wrong"].append(result)
           elif status == "⚠️ AGENT_FAILED":
               categorized["agent_failed"].append(result)
           elif status == "❌ ALL_DIFFERENT":
               categorized["all_different"].append(result)
           else:
               categorized["other"].append(result)
       
       return categorized
   
    def _fix_wrong_ground_truths(
       self,
       results: List[ValidationResult]
   ) -> List[ImprovementAction]:
       """잘못된 Ground Truth를 BuilderCore 값으로 수정"""
       
       actions = []
       
       for result in results:
           # BuilderCore 값이 정답
           correct_answer = result.logic_answer
           
           if correct_answer is not None:
               # 원본 항목 찾기
               original_item = self._find_original_item(result.question_id)
               
               if original_item:
                   # 개선된 항목 생성
                   improved_item = original_item.copy()
                   improved_item["ground_truth"] = correct_answer
                   improved_item["validation_status"] = "CORRECTED_BY_LOGIC"
                   improved_item["correction_log"] = {
                       "original_answer": result.ground_truth,
                       "corrected_answer": correct_answer,
                       "agent_answer": result.agent_answer,
                       "reason": "BuilderCore 계산값으로 수정"
                   }
                   
                   action = ImprovementAction(
                       action_type="fix_answer",
                       original_item=original_item,
                       improved_item=improved_item,
                       reason=f"Ground Truth 수정: {result.ground_truth} → {correct_answer}",
                       confidence=1.0  # BuilderCore는 100% 신뢰
                   )
                   
                   actions.append(action)
                   self.improvement_stats["fixed_answers"] += 1
       
       return actions
   
    def _improve_difficult_questions(
       self,
       results: List[ValidationResult]
   ) -> List[ImprovementAction]:
       """에이전트가 틀린 질문들을 개선"""
       
       actions = []
       
       for result in results:
           # 에이전트가 왜 틀렸는지 분석
           improvement_needed = self._analyze_agent_failure(result)
           
           if improvement_needed == "clarify":
               action = self._clarify_question(result)
           elif improvement_needed == "add_context":
               action = self._add_context_to_question(result)
           elif improvement_needed == "simplify":
               action = self._simplify_question(result)
           else:
               continue
           
           if action:
               actions.append(action)
       
       return actions
   
    def _analyze_agent_failure(
       self, 
       result: ValidationResult
   ) -> str:
       """에이전트가 실패한 원인 분석"""
       
       # 낮은 확신도 → 질문이 모호함
       if result.agent_confidence < 0.3:
           return "clarify"
       
       # 추론 단계가 너무 복잡 → 단순화 필요
       if len(result.agent_reasoning) > 10:
           return "simplify"
       
       # 컨텍스트 부족 언급 → 정보 추가
       reasoning_text = " ".join(result.agent_reasoning).lower()
       if any(word in reasoning_text for word in ["unclear", "missing", "unknown", "assume"]):
           return "add_context"
       
       return "none"
   
    def _clarify_question(
       self,
       result: ValidationResult
   ) -> Optional[ImprovementAction]:
       """모호한 질문을 명확하게 개선"""
       
       # LLM을 사용하여 질문 개선
       clarification_prompt = f"""
다음 질문을 에이전트가 이해하지 못했습니다.

원본 질문: {result.question}
정답: {result.ground_truth}
에이전트 답변: {result.agent_answer}
에이전트의 혼란: {result.agent_reasoning[:3] if result.agent_reasoning else "추론 실패"}

이 질문을 더 명확하고 구체적으로 다시 작성하세요.
모호한 부분을 제거하고, 정확히 무엇을 묻는지 명시하세요.
"""
       
       schema = {
           "type": "object",
           "properties": {
               "improved_question": {"type": "string"},
               "changes_made": {"type": "array", "items": {"type": "string"}},
               "clarity_score": {"type": "number", "minimum": 0, "maximum": 1}
           },
           "required": ["improved_question", "changes_made"]
       }
       
       try:
           response = _call_llm_json(
               messages=[
                   {"role": "user", "content": clarification_prompt}
               ],
               schema=schema,
               temperature=0.2
           )
           
           original_item = self._find_original_item(result.question_id)
           if original_item and response.get("improved_question"):
               improved_item = original_item.copy()
               improved_item["question"] = response["improved_question"]
               improved_item["improvement_log"] = {
                   "original_question": result.question,
                   "changes": response.get("changes_made", []),
                   "reason": "에이전트 이해도 개선"
               }
               
               action = ImprovementAction(
                   action_type="clarify_question",
                   original_item=original_item,
                   improved_item=improved_item,
                   reason="질문 명확화",
                   confidence=response.get("clarity_score", 0.7)
               )
               
               self.improvement_stats["clarified_questions"] += 1
               return action
               
       except Exception as e:
           print(f"질문 개선 실패: {e}")
       
       return None
   
    def _handle_problematic_items(
       self,
       results: List[ValidationResult]
   ) -> List[ImprovementAction]:
       """모든 답이 다른 문제 항목들 처리"""
       
       actions = []
       
       for result in results:
           # 전면 재생성 시도
           action = self._regenerate_item_completely(result)
           if action:
               actions.append(action)
           else:
               # 재생성 실패 시 제거
               action = self._mark_for_removal(result)
               if action:
                   actions.append(action)
       
       return actions
   
    def _regenerate_item_completely(
        self,
       result: ValidationResult
   ) -> Optional[ImprovementAction]:
       """항목을 완전히 재생성"""
       
       # BuilderCore 답변을 기준으로 새 질문 생성
       if result.logic_answer is None:
           return None
       
       regeneration_prompt = f"""
네트워크 설정에서 답이 "{result.logic_answer}"인 새로운 질문을 생성하세요.

원래 실패한 질문: {result.question}
문제점: 에이전트({result.agent_answer}), 원래 정답({result.ground_truth}), 실제 답({result.logic_answer})이 모두 달랐습니다.

명확하고 구체적인 새 질문을 만들어주세요.
"""
       
       schema = {
           "type": "object",
           "properties": {
               "new_question": {"type": "string"},
               "question_type": {"type": "string"},
               "complexity": {"type": "string", "enum": ["basic", "intermediate", "advanced"]},
               "reasoning": {"type": "string"}
           },
           "required": ["new_question", "complexity"]
       }
       
       try:
           response = _call_llm_json(
               messages=[{"role": "user", "content": regeneration_prompt}],
               schema=schema,
               temperature=0.3
           )
           
           if response.get("new_question"):
               original_item = self._find_original_item(result.question_id)
               if original_item:
                   improved_item = {
                       "test_id": result.question_id,
                       "question": response["new_question"],
                       "ground_truth": result.logic_answer,
                       "complexity": response.get("complexity", "intermediate"),
                       "category": original_item.get("category", "unknown"),
                       "validation_status": "REGENERATED",
                       "regeneration_log": {
                           "original_question": result.question,
                           "reason": "완전 재생성 - 모든 답변 불일치",
                           "logic_answer_used": True
                       }
                   }
                   
                   return ImprovementAction(
                       action_type="regenerate",
                       original_item=original_item,
                       improved_item=improved_item,
                       reason="전면 재생성",
                       confidence=0.8
                   )
                   
       except Exception as e:
           print(f"재생성 실패: {e}")
       
       return None
   
    def _apply_improvements(
       self,
       original_dataset: List[Dict[str, Any]],
       improvement_actions: List[ImprovementAction]
   ) -> List[Dict[str, Any]]:
       """개선 액션을 데이터셋에 적용"""
       
       # ID를 키로 하는 맵 생성
       improvements_map = {}
       for action in improvement_actions:
           if action.improved_item:
               test_id = action.original_item.get("test_id")
               if test_id:
                   improvements_map[test_id] = action.improved_item
       
       # 개선된 데이터셋 생성
       improved_dataset = []
       removed_count = 0
       
       for item in original_dataset:
           test_id = item.get("test_id")
           
           if test_id in improvements_map:
               # 개선된 버전으로 교체
               improved_dataset.append(improvements_map[test_id])
           else:
               # 제거 대상 체크
               should_remove = any(
                   action.action_type == "remove" and 
                   action.original_item.get("test_id") == test_id
                   for action in improvement_actions
               )
               
               if not should_remove:
                   improved_dataset.append(item)
               else:
                   removed_count += 1
       
       print(f"\n개선 완료: {len(improvements_map)}개 수정, {removed_count}개 제거")
       
       return improved_dataset
   
    def _print_improvement_report(self, report: Dict[str, Any]) -> None:
       """개선 리포트 출력"""
       
       print("\n" + "="*60)
       print("📈 개선 결과")
       print("="*60)
       
       print(f"\n총 개선 액션: {report['total_improvements']}개")
       
       stats = report['improvement_stats']
       print("\n개선 유형별 통계:")
       print(f"  - 정답 수정: {stats['fixed_answers']}개")
       print(f"  - 질문 명확화: {stats['clarified_questions']}개")
       print(f"  - 컨텍스트 추가: {stats['added_context']}개")
       print(f"  - 제거된 항목: {stats['removed_items']}개")
       
       if report.get('actions_by_type'):
           print("\n액션 타입별 분포:")
           for action_type, count in report['actions_by_type'].items():
               print(f"  - {action_type}: {count}개")
       
       print(f"\n개선 성공률: {report['success_rate']:.1%}")
       print("="*60)
