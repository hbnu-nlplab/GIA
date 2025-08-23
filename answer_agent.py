from typing import Dict, Any, List
import json

from utils.builder_core import BuilderCore

class AnswerAgent:
    """Reasoning plan executor that synthesizes a descriptive answer."""

    def __init__(self, network_facts: Dict[str, Any]):
        self.network_facts = network_facts
        self.builder = BuilderCore(network_facts.get("devices", []))
        self.evidence: Dict[str, Any] = {}

    def execute_plan(self, question: str, plan: List[Dict[str, Any]]) -> str:
        """Execute reasoning steps and return synthesized answer."""
        self.evidence = {}

        for step in sorted(plan, key=lambda x: x.get("step", 0)):
            metric = step.get("required_metric")
            if not metric:
                continue
            try:
                result = self.builder.calculate_metric(metric)
            except Exception as e:
                result = f"error: {e}"
            self.evidence[f"step_{step.get('step')}_{metric}"] = result

        return self._synthesize_answer(question, plan)

    def _synthesize_answer(self, question: str, plan: List[Dict[str, Any]]) -> str:
        """Combine evidence into a narrative answer.

        현재 구현은 간단히 증거 데이터를 JSON 문자열로 반환합니다.
        추후 LLM을 이용해 자연스러운 서술형 답변을 생성할 수 있습니다.
        """
        summary = {
            "question": question,
            "plan": plan,
            "evidence": self.evidence,
        }
        return json.dumps(summary, ensure_ascii=False, indent=2)
