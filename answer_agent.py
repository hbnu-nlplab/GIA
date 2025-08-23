from typing import Dict, Any, List, Union
import json

from utils.builder_core import BuilderCore
from utils.llm_adapter import _call_llm_json

class AnswerAgent:
    """Reasoning plan executor that synthesizes a descriptive answer."""

    def __init__(self, network_facts: Dict[str, Any]):
        self.network_facts = network_facts
        self.builder = BuilderCore(network_facts.get("devices", []))
        self.evidence: Dict[str, Any] = {}

    def execute_plan(self, question: str, plan: Union[List[Dict[str, Any]], str]) -> str:
        """Execute reasoning steps and return synthesized answer."""
        self.evidence = {}

        # Handle string-based plans
        if isinstance(plan, str):
            return self._synthesize_text_answer(question, plan)

        # Handle None or empty plans
        if not plan:
            return self._synthesize_text_answer(question, "No reasoning plan provided")

        # Handle list-based plans (original behavior)
        if isinstance(plan, list):
            for step in sorted(plan, key=lambda x: x.get("step", 0) if isinstance(x, dict) else 0):
                if not isinstance(step, dict):
                    continue
                metric = step.get("required_metric")
                if not metric:
                    continue
                params = step.get("metric_params") or {}
                try:
                    result = self.builder.calculate_metric(metric, params)
                except Exception as e:
                    result = f"error: {e}"
                self.evidence[f"step_{step.get('step')}_{metric}"] = result

            return self._synthesize_answer(question, plan)
        
        # Handle other types as text
        return self._synthesize_text_answer(question, str(plan))

    def _synthesize_text_answer(self, question: str, plan_text: str) -> str:
        """Handle text-based reasoning plans."""
        # Try to extract metrics from the plan text
        potential_metrics = [
            "ssh_missing_count", "ssh_all_enabled_bool", "ssh_enabled_devices",
            "ibgp_missing_pairs_count", "ibgp_fullmesh_ok", 
            "vrf_without_rt_count", "l2vpn_unidir_count",
            "bgp_inconsistent_as_count", "aaa_enabled_devices"
        ]
        
        relevant_metrics = []
        plan_lower = plan_text.lower()
        
        # Find relevant metrics based on question content
        question_lower = question.lower()
        if "ssh" in question_lower:
            relevant_metrics.extend(["ssh_missing_count", "ssh_enabled_devices", "ssh_all_enabled_bool"])
        if "bgp" in question_lower:
            relevant_metrics.extend(["ibgp_missing_pairs_count", "ibgp_fullmesh_ok", "bgp_inconsistent_as_count"])
        if "vrf" in question_lower:
            relevant_metrics.extend(["vrf_without_rt_count"])
        if "aaa" in question_lower:
            relevant_metrics.extend(["aaa_enabled_devices"])
        if "l2vpn" in question_lower:
            relevant_metrics.extend(["l2vpn_unidir_count"])
        
        # If no specific metrics found, use general metrics
        if not relevant_metrics:
            relevant_metrics = ["ssh_enabled_devices", "ibgp_missing_pairs_count"]
        
        # Calculate relevant metrics
        for metric in relevant_metrics:
            try:
                result = self.builder.calculate_metric(metric)
                self.evidence[metric] = result
            except Exception as e:
                self.evidence[metric] = f"error: {e}"
        
        return self._synthesize_answer(question, plan_text)

    def _synthesize_answer(self, question: str, plan: Union[List[Dict[str, Any]], str]) -> str:
        """Combine evidence into a narrative answer.

        LLM을 호출하여 증거를 기반으로 한 자연스러운 답변을 생성하고,
        실패 시에는 증거 요약 JSON을 반환한다.
        """
        # First try to synthesize a natural language answer using LLM
        schema = {
            "title": "AnswerSynthesis",
            "type": "object",
            "properties": {
                "final_answer": {"type": "string"}
            },
            "required": ["final_answer"],
            "additionalProperties": False
        }

        system_prompt = (
            "당신은 네트워크 분석 전문가입니다. 제공된 증거를 바탕으로 질문에 대해 "
            "한국어로 명확하고 간결하게 답변하세요."
        )

        evidence_text = json.dumps(self.evidence, ensure_ascii=False, indent=2)
        plan_text = plan if isinstance(plan, str) else json.dumps(plan, ensure_ascii=False)

        user_prompt = f"질문: {question}\n추론 단계: {plan_text}\n증거: {evidence_text}\n최종 답변을 한 문단으로 작성하세요."

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        try:
            data = _call_llm_json(
                messages,
                schema,
                temperature=0.2,
                model="gpt-4o-mini",
                max_output_tokens=600,
                use_responses_api=False,
            )
            if isinstance(data, dict) and data.get("final_answer"):
                return data["final_answer"].strip()
        except Exception:
            # If LLM call fails, fall back to returning structured summary
            pass

        summary = {
            "question": question,
            "plan": plan,
            "evidence": self.evidence,
        }
        return json.dumps(summary, ensure_ascii=False, indent=2)
