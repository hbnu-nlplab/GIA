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
        """Return a concise final answer based on collected evidence.

        LLM을 계산기로 활용하여 증거에서 최종 정답 값만 도출한다. 실패 시
        증거 요약 JSON을 반환한다.
        """
        schema = {
            "title": "AnswerSynthesis",
            "type": "object",
            "properties": {
                "final_answer": {"type": ["string", "number", "array"]}
            },
            "required": ["final_answer"],
            "additionalProperties": False,
        }

        system_prompt = (
            "당신은 데이터를 분석하여 최종 결론을 도출하는 정확한 계산기입니다. "
            "주어진 질문과 데이터를 바탕으로, 다른 설명 없이 오직 최종 정답 값만을 "
            "계산하여 반환하세요."
        )

        evidence_text = json.dumps(self.evidence, ensure_ascii=False, indent=2)
        user_prompt = (
            f"[질문]\n{question}\n\n[수집된 데이터]\n{evidence_text}\n\n"
            "위 데이터를 근거로 질문에 대한 최종 정답을 계산하세요.\n\n"
            "[응답 형식 규칙]\n"
            "- 리스트: [\"A\", \"B\"]\n"
            "- 숫자: 4\n"
            "- 문자열: \"192.168.1.1\"\n"
            "- 추가 설명 금지"
        )

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        try:
            data = _call_llm_json(
                messages,
                schema,
                temperature=0.0,
                model="gpt-4o-mini",
                max_output_tokens=300,
                use_responses_api=False,
            )
            ans = data.get("final_answer") if isinstance(data, dict) else None
            if ans is not None:
                if isinstance(ans, (list, dict)):
                    return json.dumps(ans, ensure_ascii=False)
                return str(ans).strip()
        except Exception:
            pass

        summary = {
            "question": question,
            "plan": plan,
            "evidence": self.evidence,
        }
        return json.dumps(summary, ensure_ascii=False, indent=2)
