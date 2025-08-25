from typing import Dict, Any, List, Union, Set
import json

from utils.builder_core import BuilderCore
from utils.llm_adapter import _call_llm_json
from utils.config_manager import get_settings

settings = get_settings()

class AnswerAgent:
    """Reasoning plan executor that synthesizes a descriptive answer."""

    def __init__(self, network_facts: Dict[str, Any]):
        self.network_facts = network_facts
        self.builder = BuilderCore(network_facts.get("devices", []))
        self.evidence: Dict[str, Any] = {}
        self.referenced_files: Set[str] = set()

    def execute_plan(self, question: str, plan: Union[List[Dict[str, Any]], str]) -> Dict[str, Any]:
        """Execute reasoning steps and return synthesized answer and source files."""
        self.evidence = {}
        self.referenced_files = set()

        # Handle string-based plans
        if isinstance(plan, str):
            answer = self._synthesize_text_answer(question, plan)
            return {"answer": answer, "source_files": sorted(self.referenced_files)}

        # Handle None or empty plans
        if not plan:
            answer = self._synthesize_text_answer(question, "No reasoning plan provided")
            return {"answer": answer, "source_files": sorted(self.referenced_files)}

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
                    result, files = self.builder.calculate_metric(metric, params)
                except Exception as e:
                    result = f"error: {e}"
                    files = []
                self.evidence[f"step_{step.get('step')}_{metric}"] = result
                self.referenced_files.update(files)

            answer = self._synthesize_answer(question, plan)
            return {"answer": answer, "source_files": sorted(self.referenced_files)}

        # Handle other types as text
        answer = self._synthesize_text_answer(question, str(plan))
        return {"answer": answer, "source_files": sorted(self.referenced_files)}

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
                result, files = self.builder.calculate_metric(metric)
                self.evidence[metric] = result
                self.referenced_files.update(files)
            except Exception as e:
                self.evidence[metric] = f"error: {e}"
        
        return self._synthesize_answer(question, plan_text)

    def _synthesize_answer(self, question: str, plan: Union[List[Dict[str, Any]], str]) -> str:
        """Return a structured answer optimized for evaluation metrics.

        The answer is encoded as a JSON string with the following schema:
        {
            "eval_targets": {
                "exact_match": <single concise value>,
                "f1_score": [<items for list-based answers>]
            },
            "explanation": <one or two sentence rationale>
        }
        """

        schema = {
            "title": "StructuredAnswer",
            "type": "object",
            "properties": {
                "eval_targets": {
                    "type": "object",
                    "properties": {
                        "exact_match": {"type": ["string", "number", "boolean"]},
                        "f1_score": {
                            "type": ["array", "null"],
                            "items": {"type": ["string", "number", "boolean"]}
                        }
                    },
                    "required": ["exact_match", "f1_score"],
                    "additionalProperties": False
                },
                "explanation": {"type": "string"}
            },
            "required": ["eval_targets", "explanation"],
            "additionalProperties": False
        }

        evidence_text = json.dumps(self.evidence, ensure_ascii=False, indent=2)

        system_prompt = (
            "당신은 네트워크 데이터를 분석하여 평가용 정답을 생성하는 도우미입니다. "
            "질문과 증거를 바탕으로 위 스키마에 맞춘 JSON 답변만 제공하세요."
        )

        user_prompt = f"""
질문: {question}

수집된 증거:
{evidence_text}

[응답 지침]
- eval_targets.exact_match에는 가장 핵심적인 단일 값을 넣으세요.
- eval_targets.f1_score에는 정답이 리스트일 때 항목들의 리스트를 넣고, 그렇지 않으면 null 또는 빈 리스트를 사용하세요.
- explanation에는 위 증거를 근거로 결론에 도달한 이유를 한두 문장으로 서술하세요.

JSON 외의 다른 텍스트는 포함하지 마세요.
"""

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        try:
            data = _call_llm_json(
                messages,
                schema,
                temperature=0.0,
                model=settings.models.answer_synthesis,
                max_output_tokens=500,
                use_responses_api=False,
            )
            if isinstance(data, dict):
                return json.dumps(data, ensure_ascii=False)
        except Exception as e:
            import logging
            logging.warning(f"AnswerAgent LLM synthesis failed: {e}")

        fallback = {
            "eval_targets": {"exact_match": "", "f1_score": []},
            "explanation": self._format_evidence() if self.evidence else "No evidence available."
        }
        return json.dumps(fallback, ensure_ascii=False)

    def _format_evidence(self) -> str:
        """Evidence를 읽기 쉬운 형태로 포맷팅"""
        if not self.evidence:
            return "수집된 증거가 없습니다."
        
        formatted = []
        for key, value in self.evidence.items():
            # step_1_bgp_peer_count -> "1단계: BGP 피어 수"
            if key.startswith('step_'):
                parts = key.split('_')
                if len(parts) >= 3:
                    step_num = parts[1]
                    metric_name = '_'.join(parts[2:])
                    formatted.append(f"• {step_num}단계 ({metric_name}): {self._format_value(value)}")
                else:
                    formatted.append(f"• {key}: {self._format_value(value)}")
            else:
                # 메트릭 이름을 한국어로 변환
                korean_name = self._translate_metric_name(key)
                formatted.append(f"• {korean_name}: {self._format_value(value)}")
        
        return '\n'.join(formatted)

    def _translate_metric_name(self, metric_name: str) -> str:
        """메트릭 이름을 한국어로 번역"""
        translations = {
            'ssh_enabled_devices': 'SSH 활성화된 장비',
            'ssh_missing_count': 'SSH 미설정 장비 수',
            'ssh_all_enabled_bool': 'SSH 전체 활성화 여부',
            'ibgp_missing_pairs_count': 'iBGP 누락 페어 수',
            'ibgp_fullmesh_ok': 'iBGP 풀메시 정상 여부',
            'bgp_inconsistent_as_count': 'BGP AS 불일치 수',
            'aaa_enabled_devices': 'AAA 활성화된 장비',
            'vrf_without_rt_count': 'RT 미설정 VRF 수',
            'l2vpn_unidir_count': '단방향 L2VPN 수',
            'bgp_peer_count': 'BGP 피어 수',
            'interface_count': '인터페이스 수',
            'ospf_area_count': 'OSPF 영역 수'
        }
        return translations.get(metric_name, metric_name)

    def _format_value(self, value) -> str:
        """값을 읽기 쉬운 형태로 포맷팅"""
        if isinstance(value, bool):
            return "✅ 정상" if value else "❌ 문제"
        elif isinstance(value, (int, float)) and value == 0:
            return "0 (문제없음)"
        elif isinstance(value, list):
            if len(value) == 0:
                return "없음"
            elif len(value) <= 3:
                return f"{', '.join(map(str, value))}"
            else:
                return f"{', '.join(map(str, value[:3]))}... (총 {len(value)}개)"
        elif isinstance(value, str) and value.startswith("error:"):
            return f"⚠️ {value}"
        else:
            return str(value)

    def _generate_template_answer(self, question: str, evidence_summary: str) -> str:
        """LLM 실패 시 템플릿 기반 답변 생성"""
        if "증거가 없습니다" in evidence_summary:
            return f"""
질문 "{question}"에 대한 분석을 시도했지만, 관련 증거를 수집할 수 없었습니다.

이는 다음과 같은 원인일 수 있습니다:
• 네트워크 설정 데이터에서 관련 정보를 찾을 수 없음
• 질문과 관련된 메트릭이 아직 구현되지 않음
• 데이터 파싱 과정에서 오류 발생

더 구체적인 분석을 위해서는 네트워크 설정 파일과 질문의 적합성을 확인해 주세요.
"""
        
        return f"""
질문 "{question}"에 대한 분석 결과:

수집된 증거:
{evidence_summary}

위 증거를 바탕으로 네트워크의 현재 상태를 파악할 수 있습니다. 
구체적인 수치와 설정 상태를 통해 해당 질문에 대한 답변을 도출할 수 있으며,
문제가 발견된 경우 적절한 해결책을 고려해야 합니다.

💡 더 정확한 분석을 위해서는 LLM 기반 답변 생성 기능을 활용하시기 바랍니다.
"""

    def _simple_llm_call(self, question: str, evidence_summary: str) -> str:
        """간단한 프롬프트로 LLM 호출 - 최후의 수단"""
        try:
            simple_prompt = f"""네트워크 전문가로서 다음 질문에 답하세요.

질문: {question}

증거:
{evidence_summary}

위 증거를 바탕으로 질문에 대해 전문적이고 구체적인 답변을 한국어로 작성하세요. 증거의 수치와 상태를 언급하며 실무적인 관점에서 설명해주세요."""

            schema = {
                "title": "SimpleAnswer",
                "type": "object",
                "properties": {"answer": {"type": "string"}},
                "required": ["answer"],
                "additionalProperties": False,
            }

            messages = [{"role": "user", "content": simple_prompt}]
            data = _call_llm_json(
                messages,
                schema,
                temperature=0.1,
                model=settings.models.answer_synthesis,
                max_output_tokens=600,
                use_responses_api=False,
            )
            answer = data.get("answer") if isinstance(data, dict) else None
            if isinstance(answer, str):
                print(f"✅ 간단한 LLM 호출 성공 (길이: {len(answer)}자)")
                return answer
        except Exception as e:
            print(f"🚨 간단한 LLM 호출도 실패: {e}")
        return self._generate_template_answer(question, evidence_summary)
