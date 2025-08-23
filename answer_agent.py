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
        """수집된 증거를 바탕으로 최종 답변 생성 - 핵심 구현!"""
        
        # Evidence가 비어있으면 기본 답변
        if not self.evidence:
            return self._generate_template_answer(question, "수집된 증거가 없습니다.")
        
        # 증거 요약 생성
        evidence_summary = self._format_evidence()
        
        # LLM에게 최종 답변 생성 요청 - 강화된 프롬프트
        synthesis_prompt = f"""당신은 네트워크 설정 전문가입니다. 수집된 증거를 바탕으로 질문에 대한 정확하고 구체적인 답변을 생성하세요.

질문: {question}

수집된 증거:
{evidence_summary}

실행된 계획:
{json.dumps(plan, indent=2, ensure_ascii=False) if isinstance(plan, list) else plan}

요구사항:
1. 증거에 기반한 구체적이고 정확한 답변 작성
2. 수치나 장비명 등 구체적 데이터 포함
3. 문제가 발견되면 원인과 해결책 제시
4. 전문적이면서도 이해하기 쉬운 서술형 답변
5. 증거가 부족하면 명시적으로 언급

답변:"""
        
        # Schema 정의 - 간단하게 수정
        schema = {
            "type": "object",
            "properties": {
                "final_answer": {
                    "type": "string"
                }
            },
            "required": ["final_answer"],
            "additionalProperties": False
        }

        messages = [
            {"role": "system", "content": "당신은 네트워크 설정 분석 전문가입니다. 제공된 증거를 정확히 분석하여 신뢰할 수 있는 답변을 생성하세요."},
            {"role": "user", "content": synthesis_prompt}
        ]

        try:
            # 직접 OpenAI API 호출로 단순화
            import openai
            
            response = openai.chat.completions.create(
                model="gpt-4o-mini",
                messages=messages,
                temperature=0.1,
                max_tokens=800
            )
            
            final_answer = response.choices[0].message.content.strip()
            
            # 답변이 있으면 반환
            if final_answer and len(final_answer) > 20:  # 최소 길이 체크
                print(f"✅ LLM 답변 생성 성공 (길이: {len(final_answer)}자)")
                return final_answer
            else:
                print(f"⚠️ LLM 답변이 너무 짧음: {len(final_answer)}자")
                
        except Exception as e:
            print(f"🚨 OpenAI API 호출 실패: {e}")
            
            # OpenAI 직접 호출 실패 시 기존 방식 시도
            try:
                data = _call_llm_json(
                    messages,
                    schema,
                    temperature=0.1,
                    model="gpt-4o-mini",
                    max_output_tokens=800,
                    use_responses_api=False,
                )
                
                if isinstance(data, dict) and data.get("final_answer"):
                    final_answer = data["final_answer"].strip()
                    print(f"✅ JSON LLM 답변 생성 성공 (길이: {len(final_answer)}자)")
                    return final_answer
                    
            except Exception as e2:
                print(f"🚨 JSON LLM도 실패: {e2}")
                # 최후의 수단: 간단한 프롬프트로 재시도
                return self._simple_llm_call(question, evidence_summary)

        # 모든 시도 실패 시 기본 답변
        return self._generate_template_answer(question, evidence_summary)

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
            import openai
            
            simple_prompt = f"""네트워크 전문가로서 다음 질문에 답하세요.

질문: {question}

증거:
{evidence_summary}

위 증거를 바탕으로 질문에 대해 전문적이고 구체적인 답변을 한국어로 작성하세요. 증거의 수치와 상태를 언급하며 실무적인 관점에서 설명해주세요."""

            response = openai.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": simple_prompt}],
                temperature=0.1,
                max_tokens=600
            )
            
            answer = response.choices[0].message.content.strip()
            print(f"✅ 간단한 LLM 호출 성공 (길이: {len(answer)}자)")
            return answer
            
        except Exception as e:
            print(f"🚨 간단한 LLM 호출도 실패: {e}")
            return self._generate_template_answer(question, evidence_summary)
