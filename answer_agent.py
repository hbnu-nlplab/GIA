from typing import Dict, Any, List, Union, Set, Tuple
import json
import re

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

    def execute_plan(
        self,
        question: str,
        plan: Union[List[Dict[str, Any]], str],
        answer_type: str = "long",
    ) -> Dict[str, Any]:
        """Execute reasoning steps and return ground truth, explanation and source files."""
        self.evidence = {}
        self.referenced_files = set()

        if isinstance(plan, str):
            ground_truth, explanation = self._synthesize_text_answer(question, plan, answer_type)
            return {
                "ground_truth": ground_truth,
                "explanation": explanation,
                "source_files": sorted(self.referenced_files),
            }

        if not plan:
            ground_truth, explanation = self._synthesize_text_answer(
                question, "No reasoning plan provided", answer_type
            )
            return {
                "ground_truth": ground_truth,
                "explanation": explanation,
                "source_files": sorted(self.referenced_files),
            }

        if isinstance(plan, list):
            for step in sorted(
                plan, key=lambda x: x.get("step", 0) if isinstance(x, dict) else 0
            ):
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
            ground_truth, explanation = self._synthesize_json_answer(
                question, plan, answer_type
            )
            return {
                "ground_truth": ground_truth,
                "explanation": explanation,
                "source_files": sorted(self.referenced_files),
            }

        ground_truth, explanation = self._synthesize_text_answer(
            question, str(plan), answer_type
        )
        return {
            "ground_truth": ground_truth,
            "explanation": explanation,
            "source_files": sorted(self.referenced_files),
        }

    def _synthesize_text_answer(
        self, question: str, plan_text: str, answer_type: str = "long"
    ) -> Tuple[Any, str]:
        """Handle text-based reasoning plans."""
        potential_metrics = [
            # 실제 구현된 메트릭들만 포함
            "ssh_missing_count", "ssh_enabled_devices", "ssh_missing_devices",
            "ibgp_missing_pairs_count", "ibgp_fullmesh_ok", "ibgp_missing_pairs",
            "vrf_without_rt_count", "vrf_without_rt_pairs", "l2vpn_unidir_count",
            "aaa_enabled_devices", "aaa_missing_devices", "ssh_present_bool",
            "bgp_neighbor_count", "interface_count", "ospf_area0_if_count"
        ]

        relevant_metrics: List[str] = []
        plan_lower = plan_text.lower()

        question_lower = question.lower()
        if "ssh" in question_lower:
            relevant_metrics.extend(["ssh_missing_count", "ssh_enabled_devices", "ssh_missing_devices", "ssh_present_bool"])
        if "bgp" in question_lower:
            relevant_metrics.extend(["ibgp_missing_pairs_count", "ibgp_fullmesh_ok", "ibgp_missing_pairs", "bgp_neighbor_count"])
        if "vrf" in question_lower:
            relevant_metrics.extend(["vrf_without_rt_count", "vrf_without_rt_pairs"])
        if "aaa" in question_lower:
            relevant_metrics.extend(["aaa_enabled_devices", "aaa_missing_devices"])
        if "l2vpn" in question_lower:
            relevant_metrics.extend(["l2vpn_unidir_count"])
        if "interface" in question_lower or "인터페이스" in question_lower:
            relevant_metrics.extend(["interface_count"])
        if "ospf" in question_lower:
            relevant_metrics.extend(["ospf_area0_if_count"])

        if not relevant_metrics:
            relevant_metrics = ["ssh_enabled_devices", "ibgp_missing_pairs_count"]

        for metric in relevant_metrics:
            try:
                result, files = self.builder.calculate_metric(metric)
                self.evidence[metric] = result
                self.referenced_files.update(files)
            except Exception as e:
                self.evidence[metric] = f"error: {e}"

        return self._synthesize_json_answer(question, plan_text, answer_type)

    def _synthesize_json_answer(
        self,
        question: str,
        plan: Union[List[Dict[str, Any]], str],
        answer_type: str = "long",
    ) -> Tuple[Any, str]:
        """Return structured ground truth and explanation derived from LLM output."""
        schema = {
            "title": "StructuredAnswer",
            "type": "object",
            "properties": {
                "ground_truth": {
                    "type": ["string", "boolean", "number", "array", "null"],
                    "description": """
                **[매우 중요]** 질문에 대한 핵심적이고 직접적인 '정답' 그 자체.
                - 질문이 '개수'를 물으면: 숫자 (예: 0, 1, 5)
                - 질문이 '목록'을 물으면: 문자열의 배열 (예: ["CE1", "CE2"])
                - 질문이 '이름'이나 '값' 하나를 물으면: 문자열 (예: "CE1")
                - 질문이 '분석'이나 '설명'을 요구하면: 완벽한 서술형 문장 (예: "iBGP 풀메시가 정상 작동하여...")
                - **절대 '정답을 찾는 과정'을 서술하지 말 것.**
                """,
                },
                "explanation": {
                    "type": "string",
                    "description": "위 ground_truth가 왜 정답인지, 제공된 증거(evidence)를 바탕으로 상세히 설명하는 문장.",
                },
            },
            "required": ["ground_truth", "explanation"],
        }

        evidence_summary = (
            self._format_evidence() if self.evidence else "No evidence available."
        )

        system_prompt = f"""
당신은 네트워크 데이터를 분석하여 '정답'과 '해설'을 엄격하게 분리하여 생성하는 AI 에이전트입니다.

**[당신의 임무]**
1. 주어진 '질문'과 '증거(evidence)'를 분석합니다.
2. 질문의 의도를 파악하여, 채점에 사용될 수 있는 명확한 **'ground_truth'(정답)**를 먼저 결정합니다.
3. 그 다음, 해당 정답이 나온 이유를 **'explanation'(해설)**으로 상세히 서술합니다.

**[엄격한 규칙]**
- `ground_truth` 필드에는 절대, 절대 설명을 넣지 마세요. 오직 '정답' 값만 포함해야 합니다.
- 질문이 특정 숫자나 목록을 요구하면, `ground_truth`는 반드시 해당 형식(숫자, 배열)을 따라야 합니다.
- `explanation`은 항상 완전한 문장 형태여야 합니다.
"""

        user_prompt = f"""
- **질문**: {question}
- **질문 유형 힌트**: {answer_type}
- **분석된 증거**: 
{evidence_summary}

위 정보를 바탕으로, JSON 스키마의 규칙에 따라 'ground_truth'와 'explanation'을 생성하세요.
'질문 유형 힌트'가 'short'이면 `ground_truth`는 숫자, 리스트, 단일 문자열일 가능성이 높습니다.
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
                max_output_tokens=700,
                use_responses_api=False,
            )
            if isinstance(data, dict):
                ground_truth = data.get("ground_truth")
                explanation = data.get("explanation", "")
                if ground_truth is not None:
                    return ground_truth, explanation
        except Exception as e:
            import logging
            logging.warning(f"AnswerAgent LLM synthesis failed: {e}")

        # 폴백: 간단 LLM 호출 또는 템플릿 생성으로 답변 확보
        try:
            fallback_answer = self._simple_llm_call(question, evidence_summary)
            return fallback_answer, evidence_summary
        except Exception:
            # 최후 폴백: 증거 요약을 explanation으로, 간단한 문장 생성
            return (
                f"질문에 대한 분석 결과는 증거 요약을 참조하세요. 주요 증거: {evidence_summary[:200]}...",
                evidence_summary,
            )

    def _extract_ground_truth(self, eval_targets: Dict[str, Any], explanation: str) -> Any:
        """Infer ground truth from explanation text or eval_targets."""
        ce_matches = re.findall(r"CE\d+", explanation)
        if ce_matches:
            unique: List[str] = []
            for m in ce_matches:
                if m not in unique:
                    unique.append(m)
            return unique[0] if len(unique) == 1 else unique

        if any(kw in explanation for kw in ["없습니다", "없음", "0개"]):
            f1 = eval_targets.get("f1_score") if isinstance(eval_targets, dict) else None
            if isinstance(f1, list):
                return []
            return 0

        num_match = re.search(r"(-?\d+)", explanation)
        if num_match:
            try:
                return int(num_match.group(1))
            except ValueError:
                pass

        if isinstance(eval_targets, dict):
            f1 = eval_targets.get("f1_score")
            if isinstance(f1, list) and f1:
                return f1
            return eval_targets.get("exact_match")

        return ""

    def _format_evidence(self) -> str:
        """Evidence를 읽기 쉬운 형태로 포맷팅"""
        if not self.evidence:
            return "수집된 증거가 없습니다."

        formatted = []
        for key, value in self.evidence.items():
            if key.startswith('step_'):
                parts = key.split('_')
                if len(parts) >= 3:
                    step_num = parts[1]
                    metric_name = '_'.join(parts[2:])
                    formatted.append(f"• {step_num}단계 ({metric_name}): {self._format_value(value)}")
                else:
                    formatted.append(f"• {key}: {self._format_value(value)}")
            else:
                korean_name = self._translate_metric_name(key)
                formatted.append(f"• {korean_name}: {self._format_value(value)}")
        return '\n'.join(formatted)

    def _translate_metric_name(self, metric_name: str) -> str:
        translations = {
            # SSH 관련
            'ssh_enabled_devices': 'SSH 활성화된 장비',
            'ssh_missing_devices': 'SSH 미설정 장비',
            'ssh_missing_count': 'SSH 미설정 장비 수',
            'ssh_all_enabled_bool': 'SSH 전체 활성화 여부',
            'ssh_present_bool': 'SSH 설정 존재 여부',
            'ssh_version_text': 'SSH 버전',
            'ssh_acl_applied_check': 'SSH ACL 적용 여부',
            
            # BGP 관련
            'ibgp_fullmesh_ok': 'iBGP 풀메시 정상 여부',
            'ibgp_missing_pairs': 'iBGP 누락 페어',
            'ibgp_missing_pairs_count': 'iBGP 누락 페어 수',
            'ibgp_under_peered_devices': 'iBGP 피어 부족 장비',
            'ibgp_under_peered_count': 'iBGP 피어 부족 장비 수',
            'neighbor_list_ibgp': 'iBGP 이웃 목록',
            'neighbor_list_ebgp': 'eBGP 이웃 목록',
            'ebgp_remote_as_map': 'eBGP 원격 AS 매핑',
            'ibgp_update_source_missing_set': 'iBGP 업데이트 소스 누락',
            'bgp_local_as_numeric': 'BGP 로컬 AS 번호',
            'bgp_neighbor_count': 'BGP 이웃 수',
            'bgp_inconsistent_as_count': 'BGP AS 불일치 수',
            'bgp_peer_count': 'BGP 피어 수',
            'bgp_advertised_prefixes_list': 'BGP 광고 프리픽스 목록',
            
            # VRF 관련
            'vrf_rd_map': 'VRF RD 매핑',
            'vrf_rt_list_per_device': 'VRF RT 목록',
            'vrf_without_rt_pairs': 'RT 미설정 VRF 쌍',
            'vrf_without_rt_count': 'RT 미설정 VRF 수',
            'vrf_interface_bind_count': 'VRF 인터페이스 바인딩 수',
            'vrf_rd_format_invalid_set': 'RD 형식 오류 VRF',
            'vrf_bind_map': 'VRF 바인딩 매핑',
            'vrf_names_set': 'VRF 이름 목록',
            'vrf_count': 'VRF 개수',
            
            # L2VPN 관련
            'l2vpn_pairs': 'L2VPN 페어',
            'l2vpn_unidirectional_pairs': '단방향 L2VPN 페어',
            'l2vpn_unidir_count': '단방향 L2VPN 수',
            'l2vpn_pwid_mismatch_pairs': 'PW-ID 불일치 L2VPN 페어',
            'l2vpn_mismatch_count': 'L2VPN 불일치 수',
            'l2vpn_pw_id_set': 'L2VPN PW-ID 목록',
            
            # OSPF 관련
            'ospf_proc_ids': 'OSPF 프로세스 ID',
            'ospf_area0_if_list': 'OSPF Area 0 인터페이스 목록',
            'ospf_area0_if_count': 'OSPF Area 0 인터페이스 수',
            'ospf_area_set': 'OSPF 영역 목록',
            'ospf_area_count': 'OSPF 영역 수',
            'ospf_process_ids_set': 'OSPF 프로세스 ID 목록',
            
            # AAA 관련
            'aaa_enabled_devices': 'AAA 활성화된 장비',
            'aaa_missing_devices': 'AAA 미설정 장비',
            'aaa_present_bool': 'AAA 설정 존재 여부',
            'password_policy_present_bool': '패스워드 정책 존재 여부',
            
            # 인터페이스 관련
            'interface_count': '인터페이스 수',
            'interface_ip_map': '인터페이스 IP 매핑',
            'interface_vlan_set': 'VLAN 목록',
            'subinterface_count': '서브인터페이스 수',
            'interface_mop_xenabled_bool': 'MOP xenabled 설정',
            
            # 시스템 관련
            'system_hostname_text': '호스트네임',
            'system_version_text': '시스템 버전',
            'system_timezone_text': '시간대',
            'system_user_count': '시스템 사용자 수',
            'system_user_list': '시스템 사용자 목록',
            'system_mgmt_address_text': '관리 IP 주소',
            'system_users_detail_map': '시스템 사용자 상세',
            'ios_config_register_text': 'Config Register 값',
            'logging_buffered_severity_text': '로깅 버퍼 심각도',
            'http_server_enabled_bool': 'HTTP 서버 활성화',
            'ip_forward_protocol_nd_bool': 'IP Forward Protocol ND',
            'ip_cef_enabled_bool': 'IP CEF 활성화',
            'vty_first_last_text': 'VTY 라인 범위',
            'vty_login_mode_text': 'VTY 로그인 모드',
            'vty_password_secret_text': 'VTY 패스워드 시크릿',
            'vty_transport_input_text': 'VTY 전송 입력',
            
            # 서비스 관련
            'mpls_ldp_present_bool': 'MPLS LDP 존재 여부',
            'rt_export_count': 'RT Export 수',
            'rt_import_count': 'RT Import 수',
            'qos_policer_applied_interfaces_list': 'QoS Policer 적용 인터페이스',
            
            # 명령어 관련
            'cmd_show_bgp_summary': 'BGP 요약 명령어',
            'cmd_show_ip_interface_brief': 'IP 인터페이스 요약 명령어',
            'cmd_show_ip_route_ospf': 'OSPF 라우팅 테이블 명령어',
            'cmd_show_processes_cpu': 'CPU 프로세스 명령어',
            'cmd_show_l2vpn_vc': 'L2VPN VC 명령어',
            'cmd_show_ip_ospf_neighbor': 'OSPF 이웃 명령어',
            'cmd_show_users': '사용자 목록 명령어',
            'cmd_show_logging': '로깅 명령어',
            'cmd_ssh_direct_access': 'SSH 직접 접속 명령어',
            'cmd_set_static_route': '정적 라우팅 설정 명령어',
            'cmd_set_bgp_routemap': 'BGP 라우트맵 설정 명령어',
            'cmd_set_interface_description': '인터페이스 설명 설정 명령어',
            'cmd_create_vrf_and_assign': 'VRF 생성 및 할당 명령어',
            'cmd_set_ospf_cost': 'OSPF 비용 설정 명령어',
            'cmd_set_vty_acl': 'VTY ACL 설정 명령어',
            'cmd_set_hostname': '호스트네임 설정 명령어',
            'cmd_ssh_proxy_jump': 'SSH 프록시 점프 명령어',
        }
        return translations.get(metric_name, metric_name)

    def _format_value(self, value) -> str:
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
        if "증거가 없습니다" in evidence_summary:
            return f"""\n질문 "{question}"에 대한 분석을 시도했지만, 관련 증거를 수집할 수 없었습니다.\n\n이는 다음과 같은 원인일 수 있습니다:\n• 네트워크 설정 데이터에서 관련 정보를 찾을 수 없음\n• 질문과 관련된 메트릭이 아직 구현되지 않음\n• 데이터 파싱 과정에서 오류 발생\n\n더 구체적인 분석을 위해서는 네트워크 설정 파일과 질문의 적합성을 확인해 주세요.\n"""

        return f"""\n질문 "{question}"에 대한 분석 결과:\n\n수집된 증거:\n{evidence_summary}\n\n위 증거를 바탕으로 네트워크의 현재 상태를 파악할 수 있습니다.\n구체적인 수치와 설정 상태를 통해 해당 질문에 대한 답변을 도출할 수 있으며,\n문제가 발견된 경우 적절한 해결책을 고려해야 합니다.\n\n💡 더 정확한 분석을 위해서는 LLM 기반 답변 생성 기능을 활용하시기 바랍니다.\n"""

    def _simple_llm_call(self, question: str, evidence_summary: str) -> str:
        try:
            simple_prompt = f"""네트워크 전문가로서 다음 질문에 답하세요.\n\n질문: {question}\n\n증거:\n{evidence_summary}\n\n위 증거를 바탕으로 질문에 대해 전문적이고 구체적인 답변을 한국어로 작성하세요. 증거의 수치와 상태를 언급하며 실무적인 관점에서 설명해주세요."""

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
