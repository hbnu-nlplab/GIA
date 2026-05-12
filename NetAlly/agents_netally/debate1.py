"""
debate1.py
----------
1차 토론(Debate 1) 에이전트 정의 모듈.

파이프라인: Collector → Verifier → Synthesizer

- Agent 1 (Collector):   질문에 관련된 원시 정보를 컨텍스트에서 추출
- Agent 2 (Verifier):    추출된 정보에서 불필요한 내용을 제거하여 정제
- Agent 3 (Synthesizer): 정제된 패시지를 바탕으로 후보 답변 생성
"""

import re
import json
import logging
from contextlib import contextmanager
from agents_netally.model_loader import get_models, USE_LOCAL, invoke_with_tokens
import threading

logger = logging.getLogger("agents_netally")

# GPU 접근 직렬화 락 — 로컬 GPU 모드에서만 유효 (클라우드 API 모드에서는 사용 안 함)
_gpu_lock = threading.Lock()

@contextmanager
def gpu_lock():
    """USE_LOCAL=True일 때만 락을 획득한다. 클라우드 모드에서는 즉시 통과."""
    if USE_LOCAL:
        with _gpu_lock:
            yield
    else:
        yield


def _get_text(response):
    """LangChain 응답 객체 또는 일반 문자열에서 텍스트 내용만 안전하게 추출한다."""
    return response.content if hasattr(response, 'content') else str(response)


def _add_tokens(state: dict, model_key: str, in_tok: int, out_tok: int) -> dict:
    tok = state.get("token_usage", {"model_a": {"input": 0, "output": 0},
                                     "model_b": {"input": 0, "output": 0}})
    m = tok.get(model_key, {"input": 0, "output": 0})
    return {**tok, model_key: {"input": m["input"] + in_tok, "output": m["output"] + out_tok}}


def _extract_from_tags(text: str, start_tag="[START]", end_tag="[DONE]") -> str:
    """
    LLM 응답에서 [START]...[DONE] 태그 사이의 내용을 추출하고 정제한다.

    처리 순서:
    1. <think>...</think> 블록 제거 (Qwen3 등 reasoning 모델의 사고 과정 제거)
    2. 두 번째 [START] 이후 내용 추출 (모델이 예시를 먼저 출력하는 경우 대응)
    3. [DONE] 이전까지만 사용
    4. "Context:", "Passage:", "Answer:" 등 레이블 헤더 제거

    Args:
        text: LLM 원시 응답 텍스트
        start_tag: 추출 시작 태그 (기본값: "[START]")
        end_tag: 추출 종료 태그 (기본값: "[DONE]")
    Returns:
        str: 정제된 내용 (레이블 없는 순수 값)
    """
    print("=" * 100)
    print("Full Content:", text)

    # Step 1: <think>...</think> 블록 제거
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()

    # Step 2: [START] 기준으로 분할하여 두 번째 등장 이후 내용 선택
    # (모델이 포맷 예시를 먼저 출력한 뒤 실제 답을 출력하는 경우 대응)
    start_parts = text.split(start_tag)
    target_content = ""
    if len(start_parts) >= 3:
        target_content = start_parts[2]   # 두 번째 [START] 이후
    elif len(start_parts) == 2:
        target_content = start_parts[1]   # 첫 번째 [START] 이후
    else:
        target_content = text             # [START]가 없으면 전체 사용

    # Step 3: [DONE] 이전까지만 사용
    if end_tag in target_content:
        target_content = target_content.split(end_tag)[0]
    target_content = target_content.strip()

    print("-" * 50)
    print("Target Content for Parsing:", target_content)

    # Step 4: "Context:", "Passage:", "Answer:", "Result:" 등 레이블 헤더 제거
    cleaned = re.sub(r"^\s*(Context|Passage|Answer|Result)\s*:\s*", "", target_content,
                     flags=re.IGNORECASE | re.MULTILINE)
    cleaned = cleaned.strip()

    print("=" * 100)
    print("Parsed Content:", cleaned)

    return cleaned


def _normalize_map_str_int_comparison(answer_val: str, question: str, answer_type: str) -> str:
    """
    map_str_int 비교 질문에서 모델이 장비명을 key로 출력한 경우
    ({\"leaf2\": N, \"leaf3\": N}) → 표준 3-key 포맷으로 변환.
    ({\"difference\": N, \"host1_count\": N, \"host2_count\": N})

    조건: answer_type==map_str_int AND 질문에 "compare" 포함 AND 출력에 표준 key 없음
    """
    if answer_type != "map_str_int":
        return answer_val
    if "compare" not in question.lower():
        return answer_val
    try:
        parsed = json.loads(answer_val)
    except Exception:
        return answer_val
    # 이미 표준 포맷이면 그대로
    if "difference" in parsed or "host1_count" in parsed or "host2_count" in parsed:
        return answer_val
    # 2개의 정수 값 → 비교 포맷으로 변환
    vals = list(parsed.values())
    if len(vals) == 2 and all(isinstance(v, (int, float)) for v in vals):
        v1, v2 = int(vals[0]), int(vals[1])
        return json.dumps({"difference": abs(v1 - v2), "host1_count": v1, "host2_count": v2})
    return answer_val


# ==========================================
# 🕵️ Agent 1: Collector Node
# ==========================================
def collector_node(state: dict):
    """
    MCP 통합 Collector: 도구 카탈로그를 보고 LLM이 도구 호출 계획을 생성,
    Python이 MCP 도구를 실행하여 결과를 raw_data에 저장.
    도구가 없으면 원본 static context 추출 로직으로 fallback.

    상태 업데이트:
        raw_data (str): 도구 결과 또는 추출된 원시 정보
        tool_calls_log (list): 도구 호출 이력
        outer_loop_count (int): 외부 루프 카운터 +1
    """
    print(f"\n🕵️ [Agent 1: Collector] Strategy for: {state.get('dataset_type')}")
    models = get_models()
    llm = models.get('B', models['A'])

    # === MCP MODE: Collector가 직접 도구 선택+호출+추출 (Tool Planner 통합) ===
    tool_catalog = state.get("tool_catalog", "")
    if tool_catalog:
        from agents_netally.tool_dispatch import (
            execute_tool_calls, format_tool_results,
            get_registered_tools, _normalize_device_args,
        )
        import json as _json
        tools = get_registered_tools()
        if tools:
            feedback = state.get("feedback_to_collector", "")
            level = state.get("level", "")

            # Collector LLM이 도구 선택 + 데이터 추출을 한 번에 수행
            tool_select_prompt = f"""You are a Network Info Collector with tool access.
STEP 1: Select tools to gather data for this question.
STEP 2: After receiving tool results, extract relevant information.

AVAILABLE TOOLS:
{tool_catalog}

TOOL SELECTION GUIDE:
- Raw config text (banner, version, CDP, enable secret, static routes, console/VTY transport input, ACL):
    get_config_section(device="X", keyword="banner|version|cdp|enable|ip route|line|access-list")
    USE THIS when asking about exact config values, text content, or features not in NSO summary.
- Structured config (hostname, SSH, AAA, users, timezone, OSPF process IDs & areas, BGP AS, NTP, syslog, VTY transport input):
    nso_get_device_info(device="X") for single device, nso_get_all_device_info() for all
    USE THIS for: OSPF area comparison, BGP AS comparison, VTY settings, NTP, syslog
- Interface status map {{"GigabitEthernet0/0": "up"/"down"}}, VRF bind map {{"GigabitEthernet0/1": "VRF_A"}}:
    nso_get_interfaces(device="X") or nso_get_all_interfaces()
    USE THIS for: interface status, VRF binding, IP address per interface
- Routing table: batfish_route_table(device="X")
- BGP sessions: batfish_bgp_sessions()
- Path/reachability (L4): batfish_traceroute(src="X", dst="Y")
- Blocking device / root cause: batfish_traceroute(src="X", dst="Y") — the LAST HOP device is the blocker

FOR L5 (What-If / Failure) QUESTIONS — ALWAYS call 2 tools:
  1st: nso_get_all_device_info() — to understand network topology and routing
  2nd: the appropriate simulation tool:
    - Single link failure: batfish_link_failure(node1="X", node2="Y", src="A", dst="B")
    - TWO links fail simultaneously: batfish_multi_link_failure(link1_node1="X", link1_node2="Y", link2_node1="A", link2_node2="B", src="S", dst="D")
      IMPORTANT: If question says "both fail" or "simultaneously", you MUST use multi_link_failure, NOT two separate link_failure calls!
    - Single node failure / disrupted flows: batfish_node_failure(node="X")
    - TWO nodes fail simultaneously: batfish_multi_node_failure(node1="X", node2="Y")
      IMPORTANT: If question says "both fail" or "simultaneously", you MUST use multi_node_failure, NOT two separate node_failure calls!
    - SPOF detection: batfish_spof_detection()
    - Which device BLOCKS traffic: batfish_find_blocker(src="X", dst="Y") — returns the blocking device name
  If the simulation tool fails or returns empty, use the NSO topology data to REASON about the failure impact.

RULES:
- L1/L2/L3: 1-2 tool calls. L4: 1 tool call. L5: 2-3 tool calls.
- Device names are UPPERCASE for NSO (PE1, Leaf3), lowercase for Batfish (pe1, leaf3).
{f'- CRITIC FEEDBACK (gather this specific info): {feedback}' if feedback else ''}

QUESTION: {state["question"]}
LEVEL: {level}

Output a JSON array of tool calls. Each: {{"tool": "<name>", "args": {{...}}}}
Output ONLY the JSON array."""

            response = llm.invoke(tool_select_prompt)
            raw_text = _get_text(response)
            # gpt-oss-20b 등 reasoning 모델은 content가 비어 있고 reasoning_content에 답변이 담길 수 있음
            if not raw_text.strip():
                for key in ("reasoning_content", "reasoning", "thinking"):
                    fallback = (
                        (getattr(response, "additional_kwargs", {}) or {}).get(key)
                        or (getattr(response, "response_metadata", {}) or {}).get(key)
                    )
                    if fallback and str(fallback).strip():
                        raw_text = str(fallback)
                        print(f"  🔍 RAW LLM response (0 chars) → fallback from '{key}' ({len(raw_text)} chars): {repr(raw_text[:200])}")
                        break
                else:
                    print(f"  🔍 RAW LLM response (0 chars): '' — model returned empty content")
            else:
                print(f"  🔍 RAW LLM response ({len(raw_text)} chars): {repr(raw_text[:200])}")
            text = raw_text
            # Parse tool plan from response
            text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
            text = re.sub(r"```json\s*", "", text)
            text = re.sub(r"```\s*", "", text).strip()
            try:
                plans = _json.loads(text)
                if not isinstance(plans, list):
                    print(f"  ⚠️ Tool plan not a list: {type(plans).__name__}: {str(plans)[:100]}")
                    plans = []
            except _json.JSONDecodeError:
                match = re.search(r'\[.*\]', text, re.DOTALL)
                if match:
                    try:
                        plans = _json.loads(match.group(0))
                    except _json.JSONDecodeError:
                        print(f"  ⚠️ Tool plan parse failed: {text[:200]}")
                        plans = []
                else:
                    print(f"  ⚠️ No JSON array in LLM response: {text[:200]}")
                    plans = []

            plans = _normalize_device_args(plans)
            print(f"  📋 Tool plan: {[p.get('tool') for p in plans]}")

            if plans:
                results = execute_tool_calls(plans, tools)
                formatted = format_tool_results(results)
                tool_log = state.get("tool_calls_log", []) + [
                    {"tool": r["tool"], "args": r["args"], "elapsed_ms": r["elapsed_ms"],
                     "result": str(r.get("result", ""))[:500]}
                    for r in results
                ]
                print(f"  ✅ Collected via {len(results)} tool calls")
                return {
                    "raw_data": formatted,
                    "tool_results_raw": formatted,
                    "tool_calls_log": tool_log,
                    "outer_loop_count": state.get("outer_loop_count", 0) + 1,
                }
            else:
                print("  ⚠️ Empty tool plan, falling back to static context")

    # === FALLBACK: 원본 static context 추출 ===
    dataset_type = state.get("dataset_type", "descriptive")

    # 데이터셋 타입별 수집 전략 프롬프트
    COLLECTOR_PROMPTS = {
        "descriptive": """Focus on gathering comprehensive technical explanations and cause-effect relationships from the context.""",

        "short_answer": """Focus on finding the exact sentence or paragraph that contains the specific factual answer. Do not miss technical values. Do not rephrase the sentence; copy the relevant content directly from the context.""",

        "multiple_choice": "Identify and extract all parts of the context that relate to the provided question and options (A, B, C, D) to compare them based on your knowledge.",

        "netconfig": """
1. Target Identification: Identify the EXACT device (hostname) mentioned in the question.
   - If multiple devices are mentioned, extract ALL relevant device blocks.
2. Direct Extraction: Extract the raw configuration lines of that device only.
3. Strict Boundary: The context provided is ALREADY scoped to the target device. Extract ALL lines from top to bottom — including lines that appear BEFORE the hostname declaration (e.g., "version 15.7", "boot" lines). Do NOT skip the first few lines.
4. Include Negation: If a feature is DISABLED (e.g., "no aaa new-model", "no ip routing", "no mpls ip"), extract that line too — it is relevant evidence of absence.
5. Absent Feature: If the specific command/feature is not found at all in the target device block, write: "[FEATURE_NOT_FOUND]"
6. For COUNT/NUMBER-type questions (e.g., "how many interfaces/routes/VRFs/hops"):
   - Extract EVERY line that could be counted: all "interface X", "ip route", "network", "vrf definition", "route-target", "router bgp", "neighbor" lines.
   - For hop-count questions: extract the full interface and routing config of ALL devices in the passage (not just one device) to enable path tracing.
   - Do NOT stop at the first relevant line — completeness is critical for counting.
7. For MAP-type questions (e.g., "list all interfaces and their X"):
   - Extract EVERY interface block (GigabitEthernet, FastEthernet, Loopback, etc.) completely.
   - Include "shutdown" lines — they indicate interface state (shutdown = down, no shutdown or absent = up).
   - Include "ip vrf forwarding" lines — their absence means the interface belongs to VRF "default".
   - Include "ip address" lines — their absence means the interface has no IP address (empty string "").
   - Do NOT skip interfaces just because they lack a specific attribute.
8. No Paraphrasing: DO NOT convert the configuration into natural language sentences.
9. No Additions: Do not add any commentary, explanations, or metadata.
10. Format: Output ONLY the raw configuration text as it appears in the source.
""",

        "netconfig_topo": """
This is a TOPOLOGY-LEVEL question (L4/L5) requiring full network simulation from static configs.

CRITICAL: The context contains configurations of ALL devices in the topology. You MUST extract ALL of them completely.

1. Extract EVERY device's configuration block in full — do NOT filter by device name.
2. For each device, include ALL of the following (they are essential for routing simulation):
   - hostname
   - ALL interface blocks with ip address, mpls ip, shutdown, vrf forwarding
   - ALL static routes (ip route ...)
   - ALL routing protocol config: router ospf, router bgp, neighbor, network, redistribute
   - ALL VRF definitions and route-targets
3. Preserve device boundaries clearly so the passage shows which config belongs to which device.
4. No Paraphrasing. No additions. Output ONLY raw configuration text.
"""
    }

    # L4/L5는 전체 토폴로지 추출 전략 사용
    level = state.get("level", "")
    if dataset_type == "netconfig" and level in ("L4", "L5"):
        effective_type = "netconfig_topo"
    else:
        effective_type = dataset_type
    base_strategy = COLLECTOR_PROMPTS.get(effective_type, COLLECTOR_PROMPTS["descriptive"])

    system_prompt = f"""You are a Network Info Collector.
TASK: {base_strategy}
- Extract all relevant information VERBATIM.
- Do not summarize or lose technical precision.

### OUTPUT FORMAT:
[START]
Context:
[DONE]"""

    # Critic으로부터 받은 피드백이 있으면 프롬프트에 포함 (재수집 루프)
    feedback = state.get("feedback_to_collector", "")
    options_str = state.get('options', '')
    feedback_str = f"\n[Critic Feedback - Re-extract based on this]: {feedback}" if feedback else ""
    prompt = f"{system_prompt}\n\nQuestion: {state['question']}\nContext: {state['context']}{feedback_str}"

    if dataset_type == "multiple_choice" and options_str:
        prompt += f"Options: {options_str}\n"

    # GPU 락을 사용하여 동시 접근 방지 (로컬 모드에서 필요) 램 용량 부족 이슈
    with gpu_lock():
        response = llm.invoke(prompt)
    raw_res = _get_text(response)

    # 즉시 파싱하여 "Context:" 레이블이 없는 순수 데이터만 저장
    extracted = _extract_from_tags(raw_res)

    return {
        "raw_data": extracted,
        "outer_loop_count": state.get("outer_loop_count", 0) + 1  # 외부 루프 카운터 증가
    }


# ==========================================
# ✂️ Agent 2: Verifier Node
# ==========================================
VERIFIER_PASS_THRESHOLD = 6

VERIFIER_RUBRIC = """You are a Network Config Verifier. Score the Extracted Context against the Question using the rubric below.
Output ONLY a valid JSON object. No markdown, no preamble, no explanation outside the JSON.

## SCORING RUBRIC (total 10 points)

[C1] Device Match (0–3 pts)
  3 = The exact hostname(s) mentioned in the question appear in the extracted context.
  1 = Hostname is partially matched or unclear.
  0 = The extracted context is for a different device, or no hostname is present.
  - For TRACEROUTE/PATH/WHAT-IF questions (L4/L5): multiple device hostnames are expected.
    3 = At least 3 device hostnames are present in the extracted context.
    1 = Only 1–2 device hostnames are present.
    0 = No hostname found.

[C2] Feature / Command Presence (0–4 pts)
  4 = The specific command or configuration section asked about is present (e.g., "router bgp", "interface GigabitEthernet", "ip route", "clock timezone").
  2 = A related section exists but the specific command is missing.
  0 = The extracted context has no lines related to the feature asked.
  - IMPORTANT for TRACEROUTE/PATH/WHAT-IF questions (L4/L5):
    These questions require static routing configuration — NOT runtime command output.
    Do NOT expect or require "traceroute", "debug", "show" command outputs.
    4 = Routing-relevant config lines are present: "ip address", "ip route", "router ospf",
        "router bgp", "neighbor", "network", "mpls ip", or "route-target".
    2 = Some interface or IP address lines exist but routing protocol config is missing.
    0 = No routing-relevant lines at all.

[C3] Completeness (0–2 pts)
  - For TRACEROUTE/PATH/WHAT-IF questions (L4/L5):
      2 = The extracted context covers ALL devices listed in [All Devices] (if provided).
      1 = Some devices are missing from the extracted context.
      0 = Most devices are missing.
  - For AGGREGATE questions (containing "which device", "how many device", "all device", "what device", "each device"):
      2 = The extracted context covers ALL devices listed in [All Devices] (if provided).
      1 = Some devices are missing from the extracted context.
      0 = Most devices are missing.
  - For single-device questions:
      2 = The relevant configuration block is extracted completely (enough lines to answer the question).
      1 = Partial extraction — some relevant lines present but the block is truncated.
      0 = Only 1–2 lines, or the context is too sparse to answer the question.

[C4] Format Integrity (0–1 pt)
  1 = Output is raw config lines verbatim (not paraphrased into natural language).
  0 = The extracted context has been converted to sentences or summaries.

## OUTPUT FORMAT (strict JSON):
{
  "scores": {
    "C1_device_match": <0|1|3>,
    "C2_feature_presence": <0|2|4>,
    "C3_completeness": <0|1|2>,
    "C4_format_integrity": <0|1>
  },
  "total": <sum of scores, 0–10>,
  "failed_criteria": ["<C1|C2|C3|C4> reason", ...],
  "feedback": "<specific re-extraction instruction for the Collector if total < 6, else empty string>"
}"""

VERIFIER_RUBRIC_GENERAL = """You are a QA Verifier. Score the Extracted Context against the Question using the rubric below.
Output ONLY a valid JSON object. No markdown, no preamble, no explanation outside the JSON.

## SCORING RUBRIC (total 10 points)

[C1] Question Relevance (0–4 pts)
  4 = The extracted context directly contains information needed to answer the question.
  2 = The context is related to the topic but does not directly address the question.
  0 = The context is off-topic or unrelated to the question.

[C2] Key Information Coverage (0–4 pts)
  - For descriptive questions: coverage of concepts, causes, or explanations the question asks about.
    4 = All key concepts or explanations required to answer are present.
    2 = Some relevant content is present but important details are missing.
    0 = No relevant content for the question.
  - For short_answer questions: presence of the specific factual value (number, name, date, etc.).
    4 = The exact answer value or the sentence containing it is present in the context.
    2 = Related content exists but the precise answer value is not clearly stated.
    0 = The answer value is absent.
  - For multiple_choice questions: coverage of content related to the options (A, B, C, D).
    4 = The context contains information relevant to at least the correct option and one distractor.
    2 = Only partial option coverage (only one option addressed).
    0 = No content relevant to any option.

[C3] Completeness (0–1 pt)
  1 = The extracted context is sufficiently complete — not truncated mid-sentence or mid-paragraph.
  0 = The context is cut off or too sparse to be useful.

[C4] No Hallucination (0–1 pt)
  1 = The extracted context appears to be a faithful excerpt from the source (no fabricated content).
  0 = The context contains text that does not match the source or appears to be generated/paraphrased beyond recognition.

## OUTPUT FORMAT (strict JSON):
{
  "scores": {
    "C1_question_relevance": <0|2|4>,
    "C2_key_info_coverage": <0|2|4>,
    "C3_completeness": <0|1>,
    "C4_no_hallucination": <0|1>
  },
  "total": <sum of scores, 0–10>,
  "failed_criteria": ["<C1|C2|C3|C4> reason", ...],
  "feedback": "<specific re-extraction instruction for the Collector if total < 6, else empty string>"
}"""


def verifier_node(state: dict):
    """
    Collector가 추출한 raw_data를 점수 기반으로 관련성 검증한다.

    채점 항목 (총 10점, 임계값 6점):
        C1 Device Match       0/1/3점  — 질문의 장비가 추출 결과에 있는가
        C2 Feature Presence   0/2/4점  — 질문이 묻는 커맨드/섹션이 존재하는가
        C3 Completeness       0/1/2점  — 블록이 충분히 완전한가
        C4 Format Integrity   0/1점    — raw config 형태인가 (자연어 변환 아닌가)

    PASS (total >= 6): raw_data를 current_passage로 전달, verifier_status = "RELEVANT"
    FAIL (total <  6): feedback_to_collector에 실패 항목 기반 재추출 지시, verifier_status = "IRRELEVANT"

    상태 업데이트:
        verifier_status (str):       "RELEVANT" | "IRRELEVANT"
        current_passage (str):       raw_data 그대로 (RELEVANT일 때)
        feedback_to_collector (str): 재추출 지시사항 (IRRELEVANT일 때)
    """
    item_id  = state.get('id', '?')
    raw_data = state.get('raw_data', '').strip()
    logger.info("[Verifier][%s] START | raw_data_len=%d chars", item_id, len(raw_data))

    # 빈 값 → LLM 호출 없이 즉시 FAIL
    if not raw_data or raw_data == '[NONE]':
        logger.warning("[Verifier][%s] raw_data empty → IRRELEVANT (score: 0/10)", item_id)
        _feedback = "Extraction was empty. Re-identify the target device from the question and extract its full configuration block verbatim."
        _round = state.get("outer_loop_count", 0)
        return {
            "verifier_status": "IRRELEVANT",
            "current_passage": "",
            "feedback_to_collector": _feedback,
            "collector_retry_log": state.get("collector_retry_log", []) + [{"round": _round, "feedback": _feedback}],
        }

    if '[FEATURE_NOT_FOUND]' in raw_data:
        logger.info("[Verifier][%s] [FEATURE_NOT_FOUND] detected → RELEVANT (instant pass)", item_id)
        return {"verifier_status": "RELEVANT", "current_passage": raw_data}

    dataset_type = state.get("dataset_type", "descriptive")

    # gold context가 있는 타입(short_answer, descriptive)은 Verifier 채점 없이 즉시 통과
    if dataset_type in ("short_answer", "descriptive"):
        logger.info("[Verifier][%s] dataset_type=%s → RELEVANT (instant pass, gold context)", item_id, dataset_type)
        return {"verifier_status": "RELEVANT", "current_passage": raw_data}

    models = get_models()
    llm = models['A']

    # netconfig 타입은 설정 파일 전용 rubric, 나머지는 범용 rubric 사용
    if dataset_type in ("netconfig", "netconfig_topo"):
        rubric = VERIFIER_RUBRIC
        all_device_names = state.get("all_device_names", [])
        device_list_str = (
            f"\n[All Devices in Topology]: {', '.join(all_device_names)}"
            if all_device_names else ""
        )
        prompt = f"{rubric}\n\nQuestion: {state['question']}{device_list_str}\nExtracted Context:\n{raw_data}"
    else:
        rubric = VERIFIER_RUBRIC_GENERAL
        prompt = f"{rubric}\n\n[Question Type]: {dataset_type}\nQuestion: {state['question']}\nExtracted Context:\n{raw_data}"

    options_str = state.get('options', '')
    if dataset_type == "multiple_choice" and options_str:
        prompt += f"\nOptions: {options_str}"

    with gpu_lock():
        _resp, in_tok, out_tok = invoke_with_tokens(llm, prompt, role='A')
    response = _get_text(_resp)

    # JSON 파싱
    scores = {}
    try:
        clean = re.sub(r"<think>.*?</think>", "", response, flags=re.DOTALL).strip()
        if clean.startswith("```"):
            clean = re.sub(r"^```[a-z]*\n?", "", clean).rstrip("```").strip()
        json_match = re.search(r'\{.*\}', clean, re.DOTALL)
        result = json.loads(json_match.group(0) if json_match else clean)

        scores   = result.get("scores", {})
        total    = int(result.get("total", 0))
        failed   = result.get("failed_criteria", [])
        feedback = result.get("feedback", "Re-extract the relevant device configuration block.")

    except Exception as e:
        logger.warning("[Verifier][%s] JSON parse failed: %s → defaulting to RELEVANT", item_id, e)
        total    = VERIFIER_PASS_THRESHOLD  # 파싱 실패 시 통과 처리 (안전 폴백)
        failed   = []
        feedback = ""

    passed = total >= VERIFIER_PASS_THRESHOLD
    # netconfig: C1_device_match / C2_feature_presence, 범용: C1_question_relevance / C2_key_info_coverage
    c1 = scores.get("C1_device_match", scores.get("C1_question_relevance", "?"))
    c2 = scores.get("C2_feature_presence", scores.get("C2_key_info_coverage", "?"))
    c3 = scores.get("C3_completeness", "?")
    c4 = scores.get("C4_format_integrity", scores.get("C4_no_hallucination", "?"))
    if passed:
        logger.info(
            "[Verifier][%s] PASS | score=%d/10 | C1=%s C2=%s C3=%s C4=%s",
            item_id, total, c1, c2, c3, c4,
        )
    else:
        logger.warning(
            "[Verifier][%s] FAIL | score=%d/10 | C1=%s C2=%s C3=%s C4=%s | failed=%s | feedback=%.200s",
            item_id, total, c1, c2, c3, c4, failed, feedback,
        )

    _tok_updated = _add_tokens(state, "model_a", in_tok, out_tok)

    if passed:
        return {
            "verifier_status": "RELEVANT",
            "current_passage": raw_data,
            "feedback_to_collector": "",
            "token_usage": _tok_updated,
        }
    else:
        _round = state.get("outer_loop_count", 0)
        return {
            "verifier_status": "IRRELEVANT",
            "current_passage": "",
            "feedback_to_collector": feedback,
            "collector_retry_log": state.get("collector_retry_log", []) + [{"round": _round, "feedback": feedback}],
            "token_usage": _tok_updated,
        }

# ==========================================
# 💡 Agent 3: Synthesizer Node
# ==========================================
def synthesizer_node(state: dict):
    """
    Verifier가 정제한 패시지(current_passage)를 기반으로 최종 후보 답변을 생성한다.

    데이터셋 타입별 출력 형식:
    - descriptive:     1-2문장의 기술적 설명
    - short_answer:    컨텍스트에서 정확히 추출한 값 (패라프레이징 금지)
    - multiple_choice: "option N: [답변 텍스트]" 형식
    - netconfig:       answer_type에 맞는 형식 (text/numeric/set/map/bool/ip)
                       정보 없으면 타입별 기본값 반환 (null/0/[]/{}/ false/"No path")

    상태 업데이트:
        candidate_answer (str): 생성된 후보 답변
        debate1_answer (str):   1차 토론 답변 스냅샷 (나중에 비교용)
    """
    item_id      = state.get('id', '?')
    inner_turn   = state.get('inner_turn_count', 0)
    dataset_type = state.get("dataset_type", "descriptive")
    passage_len  = len(state.get('current_passage', ''))
    sfb          = state.get('synthesizer_feedback', '')
    logger.info(
        "[Synthesizer][%s] START | inner_turn=%d | passage_len=%d chars | has_feedback=%s",
        item_id, inner_turn, passage_len, bool(sfb)
    )
    if sfb:
        logger.info("[Synthesizer][%s] Critic feedback: %.300s", item_id, sfb)
    models = get_models()
    llm = models['A']

    # 데이터셋별 답변 생성 규칙 프롬프트
    PROMPTS = {
        "descriptive": """You are a Network Info Synthesizer for descriptive questions.
TASK: Answer the question based on the provided passage.

RULES:
1. Provide a complete technical answer in 1-2 sentences that includes both the direct answer and the technical reasoning.
2. Output ONLY your answer. Do NOT include any meta-commentary like "analysis:", "thought:", or "reasoning:".
3. If the answer involves configurations, include the exact syntax (CLI, YAML, etc.) along with a brief explanation.
4. Match the expert-level depth and completeness expected in professional network engineering documentation.""",

        "short_answer": """You are an extractive QA model.
TASK: Extract the shortest exact span from the passage that directly answers the question.

RULES:
1. Copy the MINIMUM span verbatim — the shortest text that directly and completely answers the question.
2. Do NOT output a full sentence if the answer is a phrase or clause. Trim surrounding subject/verb.
   - "when?" → output only the temporal phrase  (e.g., "after the completion of X")
   - "what?" → output only the noun phrase       (e.g., "an IUR-ENHANCED-RELOCATION-FAILURE message to RNS-A")
   - "who?"  → output only the entity name       (e.g., "RNS-B")
3. Do NOT add or remove articles (a/an/the), leading pronouns (it/they), or any word not in the passage.
4. Do NOT paraphrase — use exact wording from the passage, character for character.
5. Do NOT add explanation, reasoning, or any text outside the extracted span.
6. If the answer requires a destination or recipient (e.g., "to RNS-A"), include it.
7. Output ONLY the extracted span — nothing else.""",

        "multiple_choice": """You are a Network Info Synthesizer for multiple-choice questions.
TASK: Answer the question based on the provided passage and your expert knowledge.

RULES:
1. Select the single best answer from the given options.
2. Use your expert knowledge of telecom standards (3GPP, IEEE, etc.). If the passage conflicts with established standards, trust the standards.
3. Output your answer in this exact format: "option N: [answer text]"
4. Do NOT include any reasoning, thoughts, or explanations in your answer.
5. You MUST always select one of the provided options. Never output an empty string.""",

        "netconfig": """You are a Network Info Synthesizer for short-answer questions.
CRITICAL RULES (absolute — override everything else):
- NEVER ask a clarifying question. NEVER say "could you specify", "please provide", or any variant. You have all the context you need.
- NEVER address the user. Output ONLY the answer value.
- If the feature is absent in the Context, output the empty value for its type (see rule 3 below).

TASK:
    1. Search the Context for the specific value requested.
    2. If the Context is "[NONE]" or the information is not found, output the empty value for the answer type (null / 0 / [] / {} / false / No path).
    If the passage is [NONE] or you cannot find accurate information, answer [NONE]

    Answer FORMAT RULES (CRITICAL - MUST FOLLOW EXACTLY):

1. output the raw answer value in ONE line:
   - text type: Output the EXACT value as it appears in the config. PRESERVE original case (e.g., "Leaf1" not "leaf1", "PE1" not "pe1").
     * Feature absent/disabled: If the feature command is NOT present in the config (e.g., no `clock timezone` command → timezone is null; `no aaa new-model` or no `aaa authentication` command → AAA is "not set"). Do NOT hallucinate default values (e.g., do NOT output "UTC" for timezone, do NOT output "local" for AAA auth if the command is missing).
     * If "[FEATURE_NOT_FOUND]" is in the passage, output: not set
     * If the feature is explicitly negated (e.g., "no aaa new-model"), output: not configured
     * NETWORK PATH questions (e.g., "list the path from X to Y", "order of devices"): Output ONLY device hostnames separated by → (e.g., "pe2→p3→p2→pe1"). Use EXACT hostname case from configs. Do NOT include IP addresses. If destination is directly reachable from source (single hop), output just the source device name (e.g., "pe2"). If no route exists at all, output: No path
     * LINK FAILURE / CONNECTIVITY questions (e.g., "The 'X-Y' link ... is down. Is it possible to communicate..."): Output EXACTLY "Possible" OR "Impossible (Reason: <FAILURE_TYPE> at <device>)". Example: "Impossible (Reason: NO_ROUTE at pe1)". Do NOT output "true", "false", "yes", "no".
     * AGGREGATE questions (e.g., "device with the most/fewest interfaces", "BGP AS numbers of all devices", "iBGP Full-Mesh status"): Compute the answer across ALL device configs in the passage and format as specified in the question (e.g., "pe1: AS 65000, pe2: AS 65000" or "OK").
     * If the question is about the leaf and there is none, output: (e.g. "leafX: AS None")
   - numeric/number type: Count carefully using these rules:
     * Interface count: Count ALL interface entries in the config (GigabitEthernet, FastEthernet, Loopback, Tunnel, etc.) — do NOT skip any interface type. Each "interface X" line = 1 interface.
     * Routing table entries: Count ALL route sources — each "network" statement + each "ip route" (static) + each redistributed protocol block. Connected interfaces also contribute routes.
     * Route Target count: Count BOTH "route-target import" AND "route-target export" lines together (NOT just one direction).
     * VRF count: Count all "vrf definition X" or "ip vrf X" blocks.
     * BGP AS number: Extract the number directly after "router bgp" (e.g., "router bgp 65000" → 65000). This is a single value, not a count.
     * Hop count (path from A to B): Trace the path step by step using next-hop / neighbor information across all device configs in the passage. Count each intermediate device as 1 hop.
     * Output ONLY the final integer or decimal. No units, no explanation.
   - set type: JSON array format (e.g., ["item1", "item2"])
     * ORDERING: List physical interfaces first (GigabitEthernet, FastEthernet, etc.), Loopback interfaces LAST.
       e.g., ["GigabitEthernet0/0", "GigabitEthernet0/1", "Loopback0"]
   - map type: JSON object format. Build the map by enumerating ALL interfaces. Apply these inference rules:
     * Interface STATUS map: if "shutdown" is present → "down", if absent or "no shutdown" → "up"
     * VRF BINDING map: if "ip vrf forwarding X" is present → X, if absent → "default" (every interface not explicitly assigned is in the default VRF)
     * IP ADDRESS map: if "ip address A.B.C.D M.M.M.M" → "A.B.C.D/prefix", if absent → "" (empty string)
     * Route-target/VRF map: extract key-value pairs explicitly from config
     * NEVER output "unknown" or "null" as a value — apply the inference rules above instead.
     * Include ALL interfaces (GigabitEthernet, Loopback, etc.). Do NOT skip interfaces.
     * Empty map {} is forbidden — if passage is relevant, you MUST enumerate the interfaces.
     * ORDERING: List physical interfaces first (GigabitEthernet, FastEthernet, etc.), Loopback interfaces LAST.
       e.g., {"GigabitEthernet0/0": "...", "GigabitEthernet0/1": "...", "Loopback0": "..."}
   - boolean type: true or false
   - ip type: example: "ip address 172.16.1.2 255.255.255.0" -> Output: "172.16.1.2/24". If there is a Loopback interface, use the Loopback IP and list it LAST. If there's no Setting: "GigabitEthernet0/0: "

2. CORE SEARCH RULES (CRITICAL)
- **Scope Restriction**: Identify the target device and search ONLY within its specific configuration block (e.g., between `<Leaf1.cfg>` and the next tag). IGNORE content outside this block.
- **No Inference**: Do NOT assume settings exist just because they appear on connected devices (e.g., configurations on a PE router do NOT imply the same settings on a Leaf switch).
- **Strict 'None' Handling**: If the specific command is missing in the target block, do NOT guess or use unrelated values (like IPs). Return the Empty Value defined below.

3. If NOT_CONFIGURED or information missing:
   - text: null
   - numeric: 0
   - set, list: []
   - map: {}
   - boolean: false
   - path: No path
   """,

        "netconfig_topo": """You are a Network Routing Simulator. Your task is to answer L4/L5 network analysis questions by simulating routing behavior from static device configurations.
CRITICAL: NEVER ask a clarifying question. NEVER address the user. Output ONLY the answer value.

CONTEXT: You are given the complete configuration of ALL devices in the network topology. Use them to simulate routing.

# SIMULATION RULES:
1. ROUTING PATH (L4) — "list the path from X to Y":
   - Start at the SOURCE device. Check its routing table (static routes: "ip route", dynamic: BGP/OSPF neighbors, default route: "ip route 0.0.0.0 0.0.0.0 <next-hop>").
   - Identify which interface the next-hop IP belongs to, and which device is connected on that subnet.
   - Repeat hop-by-hop until you reach the destination IP or hit a dead end.
   - Output: device hostnames separated by → (e.g., "leaf2→pe1→p2→p3"). Use EXACT hostname case. Do NOT include IPs.
   - If no route exists to reach the destination: output "No path"
   - If destination IP belongs to an interface of a directly connected device: that device is the last hop.

2. WHAT-IF / FAULT ANALYSIS (L5) — "when link X-Y fails / device X is down":
   Follow these steps IN ORDER before writing the answer:

   [Step 1] Build the normal topology.
   - List every device and its active interfaces with IP/subnet.
   - List every routing entry (static "ip route", BGP neighbor, OSPF network) per device.

   [Step 2] Identify the normal path from source to destination.
   - Trace hop-by-hop using the routing tables built in Step 1.
   - Write the path as: src→...→dst

   [Step 3] Apply the failure.
   - Remove the specified link (both directions) or device from the topology.
   - Mark all interfaces/routes that become unavailable as a result.

   [Step 4] Re-trace the path after failure.
   - Starting from the source again, follow routing tables with the failed components removed.
   - If a device has no valid next-hop toward the destination → it has NO_ROUTE.
   - If an alternative path exists via a different next-hop → trace it fully.

   [Step 5] Determine the answer.
   - Blocking device: the first device in the path that has NO_ROUTE after failure.
   - Connectivity: "Possible (Alternative route: X→Y→Z)" if alternative path found, else "Impossible (Reason: NO_ROUTE at <device>)".
   - Count: count the number of affected routes/devices.

   [Step 6] Output ONE LINE — the final answer only (no steps, no explanation).


# Answer FORMAT RULES (CRITICAL - MUST FOLLOW EXACTLY):

1. output the raw answer value in ONE line:
   - text type: Output the EXACT value as it appears in the config. PRESERVE original case (e.g., "Leaf1" not "leaf1", "PE1" not "pe1").
     * Feature absent/disabled: If the feature command is NOT present in the config (e.g., no `clock timezone` command → timezone is null; `no aaa new-model` or no `aaa authentication` command → AAA is "not set"). Do NOT hallucinate default values (e.g., do NOT output "UTC" for timezone, do NOT output "local" for AAA auth if the command is missing).
     * If "[FEATURE_NOT_FOUND]" is in the passage, output: not set
     * If the feature is explicitly negated (e.g., "no aaa new-model"), output: not configured
     * NETWORK PATH questions (e.g., "list the path from X to Y", "order of devices"): Output ONLY device hostnames separated by → (e.g., "pe2→p3→p2→pe1"). Use EXACT hostname case from configs. Do NOT include IP addresses. If destination is directly reachable from source (single hop), output just the source device name (e.g., "pe2"). If no route exists at all, output: No path
     * LINK FAILURE / CONNECTIVITY questions (e.g., "The 'X-Y' link ... is down. Is it possible to communicate..."): Output EXACTLY "Possible" OR "Impossible (Reason: <FAILURE_TYPE> at <device>)". Example: "Impossible (Reason: NO_ROUTE at pe1)". Do NOT output "true", "false", "yes", "no".
     * AGGREGATE questions (e.g., "device with the most/fewest interfaces", "BGP AS numbers of all devices", "iBGP Full-Mesh status"): Compute the answer across ALL device configs in the passage and format as specified in the question (e.g., "pe1: AS 65000, pe2: AS 65000" or "OK").
     * If the question is about the leaf and there is none, output: (e.g. "leafX: AS None")
   - numeric/number type: Count carefully using these rules:
     * Interface count: Count ALL interface entries in the config (GigabitEthernet, FastEthernet, Loopback, Tunnel, etc.) — do NOT skip any interface type. Each "interface X" line = 1 interface.
     * Routing table entries: Count ALL route sources — each "network" statement + each "ip route" (static) + each redistributed protocol block. Connected interfaces also contribute routes.
     * Route Target count: Count BOTH "route-target import" AND "route-target export" lines together (NOT just one direction).
     * VRF count: Count all "vrf definition X" or "ip vrf X" blocks.
     * BGP AS number: Extract the number directly after "router bgp" (e.g., "router bgp 65000" → 65000). This is a single value, not a count.
     * Hop count (path from A to B): Trace the path step by step using next-hop / neighbor information across all device configs in the passage. Count each intermediate device as 1 hop.
     * Output ONLY the final integer or decimal. No units, no explanation.
   - set type: JSON array format (e.g., ["item1", "item2"])
     * ORDERING: List physical interfaces first (GigabitEthernet, FastEthernet, etc.), Loopback interfaces LAST.
       e.g., ["GigabitEthernet0/0", "GigabitEthernet0/1", "Loopback0"]
   - map type: JSON object format. Build the map by enumerating ALL interfaces. Apply these inference rules:
     * Interface STATUS map: if "shutdown" is present → "down", if absent or "no shutdown" → "up"
     * VRF BINDING map: if "ip vrf forwarding X" is present → X, if absent → "default" (every interface not explicitly assigned is in the default VRF)
     * IP ADDRESS map: if "ip address A.B.C.D M.M.M.M" → "A.B.C.D/prefix", if absent → "" (empty string)
     * Route-target/VRF map: extract key-value pairs explicitly from config
     * NEVER output "unknown" or "null" as a value — apply the inference rules above instead.
     * Include ALL interfaces (GigabitEthernet, Loopback, etc.). Do NOT skip interfaces.
     * Empty map {} is forbidden — if passage is relevant, you MUST enumerate the interfaces.
     * ORDERING: List physical interfaces first (GigabitEthernet, FastEthernet, etc.), Loopback interfaces LAST.
       e.g., {"GigabitEthernet0/0": "...", "GigabitEthernet0/1": "...", "Loopback0": "..."}
   - boolean type: true or false
   - ip type: example: "ip address 172.16.1.2 255.255.255.0" -> Output: "172.16.1.2/24". If there is a Loopback interface, use the Loopback IP and list it LAST. If there's no Setting: "GigabitEthernet0/0: "

2. CORE SEARCH RULES (CRITICAL)
- **Scope Restriction**: Identify the target device and search ONLY within its specific configuration block (e.g., between `<Leaf1.cfg>` and the next tag). IGNORE content outside this block.
- **No Inference**: Do NOT assume settings exist just because they appear on connected devices (e.g., configurations on a PE router do NOT imply the same settings on a Leaf switch).
- **Strict 'None' Handling**: If the specific command is missing in the target block, do NOT guess or use unrelated values (like IPs). Return the Empty Value defined below.

3. If NOT_CONFIGURED or information missing:
   - text: null
   - numeric: 0
   - set, list: []
   - map: {}
   - boolean: false
   - path: No path
"""
    }

    # L4/L5는 토폴로지 시뮬레이션 전략 사용
    level = state.get("level", "")
    if dataset_type == "netconfig" and level in ("L4", "L5"):
        effective_type = "netconfig_topo"
    else:
        effective_type = dataset_type

    base_system = PROMPTS.get(effective_type, PROMPTS["descriptive"])

    # answer_type 기반 포맷 힌트 추가 — Skeptic 거부율 감소 목적
    ANSWER_TYPE_HINTS = {
        "text": "\nFORMAT HINT: Output ONLY the value, not the full config line. Examples: 'transport input ssh' → output 'ssh'. 'login local' → output 'local'. 'logging buffered 51200 warnings' → output 'warnings'. Include ALL parts for multi-word values (e.g., timezone 'KST 9' not just 'KST'). Do NOT add quotes. CRITICAL: When not configured, output 'N/A'. For Cisco IOS defaults: CDP is 'Enabled' unless 'no cdp run' is present. IP source-route is 'Enabled' unless 'no ip source-route' is present. For comparison text (e.g., 'Compare BGP AS of A and B'), use format: 'deviceA: AS X, deviceB: AS Y' (use 'N/A' if not configured). Use ' -> ' for paths (NOT '→'). Use 'NOT_TRAVERSED'/'TRAVERSED' for waypoint questions.",
        "scalar_str": "\nFORMAT HINT: Output ONLY the value, not the full config line. Examples: 'transport input ssh' → 'ssh'. 'login local' → 'local'. Do NOT add quotes. When not configured, output 'N/A'. Cisco IOS defaults: CDP is 'Enabled' unless 'no cdp run' exists.",
        "number": "\nFORMAT HINT: Output a single integer. Example: 5, 12, 0",
        "scalar_int": "\nFORMAT HINT: Output a single integer. Example: 5, 12, 0",
        "set": "\nFORMAT HINT: Output a JSON array of strings. Example: [\"item1\", \"item2\"]. Use [] if none found.",
        "set_str": "\nFORMAT HINT: Output a JSON array of strings. Example: [\"item1\", \"item2\"]. Use [] if none found.",
        "map": "\nFORMAT HINT: Output a JSON object. For comparison questions, use EXACTLY these 3 keys (no others): {\"difference\": N, \"host1_count\": N, \"host2_count\": N}. Example: {\"difference\": 2, \"host1_count\": 4, \"host2_count\": 6}. For status mappings: {\"key\": \"value\"}. Use {} if none found.",
        "map_str_int": "\nFORMAT HINT: For comparison questions, use EXACTLY these 3 keys — difference, host1_count, host2_count — nothing else: {\"difference\": N, \"host1_count\": N, \"host2_count\": N}. Example: 'Compare interface count of P8 and PE2' → {\"difference\": 2, \"host1_count\": 4, \"host2_count\": 6}. Do NOT use device names as keys. For other mappings: {\"PE1\": 5, \"PE2\": 3}.",
        "map_str_str": "\nFORMAT HINT: Output a JSON object with string keys and string values. For interface status: {\"GigabitEthernet0/0\": \"up\", \"Loopback0\": \"up\"}.",
        "bool": "\nFORMAT HINT: Output exactly 'Enabled' or 'Disabled' for feature status. Output 'true' or 'false' for yes/no questions.",
        "path": "\nFORMAT HINT: Output device hostnames separated by ' -> '. Example: PE1 -> P2 -> P3 -> PE2. Or 'No path' if unreachable.",
    }
    answer_type = state.get("answer_type", "")
    format_hint = ANSWER_TYPE_HINTS.get(answer_type, "")

    system_prompt = base_system + format_hint + """
### OUTPUT FORMAT:
[START]
Answer:
[DONE]"""

    prompt = f"{system_prompt}\n\nQuestion: {state.get('question')}\nPassage: {state.get('current_passage')}"

    # Critic의 재생성 지시가 있으면 (REVISE 루프) 프롬프트에 포함
    synthesizer_feedback = state.get("synthesizer_feedback", "")
    if synthesizer_feedback:
        # 이전 라운드 답변 이력 구성 — 같은 답 반복 방지
        prev_answers = state.get("candidate_answers", [])
        if prev_answers:
            history_lines = "\n".join(
                f"  Round {entry['round']}: \"{entry['answer']}\" → REVISE"
                for entry in prev_answers
            )
            history_str = f"\n\n[Answer History - DO NOT repeat any of these]:\n{history_lines}"
        else:
            history_str = ""
        prompt += (
            f"{history_str}"
            f"\n\n[Critic Feedback - Revise your answer based on this critique]:\n{synthesizer_feedback}"
            f"\nDo NOT repeat any previously rejected answer. Fix the specific issue described above."
        )

    with gpu_lock():
        _resp, in_tok, out_tok = invoke_with_tokens(llm, prompt, role='A')
    response = _get_text(_resp)
    # "Answer:" 레이블을 제거하고 순수 답변 값만 추출
    answer_val = _extract_from_tags(response)
    # map_str_int 비교 질문에서 장비명 key → 표준 3-key 포맷으로 후처리 변환
    answer_val = _normalize_map_str_int_comparison(
        answer_val, state.get("question", ""), state.get("answer_type", "")
    )

    round_num = state.get("inner_turn_count", 0) + 1
    logger.info(
        "[Synthesizer][%s] DONE | round=%d | model_a tokens(in=%d out=%d) | candidate_answer=%.300s",
        item_id, round_num, in_tok, out_tok, answer_val
    )
    return {
        "candidate_answer": answer_val,
        "debate1_answer": answer_val,
        "candidate_answers": state.get("candidate_answers", []) + [{"round": round_num, "answer": answer_val}],
        "token_usage": _add_tokens(state, "model_a", in_tok, out_tok),
    }
