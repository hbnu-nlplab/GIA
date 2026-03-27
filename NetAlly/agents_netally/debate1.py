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
from contextlib import contextmanager
from agents_netally.model_loader import get_models
USE_LOCAL = False
import threading

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

    # === MCP MODE: 도구 카탈로그가 있으면 도구 호출 ===
    tool_catalog = state.get("tool_catalog", "")
    if tool_catalog:
        from agents_netally.tool_dispatch import (
            plan_tool_calls, execute_tool_calls, format_tool_results,
            get_registered_tools, _normalize_device_args,
        )
        tools = get_registered_tools()
        if tools:
            feedback = state.get("feedback_to_collector", "")
            level = state.get("level", "")
            plans = plan_tool_calls(llm, state["question"], tool_catalog, level, feedback)
            plans = _normalize_device_args(plans)
            print(f"  📋 Tool plan: {[p.get('tool') for p in plans]}")

            if plans:
                results = execute_tool_calls(plans, tools)
                formatted = format_tool_results(results)
                tool_log = state.get("tool_calls_log", []) + [
                    {"tool": r["tool"], "args": r["args"], "elapsed_ms": r["elapsed_ms"]}
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
7. No Paraphrasing: DO NOT convert the configuration into natural language sentences.
8. No Additions: Do not add any commentary, explanations, or metadata.
9. Format: Output ONLY the raw configuration text as it appears in the source.
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
def verifier_node(state: dict):
    """
    Collector가 추출한 원시 정보(raw_data)에서 질문과 무관한 줄을 제거한다.

    핵심 규칙:
    - 원본 텍스트를 한 글자도 수정하지 않음 (파라프레이징 금지)
    - 관련 있는 줄은 그대로 유지, 무관한 줄만 삭제
    - 출력은 요약이 아닌 원시 설정 라인들의 집합

    상태 업데이트:
        current_passage (str): 정제된 패시지 (Synthesizer에서 사용)
    """
    print("✂️ [Agent 2: Verifier] Cleaning irrelevant data...")

    # raw_data가 비어있으면 LLM 호출 없이 즉시 반환 (메타 응답 방지)
    raw_data = state.get('raw_data', '').strip()
    if not raw_data or raw_data in ('[NONE]', '[FEATURE_NOT_FOUND]'):
        print("  ⏭️ Verifier skipped: raw_data is empty or [NONE]")
        return {"current_passage": raw_data}

    # MCP 도구 결과가 있으면 Verifier bypass — 도구 출력은 이미 구조화/필터링됨
    tool_results_raw = state.get("tool_results_raw", "")
    if tool_results_raw:
        print("  ⏭️ Verifier skipped: tool-based Collector output (already structured)")
        return {"current_passage": raw_data}

    # L3~L5는 Verifier 필터링 없이 그대로 통과
    # L3: cross-device 비교 질문에서 Verifier가 필요한 context를 잘라낼 수 있음
    # L4/L5: 전체 토폴로지 config가 필요하므로 원래부터 bypass
    level = state.get("level", "")
    if level in ("L3", "L4", "L5"):
        print(f"  ⏭️ Verifier skipped: level={level}, preserving full context")
        return {"current_passage": raw_data}

    models = get_models()
    llm = models['A']

    system_prompt = """You are a Network Info Verifier.
TASK: Filter irrelevant lines from the 'Extracted Context'.

RULES:
1. STRICT RESTRAINT: Do NOT change a single character of the original text.
2. DO NOT paraphrase. DO NOT create sentences.
3. If a line is irrelevant to the device or question, DELETE the entire line.
4. If a line is relevant, KEEP it exactly as it is (Raw Config Format).
5. Output must be a collection of RAW CONFIGURATION LINES, not a summary.
6. Keep negation lines (e.g., "no aaa new-model", "no ip routing") if they are relevant to the question — they indicate a feature is disabled.
7. If the Extracted Context contains "[FEATURE_NOT_FOUND]", keep it as-is.
8. Only write [NONE] if the Extracted Context is completely empty or entirely unrelated to the question.
9. TOPOLOGY/PATH/LINK-FAILURE questions: If the question asks about a network path, route from A to B, or what happens when links go down, keep ALL device configuration blocks intact. Do NOT filter out routing tables, static routes, or configs of intermediate devices — every device's config is needed to trace the path.

### OUTPUT FORMAT:
[START]
Passage:
[DONE]"""

    prompt = f"{system_prompt}\n\nQuestion: {state['question']}\nExtracted Context: {state.get('raw_data', '')}"
    dataset_type = state.get("dataset_type", "descriptive")
    options_str = state.get('options', '')
    if dataset_type == "multiple_choice" and options_str:
        prompt += f"Options: {options_str}\n"

    with gpu_lock():
        response = _get_text(llm.invoke(prompt))
    refined = _extract_from_tags(response)
    return {"current_passage": refined}


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
    print("💡 [Agent 3: Synthesizer] Generating Answer...")
    models = get_models()
    llm = models['A']
    dataset_type = state.get("dataset_type", "descriptive")

    # 데이터셋별 답변 생성 규칙 프롬프트
    PROMPTS = {
        "descriptive": """You are a Network Info Synthesizer for descriptive questions.
TASK: Answer the question based on the provided passage.

RULES:
1. Provide a complete technical answer in 1-2 sentences that includes both the direct answer and the technical reasoning.
2. Output ONLY your answer. Do NOT include any meta-commentary like "analysis:", "thought:", or "reasoning:".
3. If the answer involves configurations, include the exact syntax (CLI, YAML, etc.) along with a brief explanation.
4. Match the expert-level depth and completeness expected in professional network engineering documentation.""",

        "short_answer": """You are a Network Info Synthesizer for short-answer questions.
TASK: Answer the question based on the provided passage.

RULES:
1. Find the exact answer span in the context.
2. Output ONLY the extracted text in answer - no explanations, no reasoning, no thoughts.
3. Do NOT paraphrase - use exact wording from context.
4. If the answer is a value with a unit, include both.
5. You must answer using the information provided in the passage.""",

        "multiple_choice": """You are a Network Info Synthesizer for multiple-choice questions.
TASK: Answer the question based on the provided passage.

RULES:
1. Select the single best answer from the given options.
2. Use your expert knowledge of telecom standards (3GPP, IEEE, etc.).
3. Output your answer in this exact format: "option N: [answer text]"
4. Do NOT include any reasoning, thoughts, or explanations in answer.""",

        "netconfig": """You are a Network Info Synthesizer for short-answer questions.
        TASK:
    1. Search the Context for the specific value requested.
    2. If the Context is "[NONE]" or the information is not found, the Passage must be "[NONE]".
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

CONTEXT: You are given the complete configuration of ALL devices in the network topology. Use them to simulate routing.

SIMULATION RULES:
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

3. OUTPUT: ONE LINE answer only. No explanation. No reasoning. Just the answer value.
   - Path: "leaf2→pe1" or "No path"
   - Device: "pe1"
   - Connectivity: "Possible (Alternative route: p1→p2→p3)" or "Impossible (Reason: NO_ROUTE at pe1)"
   - Count: integer (e.g., "18")
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
        "scalar_str": "\nFORMAT HINT: Output a single string value. Example: PE1, GigabitEthernet0/0, 65000",
        "scalar_int": "\nFORMAT HINT: Output a single integer. Example: 5, 12, 0",
        "set_str": "\nFORMAT HINT: Output a JSON array of strings. Example: [\"item1\", \"item2\"]",
        "map_str_int": "\nFORMAT HINT: Output a JSON object with string keys and integer values. Example: {\"PE1\": 5, \"PE2\": 3}",
        "map_str_str": "\nFORMAT HINT: Output a JSON object with string keys and string values. Example: {\"GigabitEthernet0/0\": \"up\", \"Loopback0\": \"up\"}",
        "bool": "\nFORMAT HINT: Output exactly 'true' or 'false' (lowercase, no quotes).",
        "path": "\nFORMAT HINT: Output device hostnames separated by arrow. Example: pe1→p2→p3→pe2. Or 'No path' if unreachable.",
    }
    answer_type = state.get("answer_type", "")
    format_hint = ANSWER_TYPE_HINTS.get(answer_type, "")

    system_prompt = base_system + format_hint + """
### OUTPUT FORMAT:
[START]
Answer:
[DONE]"""

    prompt = f"{system_prompt}\n\nQuestion: {state['question']}\nOptions: {state.get('options', 'N/A')}\nContext (Passage): {state.get('current_passage', '')}"
    options_str = state.get('options', '')
    if dataset_type == "multiple_choice" and options_str:
        prompt += f"Options: {options_str}\n"

    with gpu_lock():
        response = _get_text(llm.invoke(prompt))
    # "Answer:" 레이블을 제거하고 순수 답변 값만 추출
    answer_val = _extract_from_tags(response)

    return {
        "candidate_answer": answer_val,
        "debate1_answer": answer_val  # 1차 답변 스냅샷 저장
    }
