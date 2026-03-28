# agents_netally — MAS + MCP Tool Integration

agents_v3(팀원 MAS)를 기반으로 MCP 도구 호출을 통합한 NetAlly 전용 Multi-Agent System.

## Internal Architecture (MAS + MCP)

```
                    User Question
                    + level (L1~L5)
                    + answer_type
                         |
                         v
    +============================================+
    |            COLLECTOR (Agent 1)              |
    |                                            |
    |  1. LLM reads question + tool catalog      |
    |  2. Generates JSON tool plan               |
    |     [{"tool":"nso_get_device_info",         |
    |       "args":{"device":"PE1"}}]             |
    |  3. Executes tools (sync, sequential)       |
    |  4. Formats results as structured context   |
    |                                            |
    |  Tool Selection Guide:                      |
    |  - L1: nso_get_device_info (1 call)        |
    |  - L2: nso_get_all_device_info (cached)    |
    |  - L3: nso_get_all_* + batfish_bgp         |
    |  - L4: batfish_traceroute/reachability      |
    |  - L5: nso_get_all_device_info (topology)   |
    |       + batfish_*_failure (simulation)      |
    +============================================+
                         |
                    raw_data + tool_results_raw
                         |
                         v
    +============================================+
    |            VERIFIER (Agent 2)               |
    |                                            |
    |  - Tool results present? -> BYPASS          |
    |    (already structured, no filtering needed)|
    |  - Static context? -> LLM filtering         |
    |    (remove irrelevant config blocks)        |
    +============================================+
                         |
                    current_passage
                         |
                         v
    +============================================+
    |           SYNTHESIZER (Agent 3)             |
    |                                            |
    |  - Generates candidate answer from passage  |
    |  - answer_type format hints applied:        |
    |    text: "Output COMPLETE value, use N/A"   |
    |    set: "JSON array [...]"                  |
    |    map: "JSON object {difference:N,...}"     |
    |    number: "Single integer"                 |
    |    bool: "Enabled/Disabled"                 |
    |    path: "PE1 -> P2 -> P3 -> PE2"          |
    +============================================+
                         |
                    candidate_answer
                         |
                         v
    +===========================================+
    |  SUPPORTER (Agent 4)  <-->  SKEPTIC (Agent 5)  |
    |                                           |
    |  Supporter: 답변 지지 논거 생성             |
    |  Skeptic:  답변 비판 + 판정                |
    |    -> [ACCEPT]: final_answer 확정           |
    |    -> [CONTINUE]: inner loop 재시도         |
    |    -> [NEED_MORE_INFO]: Collector에 피드백  |
    |       (outer loop, 추가 도구 호출 가능)     |
    +===========================================+
                         |
                    final_answer
```

## Tool Execution Flow (도구 호출 상세)

```
Collector LLM
    |
    | "이 질문에 어떤 도구?" (JSON plan 생성)
    v
tool_dispatch.execute_tool_calls()
    |
    | plans = [{"tool": "nso_get_device_info", "args": {"device": "PE1"}}]
    |
    v
For each plan (sequential):
    ThreadPoolExecutor
        |
        v
    asyncio.run(tool_fn.ainvoke(args))
        |
        v
    direct_tools.py @tool
        |
        +-- NSO tools: _invoke(network_query, ...) -> nso.py RESTCONF
        |
        +-- Batfish basic: bf.traceroute() / bf.get_bgp_sessions()
        |     (순수 Python 직접 호출, @tool 중첩 없음)
        |
        +-- Batfish L4/L5: builder.acl_blocking_point() / builder.link_failure_impact()
        |     (BatfishBuilder 직접 호출, fork_snapshot 포함)
        |
        v
    format_tool_results() -> structured text for downstream agents
```

## Tool Catalog (18 tools)

### NSO Tools (5) — Config Query via RESTCONF
| Tool | Description | Returns |
|------|-------------|---------|
| `nso_get_device_info(device)` | 단일 장비 config summary | hostname, aaa, vrf, interfaces, routing... |
| `nso_get_all_device_info()` | 전체 장비 summary + **aggregations** | devices_with_aaa, interface_counts, vrf_counts... |
| `nso_get_interfaces(device)` | 인터페이스 목록 (서브트리 쿼리) | interface list |
| `nso_get_all_interfaces()` | 전체 인터페이스 + counts | per-device interface counts |
| `nso_get_routing(device, protocol)` | BGP/OSPF 라우팅 정보 | AS number, neighbors |

### Batfish Basic (4) — Static Analysis
| Tool | Description | Returns |
|------|-------------|---------|
| `batfish_reachability(src, dst)` | 도달성 테스트 | reachable, disposition |
| `batfish_traceroute(src, dst)` | 경로 추적 | path[], **hop_count**, path_str |
| `batfish_bgp_sessions(device?)` | BGP 세션 상태 | sessions, **summary** (under_peered) |
| `batfish_route_table(device)` | 라우팅 테이블 | routes, **route_count**, protocol_counts |

### Batfish L4 (4) — Detailed Analysis
| Tool | Description |
|------|-------------|
| `batfish_acl_check(src_ip, dst_ip)` | ACL 차단 분석 |
| `batfish_loop_check()` | 라우팅 루프 탐지 |
| `batfish_blackhole_check(prefix)` | 블랙홀 경로 탐지 |
| `batfish_waypoint_check(src, dst, waypoint)` | 경유 장비 검증 |

### Batfish L5 (5) — What-If Simulation
| Tool | Description |
|------|-------------|
| `batfish_link_failure(node1, node2, src?, dst?)` | 단일 링크 장애 시뮬레이션 |
| `batfish_multi_link_failure(link1_n1, link1_n2, link2_n1, link2_n2, src, dst)` | **2개 링크 동시** 장애 |
| `batfish_node_failure(node)` | 단일 노드 장애 (blast radius) |
| `batfish_multi_node_failure(node1, node2)` | **2개 노드 동시** 장애 |
| `batfish_spof_detection()` | 단일 장애점(SPOF) 탐지 |

## Key Design Decisions

### 1. @tool 중첩 금지 (Anti-pattern)
```
BAD:  @tool -> @tool.invoke()   (LangChain 결과 손실)
GOOD: @tool -> Python function() (직접 호출)
```
Batfish 도구는 `l5_analyzer.py`의 순수 Python 함수를 직접 호출.

### 2. Collector = Tool Planner 통합
agents_v3와 동일한 5-agent 구조 유지. 별도 Tool Planner LLM 제거.
```
v3 원본: Collector -> Verifier -> Synthesizer -> Supporter <-> Skeptic
netally:  동일 구조, Collector에 도구 선택 능력 추가
```

### 3. Session-level Caching
`nso_get_all_device_info()`, `nso_get_all_interfaces()`는 세션 내 캐싱.
첫 호출만 NSO 20x2 HTTP, 이후 0ms.

### 4. Aggregations (도구가 계산)
LLM이 20개 장비를 순회하며 필터링하지 않도록, 도구가 미리 집계:
```json
{
  "aggregations": {
    "devices_with_aaa": ["PE1","PE2","PE3","PE4"],
    "interface_counts": {"PE1":9, "Leaf1":8, ...},
    "vrf_counts": {"PE1":3, "Leaf1":0, ...}
  }
}
```

### 5. L5 Fallback (NSO 추론)
Batfish 시뮬레이션 실패 시, Collector가 먼저 가져온 NSO 토폴로지 데이터로 LLM이 추론.

## vs agents_v3 (원본)

| 항목 | agents_v3 | agents_netally |
|------|-----------|----------------|
| Collector 입력 | static config 텍스트 | **MCP 도구 호출 (NSO + Batfish)** |
| 도구 선택 | 없음 | LLM 프롬프트 기반 자율 선택 |
| Verifier | LLM 필터링 | 도구 결과면 **bypass** |
| Synthesizer | 기본 | answer_type **포맷 힌트** 추가 |
| Skeptic | config 텍스트 검증 | 도구 결과도 유효한 evidence로 인정 |
| 5-agent 구조 | 동일 | **동일** |
| debate loop | inner 3, outer 3 | inner 2, outer 2 |
| 도구 수 | 0 | **18** (5 NSO + 13 Batfish) |

## Files

| File | Description |
|------|-------------|
| `state.py` | NetAgentState + tool fields (tool_calls_log, tool_results_raw, tool_catalog) |
| `model_loader.py` | OpenRouter/OpenAI dual-model (A: synthesis, B: collection/critique) |
| `tool_dispatch.py` | Sync tool execution + result formatting (no async nesting) |
| `debate1.py` | Collector(도구 선택+호출), Verifier(bypass), Synthesizer(포맷힌트) |
| `debate2.py` | Supporter, Skeptic(도구 관대화 프롬프트) |
| `main_netally.py` | Entry point: build_graph() + init_models() |

## Evaluation

```bash
# Direct evaluation (no web server needed)
cd NetAlly
.venv/bin/python scripts/run_netally_eval_direct.py \
  --dataset ../Data/Pnetlab/LabB_.../en.json \
  --lab Lab-B

# Level filtering
.venv/bin/python scripts/run_netally_eval_direct.py \
  --dataset ... --include-levels L4 L5

# Scoring (TA-Acc)
python ../Experiment/code/NetConfigQA2_2/analyze_results.py results/netally_eval_direct_*.json
```

## Performance (gpt-4o-mini, 100 questions)

| Level | TA-Acc | Avg Time |
|-------|--------|----------|
| L1 | 80% | 10s |
| L2 | 100% | 13s |
| L3 | 60% | 14s |
| L4 | 85% | 7s |
| L5 | 15% | 10-230s |
| **Overall** | **68%** | **10.5s** |
