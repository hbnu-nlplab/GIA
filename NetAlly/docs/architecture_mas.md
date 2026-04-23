# NetAlly Architecture

NetAlly는 **MCP 기반 도구 호출**과 **Multi-Agent Debate**를 결합한 네트워크 설정 분석 시스템이다.
LLM이 네트워크 도구(NSO RESTCONF, Batfish)를 자율적으로 호출하여 데이터를 수집하고,
5-Agent 토론 구조로 답변 품질을 보장한다.

---

## System Overview (사용자 플로우)

```
+------------------+
|    User (Web)    |
|  "PE1의 SSH 버전?" |
+--------+---------+
         |
         | POST /api/chat (SSE)
         v
+------------------------------------------+
|           NetAlly Backend                 |
|            (FastAPI)                      |
|                                          |
|  +------------------------------------+  |
|  |         Runtime Selector            |  |
|  |  single_executor | team_multi       |  |
|  +--------+-----------+---------------+  |
|           |           |                  |
|     Single LLM   MAS (agents_netally)    |
|     + Tools       5-Agent Debate         |
|                   + MCP Tools            |
+--------+-----------+---------+-----------+
         |           |         |
         v           v         v
+--------+--+ +------+------+ +------+------+
|    NSO     | |   Batfish   | |  PNETLab   |
| (RESTCONF) | | (Simulation)| |  (LabFS)   |
+-----+------+ +------+------+ +------+------+
      |               |               |
      v               v               v
+--------------------------------------------+
|         Network Devices (PNETLab)           |
|  PE1  PE2  PE3  PE4  P1..P8  Leaf1..Leaf8  |
|              (20 nodes)                     |
+--------------------------------------------+
```

---

## User Interaction Flow (실사용 흐름)

### Flow 1: 단순 질문 (L1 — Config 조회)

```
User: "PE1의 SSH 버전은?"
  |
  v
Collector: tool_catalog 분석 -> nso_get_device_info(device="PE1") 선택
  |
  v
NSO RESTCONF: GET /data/tailf-ncs:devices/device=PE1/config
  -> config_summary: {ssh_version: 2, hostname: PE1, ...}
  |
  v
Collector: raw_data = "SSH version: 2"
  -> Verifier (bypass) -> Synthesizer -> "2"
  -> Supporter: "config에 ssh version 2 확인"
  -> Skeptic: [ACCEPT]
  |
  v
User: "2"                                    [~7초, 도구 1회]
```

### Flow 2: 집계 질문 (L2 — 전체 장비 분석)

```
User: "AAA가 활성화된 장비는?"
  |
  v
Collector: nso_get_all_device_info() 선택
  |
  v
NSO: 20개 장비 config_summary 수집 (캐시 히트 시 0ms)
  -> aggregations: {devices_with_aaa: ["PE1","PE2","PE3","PE4"]}
  |
  v
Synthesizer: ["PE1","PE2","PE3","PE4"]
  -> Skeptic: [ACCEPT]
  |
  v
User: ["PE1","PE2","PE3","PE4"]              [~13초, 도구 1회]
```

### Flow 3: 경로 분석 (L4 — Batfish Simulation)

```
User: "P6에서 10.0.5.1까지 경로?"
  |
  v
Collector: batfish_traceroute(src="p6", dst="10.0.5.1") 선택
  |
  v
Batfish: IP resolve (10.0.5.1 -> p4) -> traceroute simulation
  -> {path: ["p6","p5","p3","p4"], hop_count: 4, path_str: "p6 -> p5 -> p3 -> p4"}
  |
  v
Synthesizer: "p6 -> p5 -> p3 -> p4"
  -> Skeptic: [ACCEPT]
  |
  v
User: "p6 -> p5 -> p3 -> p4"                [~7초, 도구 1회]
```

### Flow 4: What-If 분석 (L5 — Failure Simulation)

```
User: "Leaf1-Leaf6, Leaf2-Leaf4 동시 장애 시 Leaf5→P7 도달 가능?"
  |
  v
Collector: 2개 도구 선택
  1st: nso_get_all_device_info()    <- 토폴로지 파악
  2nd: batfish_multi_link_failure(  <- 시뮬레이션
         link1_node1="leaf1", link1_node2="leaf6",
         link2_node1="leaf2", link2_node2="leaf4",
         src="leaf5", dst="p7")
  |
  v
Batfish: fork_snapshot(2개 링크 비활성화) -> differentialReachability
  -> {isolated: true, failure_reason: "NO_ROUTE at pe3"}
  |
  v
Synthesizer: "DISCONNECTED (reason: NO_ROUTE at pe3)"
  -> Skeptic: tool 결과 기반 [ACCEPT]
  |
  v
User: "DISCONNECTED (reason: NO_ROUTE at pe3)"  [~30초, 도구 2회]
```

### Flow 5: Skeptic 재시도 (Outer Loop)

```
User: "iBGP under-peered 장비?"
  |
  v
Collector: batfish_bgp_sessions() -> {summary: {under_peered_nodes: [...]}}
  -> Synthesizer: ["pe1","pe2","pe3","pe4"]
  -> Skeptic: [NEED_MORE_INFO] "under-peered 기준 확인 필요"
  |
  v  (Outer loop: Collector 재호출)
Collector: nso_get_all_device_info() -> {aggregations: {devices_with_bgp: [...]}}
  -> Synthesizer: 재생성
  -> Skeptic: [ACCEPT]
  |
  v
User: ["pe1","pe2","pe3","pe4"]
```

---

## Component Architecture

### Backend (FastAPI)

```
main.py (FastAPI, SSE)
  |
  +-- /api/chat          POST, Server-Sent Events
  +-- /api/lab/*          PNETLab 관리
  +-- /api/dashboard      Batfish 대시보드 데이터
  |
  +-- agent/runtime.py    Runtime 선택
  |     +-- SingleExecutorRuntime     (Single LLM + Tools)
  |     +-- TeamMultiAdapterRuntime   (MAS + MCP)
  |
  +-- agent/clients/
  |     +-- nso.py         NSO RESTCONF client
  |     +-- batfish.py     Batfish client (pybatfish)
  |     +-- pnetlab.py     PNETLab API client
  |
  +-- agent/direct_tools.py   Direct tool wrappers (eval용, MCP HTTP bypass)
  +-- agent/mcp_tools.py      MCP proxy tools (웹서버용)
  +-- agent/mcp_server.py     MCP server (FastMCP)
```

### MAS (agents_netally)

```
agents_netally/
  +-- main_netally.py      LangGraph 그래프 빌더
  +-- debate1.py           Collector, Verifier, Synthesizer
  +-- debate2.py           Supporter, Skeptic
  +-- tool_dispatch.py     도구 실행 엔진
  +-- model_loader.py      LLM 모델 로더 (OpenRouter/OpenAI)
  +-- state.py             NetAgentState 정의
```

### Tool Layer

```
+----------------------------------------------------+
|              Tool Dispatch Engine                    |
|  (tool_dispatch.py)                                 |
|                                                     |
|  execute_tool_calls(plans, tools)                   |
|    -> ThreadPoolExecutor per tool                   |
|    -> asyncio.run(tool.ainvoke(args))               |
|    -> format_tool_results(results)                  |
+--------+-------------------+-----------------------+
         |                   |
    NSO Tools (5)       Batfish Tools (13)
         |                   |
         v                   v
+--------+------+   +-------+--------+
| NSO RESTCONF  |   | Batfish Engine |
| (live config) |   | (simulation)   |
|               |   |                |
| - device info |   | - traceroute   |
| - interfaces  |   | - reachability |
| - routing     |   | - BGP sessions |
| - aggregations|   | - route table  |
|               |   | - ACL check    |
|   Cached per  |   | - failure sim  |
|   session     |   | - SPOF detect  |
+---------------+   +----------------+
```

---

## Data Flow (SSE Event Stream)

```
Browser                    Backend                     Tools
  |                          |                           |
  |-- POST /api/chat ------->|                           |
  |                          |                           |
  |<-- event: planning ------|                           |
  |    "Analyzing question"  |                           |
  |                          |                           |
  |<-- event: tool_call -----|--- NSO RESTCONF --------->|
  |    "nso_get_device_info" |                           |
  |                          |<-- device config ---------|
  |<-- event: tool_output ---|                           |
  |    "{hostname: PE1,...}" |                           |
  |                          |                           |
  |<-- event: thinking ------|                           |
  |    "Verifier bypass"     |                           |
  |                          |                           |
  |<-- event: thinking ------|                           |
  |    "Synthesizer: 2"      |                           |
  |                          |                           |
  |<-- event: answer --------|                           |
  |    "2"                   |                           |
  |                          |                           |
  |<-- event: complete ------|                           |
  |    {latency, tools, ...} |                           |
```

---

## Evaluation Pipeline

```
Dataset (JSON)                    Eval Runner                    Scoring
+-----------------+      +-------------------------+      +------------------+
| questions:      |      | run_netally_eval_       |      | analyze_results  |
|  - question     |----->| direct.py               |----->| .py              |
|  - gold         |      |                         |      |                  |
|  - level        |      | graph.invoke() x N      |      | TA-Acc per level |
|  - answer_type  |      | (no web server needed)  |      | TA-Acc per type  |
+-----------------+      |                         |      | Token usage      |
                         | Features:               |      | Latency stats    |
                         | - Batfish pre-load       |      +------------------+
                         | - Session caching        |
                         | - Token tracking         |
                         | - Resume support         |
                         | - Level filtering        |
                         +-------------------------+
```

---

## 4-Way Experiment Design (논문)

```
                        Tools
                    No      Yes
              +--------+--------+
        No    | Pure   | Single |
  MAS         | LLM    | + Tools|
              +--------+--------+
        Yes   | Pure   | NetAlly|
              | MAS    | MAS+MCP|
              +--------+--------+

1. Pure LLM:        LLM(.cfg context) -> answer
2. Single + Tools:  LLM + NSO/Batfish -> answer
3. Pure MAS:        5-Agent(.cfg context) -> answer
4. NetAlly MAS+MCP: 5-Agent + NSO/Batfish -> answer  (*)
```

---

## Environment

| Component | Technology | Port |
|-----------|-----------|------|
| Backend | FastAPI + Uvicorn | 8111 |
| Frontend | React + Vite | 3000 |
| NSO | cisco-nso-dev:6.6 Docker | 8080 |
| Batfish | batfish/batfish Docker | 9997/9996 |
| PNETLab | VM (Tailscale) | 80 |
| LLM | OpenRouter API / vLLM | - |

## Key Metrics

| Metric | Description |
|--------|-------------|
| TA-Acc | Type-Aware Accuracy (answer_type별 맞춤 비교) |
| Latency | 질문당 응답 시간 (ms) |
| Token Usage | LLM 호출당 프롬프트/생성 토큰 |
| Tool Calls | 질문당 MCP 도구 호출 횟수 |
| Debate Depth | MAS outer/inner loop 횟수 |
