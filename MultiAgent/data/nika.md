# NIKA 벤치마크 실행 가이드

## 개요

NIKA 벤치마크는 네트워크 장애 진단 에이전트를 평가하는 프레임워크입니다.
agents_v2의 debate graph를 연동하여 640개 케이스를 자동으로 실행하고 평가합니다.

---

## 아키텍처 비교: 원본 NIKA vs agents_v2 단독 vs MAS 연동

### 3가지 아키텍처 구성 요소 비교표

| 항목 | agents_v2 단독 (NetConfigQA) | 원본 NIKA (ReAct) | MAS 연동 NIKA (DebateAgent) |
|---|---|---|---|
| **목적** | QA 데이터셋 문제 풀이 | 네트워크 장애 RCA | 네트워크 장애 RCA |
| **에이전트 클래스** | 없음 (LangGraph 직접 실행) | `DiagnosisAgent` | `DebateAgent` |
| **에이전트 패러다임** | 고정 그래프 (debate) | ReAct (자율적 도구 선택) | 고정 컨텍스트 수집 → debate 그래프 |
| **입력** | question + context (정적 텍스트) | task_description | task_description |
| **컨텍스트 출처** | 미리 준비된 passage (정적) | 에이전트가 런타임에 동적 수집 | `_collect_context()`가 사전 수집 후 고정 |
| **MCP 도구 사용** | 없음 | 있음 — 에이전트가 자율 결정 | 있음 — 수집 단계에서 고정 순서로 호출 |
| **사용 MCP 서버** | 없음 | base + frr + bmv2 + telemetry | base + frr (수집 단계) / task (제출 단계) |
| **LangGraph 노드** | Collector → Verifier → Synthesizer → Supporter → Skeptic | 없음 (ReAct 루프) | diagnosis → submission |
| **내부 debate 그래프** | 있음 (메인 실행 단위) | 없음 | 있음 (`_run_debate()` 내에서 실행) |
| **출력** | `candidate_answer` (자유 텍스트) | `diagnosis_report` | `submission.json` (is_anomaly / faulty_devices / root_cause_name) |
| **최종 제출 처리** | 없음 | 없음 (별도 처리) | `SubmissionAgent` (ReAct, task MCP 사용) |

---

### 아키텍처 흐름 시각화

#### 원본 NIKA (ReAct — DiagnosisAgent)

```
task_description
       │
       ▼
  DiagnosisAgent (ReAct 루프)
  ┌────────────────────────────────────────────┐
  │  LLM이 추론 → 도구 선택 → 결과 관찰 → 반복   │
  │                                            │
  │  Step 1: get_reachability()                │
  │  Step 2: get_host_net_config(host_x)       │  ← 에이전트가 자율적으로
  │  Step 3: frr_show_ip_route(router_y)       │    필요한 도구를 선택
  │  Step n: ...                               │
  └────────────────────────────────────────────┘
       │
       ▼
  diagnosis_report (자유 텍스트)
       │
       ▼
  (별도 SubmissionAgent 처리)
```

#### MAS 연동 NIKA (DebateAgent)

```
task_description
       │
       ▼
[Phase 1: 사전 컨텍스트 수집 — _collect_context()]
  ┌────────────────────────────────────────────┐
  │  고정 순서로 MCP 도구 일괄 호출              │
  │                                            │
  │  1. get_reachability()                     │
  │  2. get_host_net_config(host_1)            │  ← task_description에서
  │     get_host_net_config(host_2)  ...       │    hosts/routers 파싱 후
  │  3. frr_get_bgp_conf(router_1)             │    순서 고정, 결과 문자열 조합
  │     frr_get_bgp_conf(router_2)   ...       │
  │  4. frr_get_ospf_conf(router_1)  ...       │
  │  5. list_avail_problems()                  │
  └────────────────────────────────────────────┘
       │ context 문자열 (수백~수천 토큰)
       ▼
[Phase 2: Debate Graph — _run_debate()]
  ┌─────────────────────────────────────────────────────┐
  │  agents_v2 debate graph (도구 호출 없음, LLM만 사용) │
  │                                                     │
  │  Collector → Verifier → Synthesizer                 │
  │      → Supporter → Skeptic → [라우터] → ...         │
  └─────────────────────────────────────────────────────┘
       │ candidate_answer (root cause 이름)
       ▼
[Phase 3: 제출 — SubmissionAgent (ReAct)]
  ┌────────────────────────────────────────────┐
  │  task_mcp_server 도구만 사용                │
  │  1. list_avail_problems() — 검증용          │
  │  2. submit(is_anomaly, faulty_devices,     │
  │            root_cause_name)                │
  └────────────────────────────────────────────┘
       │
       ▼
  submission.json 저장
```

#### agents_v2 단독 (NetConfigQA 평가용)

```
JSON 파일 (question + context)
       │
       ▼
[Debate Graph — build_graph()]
  ┌─────────────────────────────────────────────────────┐
  │  도구 호출 없음 — 정적 텍스트만 처리                   │
  │                                                     │
  │  Collector → Verifier → Synthesizer                 │
  │      → Supporter → Skeptic → [라우터] → ...         │
  └─────────────────────────────────────────────────────┘
       │ candidate_answer
       ▼
  netconfig_result.json 저장 (ThreadPoolExecutor 병렬)
```

---

## MCP 도구 호출 상세

### 어느 단계에서, 어떻게 호출되는가

| 단계 | 호출 주체 | 호출 방식 | 사용 도구 | 도구 결정 방식 |
|---|---|---|---|---|
| Phase 1: 컨텍스트 수집 | `_collect_context()` | 고정 순서, 비동기 일괄 호출 | base + frr MCP | 코드에 하드코딩 (자율 아님) |
| Phase 2: Debate | 각 노드 (LLM) | 없음 | — | 도구 없음 |
| Phase 3: 제출 | `SubmissionAgent` (ReAct) | LLM이 자율 선택 | task MCP | LLM이 결정 |

### Phase 1 — `_collect_context()` 상세 (`debate_agent.py`)

```python
async def _collect_context(self, task_description: str) -> str:
    mcp_config = MCPServerConfig().load_config(if_submit=False)
    hosts, routers = _parse_nodes(task_description)  # task 텍스트에서 파싱
    sections = [f"[Task]\n{task_description}"]

    client = MultiServerMCPClient(mcp_config)
    tools = {t.name: t for t in await client.get_tools()}
    # tools: kathara_base + kathara_frr + kathara_bmv2 + kathara_telemetry의 모든 도구

    # 1. 전체 연결성 — 항상 호출
    if "get_reachability" in tools:
        sections.append(f"[Reachability]\n{await _call(tools['get_reachability'], {})}")

    # 2. 호스트별 네트워크 설정 — task_description에 파싱된 hosts 수만큼
    if "get_host_net_config" in tools:
        for host in hosts:
            sections.append(f"[Host Config: {host}]\n"
                            f"{await _call(tools['get_host_net_config'], {'machine_name': host})}")

    # 3. 라우터별 BGP 설정
    if "frr_get_bgp_conf" in tools:
        for router in routers:
            sections.append(f"[BGP Config: {router}]\n"
                            f"{await _call(tools['frr_get_bgp_conf'], {'machine_name': router})}")

    # 4. 라우터별 OSPF 설정
    if "frr_get_ospf_conf" in tools:
        for router in routers:
            sections.append(f"[OSPF Config: {router}]\n"
                            f"{await _call(tools['frr_get_ospf_conf'], {'machine_name': router})}")

    # 5. 풀 수 있는 장애 목록 — Skeptic의 정답 레이블 검증에 활용
    if "list_avail_problems" in tools:
        sections.append(f"[Available Problem Names]\n"
                        f"{await _call(tools['list_avail_problems'], {})}")

    return "\n\n".join(sections)
    # → 이 문자열이 debate graph의 state["context"]로 주입됨
```

> **핵심 포인트**: Phase 1에서 도구 호출 순서·종류는 코드에 고정되어 있다.
> LLM이 "어떤 정보가 필요할지" 결정하는 것이 아니라, 항상 동일한 정보를 수집한 뒤 debate에 넘긴다.

### Phase 1 vs 원본 NIKA ReAct 비교

```
[원본 NIKA - ReAct]                        [MAS 연동 - DebateAgent]

task_description                           task_description
      │                                          │
      ▼                                          ▼ (고정 순서)
LLM: "먼저 연결성 확인"                     get_reachability()  ──┐
      │                                    get_host_net_config()  │ 코드에
      ▼                                    frr_get_bgp_conf()    │ 하드코딩,
get_reachability()                         frr_get_ospf_conf()   │ 병렬 가능
      │                                    list_avail_problems() ─┘
      ▼                                          │
LLM: "router_1 라우팅 테이블 확인 필요"          ▼
      │                               context 문자열 조합
      ▼                                          │
frr_show_ip_route(router_1)                      ▼
      │                                   debate graph 실행
      ▼                                   (도구 없음, LLM만)
LLM: "BGP 설정 의심스러움"
      │
      ▼
frr_get_bgp_conf(router_1)
      │
      ▼
 ...반복...
      │
      ▼
diagnosis_report

← LLM이 매 스텝 어떤 도구를    ← 컨텍스트는 사전에 일괄 수집,
  호출할지 동적으로 결정          debate 노드는 도구 없이 텍스트만 처리
```

### Phase 3 — SubmissionAgent 도구 호출

SubmissionAgent는 `task_mcp_server`만 사용하는 소형 ReAct 에이전트다.
도구는 2개뿐이며 LLM이 순서를 결정한다:

```
SubmissionAgent (ReAct)
  Step 1: list_avail_problems()
          → ["dns_record_error", "bgp_misconfiguration", ...]
  Step 2: submit(
            is_anomaly=True,
            faulty_devices=["router_1"],
            root_cause_name=["dns_record_error"]
          )
          → submission.json 파일 저장
```

### 사용 MCP 서버와 도구 목록

| MCP 서버 | 주요 도구 | 사용 단계 |
|---|---|---|
| `kathara_base_mcp_server` | get_reachability, ping_pair, get_host_net_config, netstat, exec_shell, curl_web_test, iperf_test | Phase 1 (수집) |
| `kathara_frr_mcp_server` | frr_get_bgp_conf, frr_get_ospf_conf, frr_show_ip_route, frr_show_running_config, frr_exec | Phase 1 (수집) |
| `kathara_bmv2_mcp_server` | P4 BMv2 관련 | Phase 1 (수집, P4 시나리오) |
| `kathara_telemetry_mcp_server` | 텔레메트리 관련 | Phase 1 (수집) |
| `task_mcp_server` | list_avail_problems, submit | Phase 3 (제출) |

---

## agents_v2 vs NIKA 상세 비교표

### 구성 요소 비교표

| 항목 | agents_v2 (MultiAgent) | NIKA debate_agent (브릿지) |
|---|---|---|
| **목적** | QA 데이터셋 문제 풀이 (NetConfigQA) | 네트워크 장애 근본 원인 분석 (RCA) |
| **입력** | question + context (정적 텍스트) | task_description + 실시간 MCP 수집 데이터 |
| **컨텍스트 출처** | 미리 준비된 passage (정적) | MCP 도구로 실시간 수집 (동적) |
| **그래프 빌드 위치** | `main_netconfig.py: build_graph()` | `debate_agent.py: _build_debate_graph()` |
| **노드 구성** | Collector → Verifier → Synthesizer → Supporter → Skeptic | 동일 (agents_v2 코드 직접 import) |
| **라우터 (Skeptic 이후)** | `check_debate_status()` | `_check()` — 동일 로직 |
| **출력** | `candidate_answer` (자유 텍스트) | debate 결과 → SubmissionAgent → JSON 제출 |
| **모델 로딩** | `model_loader.py: init_models()` | 동일 (`init_models()` 호출) |
| **Model A** | `OPENROUTER_MODEL1` (gemini-3.1-flash-lite-preview) | 동일 |
| **Model B** | `OPENROUTER_MODEL2` (gpt-4o-mini) | 동일 |
| **Model A 담당 역할** | Verifier, Synthesizer, Supporter | 동일 |
| **Model B 담당 역할** | Collector, Skeptic | 동일 |
| **루프 제어** | inner (최대 3회) + outer (최대 3회) | 동일 |
| **평가 방식** | TA-Acc (Type-Aware Accuracy) | Det.Acc / Loc.Acc / RCA.Acc + LLM Judge |

---

## 동적 컨텍스트 수집 상세 (`_collect_context`)

agents_v2는 원래 정적 텍스트(context)를 받아서 동작하도록 설계되었습니다.
NIKA 연동 시 이 context를 **MCP 도구로 실시간 수집한 네트워크 상태**로 대체합니다.

수집된 문자열이 debate graph의 `context` 필드로 주입되어 Collector가 분석합니다.

---

## 라우터(Router): Skeptic의 동적 분기

debate graph의 핵심은 **Skeptic 노드 이후의 조건부 라우터**입니다.
고정된 순서(정적)가 아니라 Skeptic의 판정 결과(동적)에 따라 다음 노드가 결정됩니다.

### 라우터 로직

```python
def _check(state):
    status = state.get("status", "ACCEPT").upper()

    if status == "ACCEPT":
        return "end"                  # 답변 확정, 종료

    if status == "CONTINUE_DEBATE":
        if state.get("inner_turn_count", 0) >= 3:
            return "end"              # 내부 토론 한계 도달, 강제 종료
        return "continue_inner"       # Supporter로 되돌아가 재논쟁

    if status == "NEED_MORE_INFO":
        if state.get("outer_loop_count", 0) >= 3:
            return "end"              # 외부 루프 한계 도달, 강제 종료
        return "backtrack_outer"      # Collector로 되돌아가 재수집

workflow.add_conditional_edges(
    "Skeptic", _check,
    {
        "end":            END,        # 종료
        "continue_inner": "Supporter", # 내부 루프: Supporter → Skeptic 반복
        "backtrack_outer":"Collector", # 외부 루프: Collector부터 전체 재실행
    }
)
```

### 3가지 판정 상태

| Skeptic 판정 | 의미 | 다음 동작 |
|---|---|---|
| `ACCEPT` | 답변이 passage에 근거하여 기술적으로 정확함 | 종료, candidate_answer 확정 |
| `CONTINUE_DEBATE` | 논리적 비약 또는 할루시네이션 의심 | Supporter로 복귀 (내부 루프) |
| `NEED_MORE_INFO` | Passage 자체가 불충분하거나 엉뚱한 장비 정보 | Collector로 복귀 (외부 루프) |

### 루프 구조 시각화

```
Collector → Verifier → Synthesizer → Supporter → Skeptic
    ▲                                    ▲             │
    │                                    │             │ CONTINUE_DEBATE
    │ NEED_MORE_INFO                     └─────────────┘  (inner, 최대 3회)
    └────────────────────────────────────────────────────
                                                      │
                                                      │ ACCEPT
                                                      ▼
                                                     END
```

---

## 디렉토리 구조

```
data/nika/
├── .env                        # nika 자체 환경 설정 (MODEL1/2는 설정하지 않음)
├── benchmark/
│   ├── benchmark_full.csv      # 640개 벤치마크 케이스 (problem, scenario, topo_size)
│   └── run_benchmark.py        # 벤치마크 실행 스크립트 (skip 로직 포함)
├── results/
│   ├── 0_summary/              # 전체 평가 요약
│   └── {problem}/{session_id}/ # 케이스별 결과
└── src/
    ├── agent/
    │   ├── debate_agent.py     # agents_v2 연동 브릿지 (핵심)
    │   ├── domain_agents/
    │   │   ├── diagnosis_agent.py   # 원본 ReAct 에이전트 (현재 미사용)
    │   │   └── submission_agent.py  # 제출 에이전트 (debate_agent가 호출)
    │   ├── llm/model_factory.py
    │   └── utils/mcp_servers.py     # MCPServerConfig (서버 경로/세션 env 설정)
    └── scripts/
        ├── step1_net_env_start.py
        ├── step2_failure_inject.py
        ├── step3_agent_run.py       # DebateAgent 선택 및 실행
        └── step4_result_eval.py
    └── nika/service/mcp_server/
        ├── kathara_base_mcp_server.py   # 네트워크 기본 도구 (ping, netstat 등)
        ├── kathara_frr_mcp_server.py    # FRR 라우터 도구 (BGP, OSPF 등)
        ├── kathara_bmv2_mcp_server.py   # P4 BMv2 도구
        ├── kathara_telemetry_mcp_server.py
        └── task_mcp_server.py           # 제출 도구 (list_avail_problems, submit)
```

---

## 환경 설정

### 1. 모델 설정 (.env 파일 구조)

agents_v2의 모델은 **MultiAgent 루트 `.env`** 에서만 설정합니다.
nika `.env`에 MODEL1/2를 설정하면 루트 설정을 덮어쓰므로 반드시 비워둡니다.

**`/home/leehj/network/GIA/MultiAgent/.env`** (모델 설정 위치):

```env
OPENROUTER_API_KEY=sk-or-v1-...
OPENROUTER_BASE_URL=https://openrouter.ai/api/v1

# agents_v2 모델 구성 (현재 설정)
OPENROUTER_MODEL1=google/gemini-3.1-flash-lite-preview  # Model A: Verifier, Synthesizer, Supporter
OPENROUTER_MODEL2=openai/gpt-4o-mini                    # Model B: Collector, Skeptic
```

**`/home/leehj/network/GIA/MultiAgent/data/nika/.env`** (nika 자체 설정):

```env
OPENROUTER_API_KEY="sk-or-v1-..."
OPENROUTER_BASE_URL="https://openrouter.ai/api/v1"
# MODEL1/2는 MultiAgent 루트 .env에서 읽음 — 여기에 설정하지 않음

AGENTS_USE_LOCAL=false          # OpenRouter(Cloud) 사용
MULTIAGENT_DIR="/home/leehj/network/GIA/MultiAgent"
```

### 2. load_env.py 수정 사항

`config/load_env.py`가 루트 `.env`를 명시적으로 로드하도록 수정되어 있음.
이 수정이 없으면 nika 실행 디렉토리의 `data/nika/.env`가 먼저 로드되어 MODEL1/2가 빈 값이 됩니다.

```python
# config/load_env.py
_ROOT_ENV = Path(__file__).resolve().parent.parent / ".env"  # MultiAgent/.env

def load_louter():
    load_dotenv(dotenv_path=_ROOT_ENV, override=True)  # 루트 .env 강제 로드
    ...
```

---

## 실행 방법

### 기본 실행 (640개 전체)

```bash
cd /home/leehj/network/GIA/MultiAgent/data/nika/benchmark

conda run -n nika python run_benchmark.py \
  --benchmark-csv ./benchmark_full.csv \
  --agent-type debate \
  --backend-model openrouter/gpt-4o-mini \
  --judge-model openrouter/gpt-4o-mini
```

### 단일 케이스 실행

```bash
conda run -n nika python run_benchmark.py \
  --problem dns_record_error \
  --scenario ospf_enterprise_dhcp \
  --topo-size l \
  --agent-type debate \
  --backend-model openrouter/gpt-4o-mini \
  --judge-model openrouter/gpt-4o-mini
```

### 주요 파라미터

| 파라미터 | 설명 | 권장값 |
|---|---|---|
| `--agent-type` | 에이전트 종류 | `debate` (agents_v2 연동) |
| `--backend-model` | submission_agent 모델 | `openrouter/gpt-4o-mini` |
| `--judge-model` | LLM judge 모델 | `openrouter/gpt-4o-mini` |
| `--max-steps` | 에이전트 최대 스텝 | 20 (기본값) |

> **주의**: `--backend-model`과 `--judge-model` 기본값이 `deepseek-chat`이므로 DeepSeek 잔액 소진 시 반드시 명시적으로 지정해야 합니다.

---

## 실행 흐름

```
run_benchmark.py (CSV 순회, skip 로직 포함)
  └─ run_single_benchmark()
       ├─ Step 1: start_net_env()      # 네트워크 환경 배포 (PNETLab, 가장 오래 걸림)
       ├─ Step 2: inject_failure()     # 장애 주입
       ├─ Step 3: start_agent()
       │    └─ DebateAgent.run()
       │         │
       │         ├─ [Phase 1] _diagnosis_node()
       │         │    ├─ _collect_context()    # MCP tools로 네트워크 상태 사전 수집
       │         │    │    ├─ get_reachability()
       │         │    │    ├─ get_host_net_config(host_x) × N
       │         │    │    ├─ frr_get_bgp_conf(router_x) × M
       │         │    │    ├─ frr_get_ospf_conf(router_x) × M
       │         │    │    └─ list_avail_problems()
       │         │    └─ _run_debate(context)  # debate graph 실행 (도구 없음)
       │         │         └─ Collector → Verifier → Synthesizer
       │         │              → Supporter → Skeptic → [라우터] → ...
       │         │                                  → candidate_answer
       │         │
       │         └─ [Phase 3] _submission_node()
       │              └─ SubmissionAgent (ReAct, task MCP 사용)
       │                   ├─ list_avail_problems()
       │                   └─ submit(is_anomaly, faulty_devices, root_cause_name)
       │                        └─ submission.json 저장
       │
       └─ Step 4: eval_results()       # LLM judge 평가 (--judge-model)
```

---

## 결과 파일

완료된 케이스는 `results/{problem}/{session_id}/`에 저장됨:

| 파일 | 내용 |
|---|---|
| `ground_truth.json` | 정답 |
| `submission.json` | 에이전트 제출 답변 (is_anomaly, faulty_devices, root_cause_name) |
| `llm_judge.json` | LLM judge 점수 (relevance/correctness/efficiency 등 1~5점) |
| `session_meta.json` | 세션 메타 (모델, 소요 시간, 토큰 수 등) |
| `conversation_diagnosis_agent.log` | debate 전체 과정 로그 |

---

## 재실행 시 스킵 로직

`run_benchmark.py`에 이미 완료된 케이스 스킵 로직이 적용되어 있음.
`submission.json`이 존재하고 `session_meta.json`의 scenario/topo_size가 일치하면 자동 스킵.

---

## 진행 상황 확인

```bash
# 완료된 problem 수
ls /home/leehj/network/GIA/MultiAgent/data/nika/results/ | grep -v "0_summary" | wc -l

# 실시간 로그
tail -f /tmp/nika_benchmark.log
```

---

## 자주 발생하는 에러

### 402 Insufficient Balance

- OpenRouter 또는 DeepSeek API 잔액 부족
- `--backend-model`과 `--judge-model`을 잔액 있는 키의 모델로 명시
- OpenRouter 충전: <https://openrouter.ai/credits>

### 모델 설정 미적용

- nika `.env`에 `OPENROUTER_MODEL1/2`가 설정되면 루트 `.env` 설정을 덮어씀
- nika `.env`에서 MODEL1/2 항목 제거 필요
