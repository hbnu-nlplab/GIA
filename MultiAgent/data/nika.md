# NIKA 벤치마크 실행 가이드

## 개요

NIKA 벤치마크는 네트워크 장애 진단 에이전트를 평가하는 프레임워크입니다.
agents_v2의 debate graph를 연동하여 640개 케이스를 자동으로 실행하고 평가합니다.

---

## agents_v2 vs NIKA 아키텍처 비교

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

### 핵심 차이: 정적 컨텍스트 vs 동적 컨텍스트

```
[ agents_v2 단독 사용 ]                 [ NIKA + debate_agent 연동 ]

  미리 준비된 context(또는 없음)             실시간 네트워크 장비
       │                                        │
       ▼                                        ▼
  Collector                               MCP Tools 호출
  (텍스트에서 관련 정보 추출)                 get_reachability()
       │                                get_host_net_config()
       ▼                                 frr_get_bgp_conf()
  Verifier → Synthesizer                 frr_get_ospf_conf()
  → Supporter → Skeptic                        │
       │                                       ▼
       ▼                               context 문자열 조합
  candidate_answer                             │
  (자유 텍스트)                                   ▼
                                       Collector → ... → Skeptic
                                               │
                                               ▼
                                       SubmissionAgent
                                       (JSON 포맷 제출)
```

---

## 동적 컨텍스트 수집 상세 (`_collect_context`)

agents_v2는 원래 정적 텍스트(context)를 받아서 동작하도록 설계되었습니다.
NIKA 연동 시 이 context를 **MCP 도구로 실시간 수집한 네트워크 상태**로 대체합니다.

```python
# debate_agent.py: _collect_context()
async def _collect_context(self, task_description: str) -> str:
    client = MultiServerMCPClient(mcp_config)
    tools = {t.name: t for t in await client.get_tools()}

    sections = [f"[Task]\n{task_description}"]

    # 1. 전체 연결성 확인
    sections.append(f"[Reachability]\n{await _call(tools['get_reachability'], {})}")

    # 2. 호스트별 네트워크 설정
    for host in hosts:
        sections.append(f"[Host Config: {host}]\n{await _call(tools['get_host_net_config'], {'machine_name': host})}")

    # 3. 라우터별 BGP/OSPF 설정
    for router in routers:
        sections.append(f"[BGP Config: {router}]\n{await _call(tools['frr_get_bgp_conf'], {'machine_name': router})}")
        sections.append(f"[OSPF Config: {router}]\n{await _call(tools['frr_get_ospf_conf'], {'machine_name': router})}")

    # 4. 풀 수 있는 장애 목록 (Skeptic이 정답 레이블 검증에 활용)
    sections.append(f"[Available Problem Names]\n{await _call(tools['list_avail_problems'], {})}")

    return "\n\n".join(sections)
```

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

### 정적 엣지 vs 동적 라우터

```python
# 정적 엣지 (항상 동일한 순서, 조건 없음)
workflow.add_edge("Collector",   "Verifier")
workflow.add_edge("Verifier",    "Synthesizer")
workflow.add_edge("Synthesizer", "Supporter")
workflow.add_edge("Supporter",   "Skeptic")

# 동적 라우터 (Skeptic 판정에 따라 분기)
workflow.add_conditional_edges("Skeptic", _check, {...})
```

정적 엣지 구간(Collector→Verifier→Synthesizer→Supporter)은 순서가 고정되어 있고,
동적 라우터(Skeptic 이후)는 LLM의 판정 결과를 상태(state)에서 읽어 런타임에 경로를 결정합니다.

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
    │   ├── llm/model_factory.py
    │   └── domain_agents/submission_agent.py
    └── scripts/
        ├── step1_net_env_start.py
        ├── step2_failure_inject.py
        ├── step3_agent_run.py
        └── step4_result_eval.py
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
       │         ├─ _collect_context() # MCP tools로 실시간 네트워크 상태 수집
       │         ├─ _run_debate()      # agents_v2 debate graph 실행
       │         │    └─ Collector → Verifier → Synthesizer
       │         │         → Supporter → Skeptic → [라우터] → ...
       │         └─ SubmissionAgent    # debate 결과 → JSON 포맷 제출 (--backend-model)
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
