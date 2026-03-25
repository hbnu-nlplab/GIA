# agents_v2 — Multi-Agent Debate System

네트워크 QA 데이터셋에 대해 5개의 LLM 에이전트가 순차적으로 토론하며 답변을 생성하는 시스템.
LangGraph 기반 상태 그래프로 구성되며, OpenRouter(클라우드) 또는 로컬 GPU 모드를 모두 지원한다.

---

## 디렉토리 구조

```
agents_v2/
├── state.py            # LangGraph 공유 상태 스키마 정의
├── model_loader.py     # LLM 모델 초기화 및 관리 (클라우드/로컬)
├── debate1.py          # Agent 1~3: Collector, Verifier, Synthesizer
├── debate2.py          # Agent 4~5: Supporter, Skeptic
├── main                # 메인 실행 코드 
├── main_netconfig.py   # 실행 진입점 — NetConfig 데이터셋
├── main_netbench.py    # 실행 진입점 — NetBench 데이터셋
├── main_teleqna.py     # 실행 진입점 — TeleQnA 데이터셋
└── readme.md           # 이 파일
.env 파일은 agents_v2 상위 디렉토리인 MultiAgent 안에 두면 됨
main 뒤에 이름 붙인 것은 병렬로 돌릴려고 여러개 만든거라 main만 보면 됨
```

---

## 에이전트 구조

```
[입력: 질문 + 컨텍스트]
        │
        ▼
  Agent 1: Collector      ← 컨텍스트에서 관련 원시 정보 추출
        │
        ▼
  Agent 2: Verifier       ← 불필요한 내용 제거, 관련 줄만 정제
        │
        ▼
  Agent 3: Synthesizer    ← 정제된 패시지로 후보 답변 생성
        │
        ▼
  Agent 4: Supporter      ← 후보 답변을 패시지 근거로 옹호
        │
        ▼
  Agent 5: Skeptic        ← 패시지-답변 일치 여부 검증 및 상태 판정
        │
   ┌────┴────────────────────────────┐
   │                                 │
ACCEPT                    CONTINUE_DEBATE / NEED_MORE_INFO
   │                         │              │
  END             Supporter 재호출    Collector 재호출
               (inner_turn_count<3)  (outer_loop_count<3)
```

### Critic 판정 기준

| 상태 | 의미 | 다음 단계 |
|---|---|---|
| `ACCEPT` | 패시지에서 근거 문장 확인, 답변 일치 | 종료 |
| `CONTINUE_DEBATE` | 패시지는 관련 있으나 논리적 비약 존재 | Supporter 재호출 (최대 3회) |
| `NEED_MORE_INFO` | 패시지 자체가 불충분 또는 다른 장비 설정 | Collector 재호출 (최대 3회) |

---

## 파일별 설명

### `state.py`

LangGraph 상태 딕셔너리(`NetAgentState`) 스키마를 정의한다.
모든 에이전트 노드가 이 상태를 읽고 일부 키만 업데이트하여 반환한다.

주요 필드:

- `question`, `context`, `dataset_type` — 입력
- `raw_data` → `current_passage` → `candidate_answer` — 처리 단계별 중간 결과
- `status` — Critic 판정 결과 (`ACCEPT` / `CONTINUE_DEBATE` / `NEED_MORE_INFO`)
- `inner_turn_count` — Supporter↔Skeptic 내부 반복 횟수
- `outer_loop_count` — Collector로 되돌아가는 외부 반복 횟수

---

### `model_loader.py`

LLM 모델을 초기화하고 전역 딕셔너리(`_LLM_DICT`)로 관리한다.
`init_models()` / `get_models()`를 통해 싱글톤으로 접근한다.

**모델 키:**

- `'A'` — Verifier, Synthesizer, Supporter 담당
- `'B'` — Collector, Skeptic 담당

**두 가지 모드:**

| 모드 | `USE_LOCAL` | 설명 |
|---|---|---|
| 클라우드 (기본) | `False` | OpenRouter API 사용 (`config/load_env.py`에서 키 로드) |
| 로컬 GPU | `True` | HuggingFace 모델 4-bit 양자화 로드, 멀티 GPU 분산 |

---

### `debate1.py`

1차 토론 에이전트 (Agent 1~3)를 정의한다.

| 함수 | 역할 |
|---|---|
| `collector_node` | 데이터셋 타입별 전략으로 컨텍스트에서 원시 정보 추출 |
| `verifier_node` | 원시 정보에서 무관한 줄 제거, 원본 텍스트 그대로 유지 |
| `synthesizer_node` | 정제된 패시지로 후보 답변 생성 (타입별 출력 형식 적용) |
| `_extract_from_tags` | `[START]...[DONE]` 태그 파싱 + `<think>` 블록 제거 |

**데이터셋별 Synthesizer 출력 형식:**

- `netconfig` — text/numeric/set/map/bool/ip 타입에 맞는 형식
- `multiple_choice` — `"option N: [답변]"` 형식
- `short_answer` — 컨텍스트에서 정확히 추출한 값
- `descriptive` — 1~2문장 기술 설명

---

### `debate2.py`

2차 토론 에이전트 (Agent 4~5)를 정의한다.

| 함수 | 역할 |
|---|---|
| `supporter_node` | 후보 답변을 패시지 근거로 옹호 (답변 자체는 수정하지 않음) |
| `skeptic_node` | 패시지-답변 일치 여부 검증 → JSON으로 `status` + `con_argument` + `feedback_to_agent1` 출력 |

Skeptic은 반드시 패시지에서 근거 문장을 직접 인용해야만 `ACCEPT`를 줄 수 있다.

---

### `main_netconfig.py` / `main_netbench.py` / `main_teleqna.py`

각 데이터셋에 대한 실행 진입점. 구조는 동일하며 `input_path`, `output_path`, `dataset_type`만 다르다.

| 파일 | 데이터셋 | dataset_type |
|---|---|---|
| `main_netconfig.py` | NetConfigQA (네트워크 설정 파일 QA) | `netconfig` |
| `main_netbench.py` | NetBench (네트워크 기술 서술형) | `descriptive` |
| `main_teleqna.py` | TeleQnA (통신 객관식) | `multiple_choice` |

**NetConfig 특이사항:**
`configs.txt`를 장비별 딕셔너리로 파싱 후, 질문에 언급된 장비명으로 해당 설정 블록만 컨텍스트로 제공한다.

---

## 환경 설정

### `.env` 파일 (프로젝트 루트 `MultiAgent/.env`)

```env
OPENROUTER_API_KEY=sk-or-...
OPENROUTER_BASE_URL=https://openrouter.ai/api/v1
OPENROUTER_MODEL1=모델ID_A   # Verifier, Synthesizer, Supporter용
OPENROUTER_MODEL2=모델ID_B   # Collector, Skeptic용
```

### 로컬 GPU 모드 전환 (`model_loader.py`)

```python
USE_LOCAL = True  # False → True로 변경
```

로컬 모드에서는 `torch`, `transformers`, `langchain_huggingface` 패키지가 필요하다.

---

## 실행 방법

### 공통 전제 조건

```bash
# 프로젝트 루트(MultiAgent/)에서 실행
# conda 환경 활성화
conda activate network

# 패키지 설치 (최초 1회)
pip install langgraph langchain langchain-openai python-dotenv tqdm
```

### NetConfig 데이터셋 실행

```bash
cd /path/to/MultiAgent
python -m agents_v2.main_netconfig
```

### NetBench 데이터셋 실행

```bash
python -m agents_v2.main_netbench
```

### TeleQnA 데이터셋 실행

```bash
python -m agents_v2.main_teleqna
```

> **주의:** `python agents_v2/main_netconfig.py` 방식이 아닌 `-m` 플래그를 사용해야
> `agents_v2` 패키지 임포트가 정상적으로 동작한다.

---

## 입출력 경로

```
MultiAgent/
├── data/
│   ├── original/netconfig/configs.txt   # 네트워크 장비 설정 파일 (NetConfig용)
│   ├── passages/full_w_context/
│   │   ├── netconfig_en2.json           # NetConfig 입력 데이터
│   │   ├── netbench_passage.json        # NetBench 입력 데이터
│   │   └── teleqna_passage.json         # TeleQnA 입력 데이터
│   ├── debate_results/agents_v2/        # 출력 결과 저장 디렉토리
│   └── log/debate_execution_full_w_context.log  # 실행 로그
└── config/load_env.py                   # 환경변수 로더
```

### 출력 JSON 필드

```json
{
  "id": "항목 ID",
  "question": "질문",
  "gold_answer": "정답",
  "debate1_passage": "Verifier가 정제한 패시지",
  "debate1_answer": "Synthesizer의 1차 답변",
  "proponent_defense": "Supporter의 옹호 의견",
  "critic_critique": "Critic의 비판 의견",
  "debate2_answer": "최종 답변",
  "debate2_rounds": "내부 토론 라운드 수",
  "duration": "처리 소요 시간(초)",
  "level": "(netconfig만) 난이도 레벨",
  "answer_type": "(netconfig만) 답변 타입",
  "answer_status": "(netconfig만) 답변 상태"
}
```

---

## 재시작 최적화

실행 중 중단되어도 이미 처리된 항목은 스킵하고 이어서 실행할 수 있다:

- 기존 결과 파일이 있으면 자동 로드
- 처리된 ID는 스킵
- 답변이 `[NONE]`인 항목은 재시도 대상에 포함
- 10건마다 결과를 파일에 저장 (손실 최소화)
- 빠진 ID 번호 자동 감지 및 출력

---

## 병렬 처리

`ThreadPoolExecutor`로 최대 50개 질문을 동시 처리한다.
클라우드 API 모드에서는 I/O 바운드이므로 높은 워커 수가 유효하다.
로컬 GPU 모드에서는 `gpu_lock`으로 GPU 접근을 직렬화하므로 워커 수를 낮추는 것이 좋다.
