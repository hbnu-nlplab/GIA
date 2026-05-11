# NetAlly 실험 운영 가이드 (leehj 전용)

> **선행 조건**: `01_SETUP_GUIDE.md`로 NetAlly 백엔드가 떠있고, 어떤 lab(LabA/B/C/D)이 NSO에 등록 + sync된 상태.
>
> 이 문서는 **실험 실행 방법 / 채점 메트릭 / 결과 저장 위치 / 결과 해석**을 정리한다.

---

## 0. 한 줄 요약

> NetAlly 평가는 `scripts/run_netally_eval_direct.py`로 실행하고, 결과는 `NetAlly/results/`에 timestamp 파일로 떨어진다. 그 결과를 `analyze_results.py`가 한 번 더 가공해서 `*_analyzed_scorecard.md`, `*_analyzed_summary.md`로 만든다. 채점 메트릭은 **TA-Acc (Type-Aware Accuracy)** — answer_type별 맞춤 비교.

---

## 1. 평가 파이프라인 개요

```
┌─────────────────────┐
│ Dataset JSON        │  ── 질문/정답이 들어있는 입력
│ (Data/Pnetlab/...)  │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ run_netally_eval_   │  ── LangGraph 통해 MAS 호출
│ direct.py           │  ── MCP 서버(8811)로 NSO/Batfish 조회
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ results/eval_*.json │  ── 질문별 답변 + tool calls + latency
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ analyze_results.py  │  ── TA-Acc 채점 + level별 집계
└──────────┬──────────┘
           │
           ▼
┌─────────────────────────────────────────────┐
│ results/eval_*_analyzed_scorecard.md        │  ← 사람이 보는 점수표
│ results/eval_*_analyzed_summary.md          │  ← level별 요약
│ results/eval_*_analyzed_detailed.csv        │  ← 질문별 raw 결과
│ results/eval_*_analyzed_errors.json         │  ← 실패 질문 모음
└─────────────────────────────────────────────┘
```

핵심 부품:

| 파일 | 역할 |
|---|---|
| `NetAlly/scripts/run_netally_eval_direct.py` | **메인 실험 실행기**. LangGraph 직접 호출 (HTTP 안 거침) |
| `NetAlly/scripts/run_netally_eval.py` | SSE 기반 실행기 (백엔드 통해 호출, 느림) |
| `Experiment/code/NetConfigQA2_2/analyze_results.py` | TA-Acc 채점기 |
| `NetAlly/scripts/build_result3_scorecards.py` | 여러 모델 결과 한 번에 묶는 집계 |
| `NetAlly/eval/scorer.py`, `tool_usage_scorer.py` | 채점 로직 (TA-Acc 계산) |

---

## 2. 실험 실행 — 단일 lab 평가

### 2.1 사전 점검 (10초)

```bash
# 1) NSO + Batfish 살아있나
docker ps | grep -E 'cisco-nso|batfish'

# 2) NetAlly 백엔드 헬스
curl -s http://localhost:8111/api/health | python3 -m json.tool | head -5

# 3) MCP 서버 살아있나 (24 tools 떠야 함)
curl -s http://localhost:8111/api/health | python3 -c \
  'import json,sys; d=json.load(sys.stdin); print("MCP tools:", d.get("mcp_health",{}).get("tool_count"))'
```

기대 출력: `MCP tools: 24`

### 2.2 LabD 평가 실행 (예시 — 작은 limit으로 먼저)

```bash
cd /home/leehj/network/GIA/NetAlly

# .env 로드
set -a; source .env; set +a

# LabD 데이터셋 — 가장 최근 영어 버전 사용
DATASET="../Data/Pnetlab/LabD_NCN_MultiAS_Complex_40nodes/Dataset/20260325_102315"
DATASET_JSON="$DATASET/LabD_NCN_MultiAS_Complex_40nodes_dataset_batfish_*_en.json"

ls -la $DATASET_JSON   # 파일 존재 확인

python3 scripts/run_netally_eval_direct.py \
  --dataset $(ls $DATASET_JSON | head -1) \
  --lab LabD \
  --limit 10
```

`--limit 10`은 처음 10개 질문만 — 파이프라인 정상 작동 확인용. 전체 실행 시 limit 제거.

### 2.3 옵션 정리

| 옵션 | 의미 |
|---|---|
| `--dataset PATH` | 입력 데이터셋 JSON 절대 경로 (**필수**) |
| `--lab Lab-D` 또는 `--lab LabD` | 어느 lab인지 (메타데이터용) |
| `--limit N` | 처음 N개 질문만 |
| `--include-levels L1 L2` | 특정 난이도만 (L1~L6) |
| `--exclude-levels L6` | 특정 난이도 제외 |
| `--max-retries 3` | 실패 시 재시도 (기본 3) |
| `--max-workers 1` | 병렬 thread 개수 (기본 1, 직렬) |
| `--output FILE.json` | resume할 기존 결과 파일 |

### 2.4 difficulty level 별 실행 (논문용)

```bash
# L1~L3만 (사실 기반 QA)
python3 scripts/run_netally_eval_direct.py \
  --dataset $(ls $DATASET_JSON | head -1) \
  --lab LabD \
  --include-levels L1 L2 L3

# L4~L5만 (시뮬레이션 기반)
python3 scripts/run_netally_eval_direct.py \
  --dataset $(ls $DATASET_JSON | head -1) \
  --lab LabD \
  --include-levels L4 L5
```

| Level | 인지 능력 | 엔진 | 예시 질문 |
|---|---|---|---|
| L1 | Fact extraction | Config parsing | "PE1의 hostname은?" |
| L2 | Aggregation | Facts traversal | "SSH 활성화 장비 수?" |
| L3 | Cross-comparison | BuilderCore | "iBGP full-mesh 완성?" |
| L4 | Simulation | Batfish traceroute | "10.0.0.1→192.168.1.1 경로?" |
| L5 | What-If | fork_snapshot + diff | "P1-P2 다운 시 영향?" |
| L6 | Diagnosis | Fault injection | (논문 범위 외) |

---

## 3. 결과 저장 위치

### 3.1 raw 평가 결과

```
NetAlly/results/
├── netally_eval_direct_Dataset_20260417_175633.json
│   └─ 질문별 답변 + tool calls + 시간 정보
├── netally_eval_direct_Dataset_20260417_175633_analyzed.json
│   └─ 채점 결과가 추가된 버전
├── netally_eval_direct_Dataset_20260417_175633_analyzed_scorecard.md
│   └─ ★ 사람이 보는 점수표 ★
├── netally_eval_direct_Dataset_20260417_175633_analyzed_summary.md
│   └─ level별 짧은 요약
├── netally_eval_direct_Dataset_20260417_175633_analyzed_detailed.csv
│   └─ 엑셀로 보기 좋은 raw
└── netally_eval_direct_Dataset_20260417_175633_analyzed_errors.json
    └─ 실패한 질문만 모음
```

파일명 패턴:
- `netally_eval_direct_` — direct 모드 실행기 ID
- `Dataset_<YYYYMMDD>_<HHMMSS>` — 실행 시점 timestamp
- `_analyzed_*` — analyze_results.py가 후처리한 파생 파일

### 3.2 여러 모델/lab 묶은 집계

```
NetAlly/result3/
├── scorecards/
│   ├── strict/         ← 엄격 채점 (정답 완전 일치)
│   └── relaxed/        ← 완화 채점 (부분 일치 허용)
├── tables/             ← 논문용 표 (markdown)
└── raw_index.md        ← 원본 결과 인덱스
```

`result3/`은 여러 모델(GPT-4o-mini, Mistral-8b, Qwen3-8b 등)을 한꺼번에 평가했을 때 비교용으로 정리하는 폴더. 단일 lab 실험만 할 거면 `results/`만 봐도 충분.

```
NetAlly/result2/        ← 이전 실험 버전 (singleLLM 모드 결과)
NetAlly/eval/           ← 채점 코드 (수정할 일 거의 없음)
```

---

## 4. 채점 메트릭 — TA-Acc (Type-Aware Accuracy)

### 4.1 왜 TA-Acc인가

BERTScore는 네트워크 도메인에서 변별력이 없다 (모든 난이도에서 0.9+). 정답이 `Leaf1, Leaf2, Leaf3` 같은 *device 이름 집합*인데 BERTScore는 단어 의미 유사도라 별 차이가 안 난다.

**TA-Acc는 answer_type별로 비교 방식을 바꾼다**:

| answer_type | 비교 방식 | 예시 |
|---|---|---|
| `set_str` | F1 (순서 무관) | 정답=`{Leaf1, Leaf2}`, 응답=`Leaf2, Leaf1` → F1=1.0 |
| `path` | Ordered Exact Match | 정답=`A→B→C`, 응답=`A→C→B` → 0.0 |
| `scalar_str` | 정규화 후 Exact | `"GigabitEthernet 0/0"` ≈ `"Gi0/0"` |
| `scalar_int` | 숫자 비교 | `"5"` == `5` |
| `bool` | 정규화 비교 | `"true"`, `"yes"` 동일 |
| `map_str_int` | Key-Value F1 | `{P1: 5, P2: 3}` |

### 4.2 scorecard.md 읽는 법

`NetAlly/results/<eval>_analyzed_scorecard.md`를 열면 대략 이런 표:

```markdown
## TA-Acc by Level

| Level | n  | TA-Acc | Format-Valid |
|-------|----|--------|--------------|
| L1    | 120| 0.92   | 0.98         |
| L2    | 95 | 0.85   | 0.91         |
| L3    | 80 | 0.71   | 0.83         |
| L4    | 50 | 0.55   | 0.72         |
| L5    | 30 | 0.42   | 0.65         |
| Total | 375| 0.78   | 0.86         |
```

- `n`: 질문 개수
- `TA-Acc`: 평균 TA-Acc 점수 (0~1)
- `Format-Valid`: 응답 형식이 채점 가능한 형태였는지 비율

**summary.md**는 같은 표 + 짧은 코멘트.

**detailed.csv**는 질문 하나하나의 결과 — Excel로 열어서 필터링 가능.

**errors.json**은 실패만 모은 거 — 디버깅에 유용.

---

## 5. 일반적인 실험 시나리오

### 5.1 시나리오 A — LabD 전체 평가 (현재 active)

```bash
cd /home/leehj/network/GIA/NetAlly
set -a; source .env; set +a

DS=$(ls ../Data/Pnetlab/LabD_NCN_MultiAS_Complex_40nodes/Dataset/*/*_en.json 2>/dev/null | sort | tail -1)
echo "Dataset: $DS"

python3 scripts/run_netally_eval_direct.py \
  --dataset "$DS" \
  --lab LabD

# 결과 확인
ls -lat results/netally_eval_direct_*$(date +%Y%m%d)* | head -5
```

### 5.2 시나리오 B — LabA로 전환 후 평가

`01_SETUP_GUIDE.md` §5에 따라 LabD → LabA 전환 후:

```bash
cd /home/leehj/network/GIA/NetAlly

# LabA 데이터셋 (예시: 가장 최근)
DS=$(ls ../Data/Pnetlab/LabA_Research_Institute_DC_10nodes/Dataset/*/*_en.json 2>/dev/null | sort | tail -1)

python3 scripts/run_netally_eval_direct.py --dataset "$DS" --lab LabA --limit 20
```

### 5.3 시나리오 C — 다른 LLM 모델 시도

`.env`에서 LLM 백엔드 갈아끼우기:

```bash
# vLLM 로컬 (RTX 3090) — 평가용으로 빠름
NETALLY_EXECUTOR_LLM_BACKEND=vllm
VLLM_BASE_URL=http://localhost:8000/v1
NETALLY_EXECUTOR_LLM_MODEL=Qwen/Qwen3-8B

# OpenRouter (다양한 모델)
NETALLY_EXECUTOR_LLM_BACKEND=openai
NETALLY_EXECUTOR_LLM_MODEL=openai/gpt-4o-mini
OPENAI_API_BASE=https://openrouter.ai/api/v1

# OpenAI 직접
NETALLY_EXECUTOR_LLM_BACKEND=openai
NETALLY_EXECUTOR_LLM_MODEL=gpt-4o-mini
unset OPENAI_API_BASE
```

`.env` 수정 후 백엔드 재기동 필수.

### 5.4 시나리오 D — 중단된 실험 재개

```bash
python3 scripts/run_netally_eval_direct.py \
  --dataset "$DS" \
  --lab LabD \
  --output results/netally_eval_direct_Dataset_20260511_120000.json
# 기존 output에 이어 쓰기 (이미 완료된 질문 skip)
```

---

## 6. 실패 디버깅

### 6.1 평가가 한 질문에서 멈춤

`Ctrl+C` 후 백엔드 로그:
```bash
tail -100 /tmp/netally-backend.log
```

가장 흔한 원인:
- MCP 서버 죽음 → 백엔드 재기동
- NSO sync 끊김 → `01_SETUP_GUIDE.md` §6.1 (ssh-rsa) 또는 §6.3 (OOB)
- LLM API rate limit → 잠시 후 재개 또는 다른 모델

### 6.2 errors.json 분석

```bash
cat results/<eval>_analyzed_errors.json | python3 -m json.tool | head -50

# 에러 패턴 빈도
python3 - <<'PY'
import json
errs = json.load(open('results/<eval>_analyzed_errors.json'))
from collections import Counter
print(Counter(e.get("error_type", "unknown") for e in errs))
PY
```

### 6.3 단일 질문 디버깅

```bash
# 백엔드 직접 호출 (SSE) — 응답 흐름 보기
curl -N http://localhost:8111/api/chat -X POST \
  -H "Content-Type: application/json" \
  -d '{"message": "What is PE1 hostname?", "session_id": "debug"}' \
  | head -50
```

---

## 7. 자주 쓰는 명령 요약

```bash
# 가장 최근 결과 파일
ls -t /home/leehj/network/GIA/NetAlly/results/*.json | head -3

# 가장 최근 scorecard 열기
cat $(ls -t /home/leehj/network/GIA/NetAlly/results/*_scorecard.md | head -1)

# 전체 result 갯수
ls /home/leehj/network/GIA/NetAlly/results/*_analyzed.json | wc -l

# scorecard 한 줄로 — TA-Acc total만
grep -E '^\| Total' $(ls -t /home/leehj/network/GIA/NetAlly/results/*_scorecard.md | head -1)
```

---

## 8. FAQ

**Q1. 실험 한 번에 얼마나 걸리나요?**
A. 질문당 평균 10~30초 (LLM 응답 + tool call). LabA(10 nodes) 전체 데이터셋(~200 질문) = 약 1~2시간. LabD(40 nodes)는 데이터셋 크기가 더 커서 4~6시간.

**Q2. limit 없이 돌리면 비용은?**
A. OpenRouter Mistral-3-8b 기준 질문당 ~$0.001. 데이터셋 500 질문 = $0.5. GPT-4o-mini는 약 5배.

**Q3. result3와 results 폴더 차이는?**
A. `results/` = 단일 실행 raw + 채점. `result3/` = 여러 모델/lab 결과를 묶은 비교표 (논문용). 일반 운영에선 `results/`만 봐도 됨.

**Q4. tool_usage_scorer는 뭔가요?**
A. TA-Acc는 *최종 답*만 보지만, tool_usage_scorer는 NetAlly가 *어떤 도구를 어떤 순서로* 호출했는지도 채점. 같은 정답이라도 NSO만 호출한 거 vs Batfish까지 검증한 거를 구분.

**Q5. dataset 새로 만들고 싶으면?**
A. `Make_Dataset/src/main_batfish.py`로 생성. `CLAUDE.md`의 Build Commands 섹션 참고. 일반 운영에선 기존 dataset 그대로 사용.

---

## 9. 다음 단계

- 환경 구조를 그림으로 한 번 더 보고 싶으면 → **`README.html`**
- 셋업/포트/매핑이 헷갈리면 → **`01_SETUP_GUIDE.md`**
- 멀티-NSO 운영 원칙 (이전 운영자의 메모) → `docs/PNETLAB_MULTI_LAB_DEPLOYMENT_RUNBOOK.md`
- 코드 자체 흐름 (LangGraph, MCP, FastAPI) → `docs/agent_langgraph.md`, `docs/architecture.md`
