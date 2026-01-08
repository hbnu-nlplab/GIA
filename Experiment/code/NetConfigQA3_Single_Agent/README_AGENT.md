# NetConfigQA Agent Evaluator 사용 가이드

## 개요

LangChain 기반 에이전트를 사용하여 Facts JSON을 효율적으로 파싱하고 처리합니다.

### 핵심 특징

- ✅ **Tool 기반 Facts 접근**: 전체 JSON 주입 대신 필요한 정보만 Tool로 질의
- ✅ **상세 메트릭 수집**: 토큰, 시간, Tool 호출, 컨텍스트 크기 등
- ✅ **정확한 계산 로직**: Number type 질문을 파이썬으로 정확하게 계산
- ✅ **캐싱**: 중복 질의 방지
- ✅ **LangChain Agent**: ReAct 패턴으로 추론 과정 추적

## 설치

### OpenAI API 사용 시

```bash
# 1. Dependencies 설치
pip install -r requirements_agent.txt

# 2. OpenAI API Key 설정
export OPENAI_API_KEY="your-api-key-here"
```

### 로컬 vLLM (GPT-OSS-20B) 사용 시

```bash
# 1. Dependencies 설치 (vLLM 포함)
pip install -r requirements_agent.txt
pip install vllm

# 2. vLLM 서버 시작 (별도 터미널)
./start_vllm_server.sh

# 또는 백그라운드 실행
nohup ./start_vllm_server.sh > vllm_server.log 2>&1 &
```

## 실행 방법

### 🚀 GPT-OSS-20B (로컬 vLLM) - 권장

**Step 1: vLLM 서버 시작** (별도 터미널)

```bash
./start_vllm_server.sh
```

**Step 2: Agent 실행** (새 터미널)

```bash
# 빠른 테스트 (10개 샘플, Phase 3 기본값)
./run_agent_gpt_oss_20b.sh 10

# Phase 명시 (3=Evidence-only, 5=Analysis tools)
./run_agent_gpt_oss_20b.sh 50 3

# 전체 평가 (762개)
./run_agent_gpt_oss_20b.sh 762

# 또는 직접 실행
python run_netconfigqa_eval_agent.py \
  --backend vllm_server \
  --model GPT-OSS-20B \
  --base_url http://localhost:8000/v1 \
  --phase 3 \
  --sample 10
```

### OpenAI API 사용

#### 기본 실행 (gpt-4o-mini)

```bash
python run_netconfigqa_eval_agent.py \
  --backend openai_api \
  --model gpt-4o-mini \
  --sample 10
```

#### 전체 평가

```bash
python run_netconfigqa_eval_agent.py \
  --backend openai_api \
  --model gpt-4o-mini
```

#### GPT-4 사용

```bash
python run_netconfigqa_eval_agent.py \
  --backend openai_api \
  --model gpt-4o \
  --sample 50
```

## 수집되는 메트릭

### 1. 쿼리별 상세 메트릭 (`metrics_agent_*.csv`)

| 메트릭 | 설명 |
| --- | --- |
| `question_id` | 질문 ID |
| `total_time` | 총 소요 시간 (초) |
| `tool_calls` | Tool 호출 횟수 |
| `prompt_tokens` | 입력 토큰 수 |
| `completion_tokens` | 출력 토큰 수 |
| `total_tokens` | 전체 토큰 수 |
| `context_size` | 실제 사용된 컨텍스트 크기 (bytes) |
| `agent_steps` | 에이전트 추론 단계 수 |
| `success` | 성공 여부 |

### 2. 집계 메트릭 (JSON `metrics_summary`)

```json
{
  "total_queries": 762,
  "successful_queries": 750,
  "success_rate": 0.984,
  "avg_time_per_query": 2.5,
  "avg_tool_calls": 1.8,
  "avg_prompt_tokens": 1200,
  "avg_completion_tokens": 50,
  "avg_total_tokens": 1250,
  "avg_context_size": 3500,
  "avg_agent_steps": 2.1,
  "total_tokens": 952500
}
```

## Agent 구조

### Available Tools

1. **query_device**
   - 특정 장비의 정보 조회
   - 입력: `device=pe1, field=hostname`
   - 사용 가능 필드(예시):
     - `hostname`, `version`, `users`, `domain_name`, `interfaces`, `interface_count`
     - `bgp`, `ospf`, `static_routes_count`, `default_route_next_hops`
     - `ssh_version_text`, `vty_transport_input_text`, `vty_login_mode_text`, `aaa_authentication_method`

2. **interface_status_map**
   - 인터페이스 상태 맵을 **바로 JSON 객체로** 반환 (map 타입 질문에 권장)
   - 입력: 장비명 (예: `p3`)
   - 출력 예시: `{"GigabitEthernet0/0": "up", "Loopback0": "up"}`

3. **calculate_routing_entries**
   - `ROUTING_TABLE_ENTRY_COUNT` 질문에 대응하는 계산 (데이터셋 정의)
   - 입력: 장비명 (예: `p3`)
   - 현재 Research_Institute_Internal_DC 데이터셋에서는 **인터페이스 개수(connected entries, Loopback 포함)**에 대응

4. **list_all_devices**
   - 모든 장비의 특정 필드 조회
   - 입력: 필드명 (예: `hostname`)

### 에이전트 동작 예시

#### 질문: "p3 장비의 라우팅 테이블 엔트리는 총 몇 개?"

#### 에이전트 추론 과정

```text
Step 1: Thought: Need to calculate routing entries for p3
Action: calculate_routing_entries
Action Input: p3
Observation: 5

Step 2: Thought: I have the answer
Final Answer: 5
```

#### 수집된 메트릭

- Tool calls: 1
- Agent steps: 2
- Tokens: ~1500
- Context size: ~200 bytes (Tool 응답만)

## 비교 분석

### 평가 결과 재분석

```bash
# Agent 결과 분석
python reanalyze_results.py "results/gpt-4o-mini_agent/results_agent_*.json"
```

### Config vs Facts 비교

| 방식 | Type-Aware Accuracy | Avg Tokens | Avg Time | Tool Calls |
| --- | --- | --- | --- | --- |
| **Config 주입** | 61.18% | ~15,000 | 3.2s | 0 |
| **Facts 주입** | 60.01% | ~12,000 | 2.8s | 0 |
| **Agent (예상)** | **65~70%** | **~2,000** | **2.5s** | **1.8** |

**예상 개선점**:

- ✅ Text type: +20%p (태그 오류 해결)
- ✅ Number type: +35%p (정확한 계산)
- ✅ 토큰 절약: -85% (필요한 정보만)
- ✅ 컨텍스트: -95% (Tool 응답만 사용)

## 결과 파일

실행 후 생성되는 파일들:

```text
results/gpt-4o-mini_agent/
├── results_agent_20260107_150000.json  # 전체 결과 + 메타데이터
├── metrics_agent_20260107_150000.csv   # 쿼리별 상세 메트릭
└── logs/
    └── eval_agent_gpt-4o-mini_20260107_150000.log  # 실행 로그
```

## 다음 단계

1. **평가 실행**

```bash
python run_netconfigqa_eval_agent.py --model gpt-4o-mini --sample 100
```

1. **결과 분석**

```bash
python reanalyze_results.py "results/gpt-4o-mini_agent/results_agent_*.json"
```

1. **메트릭 비교**

```python
import pandas as pd

# 상세 메트릭 로드
metrics = pd.read_csv("results/gpt-4o-mini_agent/metrics_agent_*.csv")

# 통계 확인
print(metrics.describe())

# Tool 호출 분포
print(metrics['tool_calls'].value_counts())

# 타입별 성능
results = json.load(open("results/gpt-4o-mini_agent/results_agent_*.json"))
df = pd.DataFrame(results['results'])
print(df.groupby('answer_type')['pred'].count())
```

## Stratified 샘플(200개) 생성 (전체 실험 전 권장)

전체 762개를 돌리기 전에, **타입/레벨이 섞인 200개**를 먼저 만들어서 Phase 3/Phase 4 비교가 공정하게 되도록 합니다.

```bash
python make_stratified_sample.py \
  --input "/home/kilab_pyj/codespace/GIA/Data/Pnetlab/Research_Institute_Internal_DC/Dataset/Research_Institute_Internal_DC_dataset_batfish_20251230_125613.json" \
  --output "/home/kilab_pyj/codespace/GIA/Experiment/code/NetConfigQA3_Single_Agent/stratified_200.json" \
  --total 200 \
  --seed 42 \
  --min_per_type 30 \
  --min_per_level 10 \
  --types "text,number,numeric,set,map" \
  --levels "L1,L2,L3,L4,L5" \
  --only_status OK
```

생성된 `stratified_200.json`을 `run_netconfigqa_eval_agent.py --questions`로 넣어서 평가하면 됩니다.

## 트러블슈팅

### OpenAI API 오류

```bash
# API Key 확인
echo $OPENAI_API_KEY

# 또는 직접 지정
python run_netconfigqa_eval_agent.py --api_key "sk-..."
```

### LangChain import 오류

```bash
pip install --upgrade langchain langchain-openai langchain-community
```

### 느린 실행 속도

```bash
# 샘플 수 제한
python run_netconfigqa_eval_agent.py --sample 50

# 더 빠른 모델 사용
python run_netconfigqa_eval_agent.py --model gpt-3.5-turbo
```

## 향후 개선 방향

- [ ] 멀티에이전트 (Retriever + Reasoner 분리)
- [ ] Facts DB (SQLite) 전환
- [ ] 더 많은 Tool (Batfish, NSO 연동)
- [ ] 캐싱 고도화
- [ ] 병렬 처리

## 문의

문제가 있으면 로그 파일 (`logs/eval_agent_*.log`)을 확인하세요.
