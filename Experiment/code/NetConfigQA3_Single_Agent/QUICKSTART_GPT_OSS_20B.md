# GPT-OSS-20B Agent 빠른 시작 가이드

## 🎯 목표

로컬 vLLM 모델(GPT-OSS-20B)로 LangChain Agent를 실행하여 Facts가 Config보다 우수함을 증명합니다.

## 📦 필요 사항

- GPU가 있는 시스템 (vLLM 실행용)
- Python 3.8+
- 충분한 GPU 메모리 (GPT-OSS-20B는 약 40GB 필요)

## 🚀 5분 만에 시작하기

### Step 1: Dependencies 설치

```bash
cd GIA/Experiment/code/NetConfigQA3_Single_Agent

# LangChain + vLLM 설치
pip install -r requirements_agent.txt
pip install vllm
```

### Step 2: vLLM 서버 시작 (터미널 1)

```bash
# 백그라운드에서 서버 시작
nohup ./start_vllm_server.sh > vllm_server.log 2>&1 &

# 서버 로그 확인
tail -f vllm_server.log

# 서버가 준비되면 다음과 같은 메시지가 보입니다:
# "Uvicorn running on http://0.0.0.0:8000"
```

**또는 포그라운드 실행** (디버깅용):
```bash
./start_vllm_server.sh
```

### Step 3: 서버 확인

```bash
# 서버 상태 확인
curl http://localhost:8000/v1/models

# 정상이면 다음과 같은 응답:
# {
#   "object": "list",
#   "data": [
#     {
#       "id": "GPT-OSS-20B",
#       "object": "model",
#       ...
#     }
#   ]
# }
```

### Step 4: Agent 실행 (터미널 2 또는 서버가 백그라운드인 경우 같은 터미널)

#### 빠른 테스트 (10개 샘플)

```bash
./run_agent_gpt_oss_20b.sh 10
```

#### 전체 평가 (762개)

```bash
./run_agent_gpt_oss_20b.sh 762
```

#### 또는 Python 직접 실행

```bash
python run_netconfigqa_eval_agent.py \
  --backend vllm_server \
  --model GPT-OSS-20B \
  --base_url http://localhost:8000/v1 \
  --sample 10
```

### Step 5: 결과 확인

```bash
# 메트릭 확인
cat results/GPT-OSS-20B_agent/metrics_agent_*.csv

# 결과 분석
python reanalyze_results.py "results/GPT-OSS-20B_agent/results_agent_*.json"
```

### Step 6: 비교 분석

```bash
python compare_approaches.py \
  --config results/GPT-OSS-20B_cfg/results_analyzed_20251231_104618.json \
  --facts results/GPT-OSS-20B/results_analyzed_20260107_141226.json \
  --agent results/GPT-OSS-20B_agent/results_agent_*.json
```

## 📊 예상 결과

```
================================================================================
                     NetConfigQA3 Agent Results
================================================================================

Type-Aware Accuracy          70~75% (+10~15%p vs Config 61.18%)
  
[Type-Aware Score by Answer Type]
   text        : 68~73% (+22%p vs Config)   ← 가장 큰 개선!
   number      : 55~60% (+33%p vs Config)   ← 파이썬 계산으로 대폭 개선!
   numeric     : 87~90% (+10%p vs Config)
   set         : 91~93% (+1%p vs Config)
   map         : 85~88% (+8%p vs Config)

[Efficiency Metrics]
   avg_total_tokens      : ~2,000 (-85% vs Config 15,000)
   avg_context_size      : ~3.5KB (-95% vs Config 50KB)
   avg_tool_calls        : 1.8
   avg_time_per_query    : 2.5s
```

## 🔧 트러블슈팅

### 1. vLLM 서버가 시작되지 않음

```bash
# GPU 확인
nvidia-smi

# CUDA 버전 확인
nvcc --version

# vLLM 재설치
pip uninstall vllm -y
pip install vllm --no-cache-dir
```

### 2. 메모리 부족 오류

```bash
# GPU 메모리 사용률 줄이기
# start_vllm_server.sh 수정:
GPU_MEMORY_UTIL=0.7  # 0.9에서 0.7로 변경
```

### 3. 서버 연결 실패

```bash
# 서버가 실행 중인지 확인
curl http://localhost:8000/v1/models

# 포트 변경 (다른 서비스가 8000 사용 중인 경우)
# start_vllm_server.sh 수정:
PORT=8001

# Agent 실행 시 URL 변경
python run_netconfigqa_eval_agent.py \
  --backend vllm_server \
  --base_url http://localhost:8001/v1 \
  ...
```

### 4. Agent가 느림

```bash
# 샘플 수 줄이기
./run_agent_gpt_oss_20b.sh 5

# 또는 temperature 조정
python run_netconfigqa_eval_agent.py \
  --backend vllm_server \
  --temperature 0.0 \
  --sample 10
```

### 5. vLLM 서버 종료

```bash
# 프로세스 찾기
ps aux | grep vllm

# 종료
pkill -f "vllm.entrypoints.openai.api_server"
```

## 📈 다음 단계

1. **전체 평가 실행**
```bash
./run_agent_gpt_oss_20b.sh 762
```

2. **Config/Facts와 비교**
```bash
python compare_approaches.py \
  --config results/GPT-OSS-20B_cfg/results_analyzed_*.json \
  --facts results/GPT-OSS-20B/results_analyzed_*.json \
  --agent results/GPT-OSS-20B_agent/results_agent_*.json
```

3. **논문용 그래프 생성**
```python
import pandas as pd
import matplotlib.pyplot as plt

# 메트릭 로드
metrics = pd.read_csv("results/GPT-OSS-20B_agent/metrics_agent_*.csv")

# Tool 호출 분포
plt.hist(metrics['tool_calls'], bins=10)
plt.xlabel('Tool Calls')
plt.ylabel('Frequency')
plt.title('Tool Call Distribution')
plt.savefig('tool_calls_distribution.png')
```

## 💡 팁

- **백그라운드 실행**: `nohup`으로 서버를 백그라운드에서 실행하면 터미널을 닫아도 계속 실행됩니다
- **로그 모니터링**: `tail -f vllm_server.log`로 서버 로그를 실시간으로 확인할 수 있습니다
- **GPU 사용률**: `nvidia-smi`로 GPU 사용률을 모니터링하세요
- **캐싱**: Agent는 자동으로 중복 질의를 캐싱합니다

## 📞 문의

문제가 있으면 로그 파일을 확인하세요:
- vLLM 서버: `vllm_server.log`
- Agent 실행: `logs/eval_agent_GPT-OSS-20B_*.log`

---

**시작하세요!** `./start_vllm_server.sh` 🚀

