# NetConfigQA2.0 Evaluation Suite (v2.2)

> IEEE TNSM 실험용 — vLLM 서버-클라이언트 분리 평가 파이프라인

## 파일 구조

```
NetConfigQA2_2/
├── run_eval_vllm_client.py  ← 클라이언트 추론 (AsyncOpenAI, vLLM/OpenAI 통합)
├── start_vllm_server.sh     ← GPU 서버측 vLLM 런처
├── analyze_results.py       ← TA-Acc 채점 + 전통 메트릭
├── make_figure.py           ← 논문용 Figure 생성
├── run_all_scoring.sh       ← 전체 결과 일괄 채점
├── run_eval_vllm_offline.py ← (백업) 로컬 GPU vLLM Offline 모드
├── logs/
└── results/
    └── <Model>/<LabX>/results_raw_vllm_*.json
```

## 아키텍처

```
[GPU Server]                              [Windows Client]
bash start_vllm_server.sh gpt-oss
  vLLM serving on 0.0.0.0:8000
      (Tailscale VPN)                     python run_eval_vllm_client.py \
                                            --server 100.x.x.x:8000 --lab all
                                            1. GET /v1/models -> auto detect
                                            2. Lab A~D 순차
                                            3. AsyncOpenAI + Semaphore(8)
                                            4. results_raw_vllm_*.json 저장
```

## 실행 방법

### 1. 서버: vLLM 시작

```bash
# GPU 서버에서 실행 (모델 alias 선택)
bash start_vllm_server.sh gpt-oss       # openai/gpt-oss-20b
bash start_vllm_server.sh qwen3-coder   # Qwen3-Coder-30B-A3B-AWQ
bash start_vllm_server.sh glm-flash     # GLM-4.7-Flash-AWQ
bash start_vllm_server.sh qwen3.5       # Qwen3.5-27B-AWQ
```

### 2. 클라이언트: 서버 테스트

```bash
# 연결 + 추론 + 동시성 자동 테스트
python run_eval_vllm_client.py --server 100.x.x.x:8000 --test
```

### 3. 클라이언트: 추론 실행

```bash
# vLLM 서버 모드
python run_eval_vllm_client.py --server 100.x.x.x:8000 --lab all
python run_eval_vllm_client.py --server 100.x.x.x:8000 --lab A --limit 5   # 디버깅

# OpenAI API 모드 (GPT-4o-mini)
python run_eval_vllm_client.py --openai gpt-4o-mini --lab all

# 체크포인트 재개
python run_eval_vllm_client.py --server 100.x.x.x:8000 --lab all --resume

# 옵션
--concurrency 4        # 동시 요청 수 (기본 8)
--include-levels L1 L2 # 특정 레벨만
--exclude-levels L6    # 제외 (기본 L6)
--timeout 300          # 요청당 타임아웃 (초)
```

### 4. 채점

```bash
# 단일 결과
python analyze_results.py results/GPT-OSS-20B/LabA/results_raw_vllm_*.json

# 전체 일괄 채점
bash run_all_scoring.sh
```

## 모델 목록

| # | 모델 | 서버 Alias | Backend |
|---|---|---|---|
| 1 | GPT-4o-mini | — | `--openai gpt-4o-mini` |
| 2 | GPT-OSS-20B | `gpt-oss` | vLLM server |
| 3 | Qwen3-Coder | `qwen3-coder` | vLLM server |
| 4 | GLM-4.7-Flash | `glm-flash` | vLLM server |
| 5 | Qwen3.5-27B | `qwen3.5` | vLLM server |

## Lab 데이터셋

| Lab | 노드 | QA | 경로 |
|-----|:---:|:---:|------|
| A | 10 | 1,264 | Data/Pnetlab/LabA_.../Dataset/ |
| B | 20 | 2,154 | Data/Pnetlab/LabB_.../Dataset/ |
| C | 30 | 2,673 | Data/Pnetlab/LabC_.../Dataset/ |
| D | 40 | 3,371 | Data/Pnetlab/LabD_.../Dataset/ |

## 의존성

클라이언트: `pip install openai` (torch/vllm 불필요)
서버: `pip install vllm`

## 재현성 설정

- `temperature=0.0`
- `max_model_len=40960` (서버)
- `max_tokens`: L1-L2=4096, L3=8192, L4-L5=16384
- 50건마다 체크포인트 저장, `--resume`으로 재개 가능
