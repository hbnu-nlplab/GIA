# NetConfigQA2.0 Evaluation Suite (v2.2)

> IEEE TNMS 실험용 — Ollama 기반 로컬 평가 파이프라인

## 파일 구조

```
NetConfigQA2_2/
├── run_eval.py          ← 추론 (Ollama/OpenAI API)
├── analyze_results.py   ← TA-Acc 채점 + 전통 메트릭
├── make_figure.py       ← 논문용 Figure 생성
├── logs/                ← 실행 로그
└── results/             ← 모델×Lab별 결과
    ├── gpt-oss_20b_LabA/
    ├── qwen3.5_27b_LabB/
    └── ...
```

## 실행 방법

### 1. 사전 준비

```bash
# Ollama 설치 (https://ollama.com/download/windows)
# 모델 다운로드
ollama pull gpt-oss:20b
ollama pull qwen3-coder:30b-a3b-q4_K_M
ollama pull gemma3:27b-it-q4_K_M
ollama pull glm-4.7-flash:q4_K_M
ollama pull qwen3.5:27b

# Python 의존성 (GIA 루트 .venv 사용)
pip install openai
```

### 2. 추론 실행

```bash
# 디버깅: 단일 모델, 단일 Lab, 10샘플만
python run_eval.py --model gpt-oss:20b --lab A --limit 10

# 본실험: 전체 (6모델 × 4Lab = 24회)
python run_eval.py --model all --lab all

# 특정 조합만
python run_eval.py --model qwen3.5:27b glm-4.7-flash:q4_K_M --lab A B

# OpenAI API 모델
python run_eval.py --model gpt-4o-mini --lab all --backend openai
```

### 3. 채점

```bash
# 단일 결과
python analyze_results.py results/gpt-oss_20b_LabA/results_raw_*.json

# 전체 결과 비교
python analyze_results.py results/*/results_raw_*.json -o comparison_report.md
```

### 4. 시각화

```bash
python make_figure.py results/gpt-oss_20b_LabA/results_raw_*_analyzed_*.json
```

## 모델 목록

| # | 모델 | Ollama 태그 | Backend |
|---|---|---|---|
| 1 | GPT-4o-mini | (OpenAI API) | openai |
| 2 | GPT-OSS-20B | `gpt-oss:20b` | ollama |
| 3 | Qwen3-Coder | `qwen3-coder:30b-a3b-q4_K_M` | ollama |
| 4 | Gemma-3-27B | `gemma3:27b-it-q4_K_M` | ollama |
| 5 | GLM-4.7-Flash | `glm-4.7-flash:q4_K_M` | ollama |
| 6 | Qwen3.5-27B | `qwen3.5:27b` | ollama |

## Lab 데이터셋

| Lab | 노드 | QA | 경로 |
|-----|:---:|:---:|------|
| A | 10 | 1,264 | Data/Pnetlab/LabA_.../Dataset/ |
| B | 20 | 2,154 | Data/Pnetlab/LabB_.../Dataset/ |
| C | 30 | 2,673 | Data/Pnetlab/LabC_.../Dataset/ |
| D | 40 | 3,371 | Data/Pnetlab/LabD_.../Dataset/ |

## 재현성 설정

- `temperature=0.0` (결정적 출력)
- `num_ctx=32768` (모든 모델 공통)
- `max_output_tokens=4096`
