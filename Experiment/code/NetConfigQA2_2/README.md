# NetConfigQA2.0 Evaluation Suite (v2.2)

> IEEE TNSM 실험용 평가/채점 파이프라인

현재 이 폴더에서 실험에 실제로 쓰는 주력 경로는 `run_eval_vllm_offline.py` 기반의 로컬 GPU 평가와, 그 결과를 채점/집계하는 `analyze_results.py`, `run_all_scoring.sh`, `aggregate_paper_results.py` 입니다.

`run_eval_vllm_client.py` + `start_vllm_server.sh` 조합도 남아 있지만, 최근 실험과 디버깅은 `offline` 경로 기준으로 진행했습니다.

## 파일 구조

```text
NetConfigQA2_2/
├── run_eval_vllm_offline.py   ← 로컬 GPU vLLM Offline 평가
├── run_eval_vllm_client.py    ← 원격 vLLM/OpenAI 서버 클라이언트 평가
├── start_vllm_server.sh       ← vLLM API 서버 실행 스크립트
├── analyze_results.py         ← TA-Acc + EM/F1 + ROUGE/BLEU/BERTScore 채점
├── run_all_scoring.sh         ← results/ 전체 일괄 채점
├── aggregate_paper_results.py ← 모델/Lab 전체 통합 표/랭킹 생성
├── make_figure.py             ← 논문용 Figure 생성
├── logs/
└── results/
    └── <Model>/<LabX>/
        ├── results_raw_vllm_*.json
        ├── results_analyzed_vllm_*.json
        ├── results_analyzed_vllm_*_summary.md
        └── results_analyzed_vllm_*_scorecard.md
```

## 현재 상태

- 기본 평가 엔진: `run_eval_vllm_offline.py`
- 기본 backend:
  - 로컬 HF/vLLM 모델: `vllm_offline`
  - API 모델: `openai`, `openrouter`
- 최근 추가/수정된 주요 기능:
  - `finish_reason`, `output_tokens`, `request_max_tokens`, `truncated_flag` 저장
  - `--hard-levels-only`로 `L4/L5`만 재실험 가능
  - `--l4-max-tokens`, `--l5-max-tokens`로 고난도 출력 길이 override 가능
  - `--max-model-len auto`로 vLLM 공식 auto-fit 사용 가능
  - `--structured-outputs` 옵션 추가
    - 기본값은 `off`
    - 기본 비활성화 이유: xgrammar/regex 제약이 일부 대형 배치에서 속도를 크게 떨어뜨릴 수 있음

## 권장 실행 순서

1. `run_eval_vllm_offline.py`로 raw 결과 생성
2. `analyze_results.py` 또는 `run_all_scoring.sh`로 채점
3. `aggregate_paper_results.py`로 전체 통합표/랭킹 생성
4. 필요하면 `make_figure.py`로 Figure 생성

## Offline 평가 사용법

### 기본 실행

```bash
NetAlly/.venv/bin/python Experiment/code/NetConfigQA2_2/run_eval_vllm_offline.py \
  --model Qwen3.5-9B \
  --lab A
```

### 여러 모델/여러 Lab 실행

```bash
NetAlly/.venv/bin/python Experiment/code/NetConfigQA2_2/run_eval_vllm_offline.py \
  --model Qwen3.5-9B gpt-oss:20b \
  --lab A B C D
```

### 디버깅용 소량 실행

```bash
NetAlly/.venv/bin/python Experiment/code/NetConfigQA2_2/run_eval_vllm_offline.py \
  --model Qwen3.5-4B \
  --lab D \
  --limit 10
```

### 고난도 L4/L5만 재실험

```bash
NetAlly/.venv/bin/python Experiment/code/NetConfigQA2_2/run_eval_vllm_offline.py \
  --model Qwen3.5-4B \
  --lab D \
  --hard-levels-only \
  --l4-max-tokens 8192 \
  --l5-max-tokens 8192
```

### vLLM 공식 auto-fit 사용

```bash
NetAlly/.venv/bin/python Experiment/code/NetConfigQA2_2/run_eval_vllm_offline.py \
  --model Qwen3.5-4B \
  --lab D \
  --max-model-len auto
```

### auto-fit + 고난도 재실험 조합

```bash
NetAlly/.venv/bin/python Experiment/code/NetConfigQA2_2/run_eval_vllm_offline.py \
  --model Qwen3.5-4B \
  --lab D \
  --max-model-len auto \
  --hard-levels-only \
  --l4-max-tokens 8192 \
  --l5-max-tokens 8192
```

### structured outputs를 다시 시험하고 싶을 때만

```bash
NetAlly/.venv/bin/python Experiment/code/NetConfigQA2_2/run_eval_vllm_offline.py \
  --model Qwen3.5-4B \
  --lab D \
  --max-model-len auto \
  --hard-levels-only \
  --l4-max-tokens 8192 \
  --l5-max-tokens 8192 \
  --structured-outputs
```

## 주요 CLI 옵션

| 옵션 | 의미 |
|---|---|
| `--model ...` | 모델 태그 1개 이상 |
| `--lab ...` | `A B C D` 중 1개 이상 |
| `--gpu_util` | vLLM `gpu_memory_utilization` 상한 |
| `--limit` | 앞에서부터 N개만 평가 |
| `--include-levels` | 특정 난이도만 포함 |
| `--exclude-levels` | 특정 난이도 제외, 기본 `L6` |
| `--hard-levels-only` | `L4`, `L5`만 강제 평가 |
| `--l4-max-tokens` | `L4` 생성 토큰 상한 override |
| `--l5-max-tokens` | `L5` 생성 토큰 상한 override |
| `--max-model-len auto` | vLLM 공식 auto-fit 사용 |
| `--max-model-len <int>` | 모델별 `max_model_len` 강제 지정 |
| `--structured-outputs` | vLLM structured outputs 사용, 기본값은 꺼짐 |

## 현재 주요 모델 태그

| 모델 태그 | 표시 이름 | Backend |
|---|---|---|
| `gpt-oss:20b` | GPT-OSS-20B | `vllm_offline` |
| `qwen3-coder:30b-a3b-AWQ` | Qwen3-Coder | `vllm_offline` |
| `Nemotron-Cascade-2-30B-A3B-AWQ` | Nemotron-Cascade-2-30B-A3B | `vllm_offline` |
| `Gemma-3-27B-W4A16` | Gemma-3-27B | `vllm_offline` |
| `Qwen3.5-9B` | Qwen3.5-9B | `vllm_offline` |
| `Qwen3.5-4B` | Qwen3.5-4B | `vllm_offline` |
| `Foundation-Sec-8B` | Foundation-Sec-8B | `vllm_offline` |
| `gpt-4o-mini` | GPT-4o-mini | `openai` |

OpenRouter free 모델 태그도 들어 있지만, free tier rate limit 때문에 본 실험 전수평가에는 비권장입니다.

## Scoring 사용법

### 단일 raw 결과 채점

```bash
NetAlly/.venv/bin/python Experiment/code/NetConfigQA2_2/analyze_results.py \
  Experiment/code/NetConfigQA2_2/results/Qwen3.5-9B/LabA/results_raw_vllm_*.json
```

### 전체 결과 일괄 채점

```bash
bash Experiment/code/NetConfigQA2_2/run_all_scoring.sh
```

`run_all_scoring.sh`는 현재:
- `NetAlly/.venv`를 우선 사용
- raw 파일 timestamp별로 대응되는 analyzed 파일이 없을 때만 채점
- 최신 raw 결과가 예전 analyzed 때문에 skip되지 않도록 수정됨

### 논문용 통합 표/랭킹 생성

```bash
NetAlly/.venv/bin/python Experiment/code/NetConfigQA2_2/aggregate_paper_results.py \
  --results-dir Experiment/code/NetConfigQA2_2/results \
  --labs LabA LabB LabC LabD \
  --output-md Experiment/code/NetConfigQA2_2/results/paper_summary_all_labs.md \
  --output-csv Experiment/code/NetConfigQA2_2/results/paper_summary_all_labs.csv \
  --output-rank-csv Experiment/code/NetConfigQA2_2/results/paper_summary_all_labs_ranking.csv
```

### Figure 생성

```bash
NetAlly/.venv/bin/python Experiment/code/NetConfigQA2_2/make_figure.py \
  Experiment/code/NetConfigQA2_2/results/Qwen3.5-9B/LabA/results_analyzed_vllm_*.json
```

## 계산 가능한 메트릭

현재 `analyze_results.py`에서 계산되는 주요 메트릭:

- `Type-Aware Accuracy (TA-Acc)`
- `Exact Match (EM)`
- `Token F1`
- `ROUGE`
- `BLEU`
- `BERTScore`
- `Format Stability`

주의:
- `ROUGE/BLEU/BERTScore/matplotlib`는 의존성 설치가 필요함
- 미설치 시 예전처럼 `0.0`으로 숨기지 않고 `N/A`로 표시되도록 수정됨

### 필요한 의존성

```bash
NetAlly/.venv/bin/pip install rouge-score bert-score nltk matplotlib
```

## 결과 파일 해석

raw 결과 JSON 각 샘플에는 최근 다음 필드가 추가되었습니다.

- `finish_reason`
- `stop_reason`
- `output_tokens`
- `request_max_tokens`
- `truncated_flag`

이 값으로 다음을 구분할 수 있습니다.

- `finish_reason = "length"` 또는 `truncated_flag = true`
  - 출력이 generation budget에 걸려 잘린 경우
- `truncated_flag = false`인데도 `format_parseable = false`
  - 토큰 부족보다 형식 준수 실패/모델 품질 문제일 가능성이 큼

## 현재까지 확인된 문제

### 1. `max_model_len`과 `max_tokens`는 다른 문제

- `max_model_len`
  - 입력 + 출력 전체 시퀀스 상한
  - 너무 낮으면 아예 프롬프트가 안 들어감
- `max_tokens`
  - 출력 생성 상한
  - 너무 낮으면 답변 생성 중 `length`로 잘릴 수 있음

예:
- `Qwen3.5-4B LabD`는 과거 `32768`에서 입력 초과로 실패
- 이후 `40960` 또는 `--max-model-len auto`로 입력 문제는 완화
- 하지만 `L4/L5`는 `finish_reason=length`가 많이 나와 출력 budget 문제도 존재

### 2. structured outputs는 기본적으로 꺼두는 것이 안전

이유:
- xgrammar/regex/json constraint가 일부 대형 배치에서 속도를 심하게 떨어뜨릴 수 있음
- 특히 `L4/number` 대량 배치에서 decode가 매우 느려질 수 있었음
- 그래서 현재 기본값은 `off`

즉:
- 기본 실험: `--structured-outputs` 없이 실행
- 필요할 때만 별도 실험으로 켜서 비교

### 3. OpenRouter free 모델은 본 실험 전수평가에 부적합

이유:
- free tier rate limit
- provider routing 변동성
- privacy / reasoning 설정 이슈

따라서 OpenRouter free 모델은 파일럿/보조 비교용으로만 권장

## VRAM / KV Cache / 실험 운영 메모

### 핵심 원칙

- VRAM이 부족하면 큰 모델은 로드 자체가 안 되거나 KV cache가 매우 작아짐
- KV cache가 작으면 긴 prompt + 긴 출력 조합이 어려워짐
- `max_model_len`을 무작정 크게 잡으면 VRAM 사용량과 KV cache 예약량이 급증함

### A5000 24GB 기준 경험칙

- `Qwen3.5-4B`, `Qwen3.5-9B`
  - 비교적 여유 있음
  - `--max-model-len auto` 사용 가치가 큼
- `GPT-OSS-20B`, `Nemotron-Cascade-2-30B-A3B`
  - 긴 Lab D / 고난도에서 budget과 KV cache를 같이 신경써야 함
- `Gemma-3-27B-W4A16`
  - A5000에서는 매우 빡빡함
  - 큰 `max_model_len` 상향은 비추천

### A6000 48GB를 쓸 수 있다면

- 중대형 모델에서 훨씬 유리
- 긴 context와 큰 KV cache를 더 안정적으로 확보 가능
- 하지만 `finish_reason=length` 같은 출력 budget 문제를 VRAM만으로 해결하는 것은 아님

### 실무 권장

1. 먼저 `--max-model-len auto`로 입력 컨텍스트 문제를 줄임
2. 그래도 `truncated_flag=true`가 많으면 `--l4-max-tokens`, `--l5-max-tokens`를 올림
3. structured outputs는 속도 문제가 없을 때만 별도 비교 실험

## 재현성과 공정성 메모

- `temperature=0.0`
- 모델별 prompt/config bundle은 동일
- 최근 실험에선 고난도 재실험 시 `L4/L5`만 토큰 budget을 별도로 조정
- `paper_summary_all_labs.*`는 raw/analyzed 결과를 재사용해 전체 모델 비교표를 만듦

## 권장 실험 예시

### 1. 기본 전수평가

```bash
NetAlly/.venv/bin/python Experiment/code/NetConfigQA2_2/run_eval_vllm_offline.py \
  --model Qwen3.5-9B \
  --lab A B C D
```

### 2. Lab D 고난도만 재평가

```bash
NetAlly/.venv/bin/python Experiment/code/NetConfigQA2_2/run_eval_vllm_offline.py \
  --model Qwen3.5-4B \
  --lab D \
  --max-model-len auto \
  --hard-levels-only \
  --l4-max-tokens 8192 \
  --l5-max-tokens 8192
```

### 3. 재평가 후 통합표 갱신

```bash
NetAlly/.venv/bin/python Experiment/code/NetConfigQA2_2/aggregate_paper_results.py \
  --results-dir Experiment/code/NetConfigQA2_2/results \
  --labs LabA LabB LabC LabD \
  --output-md Experiment/code/NetConfigQA2_2/results/paper_summary_all_labs.md \
  --output-csv Experiment/code/NetConfigQA2_2/results/paper_summary_all_labs.csv \
  --output-rank-csv Experiment/code/NetConfigQA2_2/results/paper_summary_all_labs_ranking.csv
```
