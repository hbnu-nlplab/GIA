# pipeline_v2 — Modular RAG / Non‑RAG Pipelines

분리 구조로 실험을 빠르고 명확하게 반복할 수 있도록 `pipeline_v2`를 제공합니다. 공통 유틸 모듈을 중심으로 Non‑RAG 파이프라인, RAG 파이프라인, 결과 비교 리포트를 독립 실행 스크립트로 구성했습니다.

## 폴더 구조

```
Network-Management-System-main/pipeline_v2/
├── README.md
├── config.py                 # 공통 설정 (환경변수로 override 가능)
├── compare_results.py        # 결과 통합(리치 리포트 + LaTeX 표)
├── non_rag_pipeline.py       # Non‑RAG 전용 실행 스크립트
├── rag_pipeline.py           # RAG 전용 실행 스크립트
└── common/
    ├── __init__.py
    ├── data_utils.py         # CSV 로드, 섹션 파싱, 토큰 계산
    ├── evaluation.py         # EM/F1(+옵션: BERT/ROUGE) 평가
    └── llm_utils.py          # ExperimentLogger, TrackedOpenAIClient
```

## 요구 사항

- Python 3.10+
- 의존성: 저장소 루트의 `requirements.txt` 사용 권장
  - 최소: `openai`, `chromadb`, `tiktoken`, `langchain-huggingface`, `pandas`
  - 평가 확장(선택): `bert-score`, `rouge`

설치 예:

```
pip install -r requirements.txt
```

## 환경 변수

- `OPENAI_API_KEY` (필수): OpenAI API Key
- 선택:
  - `CHROMADB_PATH` (기본: `Network-Management-System-main/docs7_export`)
  - `XML_DIRECTORY` (기본: `Network-Management-System-main/xml_parssing`)
  - `CSV_PATH` (기본: `Network-Management-System-main/dataset/test_fin.csv`)
  - `LLM_MODEL` (기본: `gpt-4o-mini`), `LLM_TEMPERATURE` (기본: 0.05)
  - `EMBEDDING_MODEL` (기본: `Qwen/Qwen3-Embedding-8B`)
  - `EMBEDDING_DEVICE` (기본: `cuda:1`, CPU 사용 시 `cpu`)
  - `MAX_ITERATIONS` (기본: 3), `DEFAULT_TOP_K_VALUES` (기본: `5,10,15`)
  - `NON_RAG_CHUNK_SIZE` (기본: 50000 토큰)

예시(Unix 계열):

```
export OPENAI_API_KEY="sk-..."
export EMBEDDING_DEVICE=cpu
```

## 빠른 시작

**⚠️ 중요: pipeline_v2 디렉토리에서 실행하세요**

```bash
cd Network-Management-System-main/pipeline_v2
export OPENAI_API_KEY="your-api-key-here"
```

### 1. Non‑RAG 실험 실행

```bash
# 모든 질문으로 실행 (기본)
python non_rag_pipeline.py --output-dir ../experiment_results/non_rag_run

# 처음 20개 질문만 빠른 테스트
python non_rag_pipeline.py \
  --output-dir ../experiment_results/non_rag_test \
  --max-questions 20
```

### 2. RAG 실험 실행 (복수 top‑k)

```bash
# 기본 설정 (k=5,10,15, 최대 3회 반복)
python rag_pipeline.py --output-dir ../experiment_results/rag_run

# 커스텀 설정
python rag_pipeline.py \
  --top-k 5,10,15 \
  --max-iterations 3 \
  --output-dir ../experiment_results/rag_custom
```

### 3. 결과 통합 분석 (Markdown + LaTeX 표)

```bash
# 기본 비교 (자동으로 .tex 파일도 생성)
python compare_results.py \
  --non-rag ../experiment_results/non_rag_run \
  --rag ../experiment_results/rag_run \
  --output ../experiment_results/comparison_report.md

# LaTeX 파일 경로 명시
python compare_results.py \
  --non-rag ../experiment_results/non_rag_run \
  --rag ../experiment_results/rag_run \
  --output ../experiment_results/comparison_report.md \
  --latex-output ../experiment_results/paper_table.tex
```

### 4. 전체 실험 자동 실행

**가장 쉬운 방법** - 모든 실험을 자동으로 실행:

```bash
# 모든 질문으로 전체 실험
./run_full_experiment.sh

# 처음 20개 질문만 빠른 테스트
./run_full_experiment.sh 20
```

이 스크립트는 다음을 자동으로 수행합니다:
- ✅ API 키 확인
- 🔹 Non-RAG 실험 실행
- 🔹 RAG 실험 실행 (k=5,10,15)
- 📊 결과 통합 분석
- 📈 성능 요약 미리보기

## 구성(설정) 가이드 — `config.py`

환경 변수를 우선 적용하고, 미지정 시 기본값을 사용합니다.

- `OPENAI_API_KEY`: OpenAI 키(권장: 환경변수)
- 경로: `CHROMADB_PATH`, `XML_DIRECTORY`, `CSV_PATH`, `EXPERIMENT_BASE_DIR`
- LLM: `LLM_MODEL`, `LLM_TEMPERATURE`
- Non‑RAG: `NON_RAG_USE_EMBEDDING`(기본 False), `NON_RAG_CHUNK_SIZE`
- RAG: `EMBEDDING_MODEL`, `EMBEDDING_DEVICE`, `MAX_ITERATIONS`, `DEFAULT_TOP_K_VALUES`

## 각 스크립트 설명

### 1) `non_rag_pipeline.py`
- 전체 XML 원문을 LLM 컨텍스트에 제공하여 직접 추출
- 주요 옵션: `--output-dir`, `--max-questions`
- 결과: `results_*.json` 내에 `results`(각 문항별)와 `evaluation`(EM/F1 등) 저장

### 2) `rag_pipeline.py`
- ChromaDB에서 후보 검색 → LLM 재순위화(Re-ranking) → 컨텍스트 구성 → 답변/최적화
- 컬렉션 비어있을 경우 `XML_DIRECTORY`의 XML을 자동 임베딩
- 주요 옵션: `--top-k`, `--max-iterations`, `--output-dir`
- 결과: `rag_k{K}.json`(각 k별) + `rag_all_results.json`

### 3) `compare_results.py`
- Non‑RAG, RAG 결과(JSON 파일 또는 디렉토리)를 입력으로 수집
- Markdown 리치 리포트 + LaTeX 표 파일 동시 생성
- 하이라이트: 최고 EM/F1 설정 및 Non‑RAG 대비 개선폭
- 표 지표: `Overall EM`, `Overall F1`, `Rule-based EM`, `Enhanced LLM GT EM`

## 결과물 구조 (ExperimentLogger)

각 실행은 타임스탬프별 폴더를 생성하고 다음 산출물을 저장합니다.

- `results/`: 요약 JSON(`results_*.json`, `rag_k*.json`, `rag_all_results.json`)
- `logs/`: 상세 단계 로그(JSON)
- `llm_history/`: LLM 요청/응답 기록(JSON) + 요약
- `console_output/`: 캡처된 콘솔 출력

## 성능 팁

- GPU가 없거나 메모리 부족 시 `EMBEDDING_DEVICE=cpu`로 설정
- RAG 최초 실행 시 XML 자동 임베딩이 수행되어 시간이 소요될 수 있음
- `NON_RAG_CHUNK_SIZE`는 전체 XML을 몇 토큰까지 컨텍스트로 넣을지 제어(기본 50k)
- `--max-questions`로 빠른 서브셋 검증 가능

## 문제 해결

### 🔑 API 키 관련
```bash
# API 키 미설정 오류
export OPENAI_API_KEY="sk-proj-your-actual-key-here"

# API 키 확인
echo $OPENAI_API_KEY
```

### 📁 경로 관련
```bash
# 실행 위치 확인 (pipeline_v2에서 실행해야 함)
pwd  # /path/to/Network-Management-System-main/pipeline_v2

# XML 디렉토리 확인
ls ../xml_parssing/  # XML 파일들이 있어야 함

# CSV 데이터셋 확인
ls ../dataset/test_fin.csv  # 평가 데이터가 있어야 함
```

### 🖥️ GPU/메모리 관련
```bash
# GPU 메모리 부족 시 CPU 사용
export EMBEDDING_DEVICE=cpu

# 토큰 제한 조정
export NON_RAG_CHUNK_SIZE=30000  # 기본 50000에서 줄이기
```

### 🔧 일반적인 오류들

- **ModuleNotFoundError**: `pip install -r ../requirements.txt`로 의존성 설치
- **ChromaDB 오류**: 첫 실행 시 XML 자동 임베딩으로 시간 소요 (정상)
- **JSON 파일 없음**: 실험이 완료되지 않았거나 output-dir 경로 확인 필요
- **메모리 부족**: `--max-questions 5`로 소수 질문만 테스트

### 📊 결과 확인

```bash
# 실험 진행 상황 확인
ls -la ../experiment_results/

# 로그 확인
tail -f ../experiment_results/*/console_output/console_*.txt

# JSON 결과 미리보기
head -20 ../experiment_results/*/results/*.json
```

## 논문용 LaTeX 표

- `compare_results.py`가 `--latex-output`으로 `.tex` 파일을 별도 저장
- 열: `Method, Setting, Overall EM, Overall F1, Rule-based EM, Enhanced LLM GT EM`
- 최고 EM/F1은 `\textbf{}`로 강조 표기됨

## 재현성 노트

- LLM/임베딩 모델 버전, 하이퍼파라미터, 데이터 경로를 명시적으로 기록하여 재현성 확보
- 결과 JSON과 함께 `config` 섹션이 저장되므로 실험 조건을 추적할 수 있음

## 명령어 도움말

각 스크립트의 모든 옵션을 확인하려면:

```bash
python non_rag_pipeline.py --help
python rag_pipeline.py --help
python compare_results.py --help
```

## 실행 예시 및 결과

### 샘플 실행 시간
- **Non-RAG** (30 질문): 약 3-5분
- **RAG** (30 질문, k=5,10,15): 약 15-20분
- **결과 비교**: 1분 이내

### 예상 결과 구조
```
experiment_results/
├── non_rag_run_20250908_143052/
│   ├── results/
│   │   └── results_20250908_143052.json
│   ├── logs/
│   ├── llm_history/
│   └── console_output/
├── rag_run_20250908_143155/
│   ├── results/
│   │   ├── rag_k5.json
│   │   ├── rag_k10.json
│   │   ├── rag_k15.json
│   │   └── rag_all_results.json
│   └── ...
└── comparison_report.md
```

### 성능 벤치마크 (참고용)
| 방법 | Overall EM | Overall F1 | 평균 처리시간 |
|------|------------|------------|---------------|
| Non-RAG | 0.8500 | 0.9200 | 2.5초/문항 |
| RAG (k=5) | 0.8200 | 0.8800 | 8.7초/문항 |
| RAG (k=10) | 0.8350 | 0.8950 | 12.3초/문항 |

## 병렬 실험 실행

여러 실험을 동시에 실행하려면:

```bash
# 백그라운드에서 Non-RAG 실행
python non_rag_pipeline.py --output-dir ../experiment_results/non_rag_run &

# 백그라운드에서 RAG 실행  
python rag_pipeline.py --output-dir ../experiment_results/rag_run &

# 모든 작업 완료 대기
wait

# 결과 통합
python compare_results.py \
  --non-rag ../experiment_results/non_rag_run \
  --rag ../experiment_results/rag_run \
  --output ../experiment_results/final_comparison.md

echo "✅ 모든 실험이 완료되었습니다!"
```

## 빠른 검증 (개발용)

개발이나 디버깅 시 빠른 테스트:

```bash
# 1개 질문으로만 빠른 검증
python Network-Management-System-main/pipeline_v2/non_rag_pipeline.py --max-questions 1 --output-dir ../test_results/non_rag_quick

python Network-Management-System-main/pipeline_v2/rag_pipeline.py --top-k 5 --output-dir ../test_results/rag_quick

# 결과 비교
python Network-Management-System-main/pipeline_v2/compare_results.py \
  --non-rag ../test_results/non_rag_quick \
  --rag ../test_results/rag_quick \
  --output ../test_results/quick_test.md
```
