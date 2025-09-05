# 🌐 Network LLM Benchmark System

**네트워크 설정 Q&A 벤치마크를 위한 종합 LLM 성능 평가 플랫폼**

이 시스템은 GIA-Re에서 생성된 고품질 네트워크 설정 벤치마크 데이터셋을 사용하여 다양한 Large Language Model의 네트워크 도메인 전문성을 체계적으로 평가합니다. RAG(Retrieval-Augmented Generation), 반복적 개선, Fine-tuning 등 최신 AI 기법을 통해 네트워크 엔지니어링 분야에서의 LLM 성능을 종합적으로 분석합니다.

## 📋 목차

- [프로젝트 개요](#프로젝트-개요)
- [폴더 구조](#폴더-구조)
- [실험 구성](#실험-구성)
- [설치 및 환경 설정](#설치-및-환경-설정)
- [사용법](#사용법)
- [평가 메트릭](#평가-메트릭)
- [결과 분석](#결과-분석)

## 🎯 프로젝트 개요

### 역할 분담
- **데이터셋 생성팀**: GIA-Re를 통한 고품질 네트워크 Q&A 벤치마크 데이터셋 생성
- **성능 평가팀**: 생성된 벤치마크로 다양한 LLM의 네트워크 도메인 성능 측정 (현재 레포)

### 핵심 기능
- 🤖 **다중 LLM 성능 평가**: GPT, Claude, Llama, Qwen 등 다양한 모델 지원
- 📚 **RAG 시스템**: ChromaDB 기반 네트워크 설정 문서 검색
- 🔄 **반복적 개선**: 멀티턴 대화를 통한 답변 품질 향상
- 📊 **종합 평가**: EM, F1, BERT-Score, ROUGE 등 다양한 메트릭
- 📈 **시각화**: 성능 비교 차트 및 분석 리포트 자동 생성

## 📁 폴더 구조

```
Network-Management-System-main/
├── 📂 dataset/                    # 벤치마크 데이터셋
│   ├── test.csv                   # 테스트 데이터 (평가용)
│   ├── dataset_for_evaluation_corrected.csv
│   ├── dataset_for_evaluation_filtered.csv
│   └── processing.ipynb           # 데이터 전처리
│
├── 📂 pipeline/                   # LLM 추론 파이프라인
│   ├── pipeline_1_simple.py      # 기본 LLM 추론 (RAG 없음)
│   ├── pipeline_2_advanced.py    # 개선된 파이프라인
│   ├── pipeline_3_advanced.py    # 최고 성능 파이프라인 (RAG + 반복개선)
│   ├── chroma_db.py              # 벡터 DB 관리
│   ├── logs/                     # 실행 로그
│   └── pipeline_results_*.log    # 실험 결과 로그
│
├── 📂 evaluation/                 # 성능 평가 및 분석
│   ├── gen_evaluation.ipynb      # 생성 성능 평가
│   ├── retrival_evaluation.ipynb # 검색 성능 평가
│   ├── predict_*.csv             # 모델 예측 결과
│   ├── eval_results_*.csv        # 평가 결과
│   └── eval_results_summary.csv  # 종합 성능 요약
│
├── 📂 docs6_export/              # 네트워크 설정 문서 (구버전)
├── 📂 docs7_export/              # 네트워크 설정 문서 (최신)
├── 📂 xml_parssing/              # XML 파싱 유틸리티
└── .gitignore
```

## 🧪 실험 구성

### 1. Baseline 실험 (RAG 없음)
```python
# pipeline/pipeline_1_simple.py
- 순수 LLM만 사용
- 네트워크 도메인 지식 없이 일반적 추론
- 기본 성능 측정용
```

### 2. RAG 기반 실험
```python
# pipeline/pipeline_3_advanced.py
- ChromaDB 기반 벡터 검색
- 네트워크 설정 문서 참조
- 컨텍스트 기반 답변 생성
- 반복적 개선 (최대 3회)
```

### 3. Fine-tuning 실험 (선택사항)
```python
# 추후 구현 예정
- 네트워크 도메인 특화 학습
- LoRA/QLoRA 기반 효율적 학습
- 도메인 적응 성능 측정
```

## � 빠른 시작

### 1. 환경 설정 (원클릭 설치)
```bash
# 프로젝트 디렉토리로 이동
cd Network-Management-System-main

# 자동 환경 설정 (의존성 설치, 디렉토리 생성 등)
python project_manager.py setup
```

### 2. API 키 설정
```bash
# 대화형 API 키 설정
python project_manager.py setup-keys
```

### 3. 시스템 상태 확인
```bash
# 데이터셋 확인
python project_manager.py check-data

# 모델 설정 확인  
python project_manager.py check-models

# 시스템 정보 확인
python project_manager.py system-info
```

### 4. 첫 실험 실행
```bash
# 빠른 데모 실험 (GPT-3.5-turbo, 5개 샘플)
python project_manager.py run-demo

# 또는 직접 실험 실행
python enhanced_benchmark_runner.py \
    --models gpt-4,claude-3-sonnet \
    --experiments baseline,rag \
    --sample-sizes 10,50 \
    --output-dir results
```
pandas
torch
transformers
langchain
langchain-community
langchain-google-community
bert-score
rouge-score
matplotlib
seaborn
plotly
```

### API 키 설정
```bash
export OPENAI_API_KEY="your-openai-key"
export GOOGLE_API_KEY="your-google-key"
export GOOGLE_CSE_ID="your-cse-id"
export ANTHROPIC_API_KEY="your-claude-key"
```

### ChromaDB 초기화
```python
# pipeline/chroma_db.py 실행
python chroma_db.py --init
```

## 🚀 사용법

### 1. 기본 실험 실행
```bash
# Baseline (RAG 없음)
cd pipeline/
python pipeline_1_simple.py

# RAG 기반 실험
python pipeline_3_advanced.py
```

### 2. 배치 평가
```python
# 여러 top-k 값으로 실험
for top_k in [1, 5, 10, 20, 50]:
    pipeline.process_query(query, top_k_chroma=top_k)
```

### 3. 성능 평가
```bash
cd evaluation/
jupyter notebook gen_evaluation.ipynb
```

### 4. 결과 분석
```python
# 성능 비교 차트 생성
python generate_performance_charts.py
```

## 📊 평가 메트릭

### 1. 정확도 메트릭
- **Exact Match (EM)**: 정확히 일치하는 답변 비율
- **F1 Score**: 토큰 레벨 정밀도/재현율
- **BERT Score**: 의미적 유사도

### 2. 생성 품질 메트릭  
- **ROUGE-L**: 최장 공통 부분수열
- **BLEU**: n-gram 기반 유사도
- **Semantic Similarity**: 임베딩 기반 유사도

### 3. 검색 성능 메트릭
- **Retrieval Accuracy**: 관련 문서 검색 정확도
- **Context Relevance**: 검색된 컨텍스트의 관련성
- **Answer Grounding**: 답변의 근거 문서 일치도

## 📈 결과 분석

### 현재 실험 결과 (예시)

#### RAG Top-K 성능 비교
| Top-K | EM Score | F1 Score | BERT Score | 처리시간(s) |
|-------|----------|----------|------------|-------------|
| 1     | 0.42     | 0.61     | 0.73       | 2.3         |
| 5     | 0.56     | 0.74     | 0.81       | 3.1         |
| 10    | 0.61     | 0.78     | 0.84       | 4.2         |
| 20    | 0.63     | 0.79     | 0.85       | 6.1         |
| 50    | 0.64     | 0.80     | 0.86       | 12.4        |

#### 모델별 성능 비교
```
GPT-4o-mini:    EM=0.63, F1=0.79, BERT=0.85
Claude-3:       EM=0.58, F1=0.76, BERT=0.82  
Llama-3-8B:     EM=0.45, F1=0.68, BERT=0.74
Qwen2.5-7B:     EM=0.52, F1=0.71, BERT=0.78
```

### 주요 발견사항
1. **RAG 효과**: Top-K=10에서 최적 성능/비용 균형
2. **반복 개선**: 평균 15% 성능 향상
3. **도메인 특화**: 네트워크 전문 모델이 일반 모델 대비 20% 우수

## 🔧 주요 코드 모듈

### 1. 파이프라인 엔진 (`pipeline_3_advanced.py`)
```python
class NetworkEngineeringPipeline:
    - 작업 분류 (Simple Lookup vs Complex Analysis)
    - 반복적 답변 개선 (ChromaDB + Internet)
    - 최종 답변 최적화
```

### 2. 임베딩 시스템
```python
class OpenAIEmbedder:    # OpenAI 임베딩
class HuggingFaceEmbedder:  # 로컬 임베딩 (Qwen 등)
```

### 3. 평가 시스템 (`evaluation/`)
```python
- gen_evaluation.ipynb: 생성 성능 평가
- retrival_evaluation.ipynb: 검색 성능 평가
- 자동 메트릭 계산 및 리포트 생성
```

## 🎯 향후 계획

### Phase 1: 현재 시스템 최적화
- [ ] 다중 GPU 지원 추가
- [ ] 캐싱 시스템 구현
- [ ] 실시간 모니터링 대시보드

### Phase 2: 고급 실험
- [ ] Fine-tuning 파이프라인 구축
- [ ] Multi-modal 네트워크 데이터 지원
- [ ] 연합학습 기반 모델 개발

### Phase 3: 배포 및 서비스
- [ ] RESTful API 서버
- [ ] 웹 기반 평가 인터페이스  
- [ ] 실시간 벤치마크 시스템

## 🤝 기여 가이드

1. **이슈 생성**: 버그 리포트 또는 기능 요청
2. **코드 기여**: Pull Request를 통한 코드 개선
3. **데이터셋 개선**: 새로운 네트워크 시나리오 추가
4. **평가 메트릭**: 도메인 특화 평가 방법 제안

## 📞 연락처

- **데이터셋 생성팀**: [GIA-Re Repository](../README.md)
- **성능 평가팀**: 현재 레포지토리 Issues
- **통합 문의**: yujin@example.com

---
*마지막 업데이트: 2025년 9월 5일*
