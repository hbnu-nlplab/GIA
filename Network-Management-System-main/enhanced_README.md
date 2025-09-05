# 🌐 Network Management System LLM Benchmark

**네트워크 설정 Q&A 벤치마크를 위한 종합 LLM 성능 평가 플랫폼**

## 📋 프로젝트 개요

이 프로젝트는 GIA-Re에서 생성된 고품질 네트워크 설정 벤치마크 데이터셋을 활용하여 다양한 Large Language Model(LLM)들의 네트워크 도메인 전문성을 체계적으로 평가합니다.

### 🎯 핵심 목표
- **도메인 특화 성능 측정**: 네트워크 엔지니어링 분야에서의 LLM 성능 평가
- **RAG 시스템 효과 분석**: 검색 증강 생성의 네트워크 도메인 적용 효과
- **모델별 비교 분석**: GPT, Claude, Llama, Qwen 등 다양한 모델 성능 비교
- **반복 개선 효과**: 멀티턴 대화를 통한 답변 품질 향상 측정

## 🏗 시스템 아키텍처

```
GIA-Re Dataset → Benchmark Runner → LLM Pipeline → Evaluation Metrics → Analysis Report
                      ↓                ↓              ↓                ↓
                Configuration → [Baseline/RAG] → [BERT/ROUGE/EM] → Visualization
```

## 📁 상세 폴더 구조

```
Network-Management-System-main/
├── 📊 dataset/                          # 벤치마크 데이터셋
│   ├── test.csv                         # 메인 평가 데이터 (459 Q&A)
│   ├── dataset_for_evaluation_corrected.csv
│   ├── dataset_for_evaluation_filtered.csv
│   └── processing.ipynb                 # 데이터 전처리 노트북
│
├── 🔄 pipeline/                         # LLM 추론 파이프라인
│   ├── pipeline_1_simple.py           # Baseline: 순수 LLM
│   ├── pipeline_2_advanced.py         # 개선된 프롬프팅
│   ├── pipeline_3_advanced.py         # RAG + 반복개선 (최고성능)
│   ├── chroma_db.py                   # 벡터 데이터베이스 관리
│   ├── logs/                          # 실행 로그 디렉토리
│   └── pipeline_results_*.log         # 실험 결과 로그
│
├── 📈 evaluation/                       # 성능 평가 및 분석
│   ├── gen_evaluation.ipynb           # 생성 성능 평가 노트북
│   ├── retrival_evaluation.ipynb      # 검색 성능 평가 노트북
│   ├── predict_*.csv                  # 모델 예측 결과 (샘플별)
│   ├── eval_results_*.csv             # 평가 메트릭 결과
│   └── eval_results_summary.csv       # 종합 성능 요약
│
├── 📚 docs6_export/                    # 네트워크 설정 문서 (구버전)
├── 📚 docs7_export/                    # 네트워크 설정 문서 (최신)
├── 🔧 xml_parssing/                   # XML 파싱 유틸리티
│
├── 🚀 llm_manager.py                  # 통합 LLM API 관리
├── 📊 experiment_logger.py            # 실험 로깅 및 시각화
├── ⚡ benchmark_runner.py            # 메인 벤치마크 실행기
├── ⚙️ llm_configs.json              # LLM 설정 파일
├── 🔧 benchmark_config.json         # 실험 설정 파일
├── 📋 requirements.txt               # 의존성 패키지
└── 📖 README.md                      # 이 문서
```

## 🧪 실험 설계

### 1. Baseline 실험 (순수 LLM)
```python
실험명: pipeline_1_simple
목적: RAG 없이 LLM 자체 성능 측정
특징: 
- 순수 모델 지식만 활용
- 네트워크 도메인 프롬프트 최적화
- 기본 성능 베이스라인 설정
```

### 2. RAG 기반 실험 (검색 증강)
```python
실험명: pipeline_3_advanced
목적: 네트워크 문서 검색을 통한 성능 향상
특징:
- ChromaDB 벡터 검색
- 관련 문서 컨텍스트 제공
- 반복적 답변 개선 (최대 3회)
- 실시간 웹 검색 보조
```

### 3. Fine-tuning 실험 (도메인 적응)
```python
실험명: (구현 예정)
목적: 네트워크 도메인 특화 학습
특징:
- LoRA/QLoRA 효율적 파인튜닝
- 도메인 특화 데이터셋 학습
- 추론 비용 vs 성능 트레이드오프 분석
```

## 📊 성능 평가 메트릭

### 1. 정확도 메트릭
- **Exact Match (EM)**: 정확한 일치율
- **BERT-Score**: 의미적 유사도 (Precision, Recall, F1)
- **ROUGE**: 요약 품질 (ROUGE-1, ROUGE-2, ROUGE-L)

### 2. 효율성 메트릭
- **응답 시간**: 질의당 평균 처리 시간
- **토큰 사용량**: 입력/출력 토큰 수
- **비용 효율성**: 달러당 성능 점수

### 3. 도메인 특화 메트릭
- **기술 용어 정확도**: 네트워크 전문 용어 사용 정확성
- **설정 구문 일치**: 실제 네트워크 설정 형식과의 일치도
- **문제 해결 능력**: 복잡한 네트워크 문제 해결 성공률

## 🔍 현재 실험 결과 (Qwen 모델)

| 샘플 수 | BERT-F1 | Exact Match | ROUGE-L | 개선율 |
|---------|---------|-------------|---------|--------|
| 1       | 0.844   | 15.1%       | 0.199   | 기준   |
| 5       | 0.843   | 16.2%       | 0.217   | +9%    |
| 10      | 0.850   | 19.8%       | 0.255   | +28%   |
| 20      | 0.855   | 20.5%       | 0.292   | +47%   |
| 50      | -       | -           | -       | 진행중  |

**핵심 인사이트**:
- RAG 샘플 수 증가 → 일관된 성능 향상
- Exact Match에서 가장 큰 개선 (15.1% → 20.5%)
- ROUGE-L 점수 47% 향상으로 답변 품질 크게 개선

## 🚀 빠른 시작

### 1. 환경 설정
```bash
# 프로젝트 클론 및 이동
cd Network-Management-System-main

# 의존성 설치
pip install -r requirements.txt

# API 키 설정 (.env 파일 생성)
OPENAI_API_KEY=your_openai_key
ANTHROPIC_API_KEY=your_anthropic_key
GOOGLE_API_KEY=your_google_key
GOOGLE_CSE_ID=your_cse_id
```

### 2. 기본 실험 실행
```bash
# Baseline 실험 (RAG 없음)
python pipeline/pipeline_1_simple.py

# RAG 기반 실험 (권장)
python pipeline/pipeline_3_advanced.py

# 통합 벤치마크 실행
python benchmark_runner.py --models gpt-4,claude-3 --experiments baseline,rag
```

### 3. 결과 분석
```bash
# 평가 메트릭 계산
jupyter notebook evaluation/gen_evaluation.ipynb

# 시각화 및 리포트 생성
python experiment_logger.py --generate-report
```

## 🔧 고급 사용법

### 1. 사용자 정의 LLM 추가
```python
# llm_configs.json에 새 모델 추가
{
  "custom_model": {
    "provider": "custom",
    "model_name": "your-model",
    "api_endpoint": "https://your-api.com",
    "max_tokens": 4096
  }
}
```

### 2. 새로운 평가 메트릭 추가
```python
# experiment_logger.py에 메트릭 함수 추가
def custom_metric(predictions, ground_truth):
    # 사용자 정의 평가 로직
    return score
```

### 3. RAG 시스템 커스터마이징
```python
# chroma_db.py에서 벡터 데이터베이스 설정 조정
collection = client.create_collection(
    name="custom_docs",
    embedding_function=custom_embedding_function
)
```

## 📈 향후 계획

### Phase 1: 현재 시스템 완성 ✅
- [x] 기본 파이프라인 구현
- [x] RAG 시스템 통합
- [x] 평가 메트릭 시스템
- [x] Qwen 모델 실험 완료

### Phase 2: 확장 및 최적화 🔄
- [ ] 다중 LLM 동시 벤치마킹
- [ ] Fine-tuning 파이프라인 구현
- [ ] 실시간 성능 대시보드
- [ ] 자동화된 실험 스케줄링

### Phase 3: 연구 및 분석 📊
- [ ] 도메인 적응 전략 연구
- [ ] 비용-성능 최적화 분석
- [ ] 네트워크 엔지니어 사용성 평가
- [ ] 논문 및 기술 보고서 작성

## 🤝 기여 방법

### 1. 새로운 LLM 모델 추가
```bash
1. llm_manager.py에 새 프로바이더 클래스 구현
2. llm_configs.json에 모델 설정 추가
3. 테스트 케이스 작성 및 검증
4. Pull Request 제출
```

### 2. 평가 메트릭 개선
```bash
1. evaluation/ 폴더에 새 메트릭 구현
2. 기존 결과와 비교 분석
3. 문서화 및 예시 제공
4. 커뮤니티 피드백 수집
```

### 3. 버그 리포트 및 기능 요청
- GitHub Issues 활용
- 재현 가능한 예시 제공
- 로그 및 환경 정보 포함

## 📚 참고 자료

### 학술 자료
- [RAG for Domain-Specific Tasks](https://arxiv.org/abs/2005.11401)
- [Network Configuration Analysis with AI](https://example.com)
- [LLM Evaluation Best Practices](https://example.com)

### 기술 문서
- [OpenAI API Documentation](https://platform.openai.com/docs)
- [ChromaDB Vector Database](https://docs.trychroma.com)
- [BERT-Score Evaluation](https://github.com/Tiiiger/bert_score)

### 프로젝트 관련
- [GIA-Re Dataset Generation](../README.md)
- [Network Configuration Standards](./docs/)
- [실험 결과 상세 분석](./evaluation/)

## 📞 연락처 및 지원

- **프로젝트 리드**: [GitHub Profile]
- **기술 지원**: [Issues 페이지]
- **협업 문의**: [이메일 주소]

---

**Made with ❤️ for Network Engineering Community**

*이 프로젝트는 네트워크 엔지니어링 분야에서 AI 기술의 실용적 적용을 목표로 합니다.*
