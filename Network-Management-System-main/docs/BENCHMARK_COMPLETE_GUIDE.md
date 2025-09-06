# 🎯 Network LLM Benchmark 완전 가이드

## 📊 프로젝트 현황 분석

### ✅ 이미 준비된 구성 요소

1. **데이터셋**
   - `dataset/test.csv`: 459개 한국어 네트워크 Q&A
   - 질문 예시: "SSH가 활성화된 장비 목록은?", "sample10 장비의 iBGP 피어 목록은?"
   - 답변 형태: JSON 리스트, 숫자 값

2. **RAG 문서 소스**
   - `docs7_export/`: 186개 네트워크 설정 파일
   - 장비별 설정 정보 (device, admin_core, aaa_user, bgp, ospf 등)
   - 메타데이터 포함 구조화된 텍스트

3. **벤치마크 시스템**
   - `enhanced_benchmark_runner.py`: 메인 벤치마크 실행기
   - `enhanced_llm_manager.py`: LLM 통합 관리
   - `enhanced_experiment_logger.py`: 실험 로깅 및 분석

4. **설정 파일들**
   - `enhanced_benchmark_config.json`: 실험 설정
   - `enhanced_llm_configs.json`: LLM 모델 설정

## 🔬 실험 종류 및 목표

### 1. Baseline 실험 (RAG 없음)
```json
{
    "목적": "순수 LLM 성능 측정",
    "방법": "모델의 내재된 네트워크 지식만 활용",
    "설정": {
        "use_rag": false,
        "max_iterations": 1
    }
}
```

### 2. RAG 기본 실험
```json
{
    "목적": "문서 검색을 통한 성능 향상 측정",
    "방법": "ChromaDB 벡터 검색 + 컨텍스트 제공",
    "설정": {
        "use_rag": true,
        "max_iterations": 1,
        "top_k_contexts": 5
    }
}
```

### 3. RAG 반복 개선 실험
```json
{
    "목적": "멀티턴 대화를 통한 답변 품질 향상",
    "방법": "RAG + 3회 반복 개선",
    "설정": {
        "use_rag": true,
        "max_iterations": 3,
        "top_k_contexts": 5
    }
}
```

### 4. RAG 확장 실험
```json
{
    "목적": "최대 성능 측정",
    "방법": "더 많은 컨텍스트 + 반복 개선",
    "설정": {
        "use_rag": true,
        "max_iterations": 3,
        "top_k_contexts": 10
    }
}
```

## 📝 실행 전 준비사항

### 1. API 키 설정
다음 파일들에서 API 키를 설정해야 합니다:

**파일: `enhanced_llm_configs.json`**
```json
{
    "gpt-4": {
        "api_key": "your-openai-api-key-here"
    },
    "claude-3-opus": {
        "api_key": "your-anthropic-api-key-here"
    }
}
```

**또는 환경변수로 설정:**
```bash
set OPENAI_API_KEY=your-key-here
set ANTHROPIC_API_KEY=your-key-here
set GOOGLE_API_KEY=your-key-here
```

### 2. 의존성 설치
```bash
pip install -r enhanced_requirements.txt
```

**주요 패키지:**
- openai>=1.0.0
- anthropic
- chromadb
- bert-score
- rouge-score
- pandas
- torch
- langchain

## 🚀 실행 명령어 가이드

### 기본 실행 패턴
```bash
cd Network-Management-System-main
python enhanced_benchmark_runner.py [OPTIONS]
```

### 1단계: 소규모 테스트 (권장 시작점)
```bash
# 10개 질문으로 빠른 테스트
python enhanced_benchmark_runner.py --max-questions 10 --models gpt-3.5-turbo

# Baseline만 테스트
python enhanced_benchmark_runner.py --baseline-only --max-questions 10

# RAG만 테스트  
python enhanced_benchmark_runner.py --rag-only --max-questions 10
```

### 2단계: 특정 모델 비교
```bash
# GPT 모델들 비교
python enhanced_benchmark_runner.py --models gpt-4,gpt-3.5-turbo --max-questions 50

# Claude 모델들 비교
python enhanced_benchmark_runner.py --models claude-3-opus,claude-3-sonnet --max-questions 50
```

### 3단계: 전체 벤치마크
```bash
# 모든 실험 유형으로 전체 데이터셋 테스트
python enhanced_benchmark_runner.py --max-questions 459

# 특정 실험만 실행
python enhanced_benchmark_runner.py --experiments baseline,rag --max-questions 459
```

## 📈 평가 메트릭 설명

### 자동 계산되는 메트릭들
1. **Exact Match**: 정확한 일치율
2. **BERT Score**: 의미적 유사도 (한국어 모델 사용)
3. **ROUGE Score**: 텍스트 중복도
4. **Latency**: 응답 시간
5. **Cost**: 예상 비용
6. **Tokens per Second**: 처리 속도

### 결과 파일 위치
- `enhanced_benchmark_experiments.db`: SQLite 실험 데이터베이스
- `results/`: HTML, PDF 리포트
- `logs/`: 상세 실행 로그

## 🤔 "상위 문서 10개 뽑아달라"는 개선 아이디어

### 현재 RAG 방식의 한계
```python
# 현재: 벡터 유사도 기반 검색
query_embedding = embed(question)
similar_docs = vector_search(query_embedding, top_k=5)
context = "\n".join(similar_docs)
```

### 제안된 LLM 기반 문서 선택
```python
# 제안: LLM이 직접 관련 문서 선택
doc_list = get_all_document_summaries()
prompt = f"""
다음 문서 목록에서 이 질문 '{question}'에 답하는 데 
가장 유용한 상위 10개 문서를 선택해주세요:

{doc_list}

선택된 문서 번호만 반환하세요: 1,5,12,23...
"""
selected_docs = llm.generate(prompt)
context = load_selected_documents(selected_docs)
```

### 구현 방법
이 아이디어를 구현하려면 새로운 RAG 모드를 추가하면 됩니다:

1. **LLM 기반 문서 선택 모드** 추가
2. **하이브리드 모드**: 벡터 검색 + LLM 선택 조합
3. **성능 비교**: 기존 방식 vs 새 방식

## 📋 권장 실행 순서

### Phase 1: 환경 설정 및 검증
1. API 키 설정 확인
2. 의존성 설치
3. 소규모 테스트 (10개 질문)

### Phase 2: 기본 실험
1. Baseline 실험 (RAG 없음)
2. RAG 기본 실험
3. 결과 비교 분석

### Phase 3: 고급 실험
1. RAG 반복 개선 실험
2. 다양한 LLM 모델 비교
3. 성능 최적화

### Phase 4: 확장 실험
1. "LLM 문서 선택" 방식 구현
2. 하이브리드 RAG 개발
3. Fine-tuning 실험 (선택사항)

## 🎯 예상 결과 및 분석 포인트

### 성능 개선 예상치
- **Baseline → RAG**: 15-30% 성능 향상
- **RAG → RAG 반복**: 5-15% 추가 향상
- **더 많은 컨텍스트**: 3-10% 추가 향상

### 주요 분석 포인트
1. **모델별 RAG 효과 차이**
2. **질문 유형별 성능 차이**
3. **비용 대비 성능 효율성**
4. **응답 시간 vs 정확도 트레이드오프**

## 🔧 문제 해결 가이드

### 일반적인 오류들
1. **API 키 오류**: 환경변수 또는 설정 파일 확인
2. **ChromaDB 오류**: 데이터베이스 경로 및 권한 확인
3. **메모리 부족**: max_questions 수를 줄여서 테스트
4. **네트워크 오류**: API 호출 재시도 설정 확인

### 성능 최적화 팁
1. **배치 처리**: 여러 질문을 동시에 처리
2. **캐싱**: 중복 검색 결과 캐시
3. **토큰 관리**: 입력/출력 토큰 수 제한
4. **병렬 처리**: 다중 모델 동시 실행

---

이 가이드를 따라 단계별로 진행하시면 체계적인 네트워크 LLM 벤치마크를 수행할 수 있습니다!
