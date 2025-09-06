# 🚀 실무 실행 체크리스트

## ⚡ 빠른 시작 (5분 안에)

### 1단계: 환경 확인
```bash
# 현재 디렉토리 확인
pwd
# c:\Users\yujin\CodeSpace\GIA-Re\Network-Management-System-main 에 있어야 함

# Python 환경 확인
python --version
# Python 3.8+ 필요

# 필수 파일 존재 확인
ls enhanced_benchmark_runner.py
ls enhanced_benchmark_config.json
ls dataset/test.csv
ls docs7_export/
```

### 2단계: 최소 설정으로 테스트
```bash
# API 키 임시 설정 (테스트용)
set OPENAI_API_KEY=your-key-here

# 의존성 빠른 설치
pip install openai pandas chromadb

# 1개 질문으로 초단기 테스트
python enhanced_benchmark_runner.py --max-questions 1 --baseline-only
```

## 📋 단계별 실행 계획

### Phase 1: 검증 단계 (30분)
- [ ] 환경 설정 완료
- [ ] API 키 설정 완료  
- [ ] 1-5개 질문으로 기본 동작 확인
- [ ] ChromaDB 문서 로딩 확인
- [ ] 결과 파일 생성 확인

### Phase 2: 기본 실험 (2시간)
- [ ] Baseline 실험 10개 질문
- [ ] RAG 실험 10개 질문
- [ ] 성능 차이 확인
- [ ] 로그 및 결과 분석

### Phase 3: 확장 실험 (반나절)
- [ ] 50개 질문으로 확장
- [ ] 다양한 LLM 모델 테스트
- [ ] RAG 파라미터 조정
- [ ] 성능 최적화

### Phase 4: 전체 벤치마크 (하루)
- [ ] 전체 459개 질문
- [ ] 모든 실험 유형
- [ ] 종합 성능 분석
- [ ] 리포트 생성

## 🔧 설정 파일 수정 가이드

### API 키 설정 방법 3가지

#### 방법 1: 환경 변수 (권장)
```bash
# Windows PowerShell
$env:OPENAI_API_KEY="sk-..."
$env:ANTHROPIC_API_KEY="sk-ant-..."

# Windows CMD
set OPENAI_API_KEY=sk-...
set ANTHROPIC_API_KEY=sk-ant-...
```

#### 방법 2: 설정 파일 직접 수정
파일: `enhanced_llm_configs.json`
```json
{
    "gpt-3.5-turbo": {
        "api_key": "sk-your-actual-key-here"
    }
}
```

#### 방법 3: .env 파일 생성
파일: `.env`
```
OPENAI_API_KEY=sk-your-key-here
ANTHROPIC_API_KEY=sk-ant-your-key-here
```

### 실험 설정 커스터마이징

#### 빠른 테스트용 설정
파일: `enhanced_benchmark_config.json` 수정
```json
{
    "max_concurrent": 1,
    "resource_limits": {
        "max_input_tokens": 2048,
        "max_output_tokens": 1024,
        "timeout_seconds": 60
    }
}
```

#### 정확도 우선 설정
```json
{
    "experiments": {
        "rag_extensive": {
            "top_k_contexts": 15,
            "max_iterations": 5
        }
    }
}
```

## 🎯 모델별 추천 설정

### 비용 효율성 우선
```bash
python enhanced_benchmark_runner.py \
  --models gpt-3.5-turbo \
  --max-questions 100 \
  --experiments baseline,rag
```

### 성능 우선
```bash
python enhanced_benchmark_runner.py \
  --models gpt-4,claude-3-opus \
  --max-questions 50 \
  --experiments rag_extensive
```

### 속도 우선
```bash
python enhanced_benchmark_runner.py \
  --models gpt-3.5-turbo \
  --max-questions 200 \
  --max-concurrent 5 \
  --experiments baseline,rag
```

## 📊 결과 분석 가이드

### 주요 확인 포인트
1. **Exact Match 점수**: 정확한 답변 비율
2. **BERT Score**: 의미적 유사도 (0.8+ 목표)
3. **응답 시간**: 질문당 평균 처리 시간
4. **비용**: 질문당 예상 비용

### 성능 개선 신호
- RAG vs Baseline: 10%+ 성능 향상
- 반복 개선: 5%+ 추가 향상
- 더 큰 컨텍스트: 3%+ 추가 향상

### 문제 신호
- RAG 성능이 Baseline보다 낮음 → 문서 품질 문제
- 응답 시간 > 30초 → 설정 최적화 필요
- 비용 > $0.1/질문 → 모델 또는 토큰 제한 필요

## 🚨 자주 발생하는 문제들

### 문제 1: ChromaDB 초기화 실패
```
증상: "RAG 시스템 초기화 실패" 오류
해결: 
- 폴더 권한 확인
- 디스크 용량 확인  
- ChromaDB 재설치: pip install --upgrade chromadb
```

### 문제 2: API 호출 한도 초과
```
증상: "Rate limit exceeded" 오류
해결:
- max_concurrent 값을 1로 설정
- API 키 사용량 확인
- 시간 간격을 두고 재실행
```

### 문제 3: 메모리 부족
```
증상: "Out of memory" 오류
해결:
- max_questions를 10으로 줄이기
- max_input_tokens 제한
- 배치 크기 축소
```

### 문제 4: 한국어 인코딩 오류
```
증상: 텍스트 깨짐 또는 읽기 오류
해결:
- 파일 인코딩을 UTF-8로 저장
- Python 기본 인코딩 설정 확인
```

## 💡 성능 최적화 팁

### 속도 최적화
1. **병렬 처리**: `max_concurrent = 3`
2. **토큰 제한**: `max_input_tokens = 4096`
3. **타임아웃 단축**: `timeout_seconds = 120`

### 정확도 최적화
1. **더 많은 컨텍스트**: `top_k_contexts = 10`
2. **반복 개선**: `max_iterations = 3`
3. **더 좋은 모델**: `gpt-4` 또는 `claude-3-opus`

### 비용 최적화
1. **효율적 모델**: `gpt-3.5-turbo`
2. **토큰 제한**: `max_output_tokens = 1024`
3. **배치 처리**: 여러 질문을 한 번에

## 📈 예상 실행 시간

### 소규모 테스트 (10개 질문)
- Baseline: 5-10분
- RAG: 10-15분
- 전체: 15-25분

### 중간 규모 (50개 질문)  
- Baseline: 20-30분
- RAG: 30-45분
- 전체: 50-75분

### 전체 벤치마크 (459개 질문)
- Baseline: 3-4시간
- RAG: 4-6시간  
- 전체: 7-10시간

## 🎉 성공 지표

### 1단계 성공
- [x] 1개 질문 성공적으로 처리
- [x] 결과 파일 생성됨
- [x] 로그에 오류 없음

### 2단계 성공  
- [x] RAG가 Baseline보다 좋은 성능
- [x] 평균 응답 시간 < 30초
- [x] BERT Score > 0.7

### 최종 성공
- [x] 전체 데이터셋 처리 완료
- [x] 모든 실험 유형 완료
- [x] 종합 리포트 생성
- [x] 성능 개선 효과 확인
