# 🎯 벤치마크 실험 체크리스트

## ✅ 이미 준비된 것들
- [x] ChromaDB 벡터 데이터베이스 시스템
- [x] 네트워크 설정 문서들 (docs7_export/)
- [x] 벤치마크 데이터셋 (dataset/test.csv)
- [x] RAG 파이프라인 (pipeline_3_advanced.py)
- [x] 평가 시스템 (benchmark_runner.py)

## 🔧 해야 할 일들

### 1단계: 환경 설정 및 API 키 확인
```bash
# API 키들이 제대로 설정되어 있는지 확인
# pipeline_3_advanced.py 파일의 21-23번째 줄 수정 필요
```

### 2단계: ChromaDB 데이터베이스 구축
```bash
# docs7_export 폴더의 문서들을 ChromaDB에 임베딩해서 저장
# 현재 경로가 /workspace/jke/chromadb_qwen 으로 설정되어 있음
```

### 3단계: 데이터셋에 맞는 프롬프트 조정
```bash
# 한국어 질문에 대한 프롬프트 최적화
# 네트워크 도메인 특화 프롬프트 개선
```

### 4단계: 실험 실행
```bash
# 1. Baseline 실험 (RAG 없음)
# 2. RAG 기반 실험 (문서 검색 활용)
# 3. Fine-tuning (선택사항)
```

## 🤔 "상위 문서 10개 뽑아달라고 하면 된다"는 의미
팀원이 말한 것은 아마도:
- 현재 ChromaDB 검색 대신에
- GPT에게 직접 "이 질문과 관련된 상위 10개 문서를 찾아달라"고 요청하는 방식
- 즉, LLM이 직접 문서 선택을 하는 방식

## 📝 다음 단계 액션 아이템
1. API 키 설정 수정
2. ChromaDB 데이터베이스 구축 스크립트 실행
3. 벤치마크 실행 테스트
4. 결과 분석 및 개선
