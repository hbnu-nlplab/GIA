# 파이프라인 설정 가이드

## 개요
네트워크 엔지니어링 LLM 파이프라인의 모든 설정값들이 코드 맨 앞부분에 체계적으로 정리되어 있습니다. 실험 전에 필요한 값들을 쉽게 수정할 수 있습니다.

## 📍 설정 위치
**파일**: `pipeline_3_advanced.py`  
**위치**: 파일 상단 (라인 10-50)  

## 🔑 API 키 설정
```python
# 🔑 API 키 설정
GOOGLE_CSE_ID = "API_key"  # Google Custom Search Engine ID
GOOGLE_API_KEY = "API_key"  # Google API Key  
OPENAI_API_KEY = ""  # OpenAI API Key
```

**설정 방법**:
1. Google Cloud Console에서 Custom Search API 키 발급
2. OpenAI 계정에서 API 키 발급
3. 위 변수들에 실제 키 값 입력

## 📂 파일 경로 설정
```python
# 📂 파일 경로 설정
CHROMADB_PATH = "/workspace/jke/chromadb_qwen"  # ChromaDB 저장 경로 (자동 생성됨)
XML_DIRECTORY = "c:/Users/yujin/CodeSpace/GIA-Re/docs/xml_분석"  # XML 파일들이 있는 디렉토리
CSV_PATH = "c:/Users/yujin/CodeSpace/GIA-Re/Network-Management-System-main/dataset/test_fin.csv"  # 평가 데이터셋
```

**주의사항**:
- `CHROMADB_PATH`: 임베딩 데이터가 저장될 경로 (자동 생성됨)
- `XML_DIRECTORY`: 원본 XML 파일들이 있는 디렉토리 경로
- `CSV_PATH`: 평가용 질문-답변 데이터셋 경로

## 🎛️ 실험 파라미터 설정
```python
# 🎛️ 실험 파라미터 설정
COLLECTION_NAME = "network_devices"  # ChromaDB 컬렉션 이름
MAX_ITERATIONS = 3  # RAG 파이프라인 최대 반복 횟수
TOP_K_VALUES = [5, 10, 20]  # RAG에서 테스트할 Top-K 값들
```

**설정 가이드**:
- `MAX_ITERATIONS`: 1-5 권장 (너무 높으면 시간 소요)
- `TOP_K_VALUES`: 실험할 상위 K개 문서 수 리스트

## 🤖 모델 설정
```python
# 🤖 모델 설정
EMBEDDING_MODEL = "Qwen/Qwen3-Embedding-8B"  # 임베딩 모델
EMBEDDING_DEVICE = "cuda:1"  # 임베딩 모델 실행 디바이스
EMBEDDING_BATCH_SIZE = 8  # 임베딩 배치 크기
LLM_MODEL = "gpt-4o-mini"  # 메인 LLM 모델
LLM_TEMPERATURE = 0.05  # LLM Temperature
```

**GPU 설정**:
- `EMBEDDING_DEVICE`: `"cuda:0"`, `"cuda:1"`, `"cpu"` 등
- GPU 메모리 부족 시 `EMBEDDING_BATCH_SIZE` 감소

**모델 선택**:
- `LLM_MODEL`: `"gpt-4o-mini"`, `"gpt-4o"`, `"gpt-3.5-turbo"` 등
- `LLM_TEMPERATURE`: 0.0-1.0 (낮을수록 일관성 높음)

## 📊 Non-RAG 설정
```python
# 📊 Non-RAG 설정
NON_RAG_USE_EMBEDDING = True  # Non-RAG에서 임베딩 기반 문서 선택 사용 여부
NON_RAG_MAX_DOCS = 5  # Non-RAG에서 선택할 최대 문서 수
NON_RAG_CHUNK_SIZE = 1500  # 청크 크기 (토큰 단위)
```

**성능 튜닝**:
- `NON_RAG_USE_EMBEDDING`: `False`면 키워드 기반 선택만 사용
- `NON_RAG_CHUNK_SIZE`: 1000-2000 권장 (컨텍스트 길이 제한)

## 🔧 기타 설정
```python
# 🔧 기타 설정
EXPERIMENT_BASE_DIR = "experiment_results"  # 실험 결과 저장 디렉토리
```

## 🚀 빠른 시작 설정

### 1. 최소 설정 (API 키만)
```python
OPENAI_API_KEY = "your-openai-api-key"  # 필수
GOOGLE_API_KEY = "your-google-api-key"  # 인터넷 검색용
```

### 2. 경로 설정
```python
XML_DIRECTORY = "path/to/your/xml/files"  # XML 파일 경로
CSV_PATH = "path/to/your/test/data.csv"  # 평가 데이터
```

### 3. 실행
```bash
python pipeline_3_advanced.py
```

## ⚡ 성능 최적화 설정

### GPU 메모리 최적화
```python
EMBEDDING_DEVICE = "cuda:0"  # 사용 가능한 GPU
EMBEDDING_BATCH_SIZE = 4     # 메모리 부족 시 감소
```

### 빠른 실험용
```python
MAX_ITERATIONS = 1           # 반복 줄이기
TOP_K_VALUES = [5]          # K 값 하나만 테스트
NON_RAG_USE_EMBEDDING = False  # 임베딩 계산 생략
```

### 고품질 실험용
```python
MAX_ITERATIONS = 5           # 더 많은 반복
TOP_K_VALUES = [3, 5, 10, 15, 20]  # 다양한 K 값
LLM_MODEL = "gpt-4o"        # 더 강력한 모델
LLM_TEMPERATURE = 0.01      # 더 일관성 있는 결과
```

## 🔍 문제 해결

### 메모리 부족
```python
EMBEDDING_BATCH_SIZE = 2     # 배치 크기 감소
EMBEDDING_DEVICE = "cpu"     # CPU 사용
NON_RAG_CHUNK_SIZE = 1000   # 청크 크기 감소
```

### API 제한
```python
LLM_MODEL = "gpt-3.5-turbo"  # 더 저렴한 모델
MAX_ITERATIONS = 1           # 호출 수 감소
```

### 처리 속도 향상
```python
NON_RAG_USE_EMBEDDING = False  # 임베딩 계산 생략
TOP_K_VALUES = [5]            # 적은 K 값
```

## 📋 실험 전 체크리스트

- [ ] API 키 설정 완료
- [ ] XML 파일 경로 확인
- [ ] 평가 데이터셋 경로 확인  
- [ ] GPU 메모리 충분한지 확인
- [ ] 디스크 공간 충분한지 확인
- [ ] 결과 저장 디렉토리 권한 확인

이제 파일 상단의 설정 섹션만 수정하면 모든 실험 파라미터를 쉽게 조정할 수 있습니다! 🎯
