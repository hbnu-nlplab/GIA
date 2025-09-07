# 자동 임베딩 가이드

## 개요
이 시스템은 사전 임베딩된 데이터가 ChromaDB에 없을 때 자동으로 XML 파일들을 임베딩합니다.

## 자동 임베딩 기능

### 1. 작동 원리
- ChromaDB 컬렉션이 비어있거나 존재하지 않을 때 자동으로 실행됩니다
- 지정된 XML 디렉토리의 모든 XML 파일을 재귀적으로 검색합니다
- 각 파일을 1500 토큰 크기의 청크로 분할합니다
- Qwen/Qwen3-Embedding-8B 모델을 사용하여 임베딩을 생성합니다
- 배치 단위로 처리하여 메모리 효율성을 높입니다

### 2. 설정 변경 사항
```python
# RAG 파이프라인 초기화 시 XML 디렉토리 경로 추가
rag_pipeline = NetworkEngineeringPipeline(
    chromadb_path=CHROMADB_PATH,
    collection_name=COLLECTION_NAME,
    max_iterations=MAX_ITERATIONS,
    xml_directory=XML_DIRECTORY  # 자동 임베딩용 XML 디렉토리
)
```

### 3. 자동 임베딩 과정
1. **초기화 시 확인**: ChromaDB 컬렉션의 문서 수를 확인
2. **XML 파일 검색**: XML 디렉토리에서 모든 .xml 파일을 재귀적으로 찾음
3. **파일 처리**: 각 파일을 다양한 인코딩으로 읽기 시도 (utf-8, utf-8-sig, latin-1, cp1252)
4. **청킹**: 텍스트를 1500 토큰 단위로 분할
5. **배치 임베딩**: 5개 청크씩 배치로 처리하여 메모리 효율성 향상
6. **메타데이터 저장**: 파일명, 경로, 청크 인덱스 등의 메타데이터 포함

### 4. 진행 상황 모니터링
```
[INFO] Collection is empty. Auto-embedding XML files from: /path/to/xml/directory
[INFO] Found 150 XML files. Starting auto-embedding...
[INFO] This may take several minutes depending on the number and size of files.
[INFO] Processing file 1/150: config1.xml
[INFO] Split into 12 chunks
[INFO] Embedded 25 chunks so far...
[INFO] Processing file 2/150: config2.xml
...
[INFO] Auto-embedding complete!
[INFO] Successfully processed: 148/150 files
[INFO] Total chunks embedded: 3420
[INFO] Collection now contains: 3420 documents
```

### 5. 에러 처리
- **인코딩 오류**: 여러 인코딩을 시도하여 파일 읽기
- **파일 처리 오류**: 개별 파일 실패 시 다음 파일로 계속 진행
- **임베딩 오류**: 배치 단위 실패 시 해당 배치만 건너뛰고 계속 진행
- **실패 파일 리포트**: 처리에 실패한 파일들의 목록 제공

### 6. 성능 최적화
- **배치 크기**: 5개 청크씩 처리하여 메모리 사용량 제어
- **진행 상황 표시**: 25개 청크마다 진행 상황 출력
- **다중 인코딩 지원**: 다양한 XML 파일 인코딩 자동 감지
- **청크 크기**: 1500 토큰으로 최적화된 청크 크기 사용

### 7. 메타데이터 구조
각 임베딩된 청크는 다음 메타데이터를 포함합니다:
```python
{
    "filename": "config1.xml",
    "file_path": "/full/path/to/config1.xml",
    "chunk_index": 0,
    "total_chunks": 12,
    "source": "auto_embedded",
    "source_directory": "/path/to/xml/directory"
}
```

## 사용법

### 1. 첫 번째 실행
```bash
# XML 파일들이 있는 디렉토리 경로 설정
XML_DIRECTORY = "path/to/your/xml/files"

# 파이프라인 실행
python pipeline_3_advanced.py
```

### 2. 이후 실행
- 이미 임베딩된 데이터가 있으면 자동 임베딩을 건너뜁니다
- 새로운 XML 파일을 추가하려면 컬렉션을 삭제하거나 새로운 컬렉션 이름을 사용하세요

### 3. 강제 재임베딩
기존 컬렉션을 삭제하고 재임베딩하려면:
```python
# ChromaDB 컬렉션 삭제
client = chromadb.PersistentClient(path=CHROMADB_PATH)
try:
    client.delete_collection(COLLECTION_NAME)
    print(f"Deleted collection: {COLLECTION_NAME}")
except:
    print(f"Collection {COLLECTION_NAME} not found")
```

## 주의사항

1. **시간 소요**: 대량의 XML 파일은 임베딩에 상당한 시간이 소요될 수 있습니다
2. **GPU 메모리**: Qwen3-Embedding-8B 모델은 GPU 메모리를 사용합니다 (cuda:1 설정)
3. **디스크 공간**: ChromaDB는 임베딩 데이터를 디스크에 저장하므로 충분한 공간이 필요합니다
4. **네트워크**: HuggingFace 모델 다운로드 시 인터넷 연결이 필요합니다

## 문제 해결

### 일반적인 문제
1. **CUDA 메모리 부족**: 배치 크기를 줄이거나 더 작은 GPU 디바이스를 사용
2. **인코딩 오류**: 시스템이 자동으로 여러 인코딩을 시도하지만, 특수한 인코딩의 경우 수동 변환 필요
3. **권한 오류**: XML 파일 및 ChromaDB 디렉토리에 대한 읽기/쓰기 권한 확인

### 로그 분석
- `[INFO]` 메시지: 정상적인 진행 상황
- `[WARNING]` 메시지: 주의가 필요하지만 계속 진행 가능
- `[ERROR]` 메시지: 개별 파일 또는 배치 처리 실패, 전체 진행에는 영향 없음

이 자동 임베딩 시스템을 통해 연구자들은 별도의 전처리 과정 없이 바로 RAG 실험을 시작할 수 있습니다.
