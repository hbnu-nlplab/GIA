# 🚀 GIA-Re 빠른 시작 가이드

> **✅ 검증 완료**: 이 가이드의 모든 단계는 2025-08-23 기준으로 정상 작동 확인되었습니다.

이 가이드는 GIA-Re 시스템을 **5분 내에** 실행할 수 있도록 도와드립니다.

## 📋 사전 요구사항

### 1. 환경 준비

```bash
# Python 버전 확인 (3.8+ 필요)
python --version

# 의존성 설치
pip install -r requirements.txt
```

### 2. 기본 테스트

```bash
# 데모 실행
python demo_implementation.py

# 결과 확인
dir output\demo_output
```

### 3. 실제 데이터 처리

```python
# Python 스크립트 또는 대화형 모드에서
from integrated_pipeline import NetworkConfigDatasetGenerator, PipelineConfig

# 설정
config = PipelineConfig(
    xml_data_dir="XML_Data",
    policies_path="policies/policies.json",
    target_categories=["BGP_Consistency"]
)

# 실행
generator = NetworkConfigDatasetGenerator(config)
dataset = generator.run()
```

## 문제 해결

### 1. 모듈 import 오류
- 프로젝트 루트 디렉터리에서 실행하고 있는지 확인
- PYTHONPATH 환경 변수 설정

### 2. XML 파일 없음 오류
- XML_Data 폴더에 샘플 파일이 있는지 확인
- 파일 경로가 올바른지 확인

### 3. LLM 관련 오류
- 개발 중에는 LLM 기능 비활성화 권장:
```bash
set GIA_USE_INTENT_LLM=0
set GIA_ENABLE_LLM_REVIEW=0
```

## 추가 도움말

자세한 내용은 README.md 파일을 참조하세요.
