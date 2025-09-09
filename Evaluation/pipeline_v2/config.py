"""공통 설정 파일 (pipeline_v2)

이 파일의 모든 값은 "환경 변수 > 아래 기본값" 우선순위로 적용됩니다.
프로덕션/공유 환경에서는 .env, CI 변수, 셸 export 등을 활용해
코드를 수정하지 않고도 설정을 변경할 수 있도록 설계되어 있습니다.

권장 사용법
- 로컬 개발: 셸에서 `export KEY=value`로 설정 후 실행
- 서버/노트북: `.env` 또는 런타임 환경변수로 주입

주의
- OpenAI API Key 등 민감정보는 절대 코드에 하드코딩하지 마세요.
- 경로는 프로젝트 루트 기준 상대 경로를 기본으로 둡니다.
"""

from __future__ import annotations

import os
from typing import List
from pathlib import Path

# .env 파일 자동 로드
def _load_env_file():
    """프로젝트 루트의 .env 파일을 자동으로 로드"""
    # 현재 파일 기준으로 프로젝트 루트 찾기
    current_dir = Path(__file__).parent
    project_root = current_dir.parent.parent  # pipeline_v2 -> Network-Management-System-main -> GIA
    env_file = project_root / ".env"
    
    if env_file.exists():
        print(f"📁 .env 파일 로드 중: {env_file}")
        loaded_keys = 0
        with open(env_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                # 주석이나 빈 줄 건너뛰기
                if not line or line.startswith('#'):
                    continue
                
                # KEY=VALUE 형태 파싱
                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip().strip('"').strip("'")  # 따옴표 제거
                    
                    # 줄바꿈, 공백, 탭 등 모든 whitespace 제거
                    value = ''.join(value.split())
                    
                    # 환경변수에 설정 (기존 값이 없을 때만)
                    if not os.getenv(key) and value:
                        os.environ[key] = value
                        if key.startswith('OPENAI_API_KEY'):
                            loaded_keys += 1
                            print(f"✅ {key}: 로드됨 (...{value[-8:]})")
        
        if loaded_keys > 0:
            print(f"🔑 총 {loaded_keys}개 API 키 로드 완료")
    else:
        print(f"⚠️ .env 파일을 찾을 수 없습니다: {env_file}")

# .env 파일 로드 실행
_load_env_file()

# 🔑 다중 API 키 설정 (Rate Limit 분산 처리용)
# - 여러 API 키를 사용하여 분당 토큰 제한을 분산시킵니다.
# - 환경변수로 OPENAI_API_KEY_1, OPENAI_API_KEY_2, ... OPENAI_API_KEY_N 설정
# - 자동으로 환경변수를 스캔하여 설정된 키를 모두 감지합니다.

def _collect_api_keys() -> List[str]:
    """환경변수에서 API 키들을 동적으로 수집"""
    keys = []
    
    # OPENAI_API_KEY_1, OPENAI_API_KEY_2, ... 패턴으로 스캔 (최대 20개까지)
    for i in range(1, 21):
        key_var = f"OPENAI_API_KEY_{i}"
        key_value = os.getenv(key_var, "").strip()
        
        # 줄바꿈, 공백, 탭 등 모든 whitespace 제거
        key_value = ''.join(key_value.split())
        
        if key_value and key_value.startswith('sk-'):
            keys.append(key_value)
            print(f"✅ {key_var}: 감지됨")
        else:
            # 연속된 빈 키가 3개 이상이면 스캔 중단
            if i > 3 and all(not os.getenv(f"OPENAI_API_KEY_{j}", "") for j in range(i, min(i+3, 21))):
                break
    
    return keys

OPENAI_API_KEYS: List[str] = _collect_api_keys()

# 기존 단일 키도 지원 (하위 호환성)
if not OPENAI_API_KEYS:
    single_key = os.getenv("OPENAI_API_KEY", "")
    if single_key and single_key.strip():
        # 줄바꿈, 공백, 탭 등 모든 whitespace 제거
        single_key = ''.join(single_key.split())
        if single_key.startswith('sk-'):
            OPENAI_API_KEYS = [single_key]

if not OPENAI_API_KEYS:
    raise ValueError("❌ OPENAI_API_KEY 또는 OPENAI_API_KEY_1~5 중 하나라도 설정해야 합니다")

# 통계 출력
print(f"🔑 사용 가능한 API 키: {len(OPENAI_API_KEYS)}개")
print(f"📊 예상 Rate Limit: {200_000 * len(OPENAI_API_KEYS):,} TPM")

# 하위 호환성을 위한 단일 키 (첫 번째 키 사용)
OPENAI_API_KEY: str = OPENAI_API_KEYS[0] if OPENAI_API_KEYS else ""

# 파일 경로
# ChromaDB 저장/로드 경로
# - RAG 파이프라인에서 임베딩 인덱스가 저장됩니다.
# - 경로가 비어 있거나 컬렉션이 없으면, XML 디렉토리로부터 자동 임베딩을 시도합니다.
CHROMADB_PATH: str = os.getenv("CHROMADB_PATH", "Network-Management-System-main/docs7_export")
# XML 원문 디렉토리
# - Non‑RAG: LLM 컨텍스트로 직접 제공되는 원문 소스
# - RAG: 최초 임베딩 소스로 사용(컬렉션 비어 있을 때 자동 임베딩)
XML_DIRECTORY: str = os.getenv("XML_DIRECTORY", "Network-Management-System-main/xml_parssing")
# 실험 데이터셋(CSV) 경로
# - 필수 컬럼: question, ground_truth (선택: explanation, origin)
CSV_PATH: str = os.getenv("CSV_PATH", "Network-Management-System-main/dataset/test_fin.csv")

# LLM 설정
# LLM 설정
# - `LLM_MODEL`: OpenAI Chat Completions 모델명. 예) gpt-4o-mini, gpt-4o, gpt-4.1
# - `LLM_TEMPERATURE`: 창의성(무작위성) 조절. 0.0~1.0, 낮을수록 결정적/일관
LLM_MODEL: str = os.getenv("LLM_MODEL", "gpt-4o-mini")
LLM_TEMPERATURE: float = float(os.getenv("LLM_TEMPERATURE", "0.05"))

# 실험 설정
# 실험 산출물(로그/결과) 기본 저장 폴더
# - 각 실행마다 타임스탬프를 포함한 하위 폴더가 자동 생성됩니다.
EXPERIMENT_BASE_DIR: str = os.getenv("EXPERIMENT_BASE_DIR", "Network-Management-System-main/experiment_results")

# ChromaDB 컬렉션명
# - 같은 인덱스를 공유하고자 할 때 동일한 컬렉션명을 사용하세요.
COLLECTION_NAME: str = os.getenv("COLLECTION_NAME", "network_devices")

# Non-RAG 설정
# Non‑RAG 설정
# - `NON_RAG_USE_EMBEDDING`: Non‑RAG에서도 임베딩 선택을 쓸지 여부(기본 False, 전체 XML 제공 전략 권장)
NON_RAG_USE_EMBEDDING: bool = os.getenv("NON_RAG_USE_EMBEDDING", "false").lower() in (
    "1",
    "true",
    "yes",
)
# - `NON_RAG_CHUNK_SIZE`: Non‑RAG에서 LLM 컨텍스트로 투입할 최대 토큰 규모(대략치)
#    • 너무 크면 토큰 한도를 초과할 수 있고, 너무 작으면 정보가 누락될 수 있습니다.
NON_RAG_CHUNK_SIZE: int = int(os.getenv("NON_RAG_CHUNK_SIZE", "50000"))

# RAG 설정
# RAG 설정
# - `EMBEDDING_MODEL`: 문서 임베딩 모델(HuggingFace 경로). 예) BGE, E5, Qwen 등
# - `EMBEDDING_DEVICE`: 임베딩 장치. "cuda:0"/"cuda:1" 또는 "cpu". GPU 미보유 시 "cpu"로 설정
# - `MAX_ITERATIONS`: RAG 답변 개선 반복 횟수(컨텍스트 보강/재수정 루프)
# - `DEFAULT_TOP_K_VALUES`: top‑k 리스트. `--top-k` 인자 미제공 시 참조
EMBEDDING_MODEL: str = os.getenv("EMBEDDING_MODEL", "Qwen/Qwen3-Embedding-8B")
EMBEDDING_DEVICE: str = os.getenv("EMBEDDING_DEVICE", "cuda:1")
EMBEDDING_BATCH_SIZE: int = int(os.getenv("EMBEDDING_BATCH_SIZE", "32"))
MAX_ITERATIONS: int = int(os.getenv("MAX_ITERATIONS", "0"))
DEFAULT_TOP_K_VALUES: List[int] = [int(x.strip()) for x in os.getenv("DEFAULT_TOP_K_VALUES", "1,5,10,20").split(",") if x.strip()]

# ChromaDB 동작 제어
# - `AUTO_EMBED_XML_ON_EMPTY`: 컬렉션이 비어 있을 때만 XML을 자동 임베딩 (기본 False: 기존 인덱스만 사용)
AUTO_EMBED_XML_ON_EMPTY: bool = os.getenv("AUTO_EMBED_XML_ON_EMPTY", "true").lower() in ("1","true","yes")

# LLM 호출 타임아웃(초)
# - 장시간 응답 지연/행걸림 방지 목적. 타임아웃 시 해당 단계는 건너뛰고 계속 진행
# - 네트워크/모델 상태에 따라 조정하세요. (권장: 5~20초)
LLM_TIMEOUT_SECONDS: int = int(os.getenv("LLM_TIMEOUT_SECONDS", "30"))
