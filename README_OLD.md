# GIA-Re: 네트워크 설정 분석 및 테스트 데이터셋 생성 시스템

## 📖 개요

**GIA-Re**는 네트워크 장비의 XML 설정 파일을 분석하여 자동으로 테스트 질문과 답변을 생성하는 지능형 시스템입니다. 교육 및 평가 목적으로 네트워크 설정의 다양한 측면(BGP, OSPF, VRF, 보안 등)을 검증하는 질문을 생성하고, 실제 설정 데이터를 기반으로 정확한 답변을 제공합니다.

### 🎯 주요 기능

- **XML 설정 파싱**: Cisco, Juniper 등 다양한 벤더의 네트워크 설정 파일 분석
- **지능형 질문 생성**: 규칙 기반 + LLM 기반 하이브리드 질문 생성
- **자동 답변 계산**: 설정 데이터 기반 정확한 답변 도출
- **다면적 평가**: 복잡도, 교육적 가치, 실무 적합성 등 종합 평가
- **시나리오 기반 테스트**: 장애 상황, 변경 상황 등 실무적 시나리오 포함

---

## 🏗️ 프로젝트 구조

```text
GIA-Re/
├── 📁 parsers/           # XML 파싱 모듈
│   ├── universal_parser.py    # 통합 XML 파서
│   └── vendor/               # 벤더별 파서 모듈
├── 📁 generators/        # 질문 생성 모듈
│   ├── rule_based_generator.py      # 규칙 기반 질문 생성
│   ├── enhanced_llm_generator.py    # LLM 기반 고급 질문 생성
│   └── llm_explorer.py             # LLM 탐색 엔진
├── 📁 assemblers/        # 테스트 조립 모듈
│   └── test_assembler.py           # 최종 테스트 데이터셋 조립
├── 📁 inspectors/        # 평가 및 검증 모듈
│   ├── evaluation_system.py       # 종합 평가 시스템
│   └── intent_inspector.py        # 의도 분석 모듈
├── 📁 utils/             # 핵심 유틸리티
│   ├── builder_core.py            # 메트릭 계산 엔진
│   └── llm_adapter.py             # LLM 연동 어댑터
├── 📁 policies/          # 정책 및 규칙 정의
│   └── policies.json              # 카테고리별 생성 정책
├── 📁 XML_Data/          # 입력 XML 파일
│   ├── ce1.xml, ce2.xml          # 고객 장비 설정
│   └── sample*.xml               # 샘플 설정 파일
├── 📁 output/            # 출력 결과
│   ├── demo_output/              # 데모 실행 결과
│   └── out_gia/                  # 최종 생성 데이터셋
├── answer_agent.py       # 답변 생성 에이전트
├── integrated_pipeline.py        # 통합 파이프라인
├── demo_implementation.py        # 데모 실행 스크립트
└── migration_guide.py           # 시스템 마이그레이션 가이드
```

---

## 🚀 빠른 시작

### 1. 환경 설정

#### 필요 조건

- Python 3.8+
- OpenAI API 키 (LLM 기능 사용시)

#### 설치

```bash
# 의존성 설치
pip install -r requirements.txt

# 환경 변수 설정 (선택적)
set OPENAI_API_KEY=your_api_key_here
set GIA_USE_INTENT_LLM=0  # 개발 중에는 LLM 사용 제한
```

### 2. 기본 실행

#### 데모 실행

```python
python demo_implementation.py
```

#### 통합 파이프라인 실행

```python
from integrated_pipeline import NetworkConfigDatasetGenerator, PipelineConfig

# 설정
config = PipelineConfig(
    xml_data_dir="XML_Data",
    policies_path="policies/policies.json",
    target_categories=["BGP_Consistency", "Security_Policy"],
    basic_questions_per_category=4
)

# 실행
generator = NetworkConfigDatasetGenerator(config)
dataset = generator.run()
print(f"생성된 질문 수: {len(dataset)}")
```

---

## 📚 주요 모듈 상세 가이드

### 1. 파서 모듈 (`parsers/`)

#### `UniversalParser`
XML 설정 파일을 표준화된 JSON 구조로 변환합니다.

```python
from parsers.universal_parser import UniversalParser

parser = UniversalParser()
facts = parser.parse_files(["XML_Data/ce1.xml"])
print(facts["devices"][0]["system"]["hostname"])
```

**주요 기능:**
- 다중 벤더 지원 (Cisco, Juniper)
- BGP, OSPF, VRF, 인터페이스 등 주요 프로토콜 파싱
- 표준화된 데이터 구조 출력

### 2. 생성기 모듈 (`generators/`)

#### `RuleBasedGenerator`
정책 기반으로 체계적인 질문을 생성합니다.

```python
from generators.rule_based_generator import RuleBasedGenerator, RuleBasedGeneratorConfig

config = RuleBasedGeneratorConfig(
    categories=["BGP_Consistency"],
    questions_per_category=5
)
generator = RuleBasedGenerator(config)
questions = generator.generate(facts)
```

#### `EnhancedLLMQuestionGenerator`
LLM을 활용한 고급 질문 생성 (현재 개발 중)

```python
from generators.enhanced_llm_generator import EnhancedLLMQuestionGenerator

generator = EnhancedLLMQuestionGenerator()
questions = generator.generate_by_complexity(facts, complexity="intermediate")
```

### 3. 빌더 코어 (`utils/builder_core.py`)

모든 메트릭 계산의 핵심 엔진입니다.

```python
from utils.builder_core import BuilderCore

builder = BuilderCore(facts["devices"])

# SSH 설정 체크
ssh_missing = builder.calculate_metric("ssh_missing_count")
print(f"SSH 미설정 장비 수: {ssh_missing}")

# BGP 피어링 체크
bgp_missing = builder.calculate_metric("ibgp_missing_pairs_count")
print(f"누락된 BGP 피어 수: {bgp_missing}")
```

#### 주요 메트릭

| 카테고리 | 메트릭 이름 | 설명 |
|---------|------------|------|
| **보안** | `ssh_missing_count` | SSH 미설정 장비 수 |
| | `ssh_all_enabled_bool` | 모든 장비 SSH 활성화 여부 |
| **BGP** | `ibgp_missing_pairs_count` | 누락된 iBGP 피어 쌍 수 |
| | `ibgp_fullmesh_ok` | 풀메시 구조 완성 여부 |
| **VRF** | `vrf_without_rt_count` | RT 미설정 VRF 수 |
| | `vrf_rd_map` | VRF별 RD 매핑 |
| **L2VPN** | `l2vpn_unidir_count` | 단방향 L2VPN 연결 수 |
| **시스템** | `system_hostname_text` | 호스트명 목록 |

### 4. 답변 에이전트 (`answer_agent.py`)

질문에 대한 구체적이고 설명적인 답변을 생성합니다.

```python
from answer_agent import AnswerAgent

agent = AnswerAgent(facts)
plan = [
    {"step": 1, "required_metric": "ssh_missing_count"},
    {"step": 2, "required_metric": "ssh_enabled_devices"}
]

answer = agent.execute_plan("SSH 설정 상태는?", plan)
print(answer)
```

---

## 🔧 주요 설정

### 1. 정책 파일 (`policies/policies.json`)

각 카테고리별 질문 생성 규칙을 정의합니다.

```json
{
  "policies": [
    {
      "category": "BGP_Consistency",
      "levels": {
        "1": [
          {
            "goal": "completeness",
            "targets": ["AS"],
            "primary_metric": "ibgp_missing_pairs_count"
          }
        ]
      }
    }
  ]
}
```

### 2. 환경 변수

| 변수명 | 기본값 | 설명 |
|--------|--------|------|
| `GIA_USE_INTENT_LLM` | `0` | LLM 의도 파싱 사용 여부 |
| `GIA_ENABLE_LLM_REVIEW` | `0` | LLM 품질 검토 활성화 |
| `OPENAI_TIMEOUT_SEC` | `30` | OpenAI API 타임아웃 |

---

## 🛠️ 커스터마이징 가이드

### 1. 새로운 메트릭 추가

`utils/builder_core.py`에 새 메트릭을 추가하는 방법:

```python
def calculate_custom_metric(self) -> int:
    """사용자 정의 메트릭 계산"""
    count = 0
    for device in self.devices:
        # 사용자 정의 로직
        if self._check_custom_condition(device):
            count += 1
    return count

# builder_core.py의 calculate_metric 메서드에 추가
elif target_metric == "custom_metric":
    return self.calculate_custom_metric()
```

### 2. 새로운 질문 카테고리 추가

1. `policies/policies.json`에 새 카테고리 정의:
```json
{
  "category": "New_Category",
  "levels": {
    "1": [
      {
        "goal": "validity",
        "targets": ["DEVICE"],
        "primary_metric": "new_metric"
      }
    ]
  }
}
```

2. `generators/rule_based_generator.py`에 생성 로직 추가

### 3. 새로운 벤더 지원 추가

1. `parsers/vendor/` 아래에 새 벤더 파서 생성
2. `parsers/universal_parser.py`에 벤더 감지 로직 추가
3. 표준 데이터 구조로 변환하는 매핑 함수 구현

---

## 🔍 디버깅 및 문제 해결

### 1. 로깅 활성화

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### 2. 자주 발생하는 문제

#### XML 파싱 오류
```python
# 파싱 결과 확인
facts = parser.parse_files(["problematic.xml"])
print(json.dumps(facts, indent=2))
```

#### 메트릭 계산 오류
```python
# 단계별 디버깅
builder = BuilderCore(facts["devices"])
try:
    result = builder.calculate_metric("problem_metric")
except Exception as e:
    print(f"메트릭 계산 오류: {e}")
    # 원시 데이터 확인
    print(f"장비 수: {len(builder.devices)}")
```

#### LLM 관련 오류
```python
# LLM 사용 비활성화로 문제 격리
os.environ["GIA_USE_INTENT_LLM"] = "0"
os.environ["GIA_ENABLE_LLM_REVIEW"] = "0"
```

### 3. 테스트 실행

```bash
python test_evaluation_system.py
```

---

## 📊 출력 형식

### 생성된 데이터셋 구조

```json
{
  "version": "1.0",
  "metadata": {
    "generation_date": "2025-08-23",
    "total_questions": 50,
    "categories": ["BGP_Consistency", "Security_Policy"]
  },
  "questions": [
    {
      "id": 1,
      "category": "BGP_Consistency",
      "question": "AS 65001에서 iBGP 피어링이 완전한 풀메시 구조를 형성하고 있습니까?",
      "answer": "아니오, 2개의 피어 연결이 누락되어 있습니다.",
      "answer_type": "boolean",
      "evidence": {
        "ibgp_missing_pairs_count": 2,
        "total_devices_in_as": 4
      },
      "complexity": "intermediate",
      "educational_value": 8.5
    }
  ]
}
```

---

## 🤝 기여 가이드

### 1. 개발 환경 설정

```bash
git clone https://github.com/YUjinEDU/GIA-Re.git
cd GIA-Re
pip install -r requirements.txt
```

### 2. 코드 스타일

- Python PEP 8 준수
- 타입 힌트 사용
- Docstring 작성 (Google 스타일)

### 3. 브랜치 전략

- `main`: 안정 버전
- `develop`: 개발 버전
- `feature/*`: 기능 개발
- `bugfix/*`: 버그 수정

---

## 📋 로드맵

### Phase 1 (현재)
- [x] 기본 XML 파싱
- [x] 규칙 기반 질문 생성
- [x] 메트릭 계산 엔진
- [ ] LLM 통합 안정화

### Phase 2 (예정)
- [ ] 웹 인터페이스
- [ ] 실시간 설정 분석
- [ ] 다국어 지원
- [ ] 클라우드 배포

### Phase 3 (장기)
- [ ] AI 기반 네트워크 최적화 제안
- [ ] 자동 설정 검증
- [ ] 시뮬레이션 환경 통합

---

## 📞 지원 및 문의

- **이슈 제보**: [GitHub Issues](https://github.com/YUjinEDU/GIA-Re/issues)
- **기능 제안**: [GitHub Discussions](https://github.com/YUjinEDU/GIA-Re/discussions)
- **이메일**: [이메일 주소 추가 필요]

---

## 📄 라이선스

이 프로젝트는 [라이선스 정보 추가 필요] 하에 배포됩니다.

---

## 🙏 감사의 말

이 프로젝트는 네트워크 교육 및 평가의 혁신을 위해 개발되었습니다. 모든 기여자들과 피드백을 제공해주신 분들께 감사드립니다.

---

**마지막 업데이트**: 2025년 8월 23일
