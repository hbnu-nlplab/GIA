# 🎯 GIA-Re: 네트워크 설정 질문-답변 데이터셋 생성 시스템

![Status](https://img.shields.io/badge/Status-Stable%20%26%20Working-green)
![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-yellow)

**GIA-Re**는 네트워크 설정 파일(XML)을 분석하여 고품질의 질문-답변 데이터셋을 자동 생성하는 AI 기반 시스템입니다.

## ✅ 프로젝트 상태

**✅ 모든 핵심 기능 정상 작동 확인됨 (2025-08-23)**

- ✅ **파이프라인 실행**: 6단계 전체 파이프라인 완료
- ✅ **XML 파싱**: 6개 네트워크 장비 파싱 성공
- ✅ **기초 질문 생성**: 38개 Rule-based 질문 생성
- ✅ **심화 질문 생성**: 10개 LLM 기반 심화 질문 생성
- ✅ **데이터 통합**: 25개 → 23개 (중복 제거)
- ✅ **품질 검증**: 22개 통과, 3개 거부
- ✅ **평가 시스템**: Answer Type 분류 100% 정확도
- ✅ **도메인 평가**: 네트워크 특화 평가 점수 0.800
- ✅ **다중 프로필**: 4개 평가 프로필 지원
- ✅ **확장 케이스**: 6개 incount 시나리오 지원

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

result = agent.execute_plan("SSH 설정 상태는?", plan)
print(result)
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

1. `generators/rule_based_generator.py`에 생성 로직 추가

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

## 📊 출력 형식 및 생성 파일 상세 가이드

### 🗂️ demo_output/ 디렉토리 구조

`python demo_implementation.py` 실행 시 `demo_output/` 폴더에 다음과 같은 파일들이 생성됩니다:

```
demo_output/
├── 📋 메타데이터 및 설정
│   ├── metadata.json              # 데이터셋 메타정보 및 생성 설정
│   └── parsed_facts.json          # XML 파싱 결과 (원시 네트워크 데이터)
│
├── 🎯 기본 질문-답변 데이터셋
│   ├── basic_dataset.json         # Rule-based 기초 질문 (38개)
│   └── enhanced_dataset.json      # LLM 기반 심화 질문 (10개)
│
├── 📊 학습용 데이터 분할
│   ├── train.json                 # 훈련용 데이터 (15개 샘플)
│   ├── validation.json            # 검증용 데이터 (3개 샘플)
│   ├── test.json                  # 테스트용 데이터 (4개 샘플)
│   └── validated_dataset.json     # 품질 검증 완료 데이터
│
├── 🏗️ 복잡도별 어셈블리 파일
│   ├── assembled_basic.json       # 기본 복잡도 질문 모음
│   ├── assembled_analytical.json  # 분석적 추론 질문 모음  
│   ├── assembled_diagnostic.json  # 진단형 질문 모음
│   ├── assembled_synthetic.json   # 합성형 복합 질문 모음
│   └── network_config_qa_dataset.json  # 최종 통합 데이터셋
│
└── 📁 cases/
    └── all_cases.json             # 6개 시나리오별 확장 케이스
```

---

### 📋 핵심 파일별 상세 설명

#### 1. `metadata.json` - 데이터셋 메타정보

**생성 과정**: 파이프라인 초기화 시 설정 정보를 기록

**목적**: 데이터셋 재현성 보장 및 설정 추적

**내용 구조**:
```json
{
  "dataset_name": "NetworkConfigQA",
  "version": "1.0", 
  "generation_config": {
    "xml_data_dir": "XML_Data",           // 원본 XML 파일 위치
    "target_categories": [                // 대상 질문 카테고리
      "BGP_Consistency",
      "Security_Policy", 
      "VRF_Consistency"
    ],
    "basic_questions_per_category": 4,    // 카테고리별 기초 질문 수
    "enhanced_questions_per_category": 2   // 카테고리별 심화 질문 수
  },
  "parsing_results": {
    "total_devices": 6,                   // 파싱된 네트워크 장비 수
    "device_summary": [...],              // 장비별 상세 정보
    "bgp_peers": 3,                       // BGP 피어 연결 수
    "vrfs_found": 4                       // 발견된 VRF 수
  },
  "generation_statistics": {
    "basic_questions_generated": 38,      // 생성된 기초 질문 수
    "enhanced_questions_generated": 10,   // 생성된 심화 질문 수
    "final_dataset_size": 22              // 최종 데이터셋 크기
  }
}
```

**활용법**: 데이터셋 버전 관리, 실험 재현, 생성 과정 추적

---

#### 2. `parsed_facts.json` - 원시 네트워크 데이터

**생성 과정**: `UniversalParser`가 XML 파일들을 표준 JSON 구조로 변환

**목적**: 원본 네트워크 설정의 구조화된 표현

**내용 구조**:
```json
{
  "devices": [
    {
      "hostname": "CE1",
      "os_type": "ios-xr",
      "bgp": {
        "as_number": "65001",
        "neighbors": [
          {
            "ip": "10.1.1.2", 
            "remote_as": "65000"
          }
        ]
      },
      "interfaces": [...],
      "vrfs": [...],
      "security": {
        "ssh_enabled": true,
        "aaa_config": {...}
      }
    }
  ],
  "global_context": {
    "as_topology": {...},
    "l2vpn_services": [...],
    "l3vpn_services": [...]
  }
}
```

**활용법**: 
- 메트릭 계산의 기초 데이터
- 새로운 질문 생성 시 참조
- 네트워크 토폴로지 분석

---

#### 3. `basic_dataset.json` - 기초 질문 데이터셋

**생성 과정**: `RuleBasedGenerator`가 정책 파일을 기반으로 체계적 질문 생성

**목적**: 기본적인 네트워크 설정 이해도 평가

**샘플 구조**:
```json
[
  {
    "id": "BASIC_DSL-SSH_ENABLED_DEVICES-21433",
    "question": "SSH가 활성화된 장비 목록은?",
    "context": "장비: CE1 | OS: ios-xr | BGP AS: 65001",
    "answer": "CE1, CE2, sample10, sample7, sample8, sample9",
    "answer_type": "short",              // short/long 분류
    "category": "basic",                 // 기본/고급 구분
    "complexity": "basic",               // 복잡도 레벨
    "level": 1,                         // 난이도 (1-5)
    "educational_focus": "기본 설정 확인",
    "grounding": {                      // 답변 근거 데이터
      "ssh_enabled_devices": [
        "CE1", "CE2", "sample10", "sample7", "sample8", "sample9"
      ],
      "ssh_missing_count": 0
    }
  }
]
```

**특징**:
- **정확한 답변**: 메트릭 기반으로 생성된 정확한 답변
- **체계적 커버리지**: 모든 주요 네트워크 영역 포함
- **근거 제공**: `grounding` 필드로 답변 근거 명시

---

#### 4. `enhanced_dataset.json` - 심화 질문 데이터셋

**생성 과정**: `EnhancedLLMQuestionGenerator`가 다양한 역할(네트워크 엔지니어, 보안 감사자 등)과 복잡도를 고려하여 LLM으로 생성

**목적**: 복합적 사고력과 실무 적용 능력 평가

**샘플 구조**:
```json
[
  {
    "id": "ENHANCED_ENHANCED-ANALYTICAL-001",
    "question": "iBGP 풀메시 누락이 경로 수렴에 미치는 영향을 분석하시오. 특히, AS 65001에서 발생할 수 있는 경로 수렴의 지연과 관련된 잠재적 문제점을 설명하시오.",
    "context": "BGP 설정 현황:\nAS 65001: 4개 장비, iBGP 피어 2개 누락\nAS 65000: 2개 장비\nAS 65003: 1개 장비",
    "answer": {
      "question": "...",
      "plan": [                         // 추론 계획 (단계별 해결 과정)
        "AS 65001 내의 모든 라우터 간에 iBGP 풀메시가 완성되지 않았을 때 발생할 수 있는 경로 수렴 지연을 이해한다.",
        "BGP의 특성과 iBGP 풀메시 구성의 중요성을 설명한다.",
        "누락된 iBGP 피어링이 초래할 수 있는 경로 수렴 지연 문제를 분석한다.",
        "경로 수렴 지연이 네트워크 성능 및 안정성에 미치는 영향을 평가한다.",
        "해결 방안과 iBGP 재구성의 필요성을 제안한다."
      ],
      "evidence": {}
    },
    "answer_type": "long",
    "category": "advanced",
    "complexity": "analytical",          // analytical/diagnostic/synthetic
    "level": 4,
    "educational_focus": "BGP 라우팅 분석",
    "role_perspective": "network_engineer",  // 생성 시 적용된 역할
    "scenario": "BGP 경로 수렴 분석"
  }
]
```

**특징**:
- **단계별 추론**: `plan` 필드로 문제 해결 과정 제시
- **역할 기반**: 다양한 직군 관점(엔지니어, 감사자, 운영자 등)
- **시나리오 중심**: 실무 상황을 반영한 복합 문제

---

#### 5. 학습용 데이터 분할 (`train.json`, `validation.json`, `test.json`)

**생성 과정**: 전체 데이터셋을 70:15:15 비율로 무작위 분할

**목적**: 머신러닝 모델 훈련 및 평가

**분할 기준**:
- **train.json (15개)**: 모델 훈련용
- **validation.json (3개)**: 하이퍼파라미터 튜닝용  
- **test.json (4개)**: 최종 성능 평가용

**활용법**:
```python
import json

# 데이터 로드
with open('demo_output/train.json', 'r') as f:
    train_data = json.load(f)

# 질문-답변 쌍 추출
for item in train_data:
    question = item['question']
    answer = item['answer']
    # 모델 훈련에 사용
```

---

#### 6. 복잡도별 어셈블리 파일

**생성 과정**: `TestAssembler`가 복잡도와 카테고리별로 질문들을 분류하여 조합

**목적**: 특정 복잡도나 영역에 초점을 맞춘 평가

| 파일명 | 복잡도 | 특징 | 용도 |
|--------|--------|------|------|
| `assembled_basic.json` | basic | 직관적 확인 문제 | 기초 지식 평가 |
| `assembled_analytical.json` | analytical | 분석적 추론 필요 | 분석 능력 평가 |
| `assembled_diagnostic.json` | diagnostic | 문제 진단형 | 트러블슈팅 평가 |
| `assembled_synthetic.json` | synthetic | 복합 상황 종합 | 종합 사고력 평가 |

**활용 예시**:
```python
# 분석적 사고력만 평가하고 싶을 때
with open('demo_output/assembled_analytical.json', 'r') as f:
    analytical_questions = json.load(f)
    
# 복잡도별 성능 분석
for complexity in ['basic', 'analytical', 'diagnostic', 'synthetic']:
    results = evaluate_model_on_complexity(complexity)
    print(f"{complexity}: {results['accuracy']}")
```

---

#### 7. `cases/all_cases.json` - 시나리오별 확장 케이스

**생성 과정**: `EnhancedDatasetConfigurator`가 6가지 네트워크 상황을 시뮬레이션

**목적**: 다양한 네트워크 상황에서의 대응 능력 평가

**6가지 케이스**:

1. **standard**: 표준 네트워크 설정
2. **bgp_peer_failure**: BGP 피어 일부 장애 상황
3. **interface_failure**: 핵심 인터페이스 장애
4. **partial_ssh_failure**: 일부 장비 SSH 접근 불가
5. **network_expansion**: 새로운 PE 라우터 추가 시나리오
6. **customer_onboarding**: 신규 고객 L3VPN 서비스 개통

**케이스 구조**:
```json
{
  "bgp_peer_failure": {
    "case_name": "bgp_peer_failure",
    "description": "BGP 피어 일부 장애 상황",
    "samples": [
      {
        "question": "BGP 피어 장애 시 대체 경로는?",
        "answer": "AS 65000을 통한 우회 경로 사용 가능",
        "answer_type": "short"
      }
    ],
    "simulation_conditions": [
      "AS 65001의 피어 연결 2개 중 1개 다운",
      "경로 수렴 시간 증가 예상"
    ]
  }
}
```

**활용법**: 
- 장애 대응 시나리오 평가
- 실무 상황별 모델 성능 분석
- 네트워크 운영 교육 자료

---

### 🎯 파일별 사용 시나리오

#### 📚 **교육 목적**
```python
# 기초 학습: basic_dataset.json 사용
basic_questions = load_json('demo_output/basic_dataset.json')
for q in basic_questions[:5]:  # 처음 5개 문제로 기초 학습
    print(f"Q: {q['question']}")
    print(f"A: {q['answer']}")
```

#### 🔍 **모델 평가**
```python
# 복잡도별 성능 분석
complexities = ['basic', 'analytical', 'diagnostic', 'synthetic']
for complexity in complexities:
    test_data = load_json(f'demo_output/assembled_{complexity}.json')
    accuracy = evaluate_model(test_data)
    print(f"{complexity} accuracy: {accuracy}")
```

#### 🏥 **장애 대응 훈련**
```python
# 시나리오별 대응 훈련
cases = load_json('demo_output/cases/all_cases.json')
for scenario_name, scenario_data in cases.items():
    print(f"시나리오: {scenario_data['description']}")
    train_on_scenario(scenario_data['samples'])
```

#### 📊 **연구 분석**
```python
# 메타데이터를 활용한 데이터셋 분석
metadata = load_json('demo_output/metadata.json')
print(f"총 장비 수: {metadata['parsing_results']['total_devices']}")
print(f"BGP 피어 수: {metadata['parsing_results']['bgp_peers']}")

# 질문 유형별 분포 분석
analyze_question_distribution(metadata['generation_statistics'])
```

---

### 💡 고급 활용 팁

#### 1. **커스텀 필터링**
```python
# 특정 카테고리만 추출
def filter_by_category(data, target_category):
    return [item for item in data if item['category'] == target_category]

bgp_questions = filter_by_category(all_data, 'BGP_Consistency')
```

#### 2. **답변 타입별 분석**
```python
# Short vs Long Answer 성능 비교
short_answers = [q for q in data if q['answer_type'] == 'short']
long_answers = [q for q in data if q['answer_type'] == 'long']

short_accuracy = evaluate(short_answers)
long_accuracy = evaluate(long_answers)
```

#### 3. **증거 기반 검증**
```python
# grounding 정보를 활용한 답변 검증
def verify_answer(question_data):
    answer = question_data['answer']
    evidence = question_data.get('grounding', {})
    # evidence를 바탕으로 답변 정확성 검증
    return validate_against_evidence(answer, evidence)
```

이 상세한 가이드를 통해 `demo_output/` 폴더의 모든 파일들을 효과적으로 활용할 수 있으며, 네트워크 AI 교육 및 평가 시스템의 완전한 이해가 가능합니다.

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
