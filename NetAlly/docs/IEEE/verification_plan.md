# NetConfigQA2.0 — 데이터셋 검증 계획서

> **목적**: IEEE TNMS 논문에서 데이터셋의 Ground Truth 신뢰성을 증명하기 위한 검증 체계 설계  
> **제약**: 네트워크 전문가 부재, 자동화 우선, PNETLab 환경 가용

---

## 0. 실행 재기준 (Rebaseline: 2026-02-13)

이번 문서는 "설계" 단계에서 "즉시 구현" 단계로 전환합니다.

| 항목 | 기존 표현 | 실행 기준 (수정) |
|---|---|---|
| 제출용 데이터셋 범위 | L1~L6 혼용 | **L1~L5 고정 (v2 1,128)** |
| L6 | 본실험 포함 가능 | **이번 제출에서는 제외** (코드 보존, 실험/평가 미포함) |
| Layer 1 시작 조건 | 바로 전수 검증 | **데이터셋 위생 정리 후** 시작 (ID 고유화, evidence placeholder 제거) |
| 구현 상태 표기 | 설계 중심 | **파일 존재/미존재 명시 + TODO 연동** |

> 제외 근거: fault별 snapshot/context 동기화 부담, baseline 공정성 저하, 일정 내 재현 검증 리스크.

### 0.1 구현 우선순위 (필수)

1. `verify_dataset.py` + `core_batfish/verifier.py` 구현 (L1~L5)
2. v2 CSV 메타데이터 정리: ID 고유화, evidence `{host}` 등 placeholder 제거
3. Layer 1 전수검증 재실행 및 보고서 산출
4. Layer 2 실측 50건 (L4 30 + L5 20)
5. Layer 3 (LLM-as-Judge) 보조 검증

---

## 1. 검증의 핵심 질문

IEEE TNMS 리뷰어가 물을 질문:

> **Q1**: "Batfish가 생성한 정답이 실제 네트워크와 일치하는가?"  
> **Q2**: "질문이 모호하지 않고 유일한 정답을 가지는가?"  
> **Q3**: "난이도 분류가 적절한가?"

### 우리의 답변 전략

```
Q1 → 검증 Layer 1 (자동 재현) + Layer 2 (실환경 교차)
Q2 → 검증 Layer 3 (LLM-as-Judge)
Q3 → 검증 Layer 3 + Layer 1의 통계 분석
```

---

## 2. 3-Layer 검증 아키텍처

```
┌──────────────────────────────────────────────────────┐
│                   검증 보고서 (최종 출력)               │
│  ├── verification_report.md                          │
│  ├── verification_failures.csv                       │
│  └── llm_judge_results.json                          │
└──────────────────────────────────────────────────────┘
                    ▲        ▲         ▲
        ┌───────────┤   ┌────┤   ┌─────┤
        │           │   │    │   │     │
┌───────────────┐ ┌──────────┐ ┌───────────────┐
│ Layer 1       │ │ Layer 2  │ │ Layer 3       │
│ 자동 재현 검증 │ │ 실환경   │ │ LLM-as-Judge  │
│ (전수검사)    │ │ 교차검증 │ │ (품질 평가)   │
│ 1,128건 전부  │ │ 50건 샘플│ │ 100건 샘플    │
└───────────────┘ └──────────┘ └───────────────┘
     Batfish          PNETLab        GPT-4o
```

---

## 3. Layer 1 — 자동 재현 검증 (Internal Consistency)

### 3.1 목적

> "동일 설정 파일 + 동일 Batfish 쿼리로 동일 정답이 나오는가?"

Ground Truth의 **내적 일관성**을 검증합니다. Batfish 버전이나 파서 변경으로 인한 불일치를 탐지합니다.

### 3.2 검증 대상: 공개본 v2 전체 1,128건 (L1~L5)

### 3.3 레벨별 검증 방법

| Level | 검증 방법 | 비교 함수 |
|:---:|---|---|
| **L1** | BuilderCore에 동일 intent 전달 → 결과 비교 | answer_type별 TA-Acc 비교 함수 |
| **L2** | BuilderCore에 GLOBAL scope intent 전달 → 결과 비교 | 동일 |
| **L3** | BuilderCore에 DEVICE_PAIR/VRF scope intent 전달 → 결과 비교 | 동일 |
| **L4** | Batfish traceroute/reachability 재실행 → 결과 비교 | 경로 정규화 후 문자열 비교 |
| **L5** | Batfish snapshot fork + link failure 재실행 → 결과 비교 | disposition 비교 |

### 3.4 구현 상세

#### 파일 구조

```
Make_Dataset/src/
├── verify_dataset.py          # 메인 실행 스크립트 (신규 구현)
├── core_batfish/
│   └── verifier.py            # 레벨별 검증 로직 (신규 구현)
├── pnetlab_cross_validation.py # Layer 2 검증 (신규 구현)
└── llm_judge.py               # Layer 3 검증 (신규 구현)
```

> 주의: 위 파일들은 2026-02-13 기준 "구현 대상"이며, TODO 문서(`TODO_execution_backlog.md`)와 동기화하여 진행합니다.

#### `verify_dataset.py` 핵심 로직

```python
class DatasetVerifier:
    """전체 데이터셋 검증 오케스트레이터"""
    
    def __init__(self, dataset_path, snapshot_path, policies_path):
        self.dataset = self._load_dataset(dataset_path)
        self.verifier = BatchVerifier(snapshot_path, policies_path)
    
    def run_full_verification(self):
        results = []
        for qa in self.dataset:
            result = self._verify_single(qa)
            results.append(result)
        return VerificationReport(results)
    
    def _verify_single(self, qa):
        """단일 QA 쌍 검증"""
        # 1. 메타데이터 검증
        meta = self._verify_metadata(qa)
        if not meta.valid:
            return VerificationResult(status="META_FAIL", reason=meta.reason)
        
        # 2. evidence에서 Batfish 쿼리 정보 추출
        evidence = json.loads(qa["evidence"])
        
        # 3. 레벨별 정답 재계산
        level = qa["level"]
        if level in ["L1", "L2", "L3"]:
            reproduced = self.verifier.reproduce_rule_based(evidence)
        elif level == "L4":
            reproduced = self.verifier.reproduce_l4(evidence)
        elif level == "L5":
            reproduced = self.verifier.reproduce_l5(evidence)
        else:
            return VerificationResult(status="SKIP", reason=f"Unknown level: {level}")
        
        # 4. 비교
        match = self._compare(qa["answer"], reproduced, qa["answer_type"])
        return VerificationResult(
            status="PASS" if match else "FAIL",
            expected=qa["answer"],
            actual=reproduced,
            metric=evidence.get("metric"),
            level=level
        )
```

#### `verifier.py` 핵심 로직

```python
class BatchVerifier:
    """레벨별 검증 실행기"""
    
    def __init__(self, snapshot_path, policies_path):
        # Batfish 세션 초기화
        self.bf = BatfishBuilder(snapshot_path, ...)
        self.bf.initialize()
        # L1-L3용 규칙 기반 엔진
        self.builder_core = BuilderCore(parsed_facts)
    
    def reproduce_rule_based(self, evidence):
        """L1-L3: intent를 BuilderCore에 재전달"""
        intent = self._evidence_to_intent(evidence)
        return self.builder_core.compute(intent)
    
    def reproduce_l4(self, evidence):
        """L4: Batfish traceroute/reachability 재실행"""
        metric = evidence["metric"]
        if "traceroute" in metric:
            return self.bf.traceroute(evidence["src"], evidence["dst"])
        elif "reachability" in metric:
            return self.bf.reachability(evidence["src"], evidence["dst"])
        elif "bounded_path" in metric:
            return self.bf.bounded_path_length(evidence["src"], evidence["dst"])
    
    def reproduce_l5(self, evidence):
        """L5: Snapshot fork + link failure 시뮬레이션"""
        return self.bf.what_if_link_failure(
            evidence["failed_link"],
            evidence["src"], 
            evidence["dst"]
        )
```

### 3.5 비교 함수 (TA-Acc 기반)

```python
def compare_answers(expected, actual, answer_type):
    """answer_type에 따라 적절한 비교 수행"""
    if answer_type == "text":
        return normalize(expected) == normalize(actual)
    elif answer_type == "number" or answer_type == "numeric":
        return float(expected) == float(actual)
    elif answer_type == "set":
        return set(parse_set(expected)) == set(parse_set(actual))
    elif answer_type == "map":
        return parse_map(expected) == parse_map(actual)
    elif answer_type == "bool":
        return str(expected).lower() == str(actual).lower()
```

### 3.6 단계별 기대 결과 (현실 반영)

| 상태 | 이전(v1) | 1차 목표(MVP) |
|---|:---:|:---:|
| PASS | 28.9% | **90%+** |
| FAIL | 6.3% | **< 8%** (원인 분류 포함) |
| SKIP | 64.8% | **< 5%** |

> 최종 목표(Stretch): PASS 95%+, FAIL <2%, SKIP <3%  
> MVP 달성 후 메타데이터/비교함수 정교화로 Stretch 목표를 달성합니다.

---

## 4. Layer 2 — PNETLab 실환경 교차 검증 (External Validity)

### 4.1 목적

> "Batfish 시뮬레이션 결과가 실제 네트워크와 일치하는가?"

이것이 **전문가 없이 사용 가능한 가장 강력한 검증 카드**입니다.

### 4.2 검증 대상: 50건 (L4 30건 + L5 20건)

L4/L5를 집중하는 이유: L1-L3은 설정 파싱이므로 Batfish 정확도가 이미 높음. L4/L5의 시뮬레이션 정확도가 논문의 핵심.

### 4.3 검증 프로세스

```
Step 1: L4 traceroute 질문 30개 선택 (카테고리 다양하게)
    ↓
Step 2: PNETLab 장비에 SSH 접속
    ↓
Step 3: 실제 traceroute/ping 명령 실행
    $ traceroute 10.0.1.1 source Loopback0
    $ ping 172.16.3.2 source 172.16.1.1
    ↓
Step 4: 결과 파싱 (hop 순서 추출)
    ↓
Step 5: Batfish 정답과 비교
    ↓
Step 6: 일치율 보고
```

### 4.4 L5 (What-If) 검증

```
Step 1: L5 link failure 질문 20개 선택
    ↓
Step 2: PNETLab에서 해당 인터페이스 shutdown
    $ conf t → interface GigX/X → shutdown
    ↓
Step 3: 경로 변화 확인 (traceroute 재실행)
    ↓
Step 4: Batfish 정답과 비교
    ↓
Step 5: 인터페이스 복원 (no shutdown)
    ↓
Step 6: 일치율 보고
```

### 4.5 반자동화 스크립트

```python
"""pnetlab_cross_validation.py — SSH를 통한 PNETLab 자동 검증"""

class PNETLabValidator:
    def __init__(self, device_credentials):
        self.ssh = paramiko.SSHClient()
    
    def validate_traceroute(self, device, dst_ip):
        """PNETLab 장비에서 실제 traceroute 실행"""
        cmd = f"traceroute {dst_ip}"
        output = self._ssh_exec(device, cmd)
        return self._parse_traceroute(output)
    
    def validate_link_failure(self, device, interface, dst_ip):
        """인터페이스 shutdown 후 경로 변화 확인"""
        self._ssh_exec(device, f"conf t\ninterface {interface}\nshutdown\nend")
        time.sleep(10)  # Convergence 대기
        result = self.validate_traceroute(device, dst_ip)
        self._ssh_exec(device, f"conf t\ninterface {interface}\nno shutdown\nend")
        return result
```

### 4.6 기대 결과

| 검증 항목 | 예상 일치율 | 비고 |
|---|:---:|---|
| L4 traceroute 경로 | 90%+ | OSPF/BGP 수렴 → Batfish 정확도 높음 |
| L4 도달성 (ACCEPTED/DENIED) | 95%+ | 정/부 판정은 안정적 |
| L5 link failure 후 경로 변화 | 85%+ | 수렴 시간 차이로 일부 불일치 가능 |

> ⚠️ 불일치 시 원인 분석: Batfish 모델 한계? 수렴 타이밍? LDP/MPLS 처리 차이?

---

## 5. Layer 3 — LLM-as-Judge (Quality Assessment)

### 5.1 목적

> "질문이 명확하고, 정답이 합리적이며, 난이도 분류가 적절한가?"

### 5.2 검증 대상: 100건 (레벨별 20건 × L1~L5)

### 5.3 평가 프롬프트

```python
JUDGE_PROMPT = """당신은 네트워크 전문가입니다. 
다음 네트워크 설정 관련 질문-정답 쌍의 품질을 평가하세요.

## 평가 대상
- **질문**: {question}
- **정답**: {answer}
- **난이도**: {level} ({level_description})
- **카테고리**: {category}
- **정답 유형**: {answer_type}

## 평가 기준 (각 1-5점)

### 1. 질문 명확성 (Clarity)
- 5: 완벽히 명확, 유일한 해석만 가능
- 3: 약간의 모호성 존재
- 1: 매우 모호, 다양한 해석 가능

### 2. 정답 합리성 (Correctness)
- 5: 제공된 정답이 명백히 정확
- 3: 정답이 그럴듯하나 확신 불가
- 1: 정답이 명백히 틀림

### 3. 난이도 적절성 (Level Appropriateness)
- 5: 설명된 난이도에 완벽히 부합
- 3: 난이도가 약간 높거나 낮음
- 1: 난이도 분류가 완전히 부적절

### 4. 교육적 가치 (Educational Value)
- 5: 네트워크 운영 능력 평가에 매우 적합
- 3: 평가 가치가 보통
- 1: 평가 가치가 없는 trivial 질문

## 출력 형식 (JSON)
{
  "clarity": <1-5>,
  "correctness": <1-5>,
  "level_appropriateness": <1-5>,
  "educational_value": <1-5>,
  "comments": "<자유 코멘트>"
}
"""
```

### 5.4 논문에서의 활용

| 지표 | 보고 내용 |
|---|---|
| 평균 Clarity | "질문의 95%가 4점 이상 → 명확성 확보" |
| 평균 Correctness | "정답의 90%가 4점 이상 → 합리성 확보" |
| 평균 Level Appropriateness | "난이도 분류의 85%가 적절" |
| 불일치 사례 분석 | 3점 이하 받은 건에 대한 정성적 논의 |

### 5.5 한계 명시

> 논문에 반드시 포함할 문구:  
> "LLM-as-Judge 검증의 한계를 인지하고 있으며, 이를 Layer 1(자동 재현)과 Layer 2(실환경 교차검증)의 **보조적 수단**으로만 활용하였다."

---

## 6. 검증 결과 보고서 형식

### 논문 Table: Dataset Verification Results

| Layer | Method | Scope | Result | Notes |
|:---:|---|:---:|---|---|
| 1 | Batfish 재현 | 1,128건 전수 | X% PASS | 내적 일관성 |
| 2a | PNETLab traceroute | L4 30건 | X% 일치 | 시뮬레이션 ↔ 실제 |
| 2b | PNETLab link failure | L5 20건 | X% 일치 | What-If 정확도 |
| 3 | LLM-as-Judge | 100건 | 평균 X/5점 | 질문 품질 |

---

## 7. 구현 일정

| 단계 | 작업 | 소요 | 완료 기준 |
|---|---|:---:|---|
| Phase 0 | v2 메타데이터 정리 (ID 고유화, evidence placeholder 제거) | 0.5~1일 | 샘플 100건 수동검사 시 재현 인자 오류 0건 |
| Phase 1 | `verify_dataset.py` + `verifier.py` 구현 (L1~L5) | 1.5~2일 | 전체 1,128건 PASS/FAIL/SKIP 산출 |
| Phase 1 | Layer 1 실행 + FAIL 원인 분류 | 0.5~1일 | `*_verification.md`, `*_verification_failures.csv` 생성 |
| Phase 2 | `pnetlab_cross_validation.py` 구현 | 0.5~1일 | traceroute/link-failure 자동 수집 가능 |
| Phase 2 | Layer 2 실행 (50건) | 1일 | 일치율 + 불일치 분류표 작성 |
| Phase 3 | `llm_judge.py` 구현 + 실행 | 0.5일 | 100건 JSON 결과 생성 |
| Phase 3 | 보고서 통합 | 0.5일 | Table II 초안 완성 |
| **합계** | **MVP 5~7일** |  |  |

### 7.1 Scope Freeze (제출용)

1. 본 제출 실험은 **L1~L5**로 고정한다.
2. L6는 코드만 유지하고, 이번 제출 실험/평가/표에서는 제외한다.
3. Layer 2 50건은 반드시 완료한다 (논문 방어 핵심).
