# NetConfigQA2.0 — 데이터셋 검증 계획서

> **목적**: IEEE TNMS 논문에서 데이터셋의 Ground Truth 신뢰성을 증명하기 위한 검증 체계
> **대상**: 데이터셋 v2 (L1~L5, 1,128 QA pairs)
> **전략**: **Hybrid Validation** (독립 파서 + 수동 로직 검증 + 실환경 에뮬레이션)
> **최종 산출물**: 논문 Section IV "Dataset Verification" 작성에 필요한 수치 및 근거

---

## 0. 문서 상태

### 0.1 선행 조건

| 항목 | 상태 | 비고 |
|---|:---:|---|
| ID 고유화 및 Evidence 수정 | **완료** | commit 4299eeb |
| 정책 스키마 검증기 도입 | **완료** | `Make_Dataset/src/validate_policies.py` |
| 데이터셋 재생성 | **대기** | 검증 로직 확정 후 수행 |

### 0.2 Scope Freeze
- 본 제출 실험은 **L1~L5**로 고정한다.
- L6는 코드만 유지하고, 이번 제출의 실험/평가/표에서는 제외한다.

---

## 1. 문제 정의: "자동 생성된 정답을 어떻게 신뢰할 수 있는가?"

### 1.1 핵심 문제: 순환 논증 (Circular Reasoning)

NetConfigQA2.0은 Batfish를 이용해 정답을 생성합니다.
리뷰어의 핵심 공격 포인트는 **"Batfish로 만든 정답을 Batfish로 검증하면(Layer 0), 틀린 로직도 '일치'한다고 나올 것"**이라는 점입니다.

이를 방어하기 위해서는 **"생성 도구와 독립적인 제2의 소스(Independent Oracle)"**가 필수적입니다.

---

## 2. 검증 전략: "Hybrid Validation"

단일 검증의 한계를 극복하기 위해, **상호보완적인 3가지 검증 방법**을 결합합니다.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                       Hybrid Verification Strategy                      │
├──────────────────────┬────────────────────────┬─────────────────────────┤
│    (1) Code-based    │    (2) Logic-based     │    (3) Reality-based    │
│  Independent Parser  │  Metric-wise Manual    │    PNETLab Emulation    │
├──────────────────────┼────────────────────────┼─────────────────────────┤
│ **대상**: L1, L2, L3 │ **대상**: L3 (Complex) │ **대상**: L4, L5        │
│ **수단**: Regex Code │ **수단**: Human Expert │ **수단**: Actual Device │
│ **비중**: 수백 건    │ **비중**: 127 metrics  │ **비중**: 50 samples    │
│ **특징**: 독립성     │ **특징**: 로직 검증    │ **특징**: 실재성        │
└──────────────────────┴────────────────────────┴─────────────────────────┘
```

> **참고**: 기존의 "Layer 0 (Pipeline QA)"는 내부 엔지니어링 무결성 확인용으로만 사용하고, 논문의 핵심 증거로는 위 3가지를 제시합니다.

### 2.1 관련 연구의 검증 방법론 (Justification)

우리의 하이브리드 접근법은 최신 연구들의 Best Practice를 통합한 것입니다.

| 연구 | 검증 방법 | 우리의 적용 |
|---|---|---|
| **TeleQnA** (2023) | **Human Expert Verification**: 자동 생성 후 전문가가 샘플 검증 | Method (2) **Metric-wise Manual Check** 적용 |
| **NetConfEval** (2024) | **Batfish Simulation**: Batfish를 Ground Truth Oracle로 활용 | Method (1) Batfish와 독립적인 **Regex Parser**로 교차 검증 |
| **NIKA** (2025) | **Execution/Telemetry**: 실제/가상 환경의 상태 정보를 정답으로 사용 | Method (3) **PNETLab 실환경** 결과와 비교 |

---

## 3. Method 1: Independent Config Parser (독립 검증)

### 3.1 목적
> "Batfish에 의존하지 않는 별도의 코드로 정답을 도출하여, Batfish 로직의 편향(Bias)을 제거한다."

### 3.2 구현 방안
순수 Python + 정규식(Regex)만을 사용하는 경량 파서를 구현합니다. Batfish 라이브러리를 일절 import하지 않습니다.

- **대상 메트릭**: L1(단순 조회), L2(단순 집계), L3(텍스트 비교) 등 **구조가 단순한 90%의 질문**
- **구현 예시**:
  ```python
  def verify_l1_hostname(qa):
      # cfg 파일에서 "hostname X" 패턴을 직접 찾음
      match = re.search(r"^hostname\s+(\S+)", config_text, re.MULTILINE)
      independent_answer = match.group(1)
      return independent_answer == qa['answer']
  ```

### 3.3 기대 효과
- L1~L3 질문의 **80~90%**를 "독립적인 코드"로 검증 가능
- "Self-Validation" 비판 원천 차단

---

## 4. Method 2: Metric-wise Manual Verification (로직 검증)

### 4.1 목적
> "자동화 도구가 놓칠 수 있는 엣지 케이스와 복잡한 로직(L3+)을 사람이 직접 확인한다."

### 4.2 수행 절차
1.  **표본 추출 (Stratified Sampling)**: 127개 메트릭(Metric ID)별로 **무작위 1개**의 QA 쌍을 추출 (총 127건).
2.  **사람 검증 (Human Inspection)**: 설정 파일(.cfg)을 직접 열어서 육안 확인.
3.  **엣지 케이스 점검**: 값이 없는 경우(`None`), 리스트가 비어있는 경우(`[]`), 조건부 로직 등.

### 4.3 기대 효과
- "The verification logic itself was validated by human experts on a representative stratified sample (N=127)."

---

## 5. Method 3: PNETLab Real-world Verification (실재성 검증)

### 5.1 목적
> "시뮬레이션(Batfish) 결과가 실제 네트워크 장비(Cisco IOS)의 동작과 일치하는가?"

### 5.2 검증 대상: 50건 (L4 30건 + L5 20건)
L4/L5는 실제 패킷 전송(Forwarding)이 관여하므로, 텍스트 파싱(Method 1)이나 육안 검사(Method 2)로는 불충분합니다.

### 5.3 수행 절차
1.  **L4 Traceroute**: PNETLab에서 `traceroute` 명령을 실행하여 홉(hop) 경로가 Batfish 예측과 일치하는지 확인.
2.  **L5 Link Failure**: PNETLab에서 인터페이스를 `shutdown` 시키고, 라우팅 테이블이 Batfish 예측대로 변경(`REROUTED`/`DISCONNECTED`)되는지 확인.

### 5.4 기대 효과
- 가장 강력한 **External Validity** 확보.
- "Simulation vs Emulator" 일치율 제시 (목표 90%+).

---

## 6. 검증 결과 보고서 형식 (논문용)

### Table: Hybrid Verification Results

| Method | Type | Scope | Sample Size | Agreement | Role |
|:---:|---|:---:|:---:|:---:|---|
| **(1)** | Independent Parser | Automatic | ~900 (L1-L3) | 99.X% | **Independence** from Batfish |
| **(2)** | Manual Check | Human | 127 (All Metrics) | 100% | **Logic Correctness** |
| **(3)** | PNETLab Emulation | Real Device | 50 (L4-L5) | 9X.X% | **External Validity** |

> **Note**: Layer 0 (Pipeline QA, Batfish 재현) 결과는 Appendix에 "Pipeline Integrity" 증거로 수록.

---

## 7. 구현 일정

| 작업 | 소요 | 비고 |
|---|:---:|---|
| **Step 1**: Independent Regex Parser 구현 | 1일 | `verify_regex.py` 구현 |
| **Step 2**: Parser 전수 검사 실행 | 0.5일 | L1-L3 자동 검증 |
| **Step 3**: Metric-wise 엑셀 생성 | 0.5일 | `make_checklist.py` |
| **Step 4**: 수동 검증 수행 (Human Check) | 1일 | 하루면 충분히 함 |
| **Step 5**: PNETLab 교차 검증 (L4/L5) | 1.5일 | 기존 계획 유지 |
| **합계** | **4.5일** | |

---

## 8. 리뷰어 예상 질문과 대비

| 예상 질문 | 우리의 답변 | 근거 |
|---|---|---|
| "Circular reasoning 아닌가?" | "Batfish 재현(Layer 0)은 내부 품질용이고, 핵심 증거는 **독립 파서(Method 1)**와 **실환경(Method 3)**에서 왔다." | Method 1/3의 독립성 |
| "독립 파서의 정확도는?" | "Cisco IOS 설정 문법은 명확하므로 Regex 오류율이 낮다. 불일치 시 수동 확인했다." | 불일치 분석 |
| "50건 샘플이 충분한가?" | "L4/L5 전체 대비 유의미한 비율이며, 층화추출로 대표성을 확보했다." | 통계적 근거 |
| "사람 검증은 편향될 수 있지 않나?" | "단순 정답 확인이 아니라 **로직(함수) 검증**에 집중했으며, TeleQnA 등 선행 연구도 채택한 방식이다." | TeleQnA 인용 |
