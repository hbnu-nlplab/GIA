# NetConfigQA2.0 — 데이터셋 검증 계획서

> **목적**: IEEE TNMS 논문에서 데이터셋의 Ground Truth 신뢰성을 증명하기 위한 검증 체계
> **대상**: 데이터셋 v2 (L1~L5, 1,128 QA pairs)
> **제약**: 네트워크 전문가 부재 → 자동화 우선, PNETLab 실환경 보조
> **최종 산출물**: 논문 Section IV "Dataset Verification" 작성에 필요한 수치 및 근거

---

## 0. 문서 상태

### 0.1 선행 조건 (완료)

| 항목 | 상태 | 비고 |
|---|:---:|---|
| ID 고유화 (`main_batfish.py`) | **완료** | `METRIC_scopeVal` 형식 (commit 4299eeb) |
| Evidence placeholder 제거 | **완료** | `scope_template` → `scope` (commit 4299eeb) |
| 데이터셋 재생성 | **미완료** | 위 수정 반영하여 재생성 필요 |

### 0.2 구현 우선순위

| 순위 | 작업 | 파일 | 상태 |
|:---:|---|---|:---:|
| 1 | Layer 1 검증기 구현 | `verify_dataset.py` + `verifier.py` | 구현 대상 |
| 2 | Layer 1 실행 + 보고서 | `*_verification_report.md` | 구현 대상 |
| 3 | Layer 2 PNETLab 교차검증 | `pnetlab_cross_validation.py` | 구현 대상 |
| 4 | Layer 3 LLM-as-Judge | `llm_judge.py` | 구현 대상 |

### 0.3 Scope Freeze

- 본 제출 실험은 **L1~L5**로 고정한다.
- L6는 코드만 유지하고, 이번 제출의 실험/평가/표에서는 제외한다.

---

## 1. 왜 검증이 필요한가?

### 1.1 IEEE 리뷰어가 물을 3가지 질문

NetConfigQA2.0은 **Batfish가 자동 생성한 Ground Truth**를 사용합니다.
리뷰어는 "그 정답이 정말 맞는가?"를 반드시 질문합니다:

> **Q1 (정답 신뢰성)**: "Batfish가 생성한 정답이 실제 네트워크와 일치하는가?"
> **Q2 (질문 품질)**: "질문이 모호하지 않고 유일한 정답을 가지는가?"
> **Q3 (난이도 적절성)**: "L1~L5 난이도 분류가 합리적인가?"

### 1.2 우리의 답변 전략

각 질문에 대해 **독립적인 검증 Layer**를 대응시킵니다:

| 리뷰어 질문 | 검증 방법 | 강도 |
|---|---|---|
| Q1 (정답 신뢰성) | **Layer 1** (자동 재현) + **Layer 2** (실환경 교차) | 강함 |
| Q2 (질문 품질) | **Layer 3** (LLM-as-Judge) | 보조적 |
| Q3 (난이도 적절성) | **Layer 3** + Layer 1 통계 분석 | 보조적 |

**핵심 논리**: Layer 1이 내적 일관성을, Layer 2가 외적 타당성을 증명합니다.
Layer 3은 사람 평가를 대리하는 보조 수단입니다.

---

## 2. 3-Layer 검증 아키텍처 (전체 그림)

```
┌────────────────────────────────────────────────────────┐
│                  검증 보고서 (최종 출력)                   │
│  ├── verification_report.md     (통합 보고서)            │
│  ├── verification_failures.csv  (FAIL 건 상세)          │
│  └── llm_judge_results.json     (LLM 평가 결과)         │
└────────────────────────────────────────────────────────┘
                   ▲        ▲         ▲
       ┌───────────┤   ┌────┤   ┌─────┤
       │           │   │    │   │     │
┌──────────────┐ ┌──────────┐ ┌──────────────┐
│ Layer 1      │ │ Layer 2  │ │ Layer 3      │
│ 자동 재현    │ │ 실환경   │ │ LLM-as-Judge │
│ (전수검사)   │ │ 교차검증 │ │ (품질 평가)  │
│              │ │          │ │              │
│ 1,128건 전부 │ │ 50건 샘플│ │ 100건 샘플   │
│ Batfish 재현 │ │ PNETLab  │ │ GPT-4o       │
└──────────────┘ └──────────┘ └──────────────┘
```

**각 Layer의 역할을 비유하면:**

| Layer | 비유 | 증명하는 것 |
|:---:|---|---|
| 1 | 시험지 채점을 다시 한번 해보는 것 | "채점 기계가 고장나지 않았다" |
| 2 | 실제 학생에게 같은 문제를 풀게 하는 것 | "시험 문제가 현실과 동떨어지지 않았다" |
| 3 | 출제 위원이 문제 품질을 검토하는 것 | "문제가 명확하고 적절한 난이도다" |

---

## 3. Layer 1 — 자동 재현 검증 (Internal Consistency)

### 3.1 목적

> "동일한 설정 파일(.cfg)과 동일한 쿼리 파라미터로 정답을 다시 계산하면 같은 결과가 나오는가?"

이것은 Ground Truth의 **내적 일관성(Internal Consistency)**을 검증합니다.

**왜 필요한가?**
- Batfish 버전 업데이트로 파서 동작이 바뀔 수 있음
- 데이터셋 생성 코드 수정 후 정답이 달라질 수 있음
- 코너 케이스(빈 값, None, 형식 변환)에서 불일치가 발생할 수 있음

### 3.2 검증 대상

전체 1,128건 (L1~L5 전수검사).

### 3.3 검증 원리: "Evidence → 재계산 → 비교"

데이터셋의 각 QA에는 `evidence` 필드가 있습니다. 이 필드에는 **정답을 다시 계산하는 데 필요한 모든 정보**가 들어 있습니다:

```
데이터셋 QA 항목
├── question: "pe2 장비의 호스트네임은 무엇입니까?"
├── answer: "pe2"
├── level: "L1"
├── answer_type: "text"
└── evidence: {
      "snapshot": "Research_Institute_Internal_DC",   ← 어떤 네트워크인지
      "metric": "system_hostname_text",               ← 어떤 메트릭인지
      "scope": {"type": "DEVICE", "host": "pe2"}     ← 어떤 대상인지
    }
```

검증기는 이 evidence를 읽고, **동일한 엔진에 동일한 파라미터를 전달**하여 정답을 다시 계산합니다.
그리고 원래 answer와 재계산 결과를 **TA-Acc 비교 함수**로 비교합니다.

### 3.4 레벨별 evidence 구조와 재계산 방법

#### L1~L3 (설정 파싱 기반)

L1~L3은 `.cfg` 파일을 파싱한 Static Facts에서 값을 추출합니다. Batfish 시뮬레이션이 필요 없습니다.

```
Evidence 예시 (L1 — 단일 장비):
  {"metric": "system_hostname_text", "scope": {"type": "DEVICE", "host": "pe2"}}

Evidence 예시 (L2 — 전체 집계):
  {"metric": "ssh_enabled_count", "scope": {"type": "GLOBAL"}}

Evidence 예시 (L3 — 비교/계산):
  {"metric": "bgp_full_mesh_status", "scope": {"type": "AS", "asn": "65001"}}
```

**재계산 방법**: `BuilderCore.compute(intent)` 호출
```python
# evidence에서 intent를 구성하여 BuilderCore에 전달
intent = {
    "metric": evidence["metric"],           # "system_hostname_text"
    "scope":  evidence["scope"]             # {"type": "DEVICE", "host": "pe2"}
}
result = builder_core.compute(intent)       # → {"answer_type": "text", "value": "pe2"}
```

#### L4 (Batfish 시뮬레이션 기반)

L4는 Batfish traceroute/reachability 분석 결과입니다. 실제 Batfish 세션이 필요합니다.

```
Evidence 예시 (traceroute):
  {"metric": "traceroute_path", "scope": {"type": "NODE_PAIR", "src": "p1", "dst": "p2"}}

Evidence 예시 (reachability):
  {"metric": "reachability_status", "scope": {"type": "NODE_PAIR", "src": "leaf1", "dst": "pe1"}}
```

**재계산 방법**: `BatfishBuilder` → `L4Analyzer` 메서드 호출
```python
# metric 이름으로 적절한 L4 메서드를 선택
metric = evidence["metric"]            # "traceroute_path"
scope  = evidence["scope"]            # {"type": "NODE_PAIR", "src": "p1", "dst": "p2"}

if metric == "traceroute_path":
    result = l4_analyzer.traceroute_path(src_location=scope["src"], dst_ip=..., target_name=scope["dst"])
elif metric == "reachability_status":
    result = l4_analyzer.reachability_status(src_ip=..., dst_ip=...)
# ... (각 L4 메트릭에 대응하는 메서드)
```

#### L5 (What-If 시뮬레이션 기반)

L5는 Batfish의 `fork_snapshot` + `differentialReachability`를 사용합니다.

```
Evidence 예시 (link failure):
  {"metric": "link_failure_impact", "scope": {"type": "LINK_FAILURE", "link": "leaf1-pe1"}}

Evidence 예시 (device failure):
  {"metric": "device_failure_impact", "scope": {"type": "DEVICE_FAILURE", "device": "p1"}}
```

**재계산 방법**: `BatfishBuilder` → `L5Analyzer` 메서드 호출
```python
metric = evidence["metric"]            # "link_failure_impact"
scope  = evidence["scope"]            # {"type": "LINK_FAILURE", "link": "leaf1-pe1"}

if metric == "link_failure_impact":
    # link를 node1, node2로 분리
    node1, node2 = scope["link"].split("-")
    result = l5_analyzer.link_failure_impact(node1, node2, src_host=..., dst_host=...)
```

### 3.5 비교 함수: TA-Acc 재사용

**핵심 설계 결정**: 검증의 비교 함수는 논문의 평가 메트릭인 **TA-Acc와 동일한 함수**를 사용합니다.

이렇게 하는 이유:
1. 리뷰어에게 "검증과 평가에 같은 기준을 썼다"고 답할 수 있음
2. 비교 함수를 새로 만들면 "왜 다른 함수를 썼는가?"라는 질문을 유발
3. 코드 일관성 (한 곳에서 관리)

```python
# TA-Acc 비교 (answer_type별 분기)
# 출처: Experiment/code/NetConfigQA2/analyze_results_netconfigqa.py 의 NetConfigQAScorer
#      + Make_Dataset/src/core_batfish/models.py 의 canonicalize()

def compare_for_verification(expected_json: str, reproduced_value: Any, answer_type: str) -> dict:
    """
    검증용 비교. TA-Acc 점수를 반환하며, 1.0이면 PASS.

    Parameters:
        expected_json: 데이터셋에 저장된 JSON 문자열 (예: '"pe2"', '["a", "b"]')
        reproduced_value: 재계산으로 얻은 Python 값 (예: "pe2", ["a", "b"])
        answer_type: 정답 유형 (예: "text", "set_str", "map_str_int")

    Returns:
        {"score": float, "match": bool}  — score=1.0이면 match=True
    """
    # 1단계: expected_json을 Python 값으로 파싱
    expected = json.loads(expected_json)

    # 2단계: 양쪽 값을 canonicalize (models.py의 정규화 함수)
    expected_canon = canonicalize(expected, answer_type)
    reproduced_canon = canonicalize(reproduced_value, answer_type)

    # 3단계: answer_type별 비교
    if answer_type in ("text", "scalar_str", "enum", "bool"):
        # 정규화 후 문자열 비교
        score = 1.0 if str(expected_canon).strip().lower() == str(reproduced_canon).strip().lower() else 0.0

    elif answer_type in ("scalar_int", "numeric"):
        # 숫자 비교
        score = 1.0 if float(expected_canon) == float(reproduced_canon) else 0.0

    elif answer_type in ("set_str", "edge_set"):
        # 집합 F1 Score
        expected_set = set(map(str, expected_canon))
        reproduced_set = set(map(str, reproduced_canon))
        if not expected_set and not reproduced_set:
            score = 1.0
        elif not expected_set or not reproduced_set:
            score = 0.0
        else:
            common = expected_set & reproduced_set
            precision = len(common) / len(reproduced_set)
            recall = len(common) / len(expected_set)
            score = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    elif answer_type in ("map_str_int", "map_str_str"):
        # Key-Value F1
        score = _map_f1(expected_canon, reproduced_canon)

    elif answer_type == "path":
        # 경로는 순서가 중요 → Exact Match
        score = 1.0 if expected_canon == reproduced_canon else 0.0

    else:
        # Fallback: 문자열 비교
        score = 1.0 if str(expected_canon) == str(reproduced_canon) else 0.0

    return {"score": score, "match": score >= 1.0}
```

### 3.6 검증 결과 분류

각 QA는 다음 4가지 상태 중 하나로 분류됩니다:

| 상태 | 의미 | 예시 |
|---|---|---|
| **PASS** | 재계산 결과가 원래 답과 일치 (score=1.0) | 대부분의 L1 질문 |
| **FAIL** | 재계산 결과가 원래 답과 불일치 | 값 형식 변환 오류, Batfish 파서 차이 |
| **SKIP** | 재계산 불가 (evidence 부족, 미지원 메트릭) | 새 메트릭 추가 후 검증기 미갱신 |
| **ERROR** | 재계산 중 예외 발생 | Batfish 세션 끊김, 타임아웃 |

### 3.7 FAIL 원인 분류 체계 (Taxonomy)

FAIL이 발생하면 논문에서 "왜 100%가 아닌가?"를 설명해야 합니다.
다음 taxonomy로 원인을 분류합니다:

| FAIL 유형 | 설명 | 대응 |
|---|---|---|
| `FORMAT_MISMATCH` | 값은 같지만 표현 형식이 다름 (예: `"True"` vs `"true"`) | 정규화 함수 보강 |
| `FLOATING_POINT` | 부동소수점 오차 (예: `0.1 + 0.2 ≠ 0.3`) | 허용 오차(epsilon) 적용 |
| `ORDERING_DIFF` | 집합형 답에서 순서만 다름 | canonicalize 로직 확인 |
| `VALUE_CHANGED` | Batfish 버전 차이로 실제 값이 다름 | 정답 갱신 또는 한계 명시 |
| `PARSER_LIMITATION` | Batfish가 특정 구문을 파싱 못함 | Limitation 섹션에 보고 |
| `EVIDENCE_INCOMPLETE` | evidence에 재계산 파라미터 부족 | evidence 보강 |

### 3.8 기대 결과

| 상태 | 1차 목표 (MVP) | 최종 목표 |
|---|:---:|:---:|
| PASS | **90%+** | **95%+** |
| FAIL | **< 8%** (원인 분류 포함) | **< 3%** |
| SKIP | **< 5%** | **< 2%** |
| ERROR | **< 1%** | **0%** |

> MVP 달성 후 FAIL 원인을 분석하여 정규화 함수 보강 → 최종 목표 달성.

---

## 4. Layer 2 — PNETLab 실환경 교차 검증 (External Validity)

### 4.1 목적

> "Batfish 시뮬레이션 결과가 **실제 라우터의 동작**과 일치하는가?"

Layer 1은 "Batfish에게 다시 물어봤더니 같은 답이 나왔다"는 것만 증명합니다.
하지만 **Batfish 자체가 틀렸을 수 있습니다**.

Layer 2는 **PNETLab에서 실제 Cisco IOS 라우터를 구동**하고,
실제 `traceroute`/`ping` 명령으로 얻은 결과와 Batfish 정답을 비교합니다.

**이것이 전문가 없이 사용 가능한 가장 강력한 검증 카드입니다.**

### 4.2 왜 L4/L5만 검증하는가?

| Level | Layer 2 대상? | 이유 |
|:---:|:---:|---|
| L1~L3 | 아니오 | 설정 파일 파싱이므로 Batfish 정확도가 매우 높음. 실측 대비 오차가 거의 없음 |
| **L4** | **예 (30건)** | traceroute 경로 → 실제 `traceroute` 명령으로 직접 비교 가능 |
| **L5** | **예 (20건)** | link failure 영향 → 실제 `shutdown` 후 경로 변화 비교 가능 |

### 4.3 검증 대상: 50건 (L4 30건 + L5 20건)

**샘플 선정 기준:**
- L4: traceroute_path 질문 중 도달/비도달 비율을 유지하여 30건 층화추출
- L5: link_failure_impact 질문 중 NONE/REROUTED/DISCONNECTED 비율 유지하여 20건 층화추출

### 4.4 L4 검증 프로세스 (상세)

```
┌─────────────────────────────────────────────────────────────────┐
│ 데이터셋 L4 질문 예시:                                           │
│   Q: "p1에서 10.0.0.1까지의 네트워크 경로를 나열해주세요"          │
│   A: "p1 → p2"                                                  │
│   evidence.scope: {"type": "NODE_PAIR", "src": "p1", "dst": "p2"} │
└─────────────────────────────────────────────────────────────────┘
                              │
                    ┌─────────┴──────────┐
                    ▼                    ▼
            ┌──────────────┐     ┌──────────────┐
            │  Batfish 정답  │     │  PNETLab 실측  │
            │  "p1 → p2"    │     │  $ traceroute  │
            │              │     │    10.0.0.1    │
            │  (데이터셋에  │     │  source Lo0    │
            │   이미 있음)  │     │               │
            └──────┬───────┘     └──────┬───────┘
                   │                    │
                   └────────┬───────────┘
                            ▼
                   ┌────────────────┐
                   │ 경로 비교       │
                   │ Batfish hop    │
                   │ vs 실제 hop    │
                   └────────┬───────┘
                            ▼
                   MATCH / MISMATCH
```

**PNETLab에서 실측하는 방법:**

```bash
# Step 1: SSH로 source 장비에 접속
ssh admin@p1.pnetlab

# Step 2: traceroute 실행 (source 인터페이스 지정)
p1# traceroute 10.0.0.1 source Loopback0

# Step 3: 출력 파싱
# Type escape sequence to abort.
# Tracing the route to 10.0.0.1
#   1 10.0.12.2 [MPLS: Label 16002 Exp 0] 4 msec 4 msec 4 msec
#                ^^^^^^^^
#                hop 1 = p2 (10.0.12.2는 p2의 인터페이스)
# → 실측 경로: p1 → p2

# Step 4: Batfish 정답 "p1 → p2"와 비교 → MATCH
```

### 4.5 L5 검증 프로세스 (상세)

```
┌─────────────────────────────────────────────────────────────────┐
│ 데이터셋 L5 질문 예시:                                           │
│   Q: "'leaf1-pe1' 링크 다운 시 'leaf1→leaf3' 트래픽 영향?"       │
│   A: "REROUTED:Rerouted: leaf1"                                 │
│   evidence.scope: {"type": "LINK_FAILURE", "link": "leaf1-pe1"} │
└─────────────────────────────────────────────────────────────────┘
                              │
                    ┌─────────┴──────────┐
                    ▼                    ▼
            ┌──────────────┐     ┌──────────────────────────┐
            │  Batfish 정답  │     │  PNETLab 실측              │
            │  "REROUTED"   │     │                            │
            │              │     │  1. 정상 경로 확인           │
            │              │     │     $ traceroute leaf3_ip   │
            │              │     │  2. 링크 shutdown            │
            │              │     │     $ conf t                │
            │              │     │     $ int GigX/X            │
            │              │     │     $ shutdown              │
            │              │     │  3. 수렴 대기 (30~60초)      │
            │              │     │  4. 경로 재확인              │
            │              │     │     $ traceroute leaf3_ip   │
            │              │     │  5. 링크 복원               │
            │              │     │     $ no shutdown           │
            └──────┬───────┘     └───────────┬──────────────┘
                   │                         │
                   └────────┬────────────────┘
                            ▼
                   ┌────────────────────────┐
                   │ 영향 비교               │
                   │ 정상→장애 경로 변화 여부 │
                   │ NONE / REROUTED /       │
                   │ DISCONNECTED            │
                   └────────┬───────────────┘
                            ▼
                   MATCH / MISMATCH
```

**수렴 대기 시간**: OSPF 기본 Hello=10초, Dead=40초이므로 **최소 45초** 대기 후 traceroute 실행.
BGP의 경우 Hold Timer=180초까지 걸릴 수 있으나, 직접 연결 링크의 interface down은 즉시 감지됨.

### 4.6 반자동화 스크립트

```python
"""pnetlab_cross_validation.py — SSH를 통한 PNETLab 교차 검증"""

class PNETLabValidator:
    """
    PNETLab 실환경에서 Batfish 정답을 교차검증합니다.

    사용법:
        validator = PNETLabValidator("device_credentials.json")
        results = validator.validate_batch(l4_samples, l5_samples)
        validator.save_report("cross_validation_results.json")
    """

    def validate_l4_traceroute(self, src_device, dst_ip) -> dict:
        """
        PNETLab 장비에서 실제 traceroute 실행 후 hop 목록 반환.

        Returns:
            {"hops": ["p1", "p2"], "raw_output": "...", "status": "OK"}
        """
        output = self._ssh_exec(src_device, f"traceroute {dst_ip} source Loopback0")
        hops = self._parse_traceroute_hops(output)  # IP→hostname 변환 포함
        return {"hops": hops, "raw_output": output, "status": "OK"}

    def validate_l5_link_failure(self, link, src_device, dst_ip) -> dict:
        """
        링크 장애 시뮬레이션 후 영향 판정.

        Process:
            1. 정상 상태 traceroute → normal_path
            2. interface shutdown → 수렴 대기 (45초)
            3. 장애 상태 traceroute → failure_path
            4. interface no shutdown (복원)
            5. normal_path vs failure_path 비교 → NONE/REROUTED/DISCONNECTED

        Returns:
            {"impact": "REROUTED", "normal_path": [...], "failure_path": [...]}
        """
        node1, node2 = link.split("-")
        interface = self._resolve_interface(node1, node2)

        # 1. 정상 경로
        normal = self._ssh_exec(src_device, f"traceroute {dst_ip} source Loopback0")
        normal_hops = self._parse_traceroute_hops(normal)

        # 2. 링크 장애
        self._ssh_exec(node1, f"configure terminal\ninterface {interface}\nshutdown\nend")
        time.sleep(45)  # OSPF/BGP 수렴 대기

        # 3. 장애 경로
        failure = self._ssh_exec(src_device, f"traceroute {dst_ip} source Loopback0")
        failure_hops = self._parse_traceroute_hops(failure)

        # 4. 복원
        self._ssh_exec(node1, f"configure terminal\ninterface {interface}\nno shutdown\nend")
        time.sleep(45)

        # 5. 영향 판정
        if failure_hops is None or len(failure_hops) == 0:
            impact = "DISCONNECTED"
        elif normal_hops == failure_hops:
            impact = "NONE"
        else:
            impact = "REROUTED"

        return {"impact": impact, "normal_path": normal_hops, "failure_path": failure_hops}
```

### 4.7 기대 결과 및 불일치 대응

| 검증 항목 | 예상 일치율 | 비고 |
|---|:---:|---|
| L4 traceroute 경로 (도달 가능) | 90%+ | OSPF/BGP ECMP 경로 선택 차이 가능 |
| L4 도달성 판정 (ACCEPTED/DENIED) | 95%+ | 정/부 판정은 안정적 |
| L5 link failure 영향 판정 | 85%+ | 수렴 타이밍, ECMP 재분배 차이 가능 |

**불일치 발생 시 처리:**

| 불일치 유형 | 원인 | 논문에서의 처리 |
|---|---|---|
| ECMP 경로 차이 | Batfish는 첫 번째 경로만 반환 | "Limitation: ECMP 환경에서 경로 선택 비결정성" |
| 수렴 타이밍 차이 | 실제 라우터의 타이머 vs Batfish 즉시 반영 | "Limitation: 수렴 과도기 동작은 모델링 범위 외" |
| MPLS/LDP 차이 | Batfish의 MPLS 지원 한계 | "Limitation: MPLS label 경로는 근사치" |

> **논문 작성 원칙**: 불일치를 숨기지 않고, 원인을 분석하여 **Limitation 섹션**에 투명하게 보고합니다.

---

## 5. Layer 3 — LLM-as-Judge (Quality Assessment)

### 5.1 목적

> "질문이 명확하고, 정답이 합리적이며, 난이도 분류가 적절한가?"

네트워크 전문가에게 1,128건을 검수받는 것이 이상적이지만, 현실적으로 불가능합니다.
대안으로 GPT-4o를 "네트워크 전문가 역할의 평가자"로 활용합니다.

### 5.2 한계 먼저 명시

> **논문에 반드시 포함할 문구:**
> "We acknowledge the limitations of LLM-based evaluation and employ it solely as a **supplementary measure** alongside Layer 1 (automated reproduction) and Layer 2 (live network cross-validation), which serve as our primary verification methods."

### 5.3 검증 대상

100건 (레벨별 20건 x L1~L5, 층화추출)

### 5.4 평가 기준 (4개 차원)

| 차원 | 영문명 | 평가 내용 | 5점 기준 | 1점 기준 |
|---|---|---|---|---|
| 질문 명확성 | Clarity | 유일한 해석만 가능한가? | 해석이 하나뿐 | 다양한 해석 가능 |
| 정답 합리성 | Correctness | 제시된 정답이 맞는가? | 명백히 정확 | 명백히 틀림 |
| 난이도 적절성 | Level Appropriateness | L1~L5 분류가 맞는가? | 완벽히 부합 | 완전히 부적절 |
| 교육적 가치 | Educational Value | NW 운영 능력 평가에 유용한가? | 매우 적합 | trivial하여 무가치 |

### 5.5 평가 프롬프트

```python
JUDGE_PROMPT = """You are a senior network engineer reviewing a network configuration QA benchmark.

## QA Pair Under Review
- **Question**: {question}
- **Ground Truth Answer**: {answer}
- **Difficulty Level**: {level} — {level_description}
- **Category**: {category}
- **Answer Type**: {answer_type}

## Evaluation Criteria (1-5 scale each)

### 1. Clarity
- 5: Perfectly unambiguous; only one interpretation possible
- 3: Slightly ambiguous but intent is clear
- 1: Highly ambiguous; multiple valid interpretations exist

### 2. Correctness
- 5: The provided answer is clearly correct given the question
- 3: The answer seems plausible but cannot be confirmed without config context
- 1: The answer is clearly wrong

### 3. Level Appropriateness
- 5: Difficulty level perfectly matches the cognitive demand
- 3: Level is slightly too high or too low
- 1: Level classification is completely inappropriate

### 4. Educational Value
- 5: Highly suitable for evaluating network operation competency
- 3: Moderate evaluation value
- 1: Trivial question with no assessment value

## Output Format (JSON only)
{
  "clarity": <1-5>,
  "correctness": <1-5>,
  "level_appropriateness": <1-5>,
  "educational_value": <1-5>,
  "comments": "<brief justification>"
}
"""
```

### 5.6 신뢰성 보강: 2회 반복 평가

동일 질문을 **2회 독립 평가**하여 **일치도(Cohen's Kappa 또는 Pearson r)**를 보고합니다.

| 지표 | 기대값 | 해석 |
|---|---|---|
| Pearson r (연속 점수) | 0.8+ | 높은 자기 일관성 |
| 2점 이상 차이 비율 | < 5% | 불안정한 평가가 적음 |

### 5.7 논문에서의 보고

| 지표 | 보고 형식 | 예시 |
|---|---|---|
| 평균 Clarity | "X% of questions scored 4+ (mean=Y)" | "95% scored 4+ (mean=4.6)" |
| 평균 Correctness | 동일 | "90% scored 4+ (mean=4.3)" |
| 평균 Level Appropriateness | 동일 | "85% scored 4+ (mean=4.1)" |
| 3점 이하 사례 | 정성적 논의 | "L3 질문 2건이 L2로 재분류 타당" |

---

## 6. 구현 파일 구조

```
Make_Dataset/src/
├── verify_dataset.py              # Layer 1 메인 실행 스크립트
│   ├── DatasetVerifier            # 오케스트레이터 클래스
│   │   ├── load_dataset()         # CSV/JSON 로드
│   │   ├── verify_all()           # 전수검증 실행
│   │   ├── verify_single()        # 단건 검증
│   │   └── generate_report()      # 보고서 생성
│   └── VerificationResult         # 결과 데이터클래스
│
├── core_batfish/
│   ├── verifier.py                # 레벨별 재계산 로직
│   │   ├── ReproductionEngine     # 재계산 엔진
│   │   │   ├── reproduce()        # evidence → 재계산 (dispatcher)
│   │   │   ├── _reproduce_l1l3()  # BuilderCore.compute() 호출
│   │   │   ├── _reproduce_l4()    # L4Analyzer 메서드 호출
│   │   │   └── _reproduce_l5()    # L5Analyzer 메서드 호출
│   │   └── AnswerComparator       # TA-Acc 기반 비교
│   │       └── compare()          # canonicalize + score
│   │
│   ├── builder_core.py            # (기존) L1-L3 계산 엔진
│   ├── l4_analyzer.py             # (기존) L4 Batfish 분석
│   ├── l5_analyzer.py             # (기존) L5 What-If 분석
│   └── models.py                  # (기존) AnswerResult, canonicalize()
│
├── pnetlab_cross_validation.py    # Layer 2 교차검증
│   └── PNETLabValidator           # SSH 기반 실측
│
└── llm_judge.py                   # Layer 3 LLM-as-Judge
    └── LLMJudge                   # GPT-4o 평가
```

---

## 7. 검증 결과 보고서 (논문 Table 초안)

### Table: Dataset Verification Results (3-Layer)

| Layer | Method | Scope | Primary Metric | Result | Notes |
|:---:|---|:---:|---|---|---|
| 1 | Automated Reproduction | 1,128 (all) | Reproduction Rate | X% PASS | Internal consistency |
| 2a | PNETLab traceroute | L4 30건 | Path Match Rate | X% match | Simulation vs. live |
| 2b | PNETLab link failure | L5 20건 | Impact Match Rate | X% match | What-If accuracy |
| 3 | LLM-as-Judge (GPT-4o) | 100건 | Mean Quality Score | X/5.0 | Supplementary |

### Table: Layer 1 FAIL Taxonomy (if applicable)

| Failure Type | Count | % | Resolution |
|---|:---:|:---:|---|
| FORMAT_MISMATCH | - | - | Normalization improved |
| VALUE_CHANGED | - | - | Documented in Limitations |
| PARSER_LIMITATION | - | - | Documented in Limitations |
| EVIDENCE_INCOMPLETE | - | - | Evidence enriched |

---

## 8. 리뷰어 예상 질문과 대비

| 예상 질문 | 우리의 답변 | 근거 |
|---|---|---|
| "Ground truth 생성에 사용한 도구가 검증에도 동일한 것은 circular reasoning 아닌가?" | "Layer 1은 내적 일관성만 검증. 외적 타당성은 Layer 2(PNETLab 실측)가 담당한다." | Layer 2 결과 |
| "50건 샘플이 충분한가?" | "L4/L5 전체 모수 대비 X%이며, 층화추출로 대표성 확보. 일치율 95% CI를 보고한다." | 통계적 근거 |
| "LLM-as-Judge를 왜 신뢰하는가?" | "신뢰하지 않는다. 보조 수단으로만 사용하며, Layer 1+2가 주 검증이다." | 명시적 한계 |
| "검증과 평가에 같은 비교 함수를 쓴 이유?" | "TA-Acc가 answer_type별 최적 비교를 제공하므로, 검증에서도 동일 기준을 적용하는 것이 일관적이다." | 코드 동일 |
| "Batfish의 한계로 인한 오답은 어떻게 처리?" | "Layer 2 불일치 건을 FAIL taxonomy로 분류하고, Limitation에 투명하게 보고한다." | FAIL taxonomy |
