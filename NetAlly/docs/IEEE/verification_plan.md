# NetConfigQA2.0 — 데이터셋 검증 계획서

> **목적**: IEEE TNMS 논문에서 데이터셋의 Ground Truth 신뢰성을 증명하기 위한 검증 체계
> **대상**: 데이터셋 v2 (L1~L5, 1,128 QA pairs)
> **제약**: 네트워크 전문가 부재 → 자동화 우선, PNETLab 실환경 보조
> **최종 산출물**: 논문 Section IV "Dataset Verification" 작성에 필요한 수치 및 근거

---

## 0. 문서 상태

### 0.1 선행 조건

| 항목 | 상태 | 비고 |
|---|:---:|---|
| ID 고유화 (`main_batfish.py`) | **완료** | `METRIC_scopeVal` 형식 (commit 4299eeb) |
| Evidence placeholder 제거 | **완료** | `scope_template` → `scope` (commit 4299eeb) |
| 데이터셋 재생성 | **미완료** | 위 수정 반영하여 재생성 필요 |

### 0.2 Scope Freeze

- 본 제출 실험은 **L1~L5**로 고정한다.
- L6는 코드만 유지하고, 이번 제출의 실험/평가/표에서는 제외한다.

### 0.3 Schema/모호성 하드닝 업데이트 (2026-02-13)

이번 라운드에서 질문 모호성 완화와 E2E 정합성을 위해 아래를 반영했다.

| 항목 | 상태 | 구현 파일 |
|---|:---:|---|
| 정책 스키마 검증기 도입 | **완료** | `Make_Dataset/src/validate_policies.py` |
| 정책 메타 통일 (`schema_version=3.1`, `submission_scope=L1-L5`) | **완료** | `Make_Dataset/policies.json` |
| L3 고위험 `compare_*` 3종 구조화(`map_str_int`) | **완료** | `Make_Dataset/policies.json`, `Make_Dataset/src/core_batfish/builder_core.py` |
| `ibgp_fullmesh_ok` deprecated + 제출 제외 | **완료** | `Make_Dataset/policies.json`, `Make_Dataset/src/core_batfish/rule_based_generator.py` |
| 데이터셋 품질 게이트(중복 ID/evidence placeholder/구조화 스키마) | **완료** | `Make_Dataset/src/validate_dataset_quality.py`, `Make_Dataset/src/main_batfish.py` |

검증 실행 순서(권장):
1. `python3 Make_Dataset/src/validate_policies.py --policies Make_Dataset/policies.json`
2. `python3 Make_Dataset/src/main_batfish.py ...`
3. `python3 Make_Dataset/src/validate_dataset_quality.py --dataset <generated_dataset.json>`

---

## 1. 문제 정의: "자동 생성된 정답을 어떻게 신뢰할 수 있는가?"

### 1.1 NetConfigQA2.0의 Ground Truth 생성 구조

NetConfigQA2.0은 다음 구조로 정답을 생성합니다:

```
Cisco IOS 설정 파일 (.cfg)
    │
    ▼
Batfish (네트워크 분석 엔진)
    │
    ├── L1~L3: 설정 파싱 → Static Facts → BuilderCore.compute()
    │          (hostname, NTP, BGP neighbor 등 설정값 추출/집계/비교)
    │
    └── L4~L5: 시뮬레이션 → traceroute, fork_snapshot
               (경로 분석, 장애 영향도 분석)
    │
    ▼
1,128개 QA 쌍 (질문 + 정답 + evidence)
```

**핵심 문제**: 정답 생성의 모든 단계가 **Batfish라는 단일 도구**에 의존합니다.

IEEE 리뷰어는 반드시 이렇게 질문합니다:

> **Q1**: "Batfish가 생성한 정답이 실제 네트워크와 일치하는가?"
> **Q2**: "질문이 모호하지 않고 유일한 정답을 가지는가?"
> **Q3**: "난이도 분류가 적절한가?"

### 1.2 순진한 접근법과 그 한계

처음에 고려한 3-Layer 검증 구조와, 각각에 대한 비판적 분석입니다.

#### 초기안: Layer 1 (자동 재현) + Layer 2 (PNETLab 실측) + Layer 3 (LLM-as-Judge)

| Layer | 방법 | 비판적 질문 | 답변 가능한가? |
|:---:|---|---|:---:|
| 1 | Batfish로 정답을 다시 계산해서 비교 | **"코드가 처음부터 틀렸으면? 다시 돌려도 같은 틀린 답이 나올 텐데?"** | 답변 불가 |
| 2 | PNETLab 실측으로 비교 | "Batfish와 독립적인 검증이므로 유효하다" | **답변 가능** |
| 3 | LLM에게 질문 품질 평가 | **"LLM이 네트워크를 이해하는지 테스트하는 벤치마크를, LLM이 검증한다고?"** | 답변 불가 |

#### Layer 1의 한계: 자기 검증의 순환

```
Batfish로 정답 생성 → Batfish로 정답 검증 → "같다!"
    ↑                                          │
    └──────── 당연히 같음 (같은 코드) ───────────┘
```

Layer 1은 **"정답이 맞다"를 증명할 수 없습니다.**
Layer 1이 실제로 증명하는 것은:
- 데이터셋 생성 파이프라인에 엔지니어링 버그가 없다
- 직렬화/역직렬화 과정에서 값이 깨지지 않았다
- Batfish 버전 업데이트로 결과가 달라지지 않았다

이것은 **"Pipeline QA (파이프라인 품질 보증)"**이지, 정답 검증이 아닙니다.

#### Layer 3의 한계: Circular Reasoning

```
연구 목표:  "LLM이 네트워크 설정을 이해할 수 있는가?"를 테스트하는 벤치마크
검증 방법:  "LLM에게 벤치마크 품질을 평가하게 한다"

→ LLM이 정답의 Correctness를 판단할 수 있다면, 벤치마크가 필요 없음
→ LLM이 판단할 수 없다면, 검증 결과를 신뢰할 수 없음
→ 어느 쪽이든 논리적으로 성립하지 않음
```

구체적으로:

| LLM-as-Judge 평가 항목 | 문제 |
|---|---|
| Clarity (질문 명확성) | LLM이 도메인을 이해해야 "모호한지" 판단 가능 → circular |
| Correctness (정답 합리성) | 이것은 Exp.2 (Single LLM 평가) 실험 그 자체 |
| Level Appropriateness | 난이도를 판단하려면 문제를 풀 수 있어야 함 → circular |
| Educational Value | 주관적 평가, 재현성 없음 |

**"질문의 언어적 품질만 평가하면 되지 않나?"** 라는 반론이 가능하지만,
네트워크 질문의 명확성을 판단하려면 결국 네트워크 도메인 이해가 필요합니다.
"pe2 장비의 OSPF area는?"이 명확한 질문인지 판단하려면 OSPF area가 뭔지 알아야 합니다.

### 1.3 검증의 본질: "독립적인 제2의 소스"

**신뢰할 수 있는 검증이란, 생성 도구와 다른 독립적인 소스로 같은 결과를 확인하는 것입니다.**

| Level | 정답의 본질 | 독립 검증 소스 |
|---|---|---|
| L1~L3 | `.cfg` 텍스트에서 읽을 수 있는 값 | **Batfish를 사용하지 않는 독립 파서** |
| L4~L5 | 네트워크 시뮬레이션 결과 | **실제 라우터 (PNETLab)** |

이 관찰에서 수정된 검증 아키텍처가 도출됩니다.

---

## 2. 수정된 검증 아키텍처

### 2.1 설계 원칙

1. **생성 도구와 검증 도구는 반드시 독립적이어야 한다** (circular reasoning 회피)
2. 모든 레벨(L1~L5)에 대해 독립 검증 소스가 존재해야 한다
3. Layer 1(Pipeline QA)은 보조 수단으로만 포지셔닝한다

### 2.2 최종 구조

```
┌─────────────────────────────────────────────────────────────┐
│                    검증 보고서 (최종 출력)                      │
│  ├── verification_report.md          (통합 보고서)            │
│  ├── verification_failures.csv       (FAIL 건 상세)          │
│  └── independent_parser_results.csv  (독립 파서 비교 결과)    │
└─────────────────────────────────────────────────────────────┘
                  ▲           ▲           ▲
      ┌───────────┤     ┌─────┤     ┌─────┤
      │           │     │     │     │     │
┌───────────┐ ┌────────────┐ ┌────────────┐
│ Layer 0   │ │ Layer 1    │ │ Layer 2    │
│ Pipeline  │ │ 독립 파서  │ │ PNETLab   │
│ QA        │ │ 교차검증   │ │ 실측       │
│           │ │            │ │            │
│ 1,128건   │ │ L1~L3 전수 │ │ L4~L5     │
│ 자동 재현 │ │ (~900건)   │ │ 50건 샘플  │
│           │ │            │ │            │
│ Batfish   │ │ Regex/     │ │ 실제      │
│ (동일엔진)│ │ 텍스트파서 │ │ Cisco IOS │
└───────────┘ └────────────┘ └────────────┘
  보조 수단     L1~L3 핵심     L4~L5 핵심
```

### 2.3 각 Layer의 역할과 증명 범위

| Layer | 무엇을 증명하는가 | 무엇을 증명하지 못하는가 | 논문에서의 위상 |
|---|---|---|---|
| **Layer 0** (Pipeline QA) | 파이프라인에 엔지니어링 버그가 없다 | 정답이 맞다 | 보조 (Appendix) |
| **Layer 1** (독립 파서) | **L1~L3 정답이 cfg 텍스트와 일치한다** | L4~L5 시뮬레이션 정확성 | **핵심** (Section IV) |
| **Layer 2** (PNETLab 실측) | **L4~L5 정답이 실제 네트워크와 일치한다** | L1~L3 파싱 정확성 | **핵심** (Section IV) |

### 2.4 왜 LLM-as-Judge를 제거했는가 (Decision Log)

| 검토 항목 | 결론 | 근거 |
|---|---|---|
| Circular reasoning 여부 | **Yes** | 벤치마크의 목적(LLM 평가)과 검증 수단(LLM)이 동일 |
| Exp.2와의 차별성 | **없음** | LLM이 정답을 판단하는 것은 Exp.2 실험 자체 |
| "언어 품질만 평가" 가능성 | **불충분** | 도메인 이해 없이 네트워크 질문의 명확성 판단 불가 |
| 대안 존재 여부 | **있음** | 독립 파서 (L1~L3) + PNETLab (L4~L5)로 전 레벨 커버 가능 |
| 최종 결정 | **제거** | 학술적으로 방어 불가능한 검증을 포함하면 오히려 논문 약화 |

> **참고**: LLM-as-Judge 자체가 나쁜 방법론은 아닙니다. 번역 품질, 요약 품질 등에는 유효합니다.
> 다만 **"LLM의 능력을 테스트하는 벤치마크"를 "LLM이 검증"하는 것**은 논리적 모순입니다.

---

## 3. Layer 0 — Pipeline QA (자동 재현 검증)

### 3.1 목적

> "데이터셋 생성 파이프라인에 엔지니어링 결함이 없는가?"

**이것은 "정답 검증"이 아니라 "소프트웨어 테스트"입니다.**

실제로 이 과정에서 이미 2건의 버그를 발견하고 수정했습니다:
- **ID 중복 버그**: 1,128행 중 고유 ID가 431개뿐이었음 (commit 4299eeb)
- **Evidence placeholder 버그**: 760건에서 `{host}` 등 미치환 변수 잔존 (commit 4299eeb)

### 3.2 검증 대상

전체 1,128건 (L1~L5 전수)

### 3.3 검증 원리: "Evidence → 재계산 → 비교"

데이터셋의 각 QA에는 `evidence` 필드가 있습니다.
이 필드에는 정답을 다시 계산하는 데 필요한 모든 정보가 들어 있습니다:

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

검증기는 evidence를 읽고, **동일한 엔진에 동일한 파라미터를 전달**하여 정답을 다시 계산합니다.

### 3.4 레벨별 재계산 방법

#### L1~L3 (BuilderCore 재실행)

```python
intent = {
    "metric": evidence["metric"],       # "system_hostname_text"
    "scope":  evidence["scope"]         # {"type": "DEVICE", "host": "pe2"}
}
result = builder_core.compute(intent)   # → {"answer_type": "text", "value": "pe2"}
```

#### L4 (L4Analyzer 재실행 — Batfish 세션 필요)

```python
metric = evidence["metric"]            # "traceroute_path"
scope  = evidence["scope"]            # {"type": "NODE_PAIR", "src": "p1", "dst": "p2"}

if metric == "traceroute_path":
    result = l4_analyzer.traceroute_path(src_location=scope["src"], ...)
elif metric == "reachability_status":
    result = l4_analyzer.reachability_status(src_ip=..., dst_ip=...)
```

#### L5 (L5Analyzer 재실행 — fork_snapshot 필요)

```python
metric = evidence["metric"]            # "link_failure_impact"
scope  = evidence["scope"]            # {"type": "LINK_FAILURE", "link": "leaf1-pe1"}

if metric == "link_failure_impact":
    node1, node2 = scope["link"].split("-")
    result = l5_analyzer.link_failure_impact(node1, node2, ...)
```

### 3.5 비교 함수: TA-Acc 재사용

검증의 비교 함수는 논문의 평가 메트릭인 **TA-Acc와 동일한 함수**를 사용합니다.

이렇게 하는 이유:
1. 리뷰어에게 "검증과 평가에 같은 기준을 썼다"고 답할 수 있음
2. 비교 함수를 새로 만들면 "왜 다른 함수를 썼는가?"라는 질문을 유발
3. 코드 일관성 (한 곳에서 관리)

TA-Acc 비교 로직 (answer_type별):

| answer_type | 비교 방식 |
|---|---|
| `text`, `scalar_str`, `enum`, `bool` | 정규화 후 문자열 비교 |
| `scalar_int`, `numeric` | 숫자 비교 |
| `set_str`, `edge_set` | 집합 F1 Score |
| `map_str_int`, `map_str_str` | Key-Value F1 |
| `path` | 순서 포함 Exact Match |

### 3.6 결과 분류

| 상태 | 의미 |
|---|---|
| **PASS** | 재계산 결과가 원래 답과 일치 (TA-Acc = 1.0) |
| **FAIL** | 재계산 결과가 원래 답과 불일치 |
| **SKIP** | 재계산 불가 (evidence 부족, 미지원 메트릭) |
| **ERROR** | 재계산 중 예외 발생 (Batfish 세션 끊김 등) |

### 3.7 FAIL 원인 분류 (Taxonomy)

| FAIL 유형 | 설명 | 대응 |
|---|---|---|
| `FORMAT_MISMATCH` | 값은 같지만 형식이 다름 (`"True"` vs `"true"`) | 정규화 보강 |
| `FLOATING_POINT` | 부동소수점 오차 | epsilon 허용 |
| `ORDERING_DIFF` | 집합에서 순서만 다름 | canonicalize 확인 |
| `VALUE_CHANGED` | Batfish 버전 차이로 값이 다름 | 정답 갱신 또는 Limitation |
| `PARSER_LIMITATION` | Batfish가 특정 구문 미지원 | Limitation 보고 |
| `EVIDENCE_INCOMPLETE` | evidence에 재계산 파라미터 부족 | evidence 보강 |

### 3.8 논문에서의 포지셔닝

Layer 0는 **"정답이 맞다"를 증명하지 않습니다.** 논문에서 다음과 같이 서술합니다:

> "We first performed automated reproduction of all 1,128 QA pairs to verify
> **pipeline integrity** — ensuring no engineering defects (serialization errors,
> ID collisions, placeholder leaks) in the generation process. This step achieved
> X% PASS rate, confirming the mechanical correctness of our pipeline.
> **Ground truth accuracy** is separately validated via Layers 1 and 2."

---

## 4. Layer 1 — 독립 Config 파서 교차검증 (L1~L3)

### 4.1 목적

> "Batfish를 사용하지 않고, .cfg 텍스트만 읽어서도 같은 정답이 나오는가?"

**이것이 L1~L3 정답의 정확성을 증명하는 핵심 검증입니다.**

### 4.2 왜 이것이 가능한가

L1~L3 질문의 정답은 **설정 파일 텍스트에서 직접 추출 가능한 값**입니다.

```
pe2.cfg 파일 내용:
  hostname pe2                         ← L1: "pe2"
  ntp server 1.1.1.1                   ← L1: NTP 서버 "1.1.1.1"
  ip ssh version 2                     ← L1: SSH 활성화 여부 "True"
  router bgp 65001                     ← L3: AS 번호 "65001"
    neighbor 10.0.0.1 remote-as 65001  ← L3: iBGP neighbor
```

이 값들은 Batfish 없이도, **단순한 텍스트 파싱(regex 또는 라인 매칭)**으로 추출할 수 있습니다.
독립 파서가 추출한 값과 Batfish(BuilderCore)가 계산한 값이 일치하면,
**두 개의 독립적인 소스가 같은 결론**에 도달한 것이므로 신뢰할 수 있습니다.

### 4.3 검증 대상

L1~L3 전수 (약 900건).

### 4.4 독립 파서의 설계 원칙

1. **Batfish 코드를 일절 사용하지 않는다** — import조차 하지 않음
2. `.cfg` 파일을 직접 읽어서 값을 추출한다
3. 메트릭별로 간단한 regex/텍스트 매칭 규칙을 작성한다
4. 복잡한 메트릭(L3 비교/계산)은 추출한 기본 값들을 조합하여 계산한다

### 4.5 메트릭별 독립 추출 방법 (예시)

```python
"""independent_config_parser.py — Batfish 없이 .cfg에서 직접 값 추출"""

class IndependentConfigParser:
    """
    Cisco IOS 설정 파일(.cfg)에서 메트릭 값을 직접 추출합니다.
    Batfish와 완전히 독립적입니다.
    """

    def parse(self, cfg_text: str, metric: str, scope: dict) -> Any:
        """
        cfg 텍스트에서 metric에 해당하는 값을 추출합니다.

        Examples:
            >>> parser.parse(cfg_text, "system_hostname_text", {"host": "pe2"})
            "pe2"
            >>> parser.parse(cfg_text, "ntp_server_list", {"host": "pe2"})
            ["1.1.1.1", "2.2.2.2"]
        """
        dispatch = {
            "system_hostname_text": self._hostname,
            "ntp_server_list": self._ntp_servers,
            "ssh_enabled": self._ssh_enabled,
            "ospf_router_id": self._ospf_router_id,
            "bgp_asn": self._bgp_asn,
            "bgp_neighbor_list": self._bgp_neighbors,
            "interface_ip_list": self._interface_ips,
            # ... (메트릭별 추출 함수)
        }
        extractor = dispatch.get(metric)
        if extractor is None:
            return None  # 미지원 메트릭 → SKIP
        return extractor(cfg_text)

    def _hostname(self, cfg_text: str) -> str:
        # "hostname pe2" → "pe2"
        match = re.search(r'^hostname\s+(\S+)', cfg_text, re.MULTILINE)
        return match.group(1) if match else None

    def _ntp_servers(self, cfg_text: str) -> list:
        # "ntp server X.X.X.X" → ["X.X.X.X", ...]
        return re.findall(r'^ntp server\s+(\S+)', cfg_text, re.MULTILINE)

    def _ssh_enabled(self, cfg_text: str) -> bool:
        # "ip ssh version 2" 존재 여부
        return bool(re.search(r'^ip ssh version', cfg_text, re.MULTILINE))

    def _bgp_asn(self, cfg_text: str) -> str:
        # "router bgp 65001" → "65001"
        match = re.search(r'^router bgp\s+(\d+)', cfg_text, re.MULTILINE)
        return match.group(1) if match else None

    def _bgp_neighbors(self, cfg_text: str) -> list:
        # "neighbor X.X.X.X remote-as YYYY" → [{"ip": "X.X.X.X", "as": "YYYY"}, ...]
        return re.findall(r'^\s*neighbor\s+(\S+)\s+remote-as\s+(\d+)', cfg_text, re.MULTILINE)
```

### 4.6 L2~L3 집계/비교 메트릭 처리

L1은 단일 장비에서 값을 추출하면 끝이지만,
L2(집계)와 L3(비교/계산)은 **여러 장비의 값을 조합**해야 합니다.

```python
class IndependentAggregator:
    """여러 장비의 파싱 결과를 집계하여 L2/L3 정답을 계산"""

    def __init__(self, all_cfgs: dict):
        """all_cfgs: {"pe1": "cfg텍스트", "pe2": "cfg텍스트", ...}"""
        self.parser = IndependentConfigParser()
        self.all_cfgs = all_cfgs

    def compute(self, metric: str, scope: dict) -> Any:
        # L1 (단일 장비)
        if scope.get("type") == "DEVICE":
            cfg = self.all_cfgs[scope["host"]]
            return self.parser.parse(cfg, metric, scope)

        # L2 (전체 집계)
        if scope.get("type") == "GLOBAL":
            if metric == "ssh_enabled_count":
                return sum(1 for cfg in self.all_cfgs.values()
                           if self.parser._ssh_enabled(cfg))
            if metric == "device_count":
                return len(self.all_cfgs)
            # ...

        # L3 (비교/계산)
        if metric == "bgp_full_mesh_status":
            # 모든 iBGP neighbor 관계를 독립 추출하여 full-mesh 여부 계산
            return self._check_bgp_full_mesh(scope.get("asn"))
```

### 4.7 커버리지 기대치

모든 L1~L3 메트릭에 대해 독립 파서를 작성하는 것은 비현실적입니다.
127개 메트릭 중 **고빈도 메트릭**부터 커버합니다:

| 커버 수준 | 메트릭 수 | QA 수 (추정) | 비고 |
|---|:---:|:---:|---|
| **Tier 1**: hostname, NTP, SSH, BGP, OSPF, interface 기본 | ~30 | ~500건 | 먼저 구현 |
| **Tier 2**: ACL, route-map, prefix-list, VRF | ~20 | ~200건 | 점진 확장 |
| **Tier 3**: 나머지 | ~50 | ~200건 | 미커버 → SKIP 처리 |

**논문 보고 방식**: "L1~L3 중 독립 파서로 커버 가능한 X건에 대해 Y% 일치를 확인하였다.
미커버 메트릭 Z건은 Batfish 고유 기능(데이터 모델 조인 등)에 의존하므로 Layer 0로만 검증하였다."

### 4.8 기대 결과

| 항목 | 목표 |
|---|---|
| 독립 파서 커버리지 | L1~L3 QA의 **70%+** |
| 커버된 QA의 일치율 | **95%+** |
| 불일치 원인 | 정규화 차이 (대소문자, 공백) → 보강 가능 |

### 4.9 불일치 시 의미

| 상황 | 해석 | 대응 |
|---|---|---|
| 독립 파서 = Batfish | 정답 신뢰 가능 | PASS |
| 독립 파서 ≠ Batfish, 독립 파서가 맞음 | Batfish 파싱 오류 | 정답 수정 |
| 독립 파서 ≠ Batfish, Batfish가 맞음 | 독립 파서 regex 한계 | 파서 보강 |
| 양쪽 다 불확실 | 판단 보류 | Limitation 보고 |

---

## 5. Layer 2 — PNETLab 실환경 교차 검증 (L4~L5)

### 5.1 목적

> "Batfish 시뮬레이션 결과가 **실제 라우터의 동작**과 일치하는가?"

Layer 2는 **PNETLab에서 실제 Cisco IOS 라우터 펌웨어를 구동**하고,
실제 `traceroute`/`ping` 명령으로 얻은 결과와 Batfish 정답을 비교합니다.

### 5.2 왜 이것이 독립적인 검증인가

```
Batfish: .cfg 파일을 읽고 네트워크를 "모델링" → 가상 traceroute
PNETLab: .cfg 파일을 실제 Cisco IOS에 적용 → 실제 패킷 포워딩

동일한 입력(.cfg), 완전히 다른 구현
→ 같은 결과가 나오면 독립적으로 확인된 것
```

**"PNETLab 세팅이 틀렸으면?"이라는 반론에 대해:**
PNETLab에 적용하는 `.cfg` 파일은 Batfish에 입력한 것과 **동일한 파일**입니다.
PNETLab은 실제 Cisco IOS 펌웨어를 실행하므로, `.cfg`를 적용하면 실제 라우터와 동일하게 동작합니다.
"세팅이 틀리는" 경우는 `.cfg` 자체가 잘못된 경우뿐이며, 이는 Batfish 입력도 동일하게 잘못된 것입니다.

### 5.3 검증 대상: 50건 (L4 30건 + L5 20건)

**샘플 선정 기준:**
- L4: traceroute_path 질문 중 도달/비도달 비율을 유지하여 30건 층화추출
- L5: link_failure_impact 질문 중 NONE/REROUTED/DISCONNECTED 비율을 유지하여 20건 층화추출

### 5.4 L4 검증 프로세스

```
┌────────────────────────────────────────────────────────────────┐
│ 데이터셋 L4 질문 예시:                                          │
│   Q: "p1에서 10.0.0.1까지의 네트워크 경로를 나열해주세요"         │
│   A: "p1 → p2"                                                 │
│   evidence.scope: {"type":"NODE_PAIR", "src":"p1", "dst":"p2"} │
└────────────────────────────────────────────────────────────────┘
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
                  │ hop 경로 비교   │
                  └────────┬───────┘
                           ▼
                  MATCH / MISMATCH
```

**PNETLab에서 실측하는 방법:**

```bash
# 1. SSH로 source 장비 접속
ssh admin@p1.pnetlab

# 2. traceroute 실행
p1# traceroute 10.0.0.1 source Loopback0

# 3. 출력 파싱
# Type escape sequence to abort.
# Tracing the route to 10.0.0.1
#   1 10.0.12.2 [MPLS: Label 16002] 4 msec
#     ^^^^^^^^^ = p2의 인터페이스 IP
# → 실측 경로: p1 → p2

# 4. Batfish 정답 "p1 → p2"와 비교 → MATCH
```

### 5.5 L5 검증 프로세스

```
┌────────────────────────────────────────────────────────────────┐
│ 데이터셋 L5 질문 예시:                                          │
│   Q: "'leaf1-pe1' 링크 다운 시 'leaf1→leaf3' 트래픽 영향?"      │
│   A: "REROUTED"                                                │
│   evidence.scope: {"type":"LINK_FAILURE", "link":"leaf1-pe1"}  │
└────────────────────────────────────────────────────────────────┘

PNETLab에서의 검증 절차:
  1. 정상 상태: traceroute leaf3_ip → 경로 기록
  2. 장애 주입: interface shutdown (leaf1-pe1 링크)
  3. 수렴 대기: 최소 45초 (OSPF Dead Timer 기반)
  4. 장애 상태: traceroute leaf3_ip → 경로 기록
  5. 비교: 경로 변화 여부 → NONE / REROUTED / DISCONNECTED
  6. 복원: no shutdown → 수렴 대기
```

**수렴 대기 시간**: OSPF Hello=10초, Dead=40초 → **최소 45초** 대기.
직접 연결 링크의 interface down은 즉시 감지되므로 45초면 충분.

### 5.6 기대 결과

| 검증 항목 | 예상 일치율 | 비고 |
|---|:---:|---|
| L4 traceroute 경로 | 90%+ | ECMP 경로 선택 차이 가능 |
| L4 도달성 판정 | 95%+ | 정/부 판정은 안정적 |
| L5 link failure 영향 | 85%+ | 수렴 타이밍 차이 가능 |

### 5.7 불일치 발생 시 처리

| 불일치 유형 | 원인 | 논문에서의 처리 |
|---|---|---|
| ECMP 경로 차이 | Batfish는 첫 번째 경로만 반환 | Limitation 보고 |
| 수렴 타이밍 차이 | 실제 라우터 타이머 vs Batfish 즉시 반영 | Limitation 보고 |
| MPLS/LDP 차이 | Batfish의 MPLS 모델 한계 | Limitation 보고 |

> **원칙**: 불일치를 숨기지 않고, 원인을 분석하여 Limitation에 투명하게 보고합니다.

---

## 6. 구현 파일 구조

```
Make_Dataset/src/
├── verify_dataset.py                  # Layer 0 메인 (Pipeline QA)
│   ├── DatasetVerifier                # 오케스트레이터
│   └── VerificationResult             # 결과 데이터클래스
│
├── core_batfish/
│   ├── verifier.py                    # Layer 0 재계산 로직
│   │   ├── ReproductionEngine         # evidence → 재계산
│   │   └── AnswerComparator           # TA-Acc 비교
│   ├── builder_core.py                # (기존) L1-L3 계산
│   ├── l4_analyzer.py                 # (기존) L4 Batfish 분석
│   ├── l5_analyzer.py                 # (기존) L5 What-If 분석
│   └── models.py                      # (기존) AnswerResult, canonicalize()
│
├── independent_config_parser.py       # Layer 1: 독립 파서 (신규)
│   ├── IndependentConfigParser        # .cfg → 메트릭 값 추출
│   └── IndependentAggregator          # L2/L3 집계
│
├── verify_independent.py              # Layer 1 실행 스크립트 (신규)
│   └── IndependentVerifier            # 독립 파서 vs 데이터셋 비교
│
└── pnetlab_cross_validation.py        # Layer 2: PNETLab 실측 (신규)
    └── PNETLabValidator               # SSH 기반 교차검증
```

---

## 7. 구현 우선순위

| 순위 | 작업 | 파일 | 비고 |
|:---:|---|---|---|
| 1 | Layer 0 검증기 (Pipeline QA) | `verify_dataset.py` + `verifier.py` | 전수 자동화 |
| 2 | Layer 1 독립 파서 (Tier 1 메트릭) | `independent_config_parser.py` | ~30 메트릭, ~500건 |
| 3 | Layer 1 실행 + 보고서 | `verify_independent.py` | 일치율 산출 |
| 4 | Layer 2 PNETLab 스크립트 | `pnetlab_cross_validation.py` | 반자동화 |
| 5 | Layer 2 실행 (50건) | 수동+스크립트 | 논문 핵심 수치 |

---

## 8. 논문 Table 초안

### Table: Dataset Verification Results

| Layer | Method | Target | Scope | Result | Notes |
|:---:|---|---|:---:|---|---|
| 0 | Automated Reproduction | L1~L5 | 1,128건 전수 | X% PASS | Pipeline integrity |
| 1 | Independent Config Parser | L1~L3 | ~X건 | Y% match | Cross-tool validation |
| 2a | PNETLab traceroute | L4 | 30건 | Y% match | Simulation vs. live |
| 2b | PNETLab link failure | L5 | 20건 | Y% match | What-If accuracy |

> Layer 0은 보조 지표로 Appendix에, Layer 1~2는 Section IV에 보고.

---

## 9. 리뷰어 예상 질문과 대비

| 예상 질문 | 우리의 답변 | 근거 |
|---|---|---|
| "Circular reasoning 아닌가?" | "Layer 0만 Batfish를 재사용. Layer 1(독립 파서)과 Layer 2(PNETLab)는 Batfish와 완전히 독립적인 소스다." | 코드 분리 증거 |
| "독립 파서의 정확도는?" | "Cisco IOS 설정 문법은 명확한 구조를 가지므로, regex 기반 추출의 오류율이 매우 낮다. 불일치 시 수동 확인하여 어느 쪽이 맞는지 보고했다." | 불일치 분석 |
| "독립 파서가 모든 메트릭을 커버하지 못하는데?" | "커버 가능한 X건에 대해 Y% 일치를 확인. 미커버 메트릭은 Batfish 고유 기능(데이터모델 조인)에 의존하며, 이는 Batfish의 학술적 검증에 의존한다." | 투명한 한계 명시 |
| "50건 샘플이 충분한가?" | "L4/L5 전체 모수 대비 X%이며, 층화추출로 대표성 확보. 95% CI를 보고한다." | 통계적 근거 |
| "왜 LLM-as-Judge를 안 했나?" | "벤치마크의 목적이 LLM 평가이므로, LLM으로 벤치마크를 검증하는 것은 circular reasoning. 대신 독립 파서와 실환경 검증으로 대체했다." | 논리적 근거 |
