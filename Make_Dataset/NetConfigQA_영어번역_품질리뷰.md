# NetConfigQA 영어 번역 품질 리뷰

> 리뷰 대상: `Research_Institute_Internal_DC_dataset_batfish_20260213_205043_en.json` (1,304 문항)

---

## 1. 전체 평가 요약

| 항목 | 평가 |
|------|------|
| **문법적 정확성** | ✅ 양호 — 문법 오류 거의 없음 |
| **질문 자연스러움** | ⚠️ 부분 개선 필요 — 일부 질문이 Batfish 내부 용어 그대로 번역됨 |
| **답변 해석 가능성** | ❌ 주요 이슈 — 질문만 보고는 답변 형태를 예측하기 어려운 경우 다수 |
| **LLM 답변 가능성** | ⚠️ Config 제공 전제 시 L1~L2는 가능, L3~L5는 질문 자체의 모호성 문제 |

---

## 2. 카테고리별 상세 리뷰

### ✅ 양호한 질문 패턴 (L1~L2 다수)

이 유형들은 영어가 자연스럽고, LLM이 config를 보고 답할 수 있음:

```
"What is the system hostname on p4?"                          ← 자연스러움
"What is the SSH version on pe2?"                             ← 자연스러움
"How many interface entries are configured on leaf4?"         ← 자연스러움
"Which devices have SSH enabled?"                             ← 자연스러움
"Which VRF names are configured on p2?"                       ← 자연스러움
"Is RIP enabled on leaf1?"                                    ← 자연스러움
"Which devices belong to OSPF area 0?"                        ← 자연스러움
"How many ACLs are defined on pe1?"                           ← 자연스러움
```

### ⚠️ 개선이 필요한 질문 패턴

---

#### Issue 1: "root cause analysis" — 의미 불일치 (30+ 문항)

```
Q: "What is the root cause analysis from leaf4 to p4?"
A: "pe2"
```

**문제점**: 네트워킹에서 "root cause analysis"는 **장애의 원인을 찾는 것**을 의미합니다. 그런데 여기서 답은 단순히 **경로상의 병목/단일 경유 장비**입니다. 질문에 "장애가 발생했다"는 전제가 없기 때문에, LLM은 "무슨 문제가 있는데 원인이 뭐냐"로 해석할 가능성이 높습니다.

**개선 제안**:
- `"Which device is the single point of failure on the path from leaf4 to p4?"`
- `"What is the critical transit node from leaf4 to p4?"`
- `"If the path from leaf4 to p4 fails, which device is the most likely bottleneck?"`

---

#### Issue 2: "asymmetric path comparison" — 어색한 표현 (10 문항)

```
Q: "What is the asymmetric path comparison between pe2 and pe1?"
A: "Forward: pe2 -> p3 -> p2 -> pe1, Reverse: pe1 -> p2 -> p3 -> pe2"
```

**문제점**: "comparison"이라는 단어가 부자연스럽습니다. 실제로 비교를 요청하는 것이 아니라, 양방향 경로를 나열해달라는 것이기 때문입니다. 또한 답변을 보면 위 예시는 사실 **대칭 경로**(symmetric)인데 질문이 "asymmetric"을 전제합니다.

**개선 제안**:
- `"What are the forward and reverse routing paths between pe2 and pe1?"`
- `"Is the routing path between pe2 and pe1 symmetric or asymmetric? Show both directions."`

**추가 이슈**: 일부 답변에서 단일 노드만 나옴:
```
Q: "What is the asymmetric path comparison between leaf1 and p1?"
A: "Forward: leaf1 -> pe1, Reverse: p1"
```
"Reverse: p1"은 **경로가 p1에서 끝난다(직접 연결)**는 의미인지, **p1이 도달 불가**라는 의미인지 모호합니다.

---

#### Issue 3: "BGP neighbor comparison" / "interface comparison" — 질문이 모호 (40+ 문항)

```
Q: "What is the BGP neighbor comparison between leaf2 and leaf3?"
A: {"difference": 0, "host1_count": 0, "host2_count": 0}
```

**문제점**: "comparison"만으로는 무엇을 비교하라는 건지 불명확합니다. 답이 JSON {difference, host1_count, host2_count}인데, 질문에서 이 구조를 유추할 수 없습니다.

**개선 제안**:
- `"Compare the number of BGP neighbors between leaf2 and leaf3."`
- `"How many BGP neighbors does each of leaf2 and leaf3 have, and what is the difference?"`

---

#### Issue 4: "What is the config change impact from leaf1 to p3?" — 맥락 부재

```
Q: "What is the config change impact from leaf1 to p3?"
A: "CHANGED (25 entries: 10.10.1.1 -> 10.10.10.32, ...)"
```

**문제점**: **어떤 config 변경**이 이루어졌는지 질문에 전혀 언급이 없습니다. Batfish의 differential analysis 기능을 직역한 것으로 보이나, 질문만 보면 "무슨 변경?"이라는 반응이 자연스럽습니다.

**개선 제안**:
- `"After modifying the configuration of leaf1, how does the routing path to p3 change?"`
- 또는 질문에 변경 시나리오를 명시: `"If leaf1's loopback IP is changed to 10.10.10.32, what is the impact on routes to p3?"`

---

#### Issue 5: "What is the differential reachability from leaf1 to p3?" — Batfish 전문 용어

```
Q: "What is the differential reachability from leaf1 to p3?"
A: "NO_DIFF"
```

**문제점**: "Differential reachability"는 Batfish 고유 용어입니다. 일반 네트워크 엔지니어도 바로 이해하기 어려우며, LLM은 더더욱 맥락 없이는 해석이 어렵습니다.

**개선 제안**:
- `"Does reachability from leaf1 to p3 change between the base and modified configurations?"`

---

#### Issue 6: "What is the triple node failure for nodes leaf1, leaf2, and leaf3?" — 답변 해석 불가

```
Q: "What is the triple node failure for nodes leaf1, leaf2, and leaf3?"
A: "NO (affected_flows: 15)"
```

**문제점**: "NO"가 무엇을 의미하는지 불명확합니다. "네트워크가 완전히 단절되지 않는다"? "장애가 발생하지 않는다"? `affected_flows: 15`와 "NO"의 관계도 모호합니다.

**개선 제안**:
- `"If nodes leaf1, leaf2, and leaf3 all fail simultaneously, is the network fully disconnected? How many flows are affected?"`
- 답변 형태도 개선: `"NOT_FULLY_DISCONNECTED (affected_flows: 15)"` 또는 JSON 구조화

---

#### Issue 7: "What is the worst case failure analysis?" — 너무 모호

```
Q: "What is the worst case failure analysis?"
A: "p2(19)"
```

**문제점**: 질문이 너무 넓고, 답변 "p2(19)"는 맥락 없이는 의미 파악이 불가합니다.

**개선 제안**:
- `"Which single device failure would disrupt the most traffic flows, and how many flows would be affected?"`

---

#### Issue 8: "What is the loop detection?" — 문법적으로 어색

```
Q: "What is the loop detection?"
A: "NONE"
```

**문제점**: "What is the loop detection?"은 영어로 부자연스럽습니다. "Loop detection이 뭐냐"가 아니라 "루프가 있느냐"를 묻는 것이므로:

**개선 제안**:
- `"Are there any routing loops detected in the network?"`

---

#### Issue 9: "What is the redundancy verification between pe1 and pe2?" — 모호

```
Q: "What is the redundancy verification between pe1 and pe2?"
```

**문제점**: "verification"의 결과가 무엇인지 질문에서 유추 불가. Pass/Fail? 경로 목록?

**개선 제안**:
- `"Is there a redundant path between pe1 and pe2? If so, what are the alternative routes?"`

---

#### Issue 10: 답변 형식 이슈 — "redundant paths"

```
Q: "What are the redundant paths from leaf1 to 10.0.0.3?"
A: ["leaf1 → pe1", "leaf1"]
```

**문제점**: `"leaf1"`이 단독으로 경로로 나열됨. 이것이 "leaf1에서 직접 도달"이라는 뜻인지, 아니면 불완전한 데이터인지 모호합니다.

---

## 3. LLM 답변 가능성 평가

### Config를 context로 제공하는 경우

| Level | LLM 답변 가능성 | 비고 |
|-------|:---:|------|
| **L1** | 🟢 높음 | 단순 조회, config만 읽으면 답변 가능 |
| **L2** | 🟢 높음 | 집계 질문, 다소 추론 필요하나 가능 |
| **L3** | 🟡 중간 | 질문의 모호성 때문에 정답 형태를 맞추기 어려움 |
| **L4** | 🟡 중간 | Traceroute 시뮬레이션 필요 — config만으로는 어려움 |
| **L5** | 🔴 낮음 | What-If 시나리오는 Batfish 수준 시뮬레이션 필요 |

### Config 없이 질문만 제공하는 경우

모든 레벨에서 **답변 불가**. 이 데이터셋은 반드시 config 파일과 함께 제공되어야 합니다.

### 핵심 우려사항

1. **L3~L5의 질문 모호성**: 질문만 보고 어떤 형태의 답이 기대되는지 파악하기 어려운 경우가 많음. `[Answer format: ...]` 힌트가 있지만, 답변의 의미적 구조(예: "NO (affected_flows: 15)")까지는 안내하지 않음.

2. **Batfish 내부 용어 직역**: "differential reachability", "config change impact", "redundancy verification" 등은 Batfish API 이름을 그대로 번역한 느낌. 일반적인 네트워크 QA 벤치마크로 쓰려면 자연어로 풀어써야 함.

3. **답변 값의 해석**: `"pe2"`, `"NO_DIFF"`, `"ALLOWED"`, `"p2(19)"` 같은 약축형 답변은 채점 기준으로는 좋지만, LLM이 **이 형태로 답변하도록 유도**하려면 질문에 예시를 포함하거나 프롬프트에서 답변 형식을 더 명확히 지정해야 합니다.

---

## 4. 종합 개선 권고

| 우선순위 | 개선 항목 | 영향 범위 |
|:---:|------|---:|
| 🔴 **1** | "root cause analysis" 질문 재작성 — 의미 불일치 가장 심각 | ~30 문항 |
| 🔴 **2** | "triple node failure", "worst case failure" 답변 구조 명확화 | ~5 문항 |
| 🟡 **3** | "comparison" 질문들에 비교 대상/기준 명시 | ~100 문항 |
| 🟡 **4** | Batfish 전문 용어를 자연어로 풀어쓰기 | ~20 문항 |
| 🟢 **5** | "loop detection" 등 문법 개선 | ~5 문항 |
| 🟢 **6** | 답변 형식에 대한 가이드를 질문에 추가 (특히 L5) | 전체 |

**전체 1,304문항 중 약 70% (L1~L2 위주)는 영어 품질이 양호**합니다. 나머지 30%는 위 이슈들이 해당되며, 특히 L3~L5 고난도 질문에 집중되어 있습니다.
