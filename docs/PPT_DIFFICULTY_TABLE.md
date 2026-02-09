# 📊 NetConfigQA 5단계 난이도 체계 (Simple Version)

> 발표 자료에 바로 사용할 수 있도록 **문항 수를 제거**하고 **핵심 키워드 위주**로 간소화했습니다.

---

## [Option 1] 핵심 가치 중심 (Best for Slide)
> 가장 직관적이고 깔끔한 형태입니다.

| Level | 속성 | 설명 | 평가 요소 | 핵심 키워드 |
|:---:|:---|:---|:---|:---|
| **L1** | **Fact** | 장비에 있는 그대로 무엇이 적혀있는가? | Config 파싱 | Hostname, IP, NTP |
| **L2** | **Stats** | 네트워크 전체 통계는 어떠한가? | 정보 수집/집계 | "몇 개?", "목록" |
| **L3** | **Logic** | 설정 간에 오류가 없는가? | 관계 비교/분석 | iBGP, VRF, L2VPN |
| **L4** | **Flow** | 패킷을 보내면 실제로 도착하는가? | 경로 시뮬레이션 | Traceroute, Loop |
| **L5** | **Impact** | 장애가 나면 어떻게 되는가? | 장애 영향 예측 | Link Failure |




---

## [Option 2] 인지 활동 중심 (Action Oriented)
> AI가 수행해야 하는 '행동'에 초점을 맞춘 버전입니다.

| Level | 인지 단계 (Cognitive Level) | 비유 (Analogy) |
|:---:|:---|:---|
| **L1** | **Extraction** (단순 추출) | 매뉴얼 읽기 (Manual Lookup) |
| **L2** | **Aggregation** (통계/집계) |  재고 조사 (Inventory Check) |
| **L3** | **Consistency** (비교/대조) |  논리 오류 찾기 (Consistency Check) |
| **L4** | **Simulation** (시뮬레이션) |  뇌내 주행 (Mental Simulation) |
| **L5** | **Reasoning** (인과 추론) |  미래 예측 (Prediction / What-If) |

---

## [Option 3] 이분법적 분류 (Simplest)
> 5단계를 **정적(Static) vs 동적(Dynamic)** 두 그룹으로 단순화하여 보여줍니다.

| Group | Levels | 핵심 활동 (Key Activity) | 설명 (Description) |
|:---|:---:|:---|:---|
| **Static Analysis**<br>(정적 분석) | **L1 ~ L3** | **Verification**<br>(검증) | 설정 파일(Text)에 적힌 규칙과 값이<br>**있는 그대로** 맞는지 확인합니다. |
| **Dynamic Reasoning**<br>(동적 추론) | **L4 ~ L5** | **Simulation**<br>(시뮬레이션) | 텍스트 너머의 **실제 동작(패킷 흐름)**과<br>**미래의 장애**를 예측합니다. |

---

## [Option 4] 레벨별 Q&A 예시 (Concrete Examples)
> 각 레벨에서 **어떤 종류의 질문**이 나오는지 구체적으로 보여줍니다.

| Level | 질문 예시 (Question) | 정답 예시 (Answer) | 핵심 포인트 |
|:---:|:---|:---|:---|
| **L1** | PE1의 호스트네임은 무엇입니까? | `pe1` | 1개 장비, 1개 값 |
| **L2** | SSH가 활성화된 장비는 총 몇 대입니까? | `8` | 전체 장비 수 세기 |
| **L3** | iBGP Full-Mesh가 올바르게 구성되어 있습니까? | `No` (PE2-PE3 누락) | A↔B 관계 비교 |
| **L4** | 10.0.0.1 → 10.0.3.1 도달이 가능합니까? | `Yes` (경로: PE1→P1→PE3) | 패킷 경로 추적 |
| **L5** | PE1-P1 링크 장애 시 10.0.0.1 → 10.0.3.1은? | `Yes` (우회: PE1→P2→PE3) | 장애 시뮬레이션 |

---

## [Option 5] 인지적 부하 단계별 (Bloom's Inspired)
> Bloom's Taxonomy 스타일로 **인지적 사고 단계**를 직관적으로 보여줍니다.

| Level | 인지 단계 | 핵심 질문 | AI에게 요구하는 것 |
|:---:|:---|:---|:---|
| **L1** | 🔍 **기억 (Remember)** | "X가 뭐야?" | 설정 파일에서 **값을 찾아라** |
| **L2** | 📊 **이해 (Understand)** | "전체가 어떻게 돼?" | 여러 장비 정보를 **요약하라** |
| **L3** | ⚖️ **분석 (Analyze)** | "A와 B가 같아?" | 설정 간 **차이를 비교하라** |
| **L4** | 🧪 **적용 (Apply)** | "이러면 어떻게 돼?" | 규칙을 적용해서 **결과를 예측하라** |
| **L5** | 💡 **평가 (Evaluate)** | "만약 X가 바뀌면?" | 가상 상황에서 **영향을 판단하라** |
