# NetAlly 검증 대시보드 기획 (Verification Dashboard Design)

## 1. 개요 (Overview)
기존의 복잡한 전체 토폴로지 맵(Spider-web) 대신, 네트워크 엔지니어가 실시간으로 가장 필요로 하는 **'네트워크 건강 상태'**와 **'분석된 인사이트'**를 한눈에 제공하는 대시보드로 전환합니다.

- **핵심 철학**: "Insight over Data" (단순 나열이 아닌 판단된 정보 제공)
- **주요 타겟**: PNETLab 등을 사용하며 설정을 검증하고 트러블슈팅하려는 엔지니어

---

## 2. 주요 기능 및 화면 구성

### A. 종합 상황판 (Status Cards)
- **전체 기기 상태**: 🟢/🔴 표시
- **프로토콜 상태**:
  - **BGP**: 연결된 세션 수 / 끊긴 세션 수
  - **OSPF**: 정상(Full) 세션 수 / 비정상 세션 수
- **설정 준수 (Compliance)**: 보안 정책, 기본 설정 가이드라인 준수 여부

### B. 인사이트 피드 (Active Insights Feed)
단순 로그가 아닌, Batfish 분석 결과를 인간이 읽기 쉬운 형태로 변환하여 제공합니다.
- **Critical (🔴)**: BGP/OSPF Down, Router ID 중복, Link Down
- **Warning (🟡)**: MTU 불일치, Hello Timer 불일치, NTP 미설정

### C. 스마트 기기 목록 (Smart Device List)
- 기기 이름 옆에 상태 아이콘 표시
- 클릭 시 상세 정보(인터페이스, 라우팅 테이블 등)로 연결

---

## 3. 인사이트 생성 전략 (Insight Strategy)

NetAlly는 **하이브리드 엔진**을 사용하여 인사이트를 생성합니다.

1. **결정론적 규칙 분석 (Batfish)**
   - 성능과 정확도를 위해 대시보드 상태값은 Batfish의 Query 결과를 직접 파싱하여 생성합니다.
   - 예: `bf.q.ospfSessionCompatibility()` 결과에서 불일치(Mismatch)가 발견되면 즉시 인사이트로 등록.

2. **생성형 AI 분석 (LLM)**
   - 사용자가 구체적인 해결책을 물어보거나 ("이거 어떻게 고쳐?"), 복잡한 설정 간의 논리적 오류를 해석할 때 에이전트가 개입합니다.

---

## 4. PNETLab 연동 및 시나리오
- 엔지니어는 PNETLab에서 설정을 변경합니다.
- NetAlly는 이를 감지(또는 명시적 체크)하여 위 대시보드에 실시간으로 반영합니다.
- **Topology Map**: 전체 맵은 필요한 경우(On-Demand)에만 팝업 등으로 호출하여 노이즈를 최소화합니다.
