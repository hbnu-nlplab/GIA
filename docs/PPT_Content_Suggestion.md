# NetConfigQA: 답변 생성 로직 (Answer Generation Logic)

사용자 요청에 따라 **"정답 생성 로직"**을 중점적으로 설명하는 슬라이드 구성안입니다. 청중이 직관적으로 이해할 수 있도록 **"Dual-Engine (이원화 엔진)"** 컨셉으로 설명을 구성하는 것을 추천합니다.

---

## 핵심 컨셉: Dual-Engine Strategy
**"질문의 성격에 따라 가장 효율적이고 정확한 엔진을 선택하여 정답을 생성합니다."**

1.  **Static Engine (정적 분석기)**: 팩트(Fact) 매칭. 빠르고 정확함. "설정이 되어 있는가?"
2.  **Dynamic Engine (동적 시뮬레이터)**: Batfish 시뮬레이션. 실제 동작 검증. "통신이 되는가?"

---

## 슬라이드 구성안 (3장 추천)

### 슬라이드 1: 정적 분석 엔진 (Static Analysis Engine)
**목표**: L1~L3 수준의 설정값 확인 및 집계 로직 설명

*   **제목**: Static Engine: Fact-Based Lookup (L1-L3)
*   **주요 내용**:
    *   **작동 원리**: 파싱된 JSON 데이터(Facts)에서 정답을 직접 조회하거나 계산.
    *   **사용 예시**: Inventory, 설정 일관성 검사.
*   **시각화 (Diagram Concept)**:
    ```mermaid
    graph LR
        Q["질문: 'R1의 인터페이스 개수는?'"] -->|"Logic: count(interfaces)"| E[Static Engine]
        E -->|"Lookup JSON"| DB[(Facts DB)]
        DB -->|"Return: 'Gig0/0, Loop0...'"| E
        E -->|"Count"| A["정답: 2개"]
    ```
*   **발표 스크립트 예시**:
    > "첫 번째는 정적 분석 엔진입니다. 질문이 '장비의 버전은?', '인터페이스 개수는?'과 같이 명확한 설정값을 요구할 때는 시뮬레이션을 돌릴 필요 없이, 미리 파싱해둔 JSON 데이터(Facts)에서 즉시 조회합니다. `BuilderCore` 클래스가 이 역할을 하며, 단순 조회뿐만 아니라 집계(`count`), 비교(`compare`) 로직도 수행하여 빠르고 정확하게 정답을 만들어냅니다."

---

### 슬라이드 2: 동적 시뮬레이션 엔진 (Dynamic Simulation Engine)
**목표**: L4~L6 수준의 복잡한 네트워크 행위(Behavior) 분석 설명 (실제 데이터 예시 포함)

*   **제목**: Dynamic Engine: Batfish Simulation (L4-L6)
*   **주요 내용**:
    *   **작동 원리**: 장비 설정을 분석하여 **Data Plane(FIB, ACL)**을 수학적으로 모델링하고, 패킷의 흐름을 **논리적으로 시뮬레이션**. (실제 패킷 전송 X)
    *   **사용 예시**: Traceroute, Reachability(도달성), Loop 탐지.
*   **시각화 (Diagram Concept)**:
    ```mermaid
    graph LR
        Q["질문: 'pe1에서 10.0.0.3까지의 경로는?'"] -->|"Logic: traceroute()"| S[Dynamic Engine]
        S -->|"Simulate Packet"| B[Batfish]
        B -->|"Result: pe1 -> p2 -> p3"| S
        S -->|"Formatting"| A["정답: 'pe1 → p2 → p3'"]
    ```
*   **실제 생성 데이터 (Example Output)**:
    ```json
    {
      "id": "TRACEROUTE_pe1_p3",
      "category": "Reachability_Analysis",
      "level": "L4",
      "question": "pe1에서 10.0.0.3까지의 네트워크 경로(장비 순서)를 나열해주세요...",
      "answer": "\"pe1 → p2 → p3\"",
      "evidence": "{\"metric\": \"traceroute_path\", \"snapshot\": \"configs\"}"
    }
    ```
*   **발표 스크립트 예시**:
    > "두 번째는 이 프로젝트의 핵심인 동적 시뮬레이션 엔진입니다. Batfish는 실제 GNS3처럼 장비를 켜는 것이 아니라, **설정 파일(Config)**을 분석하여 장비의 라우팅 테이블과 ACL 동작을 수학적으로 계산(모델링)합니다. 예를 들어 'pe1에서 10.0.0.3으로 패킷을 보내면 논리적으로 어떻게 처리되는가?'를 시뮬레이션하여, 실제 네트워크와 99% 동일한 경로('pe1 → p2 → p3') 결과를 산출해냅니다."

---

### 슬라이드 3: What-If 장애 분석 (Advanced Logic)
**목표**: 단순 상태 확인을 넘어선 고차원적 추론(L5-L6) 능력 강조

*   **제목**: Advanced Logic: What-If & Fault Injection
*   **주요 내용**:
    *   **작동 원리 (Fork & Diff)**: 현재 상태(Snapshot A)와 장애 상태(Snapshot B)를 생성하여 비교 분석.
    *   **사용 예시**: 링크 장애 시뮬레이션, SPOF(단일 장애점) 탐지.
*   **코드 로직 예시 (Pseudo Code)**:
    ```python
    # 링크 장애 시 영향 분석 로직
    def solve_link_failure(link):
        base_result = simulate(snapshot_base)      # 1. 정상 상태 시뮬레이션
        fail_result = simulate(kill_link(link))    # 2. 링크를 끊고 시뮬레이션
        
        if base_result == OK and fail_result == FAIL:
            return "DISCONNECTED" (단절됨)
        else:
            return "REROUTED" (우회 경로로 연결됨)
    ```
*   **발표 스크립트 예시**:
    > "더 나아가, 이 엔진은 '만약 ~라면?'(What-If) 질문에도 대답할 수 있습니다. 예를 들어 '메인 링크가 끊어지면 어떻게 되는가?'라는 질문을 받으면, 엔진은 내부적으로 평행 우주를 만듭니다. 정상 적인 네트워크와 링크를 강제로 끊은 네트워크를 동시에 시뮬레이션하고, 두 결과의 차이(Differential Analysis)를 분석하여 '우회 경로로 자동 복구됩니다' 또는 '서비스가 전면 중단됩니다'와 같은 수준 높은 정답을 도출해냅니다."
