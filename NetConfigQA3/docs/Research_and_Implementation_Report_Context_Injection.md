# 네트워크 에이전트 초기 컨텍스트 주입 (Context Injection) 연구 및 구현 보고서

**작성일**: 2026-01-14
**작성자**: Antigravity Pair Programmer
**대상**: 프로젝트 팀 및 이해관계자

---

## 1. 개요 (Executive Summary)

본 문서는 NetConfigQA3 에이전트의 효율성을 극대화하기 위해 수행한 **"초기 컨텍스트 주입(Context Injection)"** 기능의 연구 및 구현 과정을 기술합니다. 

기존 에이전트는 대화가 시작될 때 네트워크 상태에 대한 정보가 전혀 없는 "백지(Cold Start)" 상태였습니다. 이로 인해 사용자의 요청을 처리하기 전에 불필요한 탐색(Discovery) 도구를 호출해야 하는 비효율이 존재했습니다. 이를 해결하기 위해 최신 연구 논문(NIKA, Confucius)을 분석하고, **Topology Context Injection** 기법을 적용하여 에이전트가 "준비된 상태(Warm Start)"로 시작할 수 있도록 개선하였습니다.

---

## 2. 배경 및 문제 의식

### 2.1 기존 문제점
- **Cold Start 문제**: 에이전트 초기화 시 네트워크 구성(장비 목록, 토폴로지 등)에 대한 정보가 부재함.
- **불필요한 오버헤드**: "BGP 상태 확인해줘"라는 단순 요청에도 에이전트는 "어떤 장비가 있는지 먼저 확인하겠습니다"라며 `scan_network_devices` 툴을 호출하는 등 불필요한 턴 소모 발생.
- **사용자 경험 저하**: 즉각적인 문제 해결보다 탐색에 시간을 소모하여 응답 속도 저하.

### 2.2 목표
- 최신 논문 및 프레임워크 벤치마킹을 통한 효율적인 컨텍스트 관리 방안 도출.
- 에이전트 초기화 시점에 필수 네트워크 정보를 사전에 주입하여 탐색 단계를 최소화.

---

## 3. 선행 기술 조사 (Research)

에이전트 효율화를 위해 두 가지 주요 네트워크 에이전트 프레임워크를 조사하였습니다.

### 3.1 NIKA (A Network Arena for Benchmarking AI Agents)
- **개요**: 네트워크 트러블슈팅 에이전트를 위한 벤치마크 프레임워크.
- **컨텍스트 처리 방식**:
    - **Active Retrieval (능동적 탐색)**: 에이전트에게 `get_reachability`, `get_host_net_config` 등의 MCP 도구를 제공하고, 에이전트가 필요할 때 스스로 정보를 조회하도록 함.
    - **특징**: 다양한 시나리오 파일(Kathará lab.py)을 통해 네트워크 환경을 정의하지만, 에이전트 자체에 프리로딩(Pre-loading)된 정보보다는 도구 활용 능력에 의존함.
- **시사점**: 도구 기반의 탐색은 유연하지만, 초기 정보가 없을 경우 턴 소모가 많음.

### 3.2 Confucius (Network Management Framework)
- **개요**: Meta에서 개발한 복잡한 네트워크 관리를 위한 멀티 에이전트 프레임워크.
- **컨텍스트 처리 방식**:
    - **RAG (Retrieval-Augmented Generation)**: 방대한 네트워크 설정 및 지식 문서를 벡터 DB에 저장하고, 필요한 정보만 검색하여 프롬프트에 주입.
    - **Task Decomposition (DAG)**: 복잡한 작업을 방향성 비순환 그래프(DAG)로 분해하여 각 에이전트가 국소적인 컨텍스트만 다루도록 최적화.
- **시사점**: RAG는 대규모 네트워크에 적합하나, PNETLab과 같은 실험실 환경에서는 전체 토폴로지 요약을 주입하는 것만으로도 충분한 효과를 볼 수 있음.

### 3.3 결론: 하이브리드 접근 (Context Injection)
우리 프로젝트의 규모와 특성(PNETLab/NSO 연동)을 고려할 때, **Confucius의 "정보 주입" 개념을 경량화**하여 적용하기로 결정했습니다.
- **전략**: 에이전트 `initialize` 시점에 PNETLab에서 토폴로지 정보를 **한 번만 조회**하여 요약(Summary) 텍스트를 생성하고, 이를 시스템 프롬프트에 **고정값(Constant Context)**으로 주입합니다.

---

## 4. 구현 내용 (Implementation)

### 4.1 핵심 변경 사항 (`agent/core.py`)

1.  **`_fetch_topology_context` 메서드 추가**:
    - PNETLab API를 호출하여 현재 세션의 토폴로지(노드 목록, 장비 타입 등)를 조회합니다.
    - LLM이 이해하기 쉬운 자연어 요약본으로 변환합니다.
    ```text
    (예시)
    총 장비 수: 5대
    - PE1 (router)
    - PE2 (router)
    - SW1 (switch)
    ...
    ```

2.  **`initialize` 프로세스 개선**:
    - 에이전트 구동 시 `_fetch_topology_context`를 실행하여 정보를 메모리에 로드합니다.
    - 이 과정은 사용자 대화 시작 전에 백그라운드에서 수행되므로, 첫 대화 시점에는 이미 정보가 준비됩니다.

3.  **Prompt Engineering**:
    - 시스템 프롬프트(`SYSTEM_PROMPT`)에 `{context}` 플레이스홀더를 추가했습니다.
    - `chat` 메서드 호출 시마다 최신화된(혹은 초기에 로드된) 토폴로지 정보를 프롬프트에 동적으로 삽입합니다.

### 4.2 코드 변경 요약

```python
# agent/core.py (발췌)

SYSTEM_PROMPT = """
...
## 현재 네트워크 상태 (Context)
{context}
"""

class NetworkAgent:
    def initialize(self):
        # ...
        self.topology_context = self._fetch_topology_context()
        # ...

    def chat(self, message):
        # ...
        formatted_system_prompt = SYSTEM_PROMPT.format(context=self.topology_context)
        # ...
```

---

## 5. 결과 및 효과

### 5.1 검증 테스트 (`test_with_langsmith.py`)
- **테스트 결과**: 에이전트 초기화 로그에서 컨텍스트 로딩 성공 확인.
    ```
    [1] 에이전트 초기화...
    ⏳ 초기 네트워크 컨텍스트 로딩 중...
    ✅ 에이전트 초기화 성공
    ```
- **LangSmith 트레이싱**: 첫 번째 프롬프트에 이미 장비 목록이 포함되어 전송됨을 확인.

### 5.2 기대 효과
1.  **효율성 증대**: "장비 목록 줘"라는 질문에 대해 Tool Call 없이 즉답 가능.
2.  **비용 절감**: 불필요한 Tool 호출 및 LLM 턴 감소로 토큰 비용 절감.
3.  **지능적 추론**: "PE1에 문제가 있어"라고 했을 때, PE1이 라우터인지 스위치인지 이미 알고 있으므로 더 적절한 도구(라우팅 테이블 조회 vs MAC 테이블 조회)를 선택할 확률 증가.

---

## 6. 향후 계획

- **동적 컨텍스트 업데이트**: 현재는 초기화 시점에만 스냅샷을 찍지만, 향후에는 주기적으로 혹은 특정 이벤트 발생 시 컨텍스트를 갱신하도록 고도화.
- **상세 정보 주입**: 장비 목록뿐만 아니라 주요 인터페이스 IP나 라우팅 프로토콜 현황 등 "핵심 요약" 정보를 확장하여 주입.

---
*문서 끝.*
