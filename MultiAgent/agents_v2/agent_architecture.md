🚀 NetAgent: 5-Stage Multi-Agent System for Network Operations
NetAgent는 네트워크 환경에서 발생하는 설정 오류와 장애를 진단하기 위해 설계된 **5단계 다중 에이전트 프레임워크(5-Stage Multi-Agent Framework)**입니다.

기존 LLM이 방대한 네트워크 설정을 한 번에 처리할 때 발생하는 '환각(Hallucination)'과 '문맥 누수(Context Leakage)'를 원천 차단하기 위해, 단일 모델(Single Model) 기반의 엄격한 패시지(Passage) 생성 파이프라인과 Debate 2 (찬반 토론) 메커니즘을 결합하여 인간 엔지니어 수준의 신뢰성을 확보합니다.

👥 Core Agent Roles (5 에이전트 역할 구성)
NetAgent는 명확히 분리된 5개의 에이전트로 구성됩니다. 실험의 통제와 일관성을 위해 전체 시스템은 단일 LLM 백본(All-Local 또는 All-API) 위에서 구동되며, 각 에이전트는 독립된 시스템 프롬프트를 통해 자신의 역할만을 수행합니다.

1️⃣ Agent 1: Information Extractor (정보 추출 에이전트)
시스템의 첫 관문으로, 사용자의 질의를 분석하여 원시 데이터(Raw Data)를 수집합니다.

Our Dataset (동적 환경): MCP(Model Context Protocol) 툴을 능동적으로 호출하여 필요한 장비의 전체 설정이나 상태 정보를 Fetch 합니다.

Other Benchmarks (정적 환경): 툴 사용 없이, 데이터셋이 제공하는 전체 긴 Context 문서를 읽어들입니다.

2️⃣ Agent 2: Passage Generator (패시지 생성 에이전트)
가장 중요한 환각 방어선입니다. Agent 1이 수집한 방대한 원시 데이터에서 노이즈를 제거하고, 정답 도출에 결정적인 **10~20줄의 고순도 패시지(Passage)**만을 엄격하게 추출/생성합니다.

3️⃣ Agent 3: Answer Deriver (초기 정답 도출 에이전트)
Agent 2가 전달한 '정제된 패시지'만을 기반으로 네트워크 상태를 분석하여 논리적인 초기 결론(Candidate Answer)을 도출합니다. 전체 문맥을 보지 않기 때문에 문맥 누수(Context Leakage)가 발생하지 않습니다.

4️⃣ Agent 4: Proponent (Debate 2 - 찬성 측 에이전트)
이후 진행되는 Debate 2 토론 단계에서 찬성 및 방어(Advocate) 역할을 맡습니다. Agent 3이 도출한 초기 정답의 논리를 강화하고, 상대측의 공격에 맞서 정답의 타당성을 증명합니다.

5️⃣ Agent 5: Critic (Debate 2 - 비판 측 에이전트)
시스템 내에서 의도적인 회의론자(Skeptic) 역할을 수행합니다. Agent 3의 정답과 Agent 4의 논리에 네트워크 프로토콜 위배(예: BGP AS 불일치 등)나 논리적 비약이 없는지 비판(Critique)하고 반박 논거를 제시합니다.

🔄 Multi-Agent Workflow: The "Debate 2" Process
NetAgent의 문제 해결 과정은 단방향 출력이 아닌, 정보 정제부터 치열한 찬반 토론으로 이어지는 5단계 파이프라인을 따릅니다.

📍 Step 1: Raw Information Extraction (원시 정보 추출)
Agent 1이 질의를 분석하고 환경(동적/정적)에 맞춰 원시 네트워크 데이터를 수집하여 전달합니다.

📍 Step 2: Strict Context Scoping (패시지 생성)
Agent 2가 원시 데이터를 필터링하여 오직 답변에 필요한 '핵심 Passage'만 생성합니다. 다른 장비의 무관한 설정은 이 단계에서 모두 버려집니다.

📍 Step 3: Initial Answer Generation (초기 정답 생성)
Agent 3이 고순도 Passage를 분석하여 "장애 원인은 OSPF Area 불일치이다"와 같은 초기 정답(Draft)을 도출합니다.

📍 Step 4: Debate 2 - The Pro/Con Clash (핵심 찬반 토론) 🔥
시스템의 신뢰성을 극대화하는 Debate 2 단계가 시작됩니다.

Con (공격): Agent 5 (Critic)가 "Passage를 보면 OSPF Area는 일치한다. 문제는 인터페이스 Down이다"라며 논리적 허점을 찌릅니다.

Pro (방어/수정): Agent 4 (Proponent)는 비판을 분석하여 "네 말이 맞다. 인터페이스 상태를 간과했다"라며 논리를 수정하거나, "아니다, 가상 링크가 설정되어 있어 Area 0과 연결된다"라며 방어합니다.

피드백 루프: 두 에이전트가 주어진 Passage만으로 결론을 내지 못하면, 파이프라인 앞단(Agent 1, 2)에 추가 정보 탐색을 요청합니다.

📍 Step 5: Consensus & Final Output (합의 및 최종 정답 도출)
Agent 4와 5가 오류 없음에 합의(Consensus)하거나 지정된 토론 턴(Max Turns)이 종료되면, 가장 논리적으로 완벽하게 검증된 **최종 정답(Final Answer)**을 출력합니다.

⚙️ Experimental Setup (실험 환경 세팅)
본 연구는 통제된 실험을 위해 모델을 섞어 쓰지 않고, 5개의 에이전트 파이프라인 전체를 단일 체급의 모델로 고정하여 두 가지 세팅으로 비교 평가합니다.

Setup A (All-Local Mode): Agent 1~5 모두 vLLM (AWQ 4bit) 기반의 로컬 모델 하나만 사용하여 구동. (비용 0, 프라이버시 유지, 빠른 처리 속도 입증 목적)

Setup B (All-API Mode): Agent 1~5 모두 OpenRouter (GLM-4.7-flash) 외부 API 하나만 사용하여 구동. (최고 수준의 논리 추론 및 Debate 2 성능 확인 목적)