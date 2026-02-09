# NetAlly: Network Management를 위한 Multi-Agent System

> **목적**: 교수님께 보여드릴 Introduction 초안 + SIGCOMM 요약문  
> **작성일**: 2026-01-29

---

## Research Questions (RQ)

| RQ | 질문 |
|----|------|
| **RQ1** | Multi-Agent System이 단일 LLM 대비 복잡한 네트워크 관리 태스크(구성 조회, 검증, 장애 진단)에서 더 높은 정확도와 안정성을 보이는가? |
| **RQ2** | 시뮬레이션 환경(PNETLab)과 운영 도구(NSO, Batfish)를 통합한 하이브리드 아키텍처가 실제 네트워크 검증에 효과적인가? |
| **RQ3** | 체계적인 네트워크 구성 Q&A 벤치마크(NetConfigQA 2.0)가 LLM 기반 네트워크 관리 시스템의 평가에 적합한가? |

---

## Contributions

| # | Contribution |
|---|--------------|
| **C1** | 네트워크 관리에 특화된 Multi-Agent System(NetAlly) 설계 및 구현: Orchestrator-Executor 구조를 통한 역할 분리와 도구 기반 추론 |
| **C2** | PNETLab-NSO-Batfish를 통합한 하이브리드 검증 파이프라인: 시뮬레이션 환경에서의 자동 온보딩과 정형 검증(Formal Verification) 연동 |
| **C3** | NetConfigQA 2.0 벤치마크 데이터셋 구축: 5단계 난이도(L1~L5), 126개 질문 템플릿, 1,300+ QA 쌍으로 구성된 네트워크 구성 Q&A 평가 체계 |

---

## Introduction (한글 초안)

### 1. 배경: LLM에서 Multi-Agent System으로 (1문단)

대규모 언어 모델(LLM)은 자연어 이해와 코드 생성에서 놀라운 성능을 보여주고 있다. 그러나 단일 LLM은 복잡한 다단계 추론, 외부 도구와의 상호작용, 그리고 실시간 환경 정보 반영에서 한계를 드러낸다. 이러한 문제를 해결하기 위해 Multi-Agent System(MAS)이 등장하였으며, 여러 전문화된 에이전트가 협력하여 복잡한 태스크를 분할 정복(divide-and-conquer)하는 패러다임이 주목받고 있다. LangGraph, AutoGPT, CrewAI 등의 프레임워크는 에이전트 간 상태 공유와 도구 호출을 체계화하여 MAS 개발을 가속화하고 있다.

### 2. 네트워크 관리 도메인에서의 LLM 응용 (1문단)

네트워크 관리는 전통적으로 CLI 명령어와 스크립트에 의존하는 전문 영역이다. 최근 Cisco, Juniper 등 주요 벤더들은 LLM을 활용한 자연어 기반 네트워크 운영(ChatOps)을 시도하고 있다. 예를 들어, 운영자가 "BGP 피어 상태를 확인해줘"라고 질문하면 LLM이 적절한 CLI 명령을 생성하거나 API를 호출하여 결과를 반환한다. 학술적으로도 NetConfEval, NIKA 등 LLM의 네트워크 구성 능력을 평가하는 벤치마크와 시스템이 제안되고 있다. 그러나 대부분의 연구는 단일 장비 구성이나 정적 분석에 머물러 있으며, 실제 운영 환경의 동적 특성을 반영하지 못한다.

### 3. 기존 방법들의 한계와 비판 (1문단)

기존 LLM 기반 네트워크 관리 접근법은 세 가지 핵심적인 한계를 가진다. **첫째, 단일 에이전트의 인지 부하 문제**—복잡한 네트워크 토폴로지와 다양한 프로토콜을 하나의 LLM이 모두 처리하기에는 컨텍스트 윈도우와 추론 부담이 과중하다. **둘째, 검증 없는 생성의 위험성**—LLM이 생성한 구성이 실제로 올바른지 확인하는 메커니즘이 부재하여, 환각(hallucination)으로 인한 잘못된 구성이 네트워크 장애를 유발할 수 있다. **셋째, 평가 체계의 부족**—기존 벤치마크는 단순 텍스트 매칭에 의존하거나, 다중 장비 간 상호작용이나 What-If 분석 같은 고급 시나리오를 포함하지 않는다.

### 4. Research Questions (1문단)

본 연구는 위의 한계를 극복하기 위해 다음 세 가지 연구 질문을 설정한다. **RQ1**: Multi-Agent System이 단일 LLM 대비 복잡한 네트워크 관리 태스크에서 더 높은 정확도를 달성할 수 있는가? 우리는 Orchestrator(계획 수립)와 Executor(도구 실행)로 역할을 분리한 2-Agent 구조를 제안한다. **RQ2**: 시뮬레이션 환경과 운영 도구의 통합이 실제 네트워크 검증에 효과적인가? PNETLab에서 토폴로지를 구성하고, NSO를 통해 구성을 관리하며, Batfish로 정형 검증을 수행하는 하이브리드 파이프라인을 설계한다. **RQ3**: 체계적인 벤치마크가 LLM 기반 시스템의 평가에 적합한가? 단순 조회(L1)부터 What-If 분석(L5)까지 5단계 난이도를 포함하는 NetConfigQA 2.0 데이터셋을 구축하여 평가한다.

### 5. 제안 방법: NetAlly Multi-Agent System (1문단)

본 연구에서 제안하는 NetAlly는 네트워크 관리에 특화된 Multi-Agent System이다. 시스템은 두 개의 핵심 에이전트로 구성된다: (1) **Orchestrator**는 사용자의 자연어 질문을 분석하여 필요한 스킬과 도구를 선택하고, (2) **Executor**는 선택된 도구를 실제로 호출하여 네트워크 상태를 조회하거나 검증한다. NetAlly는 세 가지 핵심 도구를 제공한다—`network_query`(NSO를 통한 실시간 구성 조회), `network_verify`(Batfish를 통한 정형 검증 및 What-If 분석), `lab_manage`(PNETLab과의 연동 및 자동 온보딩). 특히 `scan_and_sync` 기능은 시뮬레이션 환경의 장비를 자동으로 NSO에 등록하여, 가상 환경과 운영 도구 간의 간극을 해소한다.

### 6. 평가를 위한 데이터 구축: NetConfigQA 2.0 (1문단)

LLM 기반 네트워크 관리 시스템의 체계적 평가를 위해 NetConfigQA 2.0 벤치마크를 구축하였다. 데이터셋은 5단계 난이도 체계를 따른다: **L1**(단일 장비 조회, 예: "p1의 hostname은?"), **L2**(다중 장비 집계, 예: "SSH가 활성화된 장비 수는?"), **L3**(교차 검증, 예: "iBGP full-mesh가 완성되었는가?"), **L4**(Batfish 도달성 분석, 예: "10.0.0.1에서 192.168.1.1로의 경로는?"), **L5**(What-If 분석, 예: "p1-p2 링크가 끊어지면 어떻게 되는가?"). 총 126개의 질문 템플릿과 10개 장비로 구성된 SP(Service Provider) 토폴로지를 기반으로 1,300개 이상의 QA 쌍을 생성하였다. 각 데이터는 정답뿐 아니라 Batfish 쿼리 파라미터와 검증 로직을 포함하여, 에이전트의 도구 사용 여부까지 평가할 수 있다.

### 7. Contributions (1문단)

본 연구의 기여는 다음과 같다. **첫째**, 네트워크 관리에 특화된 Multi-Agent System인 NetAlly를 설계하고 구현하였다. Orchestrator-Executor 패턴을 통해 복잡한 네트워크 태스크를 효과적으로 분할 처리하며, LangGraph 기반의 상태 관리로 에이전트 간 협업을 체계화한다. **둘째**, PNETLab(시뮬레이션), NSO(구성 관리), Batfish(정형 검증)를 통합한 하이브리드 검증 파이프라인을 제안한다. 특히 `scan_and_sync`를 통한 자동 온보딩과 `fork_snapshot`을 활용한 동적 장애 시뮬레이션은 실용적 가치가 높다. **셋째**, L1~L5 다단계 난이도를 포함하는 NetConfigQA 2.0 벤치마크를 공개하여, 향후 LLM 기반 네트워크 관리 연구의 표준 평가 체계로 활용될 수 있도록 한다.

---

## SIGCOMM 요약문 (Abstract)

### 제목 (영문)

**NetAlly: A Multi-Agent System for Verifiable Network Configuration Management**

### Abstract (영문, 250 words)

Large Language Models (LLMs) have shown remarkable capabilities in natural language understanding and code generation. However, their application to network configuration management faces critical challenges: single-agent systems struggle with complex multi-device reasoning, generated configurations lack formal verification, and existing benchmarks fail to capture operational complexity.

We present **NetAlly**, a Multi-Agent System designed for verifiable network configuration management. NetAlly employs a two-agent architecture: an **Orchestrator** that analyzes natural language queries and selects appropriate skills, and an **Executor** that invokes network management tools to retrieve or verify configurations. The system integrates three key components: (1) **PNETLab** for network simulation and topology management, (2) **Cisco NSO** for configuration retrieval and device lifecycle management, and (3) **Batfish** for formal verification and What-If analysis.

A novel **scan_and_sync** mechanism automatically reconciles simulation environments with operational tools, enabling seamless transition from lab to production. For dynamic fault analysis, NetAlly leverages Batfish's **fork_snapshot** capability to simulate link and node failures without affecting the actual network.

To systematically evaluate LLM-based network management systems, we introduce **NetConfigQA 2.0**, a benchmark comprising 1,300+ question-answer pairs across five difficulty levels: from single-device queries (L1) to What-If impact analysis (L5). Unlike existing benchmarks that rely on text matching, NetConfigQA 2.0 includes verification logic to assess whether agents correctly utilize network tools.

Experimental results demonstrate that NetAlly's multi-agent approach achieves X% higher accuracy on L4-L5 tasks compared to single-agent baselines, while the hybrid verification pipeline successfully detects Y% of configuration inconsistencies that would be missed by LLM-only solutions.

---

## 다음 단계

1. [ ] 교수님 피드백 반영
2. [ ] RQ/Contribution 구체화
3. [ ] 실험 설계 및 결과 추가
4. [ ] SIGCOMM Extended Abstract 형식으로 변환 (2-4 pages)
