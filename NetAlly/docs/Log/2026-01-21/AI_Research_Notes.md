---
type: ai-research-notes
date: 2026-01-21
project: LabMate
tags: [research, ai]
---
# AI 연구 노트 — 2026-01-21

## LabMate: Agentic 네트워크 관리를 위한 Self-Driving Network Onboarding

### 문제 (논문 표현)
**전통적인 네트워크 관리는 분산된 도구와 수동 장비 등록으로 고통받는다.** 네트워크 운영자는 관리 시스템(예: NSO)에 장비를 수동으로 등록하고, 인증을 구성하고, 상태를 동기화해야 한다—확장성이 낮고 오류가 발생하기 쉬운 노동 집약적 프로세스다. 기존 네트워크 Q&A 시스템(예: NetConfigQA, NIKA)은 사전 구성된 환경이나 정적 파일 기반 토폴로지를 가정하며, 랩이나 운영 네트워크에서 장비가 동적으로 추가/제거되는 운영 현실을 다루지 못한다.

**연구 공백**: **LLM 기반 에이전트가 네트워크 랩 환경(PNETLab)과 관리 플랫폼(NSO) 간 격차를 지능적인 장비 발견 및 등록을 통해 자율적으로 연결**하는 선행 연구 없음.

### 접근 방식 (방법론 표현)
우리는 **"Design-to-Live Sync"**를 구현하는 네트워크 Q&A를 위한 멀티 에이전트 시스템 **LabMate**를 제시한다—조정 워크플로우:
1. PNETLab API를 통해 활성 네트워크 장비 **발견** (설계/랩 환경)
2. NSO의 장비 인벤토리와 **조정** (운영 관리)
3. API 메타데이터에서 연결 파라미터(Telnet→SSH 포트 매핑) 추론하여 누락 장비 **자동 등록**
4. CDP/LLDP 프로토콜을 통해 **L1 토폴로지 추출** (정적 파일 파싱 대신)
5. 실시간으로 자동 유지되는 장비 상태로 Batfish 분석을 사용하여 **네트워크 질문 답변**

**핵심 신규성**: NIKA(Kathara 기반, 정적 토폴로지)나 NetConfigQA(파일 기반 설정)와 달리, LabMate는 **Hybrid Mode**에서 작동하여 에이전트가 데이터 파이프라인을 적극적으로 관리—레거시 랩 인프라를 소프트웨어 정의 인벤토리로 전환.

**아키텍처**: 기술 기반 도구 필터링, API-First 데이터 수집, NSO를 Single Source of Truth로 하는 2-Agent Orchestrator (계획용 GPT-4o-mini, 실행용 GPT-OSS-20B).

### 기여 (왜 중요한가)
1. **LLM 기반 네트워크 자동 등록의 첫 시연**: LabMate는 에이전트가 질문 답변을 넘어 인프라 상태를 적극적으로 관리할 수 있음을 보여줌.
2. **현실적 운영자 경험**: 정적 파일 파싱 대신 NSO(산업 표준 SDN 컨트롤러)와 CDP/LLDP(실제 발견 프로토콜) 사용.
3. **수동 오버헤드 감소**: 운영자는 네트워크 설계(PNETLab)에 집중하고 LabMate가 관리 시스템 동기화 처리.
4. **Agentic 네트워크 관리 연구 플랫폼**: 운영 시나리오(장비 장애, 설정 드리프트 등)에서 에이전트 행동 연구 가능.

**SIGCOMM 2026 관점**: LLM을 독립형 분석기보다 기존 SDN 도구의 오케스트레이터로 위치시켜 "Network AI"(NIKA, NetConfigQA)와 "Network Automation"(NSO, StackStorm) 연결.

### 증거
- **Phase 3 완료**: MCP 도구 연동, Batfish 클라이언트 사용 가능
- **아키텍처 산출물**: `architecture.md`, `docker-compose.yml`, `implementation_plan.md` 모두 API-First + NSO 중심 비전과 일치
- **예비 설계 검증**: 네트워크 접근 확인 (PNETLab/NSO localhost에 `network_mode: host`로)
- **다음**: Auto-Onboarding E2E 시연 (Phase 3.5 구현)

### 한계 / 위험
1. **장비 호환성**: 장비가 CDP 또는 LLDP 지원 가정. 오래되거나 독점적인 장비는 이 프로토콜 부족 가능.
2. **NSO 의존성**: NSO 사용 불가 시, 시스템이 파일 기반 분석으로 저하 (실시간 동기화 기능 상실).
3. **보안**: Auto-Onboarding은 NSO 인증 정보 저장/관리 필요. 적절히 암호화하지 않으면 인증 정보 유출 위험.
4. **확장성**: 대규모(100+ 장비)에서 CDP/LLDP 파싱 미테스트.
5. **평가 현실성**: NetConfigQA2.0 데이터셋은 정적 설정 사용. 공정한 평가를 위해 동적 등록 시나리오 생성 필요할 수 있음.

### 인용할 관련 연구 (또는 검색 키워드)
- **NIKA (SIGCOMM 2025)**: LLM 에이전트를 이용한 네트워크 장애 진단 (Kathara 기반, 정적 토폴로지)
- **NetConfigQA (선행 연구)**: 네트워크 Q&A 데이터셋 (파일 기반, 실시간 관리 없음)
- **NSO (Cisco)**: 우리가 연동하는 Network Services Orchestrator (SDN 컨트롤러)
- **Batfish**: 우리가 사용하는 네트워크 설정 분석 (검증 백엔드)
- **AutoConfig/ZTP**: Zero-Touch Provisioning (관련되지만 초기 장비 설정에 집중, 지속적 동기화는 아님)
- **Intent-Based Networking (IBN)**: 고수준 정책 → 네트워크 설정 (우리는 반대: 실시간 상태에서 의도 추론)
- **Software-Defined Networking (SDN)**: LabMate가 기여하는 더 넓은 분야

**검색 키워드**: "network device onboarding", "LLM network automation", "agent-driven SDN", "network topology discovery", "network management reconciliation"

### 아직 이해하지 못한 것
- **"등록 품질"을 정량적으로 평가하는 방법?** (성공률? 동기화 시간? 추론 파라미터 정확성?)
- **비교 기준선**: 현재 인간 운영자는 무엇을 하나? (수동 스크립트? Ansible 플레이북?)
- **에이전트 실패 모드**: 에이전트가 잘못된 장비를 등록하거나 PNETLab 메타데이터를 잘못 해석하면?
- **데이터셋 격차**: NetConfigQA2.0에는 "등록" 질문 없음. 새 작업 유형 필요하거나 실시간 장비 상태 요구하도록 기존 Q&A 수정?

### 다음 작업
- [ ] 문헌 검토: "network auto-discovery" + "LLM" 논문 검색
- [ ] Auto-Onboarding 평가 메트릭 정의 (정밀도, 재현율, 동기화 시간)
- [ ] SIGCOMM 초록용 "Self-Driving Network Onboarding" 섹션 초안
- [ ] Phase 3.5 구현 및 초기 성능 데이터 수집
- [ ] "장비 생명주기" 질문으로 NetConfigQA2.0 확장 고려
