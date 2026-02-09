# NetAlly Architecture (v2.0)

NetAlly는 네트워크 관리에 특화된 **Multi-Agent System**이다.  
핵심은 **Orchestrator-Executor 2-Agent 구조** + **PNETLab-NSO-Batfish 통합 검증** + **도구 기반 추론(Tool-augmented Reasoning)**이다.

---

## 1) Goals / Non-goals

### Goals
- 사용자가 config/log를 복사/붙여넣기 하지 않아도 **랩 상태를 자동 수집**
- Batfish/도구 결과를 **Evidence Pack**으로 남기고 UI에서 추적 가능
- **NSO를 Single Source of Truth**로, PNETLab API는 Discovery용으로 활용
- **CDP/LLDP 기반 L1 토폴로지** 파악 (NSO에서 추출)
- **Local / API / Hybrid LLM** 지원 (기관 정책/망 환경 대응)
- 도커 기반 배포/업데이트 용이

### Non-goals (v1)
- 운영망(production) 자동 제어를 1차 목표로 삼지 않음
- LLM이 설정을 "생성"하는 능력 자체를 연구의 중심으로 두지 않음 (검증/근거가 중심)
- **UNL 파일 직접 파싱은 v1에서 제외** (v2에서 "설계 vs 실제" 비교 기능으로 확장)

---

## 2) High-level Components

- **UI (Cockpit + Chat Drawer)**: 대시보드 중심, 채팅은 보조(해설/추천/다음 액션)
- **PNETLab API Client**: 노드 Discovery 및 포트 정보 수집
- **NSO Client**: 장비 자동 등록, sync-from, 설정 조회
- **Batfish**: 스냅샷 로딩/질의(Reachability/Trace/Policy/Diff 등)
- **Agent Orchestrator (LangGraph)**: 계획 → 도구 호출 → 증거 정리 → 응답 생성
- **LLM Runtime**:
  - Local LLM 서버
  - API LLM (예: GPT)
- **Evidence Store**: 스냅샷/쿼리결과/로그검색결과/사용자 세션 저장

---

## 3) Data Ingestion Strategy (API-First)

### Primary Workflow: PNETLab API + NSO

**1단계: Discovery** (PNETLab API)
- 실행 중인 노드 목록 조회
- 각 노드의 Telnet/SSH 포트 정보 수집

**2단계: Auto-Onboarding** (NSO)
- PNETLab에서 발견된 노드를 NSO에 자동 등록
- `sync-from`으로 실제 장비 설정 동기화

**3단계: L1 Topology** (CDP/LLDP)
- NSO에서 `show cdp neighbors detail` 수집
- 물리 연결 관계 추출 → Batfish `layer1_topology.json` 생성

### Fallback: Config Export (NSO 미사용)

NSO 없이 동작해야 할 경우:
- PNETLab "Export CFG" 기능으로 Config ZIP 다운로드
- L1 토폴로지는 제외 (Batfish L3 분석만 가능)

> **v2 확장**: UNL 파일 직접 파싱으로 "설계 vs 실제" 비교 기능 추가 예정

---

## 4) Snapshot Layout (Generated Artifacts)

스냅샷은 Batfish 규격을 따른다:

```
snapshot/
    configs/
        R1.cfg
        R2.cfg
    batfish/
        layer1_topology.json (CDP/LLDP 기반)
    dashboard_meta.json (좌표/아이콘/라벨, v2)
evidence/
    runs/<run_id>/*.json (Batfish 결과/CLI 결과/로그 결과)
```

---

## 5) 외부 서비스 연결 (NSO Integration)

LabMate는 **Batfish를 내장**하고, **NSO는 사용자가 별도로 운영**하는 구조다.
NSO 연결은 **UI 설정 화면**에서 사용자가 직접 입력한다.

### 연결 흐름

```
┌─────────────────────────────────────────────────────────────────┐
│                    사용자 환경 (PNETLab 호스트)                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────┐         ┌─────────────────────┐       │
│  │   LabMate Stack     │         │   NSO Container     │       │
│  │   (Docker Compose)  │ ──────▶ │   (사용자 별도 운영) │       │
│  │  network_mode:host  │  HTTP   │                     │       │
│  │                     │         │  - RESTCONF API     │       │
│  │  ┌───────────────┐  │         │  - Port 8888        │       │
│  │  │ LabMate Agent │──┼─────────│                     │       │
│  │  └───────────────┘  │         └─────────┬───────────┘       │
│  │  ┌───────────────┐  │                   │                   │
│  │  │    Batfish    │  │                   │ SSH/NETCONF       │
│  │  └───────────────┘  │                   ▼                   │
│  │  ┌───────────────┐  │         ┌─────────────────────┐       │
│  │  │  LabMate UI   │  │         │   PNETLab 장비들    │       │
│  │  └───────────────┘  │         │  (vIOS, CSR, etc.)  │       │
│  └─────────────────────┘         └─────────────────────┘       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 네트워크 설정 (docker-compose.yml)

```yaml
services:
  labmate:
    network_mode: host  # 호스트 네트워크 사용
    # 이를 통해 localhost로 PNETLab API, NSO API 모두 접근 가능
```

### UI 설정 화면

```
┌─────────────────────────────────────────────┐
│  ⚙️ 외부 서비스 연결                         │
├─────────────────────────────────────────────┤
│                                             │
│  📡 NSO 서버                                │
│  ┌─────────────────────────────────────┐   │
│  │ URL:      http://localhost:8888     │   │
│  │ 사용자:   admin                      │   │
│  │ 비밀번호: ********                   │   │
│  └─────────────────────────────────────┘   │
│                                             │
│  [🔍 연결 테스트]  [💾 저장]                │
│                                             │
│  ✅ 연결 성공! 등록된 장비 5대              │
│                                             │
└─────────────────────────────────────────────┘
```

### 설정 저장 위치

- **컨테이너 내부**: `/data/config/services.json`
- **Volume Mount**: `labmate_data:/data` (영속적 저장)

```json
// /data/config/services.json
{
  "nso": {
    "enabled": true,
    "base_url": "http://localhost:8888/restconf",
    "username": "admin",
    "password_encrypted": "..."
  }
}
```

### NSO 없이도 동작 (Fallback)

NSO가 연결되지 않아도 LabMate의 핵심 기능(Batfish 검증)은 작동한다.
하지만 **Hybrid Mode**에서는 NSO가 핵심 운영 플랫폼이 된다.

---

## 6) Agent Workflow: Hybrid Auto-Onboarding (Reconciliation)

LabMate는 **"설계(PNETLab)와 운영(NSO)의 일치(Reconciliation)"**를 지향한다.
사용자가 별도로 NSO에 장비를 등록할 필요 없이, 에이전트가 이를 자동화한다.

### Workflow: `Design-to-Live` Sync

1.  **Discovery**:
    - Agent가 PNETLab API (`lab_manage`)를 통해 실행 중인 노드 목록(R1, R2...)을 수집한다.
    - 동시에 NSO API (`network_query`)를 통해 등록된 장비 목록을 조회한다.

2.  **Diff & Decision**:
    - Agent는 두 목록을 비교한다.
    - *"PNETLab에는 R2가 켜져 있는데, NSO에는 등록되어 있지 않습니다."*
    - 사용자의 정책(자동/수동)에 따라 등록 절차를 수행한다.

3.  **Onboarding (Execution)**:
    - Agent가 `nso_client.register_device()` 및 `fetch-ssh-keys`, `sync-from`을 순차적으로 수행한다.
    - Telnet/SSH 포트 정보는 PNETLab API에서 가져와 자동으로 매핑한다.

4.  **Operation**:
    - 등록이 완료되면, 이후 모든 설정 조회 및 변경은 **NSO를 통해** 수행한다.
    - 이를 통해 "Legacy Network"를 "Software Defined Network" 관리 체계로 자동 편입시킨다.

> **Research Value**: 이 과정은 단순 자동화를 넘어, **"Self-Driving Network Onboarding"**의 초기 형태를 보여준다. Legacy 장비를 스스로 인지하고 관리 영역으로 가져오는 Agent의 능력을 입증한다.

### 상세 비교표

| 기능 | NSO 없음 | NSO 연결됨 |
|------|----------|-----------|
| Config 파일 분석 (Batfish) | ✅ | ✅ |
| Reachability 검증 | ✅ | ✅ |
| 실시간 장비 설정 조회 | ❌ | ✅ |
| NSO sync-from 트리거 | ❌ | ✅ |
| 자동 장비 등록 (Onboarding) | ❌ | ✅ |
| L1 토폴로지 (CDP/LLDP) | ❌ | ✅ |