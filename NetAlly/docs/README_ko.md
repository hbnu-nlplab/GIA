# NetAlly 문서 허브 (처음 시작)

이 문서는 NetAlly 문서를 한곳에서 시작할 수 있도록 만든 **단일 입구**입니다.  
웹/네트워크/코드가 익숙하지 않아도 아래 순서대로 보면 됩니다.

---

## 1. 가장 먼저 보는 순서

1. `docs/pnetlab_wiring_runbook_ko.md`  
   PNETLab에서 실제로 어떻게 배선하고 실행하는지(실전 운영 기준)
2. `docs/web_architecture_beginner_ko.md`  
   NetAlly가 프론트/백엔드/에이전트로 어떻게 동작하는지(입문)
3. `docs/testing_runbook_ko.md`  
   로컬 실행, 테스트, 데모 전 점검을 어떻게 하는지
4. `docs/backend_api.md`  
   API 계약(어떤 엔드포인트가 무엇을 반환하는지)

---

## 2. 상황별 문서 바로가기

### A) “지금 데모를 바로 살려야 함”

1. `docs/pnetlab_wiring_runbook_ko.md`
2. `docs/pnetlab_deployment_guide.md`
3. `docs/agent_flow.md`

포함 내용:
- Console Type(`linux`/`http`) 차이와 접속 문제 해결
- NetAlly CPU/RAM 권장치
- 로컬 브라우저(NSO+NetAlly 동시 접속) 방법

### B) “코드를 수정하려고 함”

1. `docs/web_architecture_beginner_ko.md`
2. `docs/onboarding_30min_code_walkthrough_ko.md`
3. `docs/backend_api.md`
4. `docs/testing_runbook_ko.md`

### C) “API/설정 계약을 확인하고 싶음”

1. `docs/backend_api.md`
2. `docs/agent_flow.md`
3. `docs/team_multi_adapter.md`

---

## 3. 용어 사전 (처음 보는 사람용)

- `PNETLab`: 네트워크 실습용 가상 랩 플랫폼입니다.
- `LabFS`: PNETLab 파일 시스템(`.unl`, `wrapper.txt`)을 직접 읽어 토폴로지를 복제하는 방식입니다.
- `NSO`: Cisco Network Services Orchestrator. 장비 등록/동기화/설정 조회의 중심 시스템입니다.
- `RESTCONF`: NSO와 HTTP로 통신할 때 쓰는 API 표준입니다.
- `Batfish`: 네트워크 설정을 정적으로 검증하는 분석 엔진입니다.
- `Snapshot`: Batfish가 분석할 입력(설정 파일 묶음) 단위입니다.
- `MCP`: 모델이 도구를 호출하는 표준 인터페이스 계층입니다.
- `SSE`: 서버가 이벤트를 실시간으로 흘려주는 스트리밍 방식입니다. (`/api/chat`)
- `OOB`: Out-Of-Band 관리망. 서비스 트래픽과 분리된 관리용 네트워크입니다.
- `Agent Backend`: 채팅 실행 경로 선택값입니다. (`single_executor`, `team_multi_adapter`, `legacy_graph`)

---

## 4. 실행 위치에 따른 운영 모드

### 모드 1) PNETLab VM 내부 Docker Node 실행 (현재 권장)

- 장점: 쿠키 없이 LabFS 동작, 데모 안정성 높음
- 핵심 설정:
  - `PNETLAB_INVENTORY_BACKEND=labfs_local`
  - `-v /opt/unetlab:/opt/unetlab:ro`

### 모드 2) 로컬 PC 실행

- 장점: 개발 편의성 높음
- 핵심 설정:
  - 백엔드 `8111`, 프론트 `3000`
  - 필요 시 `labfs_ssh`로 원격 PNETLab 파일 읽기

---

## 5. 자주 쓰는 명령어 치트시트

### 로컬 실행

```bash
cd NetAlly
./scripts/demo_up_local.sh
```

### 백엔드 테스트

```bash
cd NetAlly
uv sync --extra dev
uv run pytest -q tests
```

### 프론트 E2E 테스트

```bash
cd NetAlly/frontend
npm ci
npx playwright install --with-deps
npm run test:e2e
```

### 데모 최소 점검

```bash
cd NetAlly
./scripts/demo_precheck.sh
```

### 런타임 기본값

- `NETALLY_AGENT_BACKEND=single_executor`
- `NETALLY_TOOL_BACKEND=mcp`
- `NETALLY_MCP_ALLOW_MUTATIONS=false`

---

## 6. 접속 방식 한눈에 보기

- `PNETLab 캔버스 방식`: NetAlly 노드 더블클릭, Chromebook에서 NSO 접속
- `로컬 브라우저 방식`: SSH 터널로 NSO/NetAlly를 로컬 포트에 매핑
  - 상세: `docs/pnetlab_wiring_runbook_ko.md`

---

## 7. 문서 유지 원칙

문서 간 충돌을 줄이기 위해 다음 기준을 사용합니다.

1. 실행/배선/운영은 `docs/pnetlab_wiring_runbook_ko.md`를 기준 문서로 둡니다.
2. API 계약은 `docs/backend_api.md`를 기준 문서로 둡니다.
3. 테스트 방법은 `docs/testing_runbook_ko.md`를 기준 문서로 둡니다.
4. 다른 문서에서 동일 정보를 쓸 때는 본문 중복 대신 기준 문서 링크를 우선합니다.

추가 안내:
- `docs/Log/` 아래 문서는 과거 작업 기록(아카이브)입니다.
- 최신 운영 절차는 이 허브에서 연결된 문서를 기준으로 봐주세요.
