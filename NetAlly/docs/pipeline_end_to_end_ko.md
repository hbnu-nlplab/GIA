# NetAlly E2E 파이프라인 가이드

이 문서는 NetAlly가 실제로 어떻게 동작하는지, 프론트엔드부터 백엔드/에이전트/시각화까지를 한 번에 이해할 수 있도록 정리한 운영용 가이드입니다.

## 1. 한눈에 보는 전체 흐름

```text
[User]
  └─(Browser UI: Header / Topology / Chat / Settings)
      ├─ GET /api/topology | /api/topology/pnetlab
      ├─ POST /api/chat (SSE stream)
      ├─ POST /api/lab/refresh
      ├─ POST /api/lab/prepare
      ├─ GET/POST /api/settings
      └─ POST /api/pnetlab/auth

[FastAPI main.py]
  ├─ Runtime/Settings 관리
  ├─ Agent Runtime 생성(create_runtime)
  ├─ Chat SSE 이벤트 변환 + viz 힌트 생성
  ├─ PNETLab LabFS/API 토폴로지 제공
  └─ Lab bootstrap/prepare API 제공

[Agent Runtime]
  ├─ SingleExecutorRuntime (기본)
  ├─ LegacyGraphRuntime
  └─ TeamMultiAdapterRuntime

[Tool Backend]
  ├─ MCP tools (기본)
  └─ Legacy tools (호환)

[External/Infra]
  ├─ Batfish
  ├─ NSO
  ├─ PNETLab (LabFS or API auth)
  └─ Local env/runtime state
```

## 2. 주요 컴포넌트 역할

| 영역 | 파일 | 역할 |
|---|---|---|
| API 진입점 | `NetAlly/main.py` | 모든 REST/SSE 엔드포인트, settings 반영, runtime lazy-load |
| 에이전트 런타임 | `NetAlly/agent/runtime.py` | LLM + tool 실행 루프, `tool_call/tool_output/answer` 이벤트 생성 |
| MCP 도구 래퍼 | `NetAlly/agent/mcp_tools.py` | core/compatibility tool 정의 |
| 토폴로지 UI | `NetAlly/frontend/src/components/TopologyPanel.tsx` | topology fetch, viz overlay 매핑/강조 |
| 채팅 UI | `NetAlly/frontend/src/components/ChatPanel.tsx` | `/api/chat` SSE 수신, 메시지 + viz store 반영 |
| 설정 UI | `NetAlly/frontend/src/components/SettingsDialog.tsx` | API settings + bootstrap override + pnetlab auth 설정 |
| 헤더 액션 | `NetAlly/frontend/src/components/Header.tsx` | Refresh/Prepare 버튼과 lab API 연결 |
| 앱 상태 | `NetAlly/frontend/src/store.ts` | 전역 상태(viz, settings, source, evidence 등) |

## 3. 사용자 액션별 E2E 시퀀스

### 3.1 Topology 로드

1. `TopologyPanel`이 현재 source를 보고 API 선택
1. Batfish source면 `GET /api/topology?layer=l1|l3`
1. PNETLab source면 `GET /api/topology/pnetlab`
1. 응답 nodes/edges를 ReactFlow 포맷으로 변환
1. `viz`가 있으면 오버레이만 별도 적용

핵심 포인트:
- `viz` 변경은 topology 재조회 없이 overlay만 갱신
- alias/canonical 매칭 + hub(`net:*`) fallback으로 path 강조 보강

### 3.2 Chat + 시각화 오버레이

1. `ChatPanel`이 `POST /api/chat` 호출
1. 백엔드 `chat_stream_generator`가 SSE 이벤트 스트리밍
1. `tool_call` 시점: tool 인자 기반 `viz` 생성
1. `tool_output` 시점: tool 결과(path 등) 기반 `viz` 생성
1. 프론트가 `setViz`로 store 반영
1. `TopologyPanel`이 노드/엣지 하이라이트 적용

핵심 포인트:
- 시각화 결정은 “LLM 자연어 파싱”이 아니라 “tool I/O 룰 기반”
- 질문 시작 시 `clearViz()`로 이전 오버레이 제거

### 3.3 Refresh (신규 장비 부트스트랩)

1. Header의 Refresh 클릭
1. 로컬 Bootstrap Overrides를 `overrides`로 조합
1. `POST /api/lab/refresh`
1. 백엔드가 `bootstrap_refresh_onboard`(MCP) 또는 legacy 경로 실행
1. agent onboarding 로직이 `device_info` 자동 생성/적용

핵심 포인트:
- Overrides는 실제로 `agent/onboarding.py`의 `pick()` 경로로 반영됨

### 3.4 Prepare (Batfish 준비)

1. Header의 Prepare 클릭
1. `POST /api/lab/prepare`
1. snapshot 로드 상태 확인
1. 필요 시 init 경로 실행(설정값에 따라)
1. 결과를 evidence/status로 UI에 반영

### 3.5 Settings 반영

1. Settings Dialog에서 `Apply API Settings`
1. `POST /api/settings`
1. backend가 env 업데이트 + 관련 client/runtime invalidate/restart
1. 필요 시 MCP runtime 재기동
1. 이후 요청부터 새 설정 사용

핵심 포인트:
- 문자열 항목은 빈 값 전송 시 clear(unset) 가능
- tool backend 또는 mcp url 변경 시 MCP runtime 재기동

## 4. Settings 구조(현재 기준)

### 4.1 API Connections (백엔드 연동)

- `openai_api_key`
- `nso_base_url`, `nso_username`, `nso_password`
- `pnetlab_url`
- `batfish_host`
- `tool_backend` (`mcp` | `legacy`)
- `mcp_server_url`
- `mcp_allow_mutations`

### 4.2 Bootstrap Overrides (Refresh에 반영)

- `PNETLAB_OOB_INTF`
- `PNETLAB_DEVICE_GROUP`
- `PNETLAB_VM_IP`
- `PNETLAB_GATEWAY_IP`
- `NSO_AUTHGROUP`
- `NSO_NED_ID`

### 4.3 PNETLab Auth

- API fallback 인증용 설정
- LabFS backend 사용 시 필수 아님

## 5. 백엔드 파이프라인 상세

### 5.1 앱 시작/종료

- startup에서 tool/agent backend 상태 로드
- agent runtime은 lazy-load
- tool backend가 MCP면 embedded MCP server 시작 시도
- shutdown 시 MCP 정리

### 5.2 Runtime 생성/무효화

- `create_runtime()`으로 backend별 runtime 객체 생성
- Settings 변경 시 runtime-sensitive 항목이면 `_invalidate_runtime()`

### 5.3 Chat SSE 변환

- runtime events를 통일된 SSE 포맷으로 전달
- `tool_call`, `tool_output`, `answer`, `complete`, `error` 이벤트를 처리
- 시각화 힌트는 `_build_viz_from_tool_call/_tool_output`에서 생성

### 5.4 Topology 소스

- Batfish/NSO fallback 토폴로지
- PNETLab는 LabFS 우선, 실패 시 API fallback 가능
- icon endpoint는 정적/프록시 fallback 구조

## 6. 프론트엔드 파이프라인 상세

### 6.1 상태 관리

- Zustand store에 `viz`, `settings`, `topologySource`, `evidence` 등 보관
- Bootstrap overrides는 localStorage에 유지

### 6.2 렌더링 레이어

- ReactFlow 기반 토폴로지 렌더
- Device/Network 노드 모두 highlight 지원
- edge는 base style 보존 후 viz overlay 덮어쓰기

### 6.3 사용자 피드백

- Chat 패널에 planning/tool 실행 표시
- Evidence 패널에 refresh/prepare/tool output 요약
- Toolbar에서 source/layer 전환

## 7. 데모 실행 체크리스트

1. `GET /api/health` 정상 확인
1. `GET /api/settings`에서 backend/tool 설정 확인
1. Topology source를 PNETLab로 전환해 맵 렌더 확인
1. Refresh/Prepare 버튼 각각 1회 실행해 evidence 반영 확인
1. traceroute 질의로 path overlay 확인
1. Settings의 API Connections 값 변경 후 즉시 반영 확인

## 8. 테스트 전략 (현재 권장)

### 8.1 백엔드

```bash
cd NetAlly
uv run pytest -q tests
```

### 8.2 프론트엔드

```bash
cd NetAlly/frontend
npm run build
```

## 9. 최근 검증 결과 (2026-02-11)

- Backend tests: `44 passed`
- Frontend build: 성공
- Settings 연동 개선:
  - 미연동/혼란 항목 제거
  - API 문자열 필드 clear 지원
  - 관련 계약 테스트 추가/통과

## 10. 운영 시 주의사항

1. PNETLab Auth는 LabFS 모드에서 필요하지 않을 수 있음
1. `mcp_allow_mutations=false`면 일부 onboarding/sync 도구가 차단됨
1. Batfish snapshot 준비 상태에 따라 chat 도구 결과가 제한될 수 있음
1. OpenAI API key 미설정 시 chat runtime 로드 실패 가능

