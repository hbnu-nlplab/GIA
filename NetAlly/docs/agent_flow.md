# NetAlly Agent Flow

문서 허브: `docs/README_ko.md`

---

## 1. 목적

NetAlly 채팅 요청이 백엔드에서 어떻게 처리되는지, 그리고 `single_executor / team_multi_adapter / legacy_graph` 런타임이 어떻게 갈리는지 정리한다.

---

## 2. 공통 Chat Lifecycle

입력: `POST /api/chat`

1. 런타임 lazy-load
2. (옵션) `AUTO_PREPARE_ON_CHAT=true`면 Batfish 준비 게이트 수행
3. 런타임별 `astream()` 실행
4. SSE 계약에 맞춰 이벤트 송신
   - `planning -> tool_call -> tool_output -> answer -> complete`

---

## 3. Runtime Selection

환경/설정 키:
- `NETALLY_AGENT_BACKEND`
  - `single_executor` (기본)
  - `team_multi_adapter`
  - `legacy_graph`
- `NETALLY_TOOL_BACKEND`
  - `mcp` (기본)
  - `legacy`

런타임 생성:
- `agent/runtime.py:create_runtime(...)`

---

## 4. single_executor Flow (default)

### 특징
- Prompt-only 단일 executor
- history를 실제 대화 컨텍스트로 반영
- MCP 모드일 때 Core 16 도구만 바인딩
- step limit 10

### 처리 순서
1. `planning` 송신
2. LLM tool-call loop 시작
3. tool call 발생 시:
   - `tool_call`
   - 실제 도구 invoke
   - `tool_output`
4. tool call이 더 없으면 `answer`
5. step limit 도달 시 강제 `answer`
   - `도구 호출 한도 도달, 추가 범위 축소 질의 필요`

---

## 5. team_multi_adapter Flow

### 목적
외부 MultiAgent 그래프를 NetAlly SSE 계약으로 감싸서 호출한다.

### 브리지
- `agent/team_multi_bridge.py:run_team_multi_query(...)`

### 입력 매핑 (NetAlly -> MultiAgent state)
- `message` -> `question`
- `answer_type` -> 질문 suffix (`[answer_type=...]`)로 전달
- `history` -> context fallback 생성에 사용
- context 우선순위:
  1. 요청 `context`
  2. `NETALLY_TEAM_MULTI_CONTEXT`
  3. `NETALLY_TEAM_MULTI_CONTEXT_PATH` 파일
  4. (`dataset_type=netconfig`) `MultiAgent/data/original/netconfig/configs.txt`
  5. history 기반 context
  6. `[NONE]`

### 출력 매핑 (MultiAgent -> NetAlly)
- `final_answer` 우선
- 없으면 `debate2_answer`, `answer`, `candidate_answer` 순 fallback
- SSE로는 아래처럼 표준화:
  1. `planning`
  2. `tool_call` (`tool=team_multi_invoke`)
  3. `tool_output` (adapter result/meta 요약)
  4. `answer`

### 설정 키
- `NETALLY_TEAM_MULTI_MODULE` (기본: `agents.main_netconfig`)
- `NETALLY_TEAM_MULTI_DATASET_TYPE` (기본: `netconfig`)
- `NETALLY_TEAM_MULTI_ROOT` (기본: `<repo>/MultiAgent`)
- `NETALLY_TEAM_MULTI_CONTEXT_PATH` (선택)

---

## 6. legacy_graph Flow

### 역할
- 기존 LangGraph 기반 오케스트레이션 유지
- 롤백/비교 검증용

### 특징
- 기존 노드(`orchestrator`, `executor`, `tools`) 흐름 유지
- SSE 이벤트 타입은 현재 계약에 맞춰 동일하게 송신

---

## 7. Guardrails and Failure Handling

- runtime load 실패 시 `/api/chat`는 `error + complete` SSE 반환
- team adapter 실패 시에도 `answer` 이벤트를 반드시 송신
- mutation tool은 기본 차단:
  - `NETALLY_MCP_ALLOW_MUTATIONS=false`
- Batfish 미준비 시 `AUTO_PREPARE_ON_CHAT` 게이트에서 안내 후 종료

---

## 8. 디버깅 포인트

- `main.py`
  - runtime lazy-load, SSE 변환, settings invalidate
- `agent/runtime.py`
  - backend 분기, SSE event emission
- `agent/team_multi_bridge.py`
  - 외부 MultiAgent import/cache/invoke 매핑
- `agent/mcp_tools.py`
  - Core 16 / compatibility 6 카탈로그
- `agent/clients/nso.py`
  - NED normalize 및 RESTCONF 호출
- `agent/clients/batfish.py`
  - snapshot lifecycle 및 import path 안전성
