# NetAlly Backend API

문서 허브: `docs/README_ko.md`

---

## 1. Chat SSE API

### Endpoint
- `POST /api/chat`

### Request body
```json
{
  "message": "PE1에서 CE2까지 reachability 확인해줘",
  "history": [
    {"role": "user", "content": "이전 질문"},
    {"role": "assistant", "content": "이전 답변"}
  ],
  "answer_type": "text"
}
```

### SSE event order (fixed contract)
1. `planning`
2. `tool_call` (0회 이상)
3. `tool_output` (tool_call과 쌍)
4. `answer`
5. `complete`

### Event payload highlights
- `planning`
  - `mode`: `prompt_only | team_multi_adapter | legacy_graph`
  - `tool_backend`: `mcp | legacy | team_multi`
  - `agent_backend`: `single_executor | team_multi_adapter | legacy_graph`
  - `bound_tool_count`: 바인딩된 도구 수
  - `skills`: 하위 호환을 위해 항상 포함 (기본 `[]`)
- `tool_call`
  - `tool`, `input`, `call_id`
- `tool_output`
  - `tool`, `content`, `call_id`
- `answer`
  - `content`

### Runtime-specific behavior
- `single_executor`
  - 기본 런타임
  - MCP 사용 시 Core 16 도구만 바인딩
  - 도구 루프 최대 10 step
  - step limit 도달 시 고정 답변 반환:
    - `도구 호출 한도 도달, 추가 범위 축소 질의 필요`
- `team_multi_adapter`
  - 외부 MultiAgent 그래프 호출
  - `tool_call/tool_output`는 `team_multi_invoke` synthetic 이벤트로 송신
- `legacy_graph`
  - 기존 LangGraph 경로 (롤백용)

---

## 2. Settings API

### GET `/api/settings`
현재 런타임 설정 조회 (민감 값은 마스킹).

주요 필드:
- `tool_backend`: `mcp | legacy`
- `agent_backend`: `single_executor | team_multi_adapter | legacy_graph`
- `agent_prompt_mode`: 현재 `prompt_only`
- `executor_system_prompt`: single executor 프롬프트 override
- `team_multi_module`: team adapter 대상 Python module
- `team_multi_dataset_type`: `netconfig | descriptive | multiple_choice | short_answer`
- `team_multi_root`: 외부 MultiAgent 루트 경로
- `team_multi_context_path`: team adapter 컨텍스트 파일 경로
- `mcp_server_url`
- `mcp_allow_mutations`
- `bound_tool_count`

### POST `/api/settings`
런타임 설정 변경.

검증:
- `tool_backend`가 `mcp|legacy` 외 값이면 `422`
- `agent_backend`가 허용값 외면 `422`
- `team_multi_dataset_type`가 허용값 외면 `422`

재초기화:
- 아래 값 변경 시 에이전트 런타임 invalidate:
  - `openai_api_key`, `tool_backend`, `agent_backend`, `executor_system_prompt`
  - `team_multi_module`, `team_multi_dataset_type`, `team_multi_root`, `team_multi_context_path`

---

## 3. Health API

### GET `/api/health`

주요 필드:
- `status`
- `tool_backend`
- `agent_backend`
- `mcp_health`
- `agent_runtime_loaded`
- `agent_runtime_error`
- `bound_tool_count`

하위 호환 alias:
- `agent_graph_loaded`
- `agent_graph_error`

---

## 4. Topology and Device APIs

### GET `/api/topology?layer=l1|l3`
- Batfish snapshot이 준비되면 Batfish 기반 토폴로지 사용
- Batfish 미준비 시 NSO fallback 사용
- NSO fallback은 `get_devices(): List[str]` + `get_device_info(device)` 조합으로 노드 생성

### GET `/api/topology/pnetlab`
- LabFS(`.unl`, `wrapper.txt`) 기반 토폴로지 복제

### GET `/api/device/{device_id}`
- NSO + Batfish 장비 상세 조회

---

## 5. Lab / PNETLab APIs

- `POST /api/lab/refresh`
  - 신규 장비 refresh/onboard
- `POST /api/lab/prepare`
  - Batfish 준비 확인/초기화
- `GET /api/pnetlab/status`
  - PNETLab 인증 상태
- `POST /api/pnetlab/auth`
  - PNETLab 인증 값 반영

---

## 6. Tool Catalog (MCP)

### Core 16 (default bind target)
- NSO: `nso_list_devices`, `nso_get_device_info`, `nso_get_interfaces`, `nso_get_routing`, `nso_get_logs`
- Batfish: `batfish_reachability`, `batfish_traceroute`, `batfish_bgp_sessions`, `batfish_route_table`, `batfish_advanced_verify`
- Lab/Sync: `lab_show_inventory`, `lab_get_status`, `lab_export_configs`, `lab_init_batfish`, `sync_scan`, `bootstrap_refresh_onboard`

### Compatibility 6 (deprecated, registry에는 유지)
- `network_query`, `network_verify`, `lab_manage`, `scan_and_sync`, `check_logs`, `lab_bootstrap`

주의:
- single executor 기본 바인딩은 Core 16만 사용
- mutation은 `NETALLY_MCP_ALLOW_MUTATIONS=false` 기본 차단

---

## 7. Demo Defaults and Rollback

권장 기본값:
- `NETALLY_AGENT_BACKEND=single_executor`
- `NETALLY_TOOL_BACKEND=mcp`
- `NETALLY_MCP_ALLOW_MUTATIONS=false`

즉시 롤백:
- `agent_backend=legacy_graph`
- 필요 시 `tool_backend=legacy`
