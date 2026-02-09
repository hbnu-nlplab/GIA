# NetAlly 백엔드 API 명세

NetAlly 백엔드는 고동시성 네트워크 분석과 실시간 스트리밍을 위한 FastAPI 서버입니다.

---

## 1. 채팅 API (SSE)

**엔드포인트**: `POST /api/chat`

대화 의도를 처리하고 도구 실행을 오케스트레이션합니다.  
**Server-Sent Events (SSE)** 로 계획/도구 호출/결과를 스트리밍합니다.

### 요청 본문
```json
{
  "message": "PE1과 PE2 사이 도달성을 검증해줘",
  "history": [],
  "answer_type": "text"
}
```

### 이벤트 스트림 형식
| 이벤트 타입 | 예시 payload | 설명 |
|------------|--------------|------|
| `planning` | `{"reasoning":"...","skills":[...],"tool_backend":"mcp"}` | Orchestrator의 계획 결과 |
| `tool_call` | `{"tool":"...","args":{...}}` | 도구 실행 직전 이벤트 |
| `tool_output` | `{"content":"..."}` | 도구 실행 결과 원문 |
| `answer` | `{"content":"..."}` | 최종 응답 |
| `complete` | `{"type":"complete"}` | 스트림 종료 신호 |

---

## 2. 토폴로지 API

### 엔드포인트: `GET /api/topology`

Batfish 분석 기반 토폴로지 정보를 반환합니다.

**쿼리 파라미터**
- `layer`: `l1`(물리) 또는 `l3`(논리), 기본값 `l1`

### 엔드포인트: `GET /api/topology/pnetlab`

PNETLab의 실제 노드 좌표를 포함한 토폴로지를 반환합니다.

### 응답 예시
```json
{
  "nodes": [
    {
      "id": "PE1",
      "type": "router",
      "data": { "mgmt_ip": "10.0.0.1", "platform": "ios" },
      "position": { "x": 100, "y": 100 }
    }
  ],
  "edges": [
    {
      "id": "e-PE1-PE2",
      "source": "PE1",
      "target": "PE2",
      "label": "Gi0/0 ↔ Gi0/0",
      "animated": true
    }
  ]
}
```

---

## 3. 대시보드 API

### 엔드포인트: `GET /api/dashboard/summary`

프로토콜 상태와 이슈를 포함한 네트워크 건강 요약을 반환합니다.

### 엔드포인트: `GET /api/dashboard/reachability`

Batfish 기반 장비 간 도달성 매트릭스를 반환합니다.

### 엔드포인트: `GET /api/device/{device_id}`

장비 상세 정보(설정/라우팅/인터페이스)를 반환합니다.

---

## 4. 런타임 설정 API

### 엔드포인트: `GET /api/settings`

현재 런타임 설정을 조회합니다(비밀값은 마스킹).

주요 필드:
- `tool_backend`: `mcp` 또는 `legacy`
- `mcp_server_url`: MCP streamable-http 엔드포인트
- `mcp_allow_mutations`: 변경성 도구 허용 여부

### 엔드포인트: `POST /api/settings`

런타임 설정을 변경합니다.  
`tool_backend` 또는 `mcp_server_url` 변경 시 MCP 런타임을 재초기화합니다.

검증/오류 규칙:
- `tool_backend` 값이 유효하지 않으면 `422` + JSON `detail`
- 재기동 중 내부 오류가 나면 `500` + JSON `detail`

---

## 5. 에이전트 아키텍처 (LangGraph + MCP-lite)

백엔드는 상태 그래프 기반으로 다단계 추론을 수행합니다.  
Skill은 도구 접근 제어가 아니라 프롬프트 가이드 용도로 사용합니다.

1. **Orchestrator**: 질문 분석 및 스킬 선택
2. **Executor**: 도구 호출 루프 실행
3. **Refiner(선택)**: 중간 결과를 최종 응답으로 정리

### MCP 코어 도구 (16개)
- NSO: `nso_list_devices`, `nso_get_device_info`, `nso_get_interfaces`, `nso_get_routing`, `nso_get_logs`
- Batfish: `batfish_reachability`, `batfish_traceroute`, `batfish_bgp_sessions`, `batfish_route_table`, `batfish_advanced_verify`
- Lab/Sync: `lab_show_inventory`, `lab_get_status`, `lab_export_configs`, `lab_init_batfish`, `sync_scan`, `bootstrap_refresh_onboard`

### 호환 도구 (6개, deprecated)
- `network_query`, `network_verify`, `lab_manage`, `scan_and_sync`, `check_logs`, `lab_bootstrap`

### deprecated wrapper I/O 계약
- `network_query`, `network_verify`, `lab_manage`, `scan_and_sync`, `lab_bootstrap`: JSON 객체(`Dict[str, Any]`)
- `check_logs`: 레거시 호환을 위해 문자열(`str`) 유지

### MCP 오류 계약
- MCP 클라이언트 응답 공통 필드: `{ ok, tool, result, is_error, error, code }`
- mutation 차단 시:
  - `error`: 사람이 읽을 수 있는 차단 사유
  - `code`: `mutations_blocked`
  - `result.blocked`: `true`

---

## 6. 데모 운영 기본값 / 장애 복구

- 권장 기본 운용:
  - `tool_backend = mcp`
  - `mcp_allow_mutations = false`
- 위험 작업(bootstrap/sync/export) 시에만 mutation을 잠시 켰다가 즉시 비활성화합니다.
- 데모 중 장애 시 복구 절차:
  1. `tool_backend`를 `legacy`로 전환
  2. `mcp_server_url` 수정
  3. `/api/health` 확인 후 `mcp`로 복귀

---

## 7. Evidence 저장

도구 실행 결과는 Evidence Pack으로 수집되며,  
`/api/evidence/{run_id}`를 통해 추후 검토/감사를 위한 저장이 가능합니다.

---

## 8. API 계약/검증 자동화 메모

- 이번 스프린트에서 **공개 API 계약 변경은 없습니다**.
- 대신 회귀 탐지 강화를 위해 자동 검증을 추가했습니다.
  - 백엔드 통합 테스트: `/api/settings`, `/api/health` 런타임 반영 검증
  - 브라우저 스모크 테스트: Settings MCP 필드/저장, Chat SSE 기본 렌더 검증
  - CI: backend pytest + frontend Playwright smoke를 PR 단계에서 자동 실행
  - CI 산출물: pytest JUnit XML, Playwright report/test-results 업로드
