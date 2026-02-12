# NetAlly Agent Handoff Guide

이 문서는 새로운 Codex/에이전트 세션이 `NetAlly` 컨텍스트를 빠르게 이어받기 위한 운영 메모입니다.

## 1. 프로젝트 요약

- 목적: LLM + MCP 도구 + Batfish/NSO/PNETLab을 결합한 네트워크 운영/검증 도우미
- 핵심 UX: 채팅 SSE 기반 `planning -> tool_call -> tool_output -> answer`
- 아키텍처 성격: FastAPI 백엔드 + React/Vite 프론트 + 에이전트 런타임 분기 + MCP/Legacy 도구 백엔드

## 2. 현재 기준 상태 (검증일: 2026-02-12)

아래는 로컬 기준 실제 점검 결과:

- `scripts/demo_precheck.sh`: PASS
- `/api/health`: `tool_backend=mcp`, `agent_backend=single_executor`
- MCP tool count: `22`
- `/api/lab/prepare`: `status=not_ready` (초기 상태에서 가능)
- 백엔드 테스트: `uv run pytest -q tests` -> `44 passed`
- 프론트 빌드: `npm run build` -> 성공 (chunk size 경고 1건, 비차단)

## 3. 빠른 시작 명령

```bash
cd NetAlly
uv sync --extra dev
cd frontend && npm ci && cd ..
./scripts/demo_up_local.sh
```

기본 접속:

- Backend: `http://127.0.0.1:8111`
- Frontend: `http://127.0.0.1:3000`

데모 전 최소 점검:

```bash
cd NetAlly
./scripts/demo_precheck.sh
uv run pytest -q tests
cd frontend && npm run build
```

## 4. 핵심 디렉터리/파일 맵

- API 엔트리: `NetAlly/main.py`
- 런타임 분기: `NetAlly/agent/runtime.py`
- MCP 도구 래퍼: `NetAlly/agent/mcp_tools.py`
- MCP 서버: `NetAlly/agent/mcp_server.py`
- 토폴로지/온보딩: `NetAlly/agent/pnetlab_labfs.py`, `NetAlly/agent/onboarding.py`
- 프론트 진입: `NetAlly/frontend/src/App.tsx`
- 채팅 패널: `NetAlly/frontend/src/components/ChatPanel.tsx`
- 토폴로지 패널: `NetAlly/frontend/src/components/TopologyPanel.tsx`
- 설정 다이얼로그: `NetAlly/frontend/src/components/SettingsDialog.tsx`
- 문서 허브: `NetAlly/docs/README_ko.md`
- E2E 파이프라인 문서: `NetAlly/docs/pipeline_end_to_end_ko.md`

## 5. 런타임/백엔드 기본값

- `NETALLY_AGENT_BACKEND=single_executor`
- `NETALLY_TOOL_BACKEND=mcp`
- `NETALLY_MCP_ALLOW_MUTATIONS=false` (read-only 기본)
- MCP 기본 URL: `http://127.0.0.1:8811/mcp`

런타임 옵션:

- Agent backend: `single_executor` | `team_multi_adapter` | `legacy_graph`
- Tool backend: `mcp` | `legacy`

## 6. 주요 API 계약 포인트

- `POST /api/chat`: SSE 스트리밍 채팅
- `GET /api/topology`: Batfish 토폴로지
- `GET /api/topology/pnetlab`: PNETLab/LabFS 토폴로지
- `POST /api/lab/refresh`: 온보딩/동기화 트리거
- `POST /api/lab/prepare`: Batfish 준비/초기화 경로
- `GET/POST /api/settings`: 런타임 설정 조회/변경
- `GET /api/health`: 서비스/백엔드 상태

## 7. 작업 시 중요한 동작 특성

- 백엔드는 startup 시 runtime lazy-load를 사용한다.
- `POST /api/settings`에서 runtime-sensitive 항목 변경 시 runtime이 invalidate/restart 된다.
- `tool_backend` 또는 `mcp_server_url` 변경은 MCP runtime 재기동과 직접 연결된다.
- 시각화 오버레이(`viz`)는 LLM 자유 파싱이 아니라 tool I/O 기반 룰로 생성된다.
- PNETLab은 LabFS 우선, 실패 시 API fallback 경로를 가진다.

## 8. 자주 막히는 포인트

- `lab_prepare`가 `not_ready`: Batfish snapshot 미준비 상태일 수 있음
- 맵이 비는 경우:
  - 먼저 소스를 `Lab`으로 전환
  - `/api/topology/pnetlab` 응답 확인
  - `PNETLAB_INVENTORY_BACKEND=labfs_local` 및 `/opt/unetlab` 마운트 확인
- 채팅이 준비되지 않는 경우:
  - `/api/health`, `/api/settings` 확인
  - OpenAI API key 및 MCP health 상태 확인

## 9. 추천 문서 읽기 순서

1. `NetAlly/docs/README_ko.md`
2. `NetAlly/docs/pipeline_end_to_end_ko.md`
3. `NetAlly/docs/testing_runbook_ko.md`
4. `NetAlly/docs/backend_api.md`
5. `NetAlly/docs/onboarding_30min_code_walkthrough_ko.md`

## 10. 다음 세션 핸드오프 체크리스트

다음 세션 시작 시 아래를 먼저 확인:

1. `cd NetAlly && ./scripts/demo_precheck.sh`
2. `/api/health`에서 `tool_backend`, `agent_backend`, `mcp_health.tool_count` 확인
3. 변경 작업 전에 `uv run pytest -q tests` 현재 baseline 확인
4. 프론트 수정 시 `cd frontend && npm run build` 확인
5. 문서/코드 변경 후 이 파일(`NetAlly/agents.md`)의 "현재 기준 상태"를 갱신

## 11. 유지보수 규칙

- 이 문서는 "현재 동작하는 사실"만 기록한다. 추측/희망사항은 쓰지 않는다.
- 수치(테스트 개수, 도구 개수, 기본 포트, 기본 백엔드)는 변경 시 즉시 업데이트한다.
- 보안 정보(API key, 비밀번호, 쿠키 원문)는 절대 기록하지 않는다.
