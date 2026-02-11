# NetAlly 실행/테스트 런북 (KO)

이 문서는 처음 보는 사람도 바로 따라할 수 있도록 **실행 방법 + 테스트 방법 + 실패 시 대응**을 정리한 문서입니다.

---

## 1. 준비물

- Python 3.10+
- `uv`
- Node.js 18+
- `npm`

권장:
- `docker` (Batfish 확인용)

---

## 2. 가장 빠른 로컬 실행

```bash
cd NetAlly
./scripts/demo_up_local.sh
```

이 스크립트가 자동으로:
1. 백엔드(`8111`) 실행
2. 프론트(`3000`) 실행
3. `/api/health`, `/api/settings`, `/api/lab/prepare` 점검

중지:
- 터미널에서 `Ctrl+C`

---

## 3. 수동 실행 (디버깅용)

### 3.1 백엔드

```bash
cd NetAlly
uv sync --extra dev
uv run uvicorn main:app --host 127.0.0.1 --port 8111
```

### 3.2 프론트

```bash
cd NetAlly/frontend
npm ci
npm run dev -- --host 127.0.0.1 --port 3000
```

접속:
- 프론트: `http://127.0.0.1:3000`
- 백엔드 헬스: `http://127.0.0.1:8111/api/health`

---

## 4. 테스트 실행 방법

### 4.1 백엔드 회귀 테스트 (pytest)

```bash
cd NetAlly
uv sync --extra dev
uv run pytest -q tests
```

무엇을 검증하나:
- MCP 도구 카탈로그/권한 게이트
- `/api/settings` 런타임 반영
- SSE 이벤트 순서
- PNETLab 아이콘/토폴로지 관련 계약

### 4.2 프론트 E2E 스모크 (Playwright)

```bash
cd NetAlly/frontend
npm ci
npx playwright install --with-deps
npm run test:e2e
```

참고:
- Playwright는 `frontend/playwright.config.ts`에서 백엔드/프론트를 자동 기동합니다.
- 기본 API baseURL은 `http://127.0.0.1:8111`입니다.

헤디드 모드:

```bash
npm run test:e2e:headed
```

---

## 5. 데모 전 최소 점검 체크리스트

1. 백엔드 회귀 테스트
```bash
cd NetAlly
uv run pytest -q tests
```
2. 프론트 스모크 테스트
```bash
cd NetAlly/frontend
npm run test:e2e
```
3. 런타임 계약 점검
```bash
cd NetAlly
./scripts/demo_precheck.sh
```
4. UI에서 `Prepare` 버튼 1회 실행 후 Map 표시 확인

---

## 6. 자주 실패하는 포인트

### 6.1 Batfish 준비 실패 (`status=unavailable` 또는 `not_ready`)

확인:
- `BATFISH_HOST` 값
- Batfish 컨테이너 상태
- `curl http://127.0.0.1:9996/v2/version`

### 6.2 Map View가 비어 있음

확인 순서:
1. `🧪 Lab` 소스로 전환
2. `/api/topology/pnetlab` 응답 확인
3. `PNETLAB_INVENTORY_BACKEND=labfs_local` + `/opt/unetlab` 마운트 확인

### 6.3 Settings 저장은 되는데 동작 반영이 안 됨

확인:
- `/api/settings` 재조회
- `/api/health`에서 `tool_backend`, `mcp_health` 확인

---

## 7. 관련 문서

- 문서 허브: `docs/README_ko.md`
- PNETLab 실전 배선: `docs/pnetlab_wiring_runbook_ko.md`
- API 계약: `docs/backend_api.md`
- 에이전트 흐름: `docs/agent_flow.md`
