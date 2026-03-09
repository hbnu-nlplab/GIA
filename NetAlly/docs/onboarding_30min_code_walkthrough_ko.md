# NetAlly 30분 코드 온보딩 (웹 처음인 사람용)

이 문서는 실제 코드 화면을 보면서 30분 안에 NetAlly 구조를 이해하는 코스입니다.  
핵심은 "어떤 UI 동작이 어떤 코드와 API를 타는지"를 눈으로 연결하는 것입니다.

---

## 시작 전에 (2분)

터미널 2개를 준비합니다.

1. 서버 실행
```bash
cd NetAlly
./scripts/demo_up_local.sh
```

2. 코드 탐색
- VS Code에서 `NetAlly` 폴더 열기
- 브라우저에서 `http://127.0.0.1:3000` 열기

확인 포인트:
- precheck가 `PASS`인지
- 화면이 뜨고 우측 채팅 패널이 보이는지

---

## 0~5분: "앱 껍데기" 이해

여는 파일:
- `frontend/src/App.tsx:12`

집중해서 볼 라인:
- 전체 레이아웃 시작: `frontend/src/App.tsx:63`
- 대시보드/토폴로지 전환: `frontend/src/App.tsx:71`
- 뷰 토글 버튼: `frontend/src/App.tsx:74`
- 우측 채팅 패널: `frontend/src/App.tsx:153`

이 단계에서 이해할 것:
1. App은 "좌측 메인 뷰 + 우측 채팅" 구조다.
2. 메인 뷰는 `dashboard`와 `topology`를 스위치한다.
3. 증거(Evidence) 패널은 오버레이로 얹힌다.

실습:
- 화면에서 `Dashboard`/`Map View`를 번갈아 클릭하고, `App.tsx`의 `viewMode` 분기를 다시 본다.

---

## 5~10분: 상단 버튼이 어디로 가는지

여는 파일:
- `frontend/src/components/Header.tsx:5`

집중해서 볼 라인:
- Refresh 요청: `frontend/src/components/Header.tsx:15`
- `/api/lab/refresh` 호출: `frontend/src/components/Header.tsx:26`
- Prepare 요청: `frontend/src/components/Header.tsx:47`
- `/api/lab/prepare` 호출: `frontend/src/components/Header.tsx:50`
- Settings 열기 버튼: `frontend/src/components/Header.tsx:129`

이 단계에서 이해할 것:
1. 버튼 클릭은 거의 항상 `fetch('/api/...')`로 연결된다.
2. 응답은 즉시 화면 상태 + Evidence 스토어에 반영된다.

실습:
- 브라우저에서 `Prepare` 클릭
- 헤더 상태 점(`Batfish: ...`) 변화를 본 뒤 코드 `setPrepareStatus` 흐름 확인

---

## 10~16분: Settings 저장 흐름 (운영에서 가장 중요)

여는 파일:
- `frontend/src/components/SettingsDialog.tsx:41`
- `main.py:590`

집중해서 볼 라인:
- 다이얼로그 열릴 때 설정 조회: `frontend/src/components/SettingsDialog.tsx:74`
- `/api/settings` GET 파싱: `frontend/src/components/SettingsDialog.tsx:76`
- 저장 payload 생성: `frontend/src/components/SettingsDialog.tsx:135`
- 실제 저장 요청: `frontend/src/components/SettingsDialog.tsx:154`
- 백엔드 GET 설정 응답: `main.py:590`
- 백엔드 POST 업데이트 처리: `main.py:617`
- MCP 재기동 조건: `main.py:724`

이 단계에서 이해할 것:
1. UI는 변경된 필드만 payload로 보낸다.
2. `tool_backend`, `mcp_server_url`이 바뀌면 백엔드가 MCP 클라이언트를 리셋한다.
3. 잘못된 입력(`tool_backend`)은 422로 처리된다.

실습:
- Settings에서 `Allow MCP Mutations` 토글 후 Apply
- 저장 성공 표시 확인
- `curl http://127.0.0.1:8111/api/settings`로 반영값 확인

---

## 16~22분: 채팅 SSE 흐름 이해

여는 파일:
- `frontend/src/components/ChatPanel.tsx:17`
- `main.py:871`

집중해서 볼 라인:
- 채팅 전송: `frontend/src/components/ChatPanel.tsx:43`
- `/api/chat` 요청: `frontend/src/components/ChatPanel.tsx:54`
- SSE 라인 파싱: `frontend/src/components/ChatPanel.tsx:72`
- planning/tool_call/tool_output/answer 처리: `frontend/src/components/ChatPanel.tsx:79`
- 백엔드 SSE 생성기: `main.py:871`
- 이벤트 방출 순서: `main.py:899`, `main.py:906`, `main.py:919`, `main.py:939`, `main.py:941`

이 단계에서 이해할 것:
1. 채팅은 일반 JSON 1회 응답이 아니라 스트리밍 이벤트 흐름이다.
2. `tool_output`은 Evidence 카드 생성의 핵심 데이터다.

실습:
- 채팅에 "show devices" 입력
- 채팅에 계획/실행 로그/최종 답변이 순서대로 뜨는지 확인

---

## 22~26분: 상태 저장소(Zustand) 감 잡기

여는 파일:
- `frontend/src/store.ts:13`

집중해서 볼 라인:
- 전역 상태 인터페이스: `frontend/src/store.ts:13`
- Evidence 적재: `frontend/src/store.ts:73`
- UI 설정 저장(localStorage): `frontend/src/store.ts:156`

이 단계에서 이해할 것:
1. 공통 상태는 `useAppStore` 하나로 모인다.
2. 컴포넌트는 store 액션을 호출해서 서로 느슨하게 연결된다.

실습:
- Settings에서 `oobIntf` 변경 후 새로고침
- 값이 유지되는지 확인 (localStorage persist 확인)

---

## 26~30분: 테스트와 안정화가 어디서 보장되는지

여는 파일:
- `tests/test_chat_sse_order.py:18`
- `tests/test_settings_api_integration.py:33`
- `frontend/playwright.config.ts:5`
- `scripts/demo_precheck.sh:6`

집중해서 볼 라인:
- SSE 이벤트 순서 고정: `tests/test_chat_sse_order.py:32`
- Settings API 계약 테스트: `tests/test_settings_api_integration.py:34`
- E2E 실행 환경/서버 자동기동: `frontend/playwright.config.ts:23`
- 데모 사전점검 계약 체크: `scripts/demo_precheck.sh:45`

이 단계에서 이해할 것:
1. "동작한다"가 아니라 "계약이 깨지면 테스트가 잡는다" 상태다.
2. precheck는 데모 직전 최소 안전망이다.

실습:
```bash
cd NetAlly
uv run pytest -q tests
cd frontend && npm run test:e2e
```

---

## 온보딩 종료 체크 (셀프 점검)

아래 4개에 답할 수 있으면 다음 단계 작업 시작해도 됩니다.

1. Settings Apply를 누르면 어떤 API와 백엔드 코드가 실행되는가?
2. 채팅 SSE 이벤트 5개 순서는 무엇인가?
3. `tool_backend`를 왜 `legacy`로 전환하는 fallback이 필요한가?
4. 데모 직전에 어떤 스크립트/테스트를 반드시 돌리는가?

---

## 다음 추천

이제 바로 기능 개발을 시작할 때는 아래 순서를 고정하면 안전합니다.

1. 코드 수정
2. `uv run pytest -q tests`
3. `cd frontend && npm run test:e2e`
4. `./scripts/demo_precheck.sh`
5. 커밋
