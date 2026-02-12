# NetAlly

NetAlly는 네트워크 운영/검증을 위해 LLM + MCP 도구 + Batfish/NSO/PNETLab을 결합한 분석 도우미입니다.

- 실시간 SSE 채팅(`planning -> tool_call -> tool_output -> answer`)
- Batfish 기반 검증(Reachability, Traceroute, Route/BGP)
- PNETLab 토폴로지 복제(LabFS, 쿠키 없이)
- NSO 연동 조회/자동화

---

## NetAlly를 한 번에 이해하기

### 이 프로젝트가 해결하는 문제

운영자가 보통 겪는 문제는 다음과 같습니다.

- 도구가 분리되어 있음: NSO, Batfish, PNETLab을 각각 따로 열어야 함
- 질문에서 실행까지 오래 걸림: “A에서 B 통신되나?”를 확인하려면 수동 단계가 많음
- 데모/랩 환경 불안정: 쿠키 만료, API 인증 문제로 맵/상태가 자주 깨짐

NetAlly는 이 문제를 아래 방식으로 줄입니다.

- 채팅으로 질의 입력 → 백엔드가 필요한 도구를 자동 선택/실행
- 결과를 단순 텍스트가 아닌 근거(`tool_output`, evidence) 중심으로 제공
- PNETLab은 LabFS(`.unl`, `wrapper.txt`) 기반으로 읽어 쿠키 의존성을 줄임

### 한 번의 질문이 처리되는 방식 (End-to-End)

예: 사용자가 “PE1에서 CE2까지 도달 가능해?”라고 질문

1. 프론트가 `POST /api/chat` 요청
2. 백엔드가 `planning` 이벤트 전송 (어떤 도구를 쓸지 계획)
3. `tool_call` 이벤트 전송 (예: `batfish_reachability`)
4. 실제 도구 실행 후 `tool_output` 전송
5. 최종 `answer` 전송
6. `complete`로 스트림 종료

즉, NetAlly의 핵심은 “LLM이 답을 혼자 만드는 것”이 아니라 “도구를 호출해 근거를 만들고 요약하는 것”입니다.

### 구성 요소 역할

- `frontend/`: 사용자 화면, SSE 수신/렌더링
- `main.py`: FastAPI 엔드포인트, 런타임 설정 API, 채팅 스트림 입구
- `agent/runtime.py`: 에이전트 런타임 선택(`single_executor`, `team_multi_adapter`, `legacy_graph`)
- `agent/team_multi_bridge.py`: 외부 MultiAgent 그래프 호출 브리지(입출력 매핑)
- `agent/mcp_server.py`: MCP 도구 카탈로그(코어 16 + 호환 6)
- `agent/clients/nso.py`: NSO RESTCONF 연동
- `agent/clients/batfish.py`: Batfish 연동/스냅샷 처리
- `agent/pnetlab_labfs.py`: PNETLab LabFS 파싱(쿠키 없는 토폴로지 복제)

### 주요 용어 (처음 보는 사람용)

- `MCP`: 모델이 표준 방식으로 외부 도구를 호출하는 계층
- `LabFS`: PNETLab 파일 시스템을 직접 읽는 방식 (`/opt/unetlab`)
- `RESTCONF`: NSO와 HTTP 기반으로 통신하는 API 규격
- `Snapshot`: Batfish가 분석할 설정 데이터 묶음
- `SSE`: 서버가 이벤트를 순차적으로 스트리밍하는 방식

---

## 1. 문서 시작점

처음 보는 경우 이 순서로 보는 것을 권장합니다.

1. `docs/README_ko.md` (문서 허브)
2. `docs/pnetlab_wiring_runbook_ko.md` (실전 배선/운영)
3. `docs/testing_runbook_ko.md` (실행/테스트)
4. `docs/backend_api.md` (API 계약)

---

## 2. 빠른 시작 (로컬 개발)

### 2.1 요구 사항

- Python `>=3.10` (권장 `3.12+`)
- `uv`
- Node.js `18+`
- `npm`

### 2.2 의존성 설치

```bash
cd NetAlly
uv sync --extra dev
cd frontend && npm ci && cd ..
```

### 2.3 원클릭 실행

```bash
./scripts/demo_up_local.sh
```

기본 포트:
- Backend: `http://127.0.0.1:8111`
- Frontend: `http://127.0.0.1:3000`

이 스크립트는 시작 후 자동으로 `demo_precheck`를 수행합니다.

기본 런타임:
- `NETALLY_AGENT_BACKEND=single_executor`
- `NETALLY_TOOL_BACKEND=mcp`
- `NETALLY_MCP_ALLOW_MUTATIONS=false` (read-only 기본)

### 2.4 5분 확인 시나리오

README만 보고 최소 기능을 확인하려면 아래 순서로 진행하면 됩니다.

1. `./scripts/demo_up_local.sh` 실행
2. 브라우저에서 `http://127.0.0.1:3000` 접속
3. Header의 `Prepare` 버튼 클릭
4. Map에서 `🧪 Lab` 또는 `🔬 Batfish` 전환해 노드 렌더 확인
5. 채팅에 간단한 질의 입력
   - 예: `PE1에서 CE2까지 reachability 확인해줘`
6. 채팅 창에서 `planning -> tool_call -> tool_output -> answer` 흐름 확인

### 2.5 처음 실패할 때 체크 순서

1. `GET /api/health` 확인
2. `GET /api/settings` 확인
3. `POST /api/lab/prepare` 결과 확인
4. Map이 비면 `🧪 Lab`로 전환해 LabFS 경로 먼저 확인
5. 계속 실패하면 `docs/testing_runbook_ko.md`의 장애 섹션 확인

### 2.6 Docker Compose로 컨테이너 실행

```bash
cd NetAlly
docker compose build netally
docker compose up -d
```

`docker-compose.yml`은 repo-root 컨텍스트(`../`) + `NetAlly/Dockerfile`을 사용하도록 정렬되어 있습니다.

---

## 3. PNETLab 배포 핵심 (최신 기준)

상세는 `docs/pnetlab_wiring_runbook_ko.md`를 기준으로 보세요. 여기에는 핵심만 요약합니다.

### 3.1 Docker Node 기본 설정

- Image: `netally:latest`
- Console Type: `http`
- Console Port: `8000`
- Ethernet: `4`

### 3.2 Docker Options 권장 예시

```bash
--privileged -v /opt/unetlab:/opt/unetlab:ro --add-host=host.docker.internal:host-gateway -e PNETLAB_INVENTORY_BACKEND=labfs_local -e PNETLAB_LAB_NAME=test_nso -e NSO_BASE_URL=http://10.10.10.100:8080/restconf -e BATFISH_HOST=host.docker.internal:9997 -e BATFISH_SNAPSHOT=test_nso -e AUTO_INIT_BATFISH=true -e NETALLY_TOOL_BACKEND=mcp -e NETALLY_MCP_ALLOW_MUTATIONS=true
```

의미:
- `labfs_local` + `/opt/unetlab` 마운트: PNETLab 맵을 쿠키 없이 안정적으로 복제
- `NSO_BASE_URL`: NSO RESTCONF 대상
- `BATFISH_HOST`: 호스트 Batfish 컨테이너 접속

### 3.3 Batfish 호스트 점검

```bash
# PNETLab 호스트에서
curl -fsS http://127.0.0.1:9996/v2/version
```

`/v2`는 이미지 버전에 따라 404일 수 있으므로 `/v2/version`으로 확인합니다.

---

## 4. 접속 방법 (중요)

### 4.1 캔버스 더블클릭 시 터미널만 뜨는 경우

이건 `Console Type=linux`일 때 동작입니다.

웹 UI 접속으로 바꾸려면:
1. Node Edit에서 `Console Type=http`
2. `Console Port=8000` (또는 Primary Map Port=8000)
3. Save 후 노드 재시작

### 4.2 Admin Chromebook으로 접속

가능합니다.
- NetAlly: PNETLab 캔버스에서 NetAlly 노드 더블클릭
- NSO: Chromebook에서 `http://<NSO_ADMIN_IP>:8080/login.html`

### 4.3 로컬 브라우저에서 NSO + NetAlly 동시 접속

가능합니다. 포트 publish가 없으면 SSH 터널이 가장 안전합니다.

```bash
# 로컬 PC에서
ssh -N \
  -L 18080:10.10.10.100:8080 \
  -L 18111:<NETALLY_CONTAINER_IP>:8000 \
  root@<PNETLAB_VM_IP>
```

접속:
- NSO: `http://127.0.0.1:18080`
- NetAlly: `http://127.0.0.1:18111`

NetAlly 컨테이너 IP 확인:
```bash
docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' docker15
```

---

## 5. 리소스 권장치 (NetAlly Node)

Batfish가 호스트에서 별도 컨테이너로 돌아가더라도 NetAlly는 아래를 권장합니다.

- 최소 동작: `1 core / 1024MB`
- 데모 권장: `2 core / 2048MB`
- 안정 여유: `2 core / 3072~4096MB`

주의:
- `1 core / 256MB`는 데모 중 불안정할 수 있습니다.
- VM 전체 RAM은 `NSO + NetAlly + Batfish` 합산으로 계산해야 합니다.

---

## 6. 테스트 실행

### 6.1 백엔드 회귀

```bash
cd NetAlly
uv run pytest -q tests
```

### 6.2 프론트 E2E 스모크

```bash
cd NetAlly/frontend
npx playwright install --with-deps
npm run test:e2e
```

### 6.3 데모 전 최소 점검

```bash
cd NetAlly
./scripts/demo_precheck.sh
```

검증 항목:
- `/api/health`
- `/api/settings`
- `/api/lab/prepare`

---

## 7. 주요 API

- `POST /api/chat` SSE 채팅
- `GET /api/topology` Batfish 토폴로지
- `GET /api/topology/pnetlab` PNETLab/LabFS 토폴로지
- `POST /api/lab/prepare` Batfish 준비 상태
- `POST /api/lab/refresh` 온보딩/동기화 트리거
- `GET/POST /api/settings` 런타임 설정
- `GET /api/health` 서비스 상태

자세한 계약은 `docs/backend_api.md`를 확인하세요.

---

## 8. 프로젝트 구조 (요약)

```text
NetAlly/
├── main.py
├── agent/
│   ├── runtime.py
│   ├── team_multi_bridge.py
│   ├── graph.py
│   ├── mcp_server.py
│   ├── mcp_client.py
│   └── clients/
├── frontend/
├── docs/
├── tests/
└── scripts/
```

---

## 9. 문서 맵

- `docs/README_ko.md`: 문서 허브(추천 시작점)
- `docs/pnetlab_wiring_runbook_ko.md`: 실전 배선/운영
- `docs/pnetlab_deployment_guide.md`: 배포 절차
- `docs/testing_runbook_ko.md`: 실행/테스트
- `docs/backend_api.md`: API 명세
- `docs/web_architecture_beginner_ko.md`: 비웹 개발자용 구조 설명
- `docs/agent_flow.md`: 에이전트 이벤트/흐름
- `docs/team_multi_adapter.md`: Team Multi Adapter 설정/입출력 매핑
- `docs/setup_guide.md`: 설치 요약(영문)

---

## 10. 현재 범위와 제한

- 실장비 E2E 자동화는 환경별 편차가 있어, 현재는 PNETLab/NSO/Batfish 데모 안정화에 우선순위를 둡니다.
- PNETLab API 인증(쿠키/자동로그인)은 보조 경로이며, 토폴로지는 LabFS 경로를 우선 권장합니다.
- Batfish 분석 품질은 스냅샷 입력(설정/장비 정보)의 정확도에 영향을 받습니다.
- `NETALLY_MCP_ALLOW_MUTATIONS=false` 기본값에서는 변경성 도구가 차단되며, `/api/lab/refresh` 및 `auto_init_batfish=true`의 `/api/lab/prepare`는 `403 (mutations_blocked)`를 반환합니다.

---

## 11. 라이선스

MIT License
