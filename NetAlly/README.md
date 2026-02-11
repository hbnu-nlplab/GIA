# NetAlly

NetAlly는 네트워크 운영/검증을 위해 LLM + MCP 도구 + Batfish/NSO/PNETLab을 결합한 분석 도우미입니다.

- 실시간 SSE 채팅(`planning -> tool_call -> tool_output -> answer`)
- Batfish 기반 검증(Reachability, Traceroute, Route/BGP)
- PNETLab 토폴로지 복제(LabFS, 쿠키 없이)
- NSO 연동 조회/자동화

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
- `docs/setup_guide.md`: 설치 요약(영문)

---

## 10. 라이선스

MIT License
