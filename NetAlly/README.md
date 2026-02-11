# 🌐 NetAlly: 지능형 네트워크 검증 비서

<div align="center">

![NetAlly](https://img.shields.io/badge/v2.0-Evidence--First%20Dashboard-blue?style=for-the-badge)

![Python](https://img.shields.io/badge/Python-3.12+-green?style=flat-square&logo=python)

![React](https://img.shields.io/badge/React-18+-61DAFB?style=flat-square&logo=react)

![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=flat-square&logo=fastapi)

**NetAlly는 LLM(대규모 언어 모델)과 결정론적 분석 엔진(Batfish)을 결합하여, 네트워크 엔지니어에게 실시간 검증 인사이트와 지능형 트러블슈팅 지원을 제공하는 차세대 네트워크 분석 플랫폼입니다.** 그래도 좋아!

[📖 문서 보기](#-documentation) | [🚀 빠른 시작](#-quick-start) | [🔧 API 레퍼런스](docs/backend_api.md)

</div>

---

## ✨ 핵심 특징

### 1. 🏥 검증 대시보드 (Verification Dashboard)

복잡한 토폴로지 "거미줄" 대신, 엔지니어가 정말 필요로 하는 정보를 제공합니다:

- **프로토콜 건강 상태**: BGP/OSPF 세션의 Up/Down 현황을 한눈에.
- **액티브 인사이트**: "PE1-Leaf2 BGP 세션 다운: AS 번호 불일치 감지됨" 같은 분석된 원인 제공.
- **스마트 장비 리스트**: 장비별 상태 아이콘(🟢/🔴)으로 즉각적인 가시성 확보.

### 2. 🤖 하이브리드 분석 엔진

- **Batfish (결정론적)**: 정확하고 빠른 설정 분석 (1초 이내). 세션 상태, MTU/Timer 불일치 등.
- **LLM (생성형 AI)**: 복잡한 질문에 대한 상세 해결책 제안, 자연어 기반 대화.

### 3. 🗺️ 온디맨드 토폴로지 (On-Demand Map)

- 전체 맵은 평소에는 숨겨져 노이즈를 줄입니다.
- 필요할 때(버튼 클릭 또는 "경로 보여줘" 명령) 팝업으로 특정 경로만 확인.

### 4. 📡 실시간 SSE 채팅

- 에이전트의 사고 과정(`planning`), 도구 호출(`tool_call`), 결과(`tool_output`)를 실시간 스트리밍.
- 검증 결과는 **Evidence Panel**에 카드 형태로 자동 수집.

---

## 📁 프로젝트 구조

```
NetAlly/
├── 📄 main.py                  # FastAPI 백엔드 (SSE Chat, Topology, Dashboard API)
├── 📄 init_batfish.py          # Batfish 스냅샷 초기화 스크립트
├── 📄 langgraph.json           # LangGraph Studio 설정
├── 📄 docker-compose.yml       # Docker Compose 배포 설정
│
├── 📂 agent/                   # LangGraph 에이전트 핵심 모듈
│   ├── graph.py                # Orchestrator-Executor 기반 에이전트 그래프
│   ├── tools.py                # Legacy LangChain 도구 (호환용)
│   ├── mcp_server.py           # MCP-lite 서버 (16 core + 6 compatibility)
│   ├── mcp_client.py           # MCP streamable-http 클라이언트
│   ├── mcp_tools.py            # LangGraph에서 사용하는 MCP 프록시 도구
│   ├── state.py                # AgentState 정의
│   ├── llm_provider.py         # 하이브리드 LLM 프로바이더 (OpenAI, Ollama, vLLM)
│   ├── skill_loader.py         # 스킬 로더
│   └── clients/                # 외부 시스템 클라이언트
│       ├── batfish.py          # Batfish 분석 클라이언트
│       ├── nso.py              # NSO RESTCONF 클라이언트
│       └── pnetlab.py          # PNETLab API 클라이언트
│
├── 📂 frontend/                # React + Vite 프론트엔드
│   └── src/
│       ├── App.tsx             # 메인 레이아웃 (Dashboard/Topology 전환)
│       ├── store.ts            # Zustand 상태 관리
│       └── components/
│           ├── DashboardPanel.tsx    # 검증 대시보드 (NEW!)
│           ├── TopologyPanel.tsx     # React Flow 기반 토폴로지 맵
│           ├── ChatPanel.tsx         # SSE 채팅 UI
│           ├── EvidencePanel.tsx     # Evidence 카드 목록
│           └── Header.tsx            # 테마 전환, 설정
│
├── 📂 docs/                    # 상세 문서
│   ├── architecture.md         # 시스템 아키텍처
│   ├── dashboard_design.md     # 대시보드 기획안
│   ├── dashboard_implementation.md  # 대시보드 구현 명세
│   ├── frontend.md             # 프론트엔드 UI/UX 가이드
│   ├── backend_api.md          # API 레퍼런스
│   └── setup_guide.md          # 설치 가이드
│
├── 📂 skills/                  # 에이전트 스킬 정의 (가이드 텍스트 전용)
│
└── 📂 eval/                    # 평가 모듈 (NetConfigQA 벤치마크)
```

---

## 🚀 Quick Start

### 사전 요구 사항

- **Python 3.12+**
- **Node.js 18+** (프론트엔드 빌드용)
- **Docker** (Batfish 컨테이너 실행)
- **Batfish Docker 이미지**: `docker pull batfish/allinone`

### 1. 클론 및 환경 설정

```bash
# 1. 저장소 클론
git clone <repository_url>
cd NetAlly

# 2. Python 가상환경 생성 (uv 권장)
uv venv --python 3.12
source .venv/bin/activate

# 3. 의존성 설치 (개발/테스트 기준)
uv sync --extra dev
# editable 설치가 필요하면: uv pip install -e .

# 4. 환경변수 설정
cp .env.example .env
# .env 파일 편집: OPENAI_API_KEY, BATFISH_HOST 등 설정
```

### 2. Batfish 서비스 시작

```bash
# Batfish 컨테이너 실행
docker run -d -p 9997:9997 -p 9996:9996 --name batfish batfish/allinone

# 헬스 확인 (/v2 는 이미지 버전에 따라 404일 수 있어 /v2/version 권장)
curl -fsS http://127.0.0.1:9996/v2/version

# 스냅샷 초기화 (설정 파일 로드)
uv run python init_batfish.py
```

### 3. 백엔드 서버 실행

```bash
# FastAPI 서버 시작 (기본 포트: 8111)
uv run uvicorn main:app --reload --port 8111
```

### 4. 프론트엔드 개발 서버 실행

```bash
cd frontend
npm install
npm run dev
# 브라우저에서 http://localhost:3000 접속
```

---

## 🔌 API 엔드포인트

| 엔드포인트                | 메서드 | 설명                                 |
| ------------------------- | ------ | ------------------------------------ |
| `/api/chat`               | POST   | SSE 스트리밍 채팅 (에이전트 응답)    |
| `/api/topology`           | GET    | Batfish L3 토폴로지 (노드/엣지)      |
| `/api/dashboard/summary`  | GET    | 네트워크 건강 상태 요약 **(NEW!)**   |
| `/api/device/{device_id}` | GET    | 장비 상세 정보 (설정, 라우팅 테이블) |
| `/api/health`             | GET    | 서비스 헬스 체크                     |
| `/api/lab/refresh`        | POST   | 신규 장비 부트스트랩 (Refresh 버튼)  |
| `/api/lab/prepare`        | POST   | Batfish 준비/초기화                  |
| `/api/pnetlab/status`     | GET    | PNETLab 인증 상태                    |
| `/api/pnetlab/auth`       | POST   | PNETLab 인증 설정 (쿠키/자동로그인)  |

### Dashboard Summary 응답 예시

```json
{
  "health_score": 85,
  "protocols": {
    "bgp": { "total": 12, "up": 11, "down": 1, "status": "warning" },
    "ospf": { "total": 8, "up": 8, "down": 0, "status": "healthy" }
  },
  "issues": [
    {
      "severity": "critical",
      "type": "BGP_DOWN",
      "title": "BGP Down: PE1",
      "message": "BGP session to Leaf2 is NOT_ESTABLISHED",
      "affected_nodes": ["PE1", "Leaf2"]
    }
  ],
  "device_status": {
    "PE1": "warning",
    "PE2": "healthy",
    "Leaf1": "healthy"
  }
}
```

---

## 🛠️ 설정

### 환경변수 (`.env`)

```bash
# LLM Provider
OPENAI_API_KEY=sk-...              # OpenAI API 키
OPENAI_MODEL=gpt-4o-mini           # 사용할 모델
VLLM_BASE_URL=http://localhost:8000/v1
LANGSMITH_TRACING=false            # API 키 설정 시에만 true 권장

# Batfish
BATFISH_HOST=localhost             # Batfish 서비스 호스트
BATFISH_SNAPSHOT=default           # 기본 스냅샷 이름
BATFISH_NETWORK=default            # Alias
BATFISH_EXPORT_DIR=./snapshot      # NSO 설정 export 경로
USE_RESTCONF_EXPORT=false          # NSO CLI export 실패 시 RESTCONF fallback

# NSO (선택)
NSO_BASE_URL=http://localhost:8080 # NSO RESTCONF URL
NSO_USERNAME=admin
NSO_PASSWORD=admin
# Alias (optional)
NSO_USER=admin
NSO_PASS=admin
# Auto-discovery (optional)
PNETLAB_NSO_NODE=NSO
NSO_SCHEME=http
NSO_PORT=8080
NSO_RESTCONF_PATH=/restconf

# PNETLab (선택)
PNETLAB_URL=http://pnetlab.local
PNETLAB_COOKIES=token=...; _session=...; XSRF-TOKEN=...
PNETLAB_USERNAME=admin
PNETLAB_PASSWORD=pnetlab
PNETLAB_AUTO_LOGIN=false
PNETLAB_LAB_NAME=                # (선택) labfs_* 모드에서 사용할 .unl 이름 (예: test_nso)
PNETLAB_LAB_PATH=                # (선택) labfs_* 모드에서 사용할 .unl 경로 (예: /opt/unetlab/labs/test_nso.unl)
PNETLAB_INVENTORY_BACKEND=api    # api | labfs_local | labfs_ssh
# labfs_ssh 전용 (로컬 PC에서 PNETLab VM 파일을 읽을 때)
PNETLAB_SSH_HOST=
PNETLAB_SSH_USER=root
PNETLAB_SSH_PORT=22
PNETLAB_SSH_KEY_PATH=~/.ssh/netally_pnetlab
# 필요 시에만 사용: 예) -o StrictHostKeyChecking=accept-new
PNETLAB_SSH_OPTIONS=
PNETLAB_DEVICE_INFO=Data/Pnetlab/Research_Institute_Internal_DC/device_info.json
PNETLAB_DEVICE_INFO_AUTOGEN=true
PNETLAB_VM_IP=
PNETLAB_GATEWAY_IP=
PNETLAB_DOMAIN_NAME=lab.local
PNETLAB_ADMIN_PASSWORD=admin
PNETLAB_ENABLE_PASSWORD=
PNETLAB_OOB_INTF=
PNETLAB_DEVICE_GROUP=
NSO_AUTHGROUP=default
NSO_NED_ID=cisco-ios-cli-6.110

# Demo Automation (Optional)
AUTO_PREPARE_ON_CHAT=false         # 채팅 요청 시 Batfish 준비 자동 수행
AUTO_INIT_BATFISH=false            # 준비 실패 시 Batfish init 자동 수행

# MCP-lite
NETALLY_TOOL_BACKEND=mcp           # mcp | legacy
NETALLY_MCP_SERVER_URL=http://127.0.0.1:8811/mcp
NETALLY_MCP_ALLOW_MUTATIONS=false  # true면 변경성 도구 허용
```

### PNETLab 토폴로지 "쿠키 없이" 가져오기 (권장)
PNETLab 웹/API는 CAPTCHA/XSRF 때문에 쿠키 자동화가 불안정할 수 있습니다.
NetAlly는 그 대신 PNETLab의 파일 시스템(LabFS)을 읽어서 토폴로지를 복제합니다:

- `.unl` (토폴로지/노드 위치/아이콘/연결 메타)
- `/opt/unetlab/tmp/*/*/wrapper.txt` (실행 중인 노드의 콘솔 포트 best-effort)

#### A) PNETLab VM 내부에서 NetAlly 실행 (가장 간단/안정)
- `PNETLAB_INVENTORY_BACKEND=labfs_local`
- `PNETLAB_LAB_NAME=test_nso` 또는 `PNETLAB_LAB_PATH=/opt/unetlab/labs/test_nso.unl`

#### B) 내 PC에서 NetAlly 실행 (SSH 키로 원격 LabFS 읽기)
- `PNETLAB_INVENTORY_BACKEND=labfs_ssh`
- `PNETLAB_SSH_HOST`, `PNETLAB_SSH_KEY_PATH` 설정
- `PNETLAB_LAB_NAME` 또는 `PNETLAB_LAB_PATH` 설정

SSH 키 기본 권장:
- 로컬 키 권한: `chmod 600 ~/.ssh/netally_pnetlab`
- 가능하면 passphrase 설정 + `ssh-agent` 사용(데모 중 키 노출 방지)
- 가능하면 PNETLab에 전용 계정을 만들고(또는 `authorized_keys`에 제한 옵션 부여) 권한을 최소화

보안/안정성을 위해 NetAlly는 `ssh`에 `BatchMode=yes`를 사용합니다.
처음 연결에서 host key 확인이 필요하면, 아래 중 하나로 처리하세요:

1. (권장) 한 번만 수동으로 연결해서 host key 등록: `ssh root@<PNETLAB_IP>`
2. 자동 등록이 필요하면: `PNETLAB_SSH_OPTIONS="-o StrictHostKeyChecking=accept-new"`

### PNETLab Docker Node 운영 FAQ (중요)

#### Q1) NetAlly 노드 더블클릭 시 웹이 아니라 도커 터미널만 뜹니다

원인:
- PNETLab Docker Node의 `Console Type`이 `linux`로 되어 있으면 터미널 콘솔이 열립니다.

해결:
1. Node Edit 화면 하단에서 `Console Type = http`로 변경
2. `Console Port = 8000`(또는 `Primary Map Port = 8000`) 설정
3. Save 후 노드 재시작(Stop/Start)

참고:
- 버전에 따라 Docker `http` 콘솔 지원이 제한될 수 있습니다.
- 이 경우 `docs/pnetlab_wiring_runbook_ko.md`의 SSH 터널/로컬 브라우저 방식으로 접속하면 됩니다.

#### Q2) NetAlly 노드 CPU/RAM은 얼마나 줘야 하나요?

권장값:
- 최소 동작: `1 core / 1024MB`
- 데모 권장: `2 core / 2048MB`
- 안정 여유: `2 core / 3072~4096MB`

설명:
- `1 core / 256MB`는 부팅은 될 수 있어도 데모 중 불안정할 수 있습니다.

#### Q3) Batfish가 호스트에서 돌면 NetAlly 리소스는 줄여도 되나요?

네. Batfish JVM 메모리는 호스트 컨테이너(`netally-batfish`)가 사용하므로,
NetAlly 컨테이너는 상대적으로 작게 잡아도 됩니다.

다만 주의:
- VM 전체 RAM은 **NSO + NetAlly + Batfish**를 합쳐 충분해야 합니다.
- 데모 안정성을 위해 NetAlly는 최소 `1G`, 가능하면 `2G`를 권장합니다.

### PNETLab 아이콘(Topology) 고정하기 (권장)
PNETLab 맵을 NetAlly에서 최대한 동일하게 보이게 하려면, `.unl`이 참조하는 아이콘 파일을
NetAlly 프론트 정적 폴더에 동기화해두는 것이 가장 빠릅니다.

1. (권장) SSH 키 준비 후 1회 등록
2. 아이콘 동기화 실행

```bash
cd NetAlly

# 예시: PNETLab 호스트에서 test_nso.unl이 참조하는 아이콘을 레포로 복사
PNETLAB_INVENTORY_BACKEND=labfs_ssh \
PNETLAB_SSH_HOST=192.168.50.60 \
PNETLAB_SSH_USER=root \
PNETLAB_SSH_KEY_PATH=~/.ssh/netally_pnetlab \
PNETLAB_LAB_NAME=test_nso \
uv run python scripts/pnetlab_sync_icons.py
```

동기화된 아이콘은 `NetAlly/frontend/public/pnetlab-icons/`에 저장되며,
프론트는 `/pnetlab-icons/<icon_name>`을 우선 사용합니다(실패 시 `/api/pnetlab/icon/<icon_name>`로 fallback).

추가 옵션:
- 출력 폴더를 바꾸고 싶으면 `PNETLAB_ICON_OUT_DIR=/path/to/pnetlab-icons`를 지정할 수 있습니다.

### MCP-lite 호환/에러 계약

- Deprecated wrapper 6개는 1차 안정화 단계에서 유지:
  - `network_query`, `network_verify`, `lab_manage`, `scan_and_sync`, `check_logs`, `lab_bootstrap`
- I/O 계약:
  - `check_logs`는 legacy와 동일하게 문자열(`str`) 반환
  - 나머지 5개 wrapper는 JSON 객체(`Dict[str, Any]`) 반환
- mutation 차단 시 응답 계약:
  - `error`: 사람이 읽을 수 있는 차단 사유
  - `code`: `mutations_blocked`
  - `result.blocked`: `true`

### 데모 운영 모드 (Settings UI)

- Settings > API Connections에서 아래 항목을 런타임 제어 가능:
  - `Tool Backend` (`mcp` | `legacy`)
  - `MCP Server URL`
  - `Allow MCP Mutations`
- 권장 기본값:
  - `Tool Backend = mcp`
  - `Allow MCP Mutations = false`
- 변경성 작업이 필요할 때만 `Allow MCP Mutations = true`로 잠시 전환하고, 작업 직후 `false`로 복귀

---

## 🚑 데모 장애 대응

1. `/api/health` 확인 (`tool_backend`, `mcp_health.ok` 체크)
2. Settings에서 `Tool Backend=legacy`로 전환해 즉시 서비스 복구
3. `MCP Server URL`을 점검/수정 후 `Tool Backend=mcp`로 복귀
4. `/api/settings`와 read-only tool 1회 호출로 정상 동작 확인

---

## ✅ 테스트 실행

```bash
# 개발/테스트 의존성 동기화
uv sync --extra dev

# 1) 백엔드 회귀 테스트 (MCP 22개/게이트/호환/SSE 포함)
uv run pytest -q tests/

# 2) 프론트 E2E 스모크 (별도 터미널)
cd frontend
npm ci
npx playwright install --with-deps
npm run test:e2e
# 디버깅 시: npm run test:e2e:headed
```

### 데모 전 최소 점검 순서

1. `uv run pytest -q tests/` 통과 확인
2. `cd frontend && npm run test:e2e` 통과 확인
3. `./scripts/demo_precheck.sh` 실행 후 PASS 확인
4. `/api/health`, `/api/settings` 수동 재확인 후 데모 진행

### 원클릭 데모 실행 (로컬)

```bash
cd NetAlly
chmod +x scripts/demo_up_local.sh scripts/demo_precheck.sh
./scripts/demo_up_local.sh
```

- 기본 동작:
  - backend(`8111`) + frontend(`3000`) 동시 실행
  - 준비 완료 후 `demo_precheck.sh` 자동 실행
- 종료:
  - 터미널에서 `Ctrl+C`
- 포트/호스트 변경 예시:
  - `NETALLY_HOST=0.0.0.0 NETALLY_BACKEND_PORT=8112 NETALLY_FRONTEND_PORT=3001 ./scripts/demo_up_local.sh`

---

## 🎯 아키텍처

```mermaid
graph LR
    User([사용자]) --> FE[React 프론트엔드]
    
    subgraph NetAlly
        FE --> BE[FastAPI 백엔드]
        BE --> Agent[LangGraph 에이전트]
        
        Agent --> Tools{도구}
        Tools --> Batfish[Batfish]
        Tools --> NSO[NSO]
        Tools --> PNETLab[PNETLab]
    end
    
    Agent --> |SSE| FE
    
    style Batfish fill:#4CAF50
    style NSO fill:#2196F3
    style PNETLab fill:#FF9800
```

### 핵심 철학: "Insight over Data"

- 단순한 데이터 나열이 아닌, **분석된 인사이트**를 제공합니다.
- Batfish의 결정론적 분석으로 **정확한 문제 원인**을 진단합니다.
- LLM은 **해결책 제안**과 **복잡한 질문 처리**에 집중합니다.

---

## 📚 Documentation

| 문서                                                            | 설명                               |
| --------------------------------------------------------------- | ---------------------------------- |
| [README_ko.md](docs/README_ko.md)                               | 문서 허브(처음 시작/학습 경로/용어) |
| [architecture.md](docs/architecture.md)                         | 시스템 아키텍처, 데이터 흐름       |
| [dashboard_design.md](docs/dashboard_design.md)                 | 검증 대시보드 기획 및 UI/UX        |
| [dashboard_implementation.md](docs/dashboard_implementation.md) | 대시보드 구현 명세 (API, 컴포넌트) |
| [frontend.md](docs/frontend.md)                                 | 프론트엔드 컴포넌트 가이드         |
| [web_architecture_beginner_ko.md](docs/web_architecture_beginner_ko.md) | 비웹 개발자용 웹 구조 입문 가이드 |
| [onboarding_30min_code_walkthrough_ko.md](docs/onboarding_30min_code_walkthrough_ko.md) | 30분 코드 화면 온보딩 가이드 |
| [pnetlab_deployment_guide.md](docs/pnetlab_deployment_guide.md) | PNETLab Docker Node 배포 가이드 |
| [pnetlab_wiring_runbook_ko.md](docs/pnetlab_wiring_runbook_ko.md) | NetAlly-NSO-Chromebook 실전 배선/운영 런북 |
| [testing_runbook_ko.md](docs/testing_runbook_ko.md)             | 실행/테스트/데모 점검 런북 |
| [backend_api.md](docs/backend_api.md)                           | REST API 레퍼런스                  |
| [setup_guide.md](docs/setup_guide.md)                           | Docker 배포 및 환경 설정           |

처음 시작은 `docs/README_ko.md`를 권장합니다.

---

## 🧪 평가 (NetConfigQA Benchmark)

NetAlly는 NetConfigQA 벤치마크에서 네트워크 구성 QA 성능을 테스트할 수 있습니다.

```bash
# 샘플 10개로 빠른 테스트
uv run python -m eval.runner --dataset ../Data/Dataset/NetConfigQA2.csv --sample 10

# 전체 평가
uv run python -m eval.runner --dataset ../Data/Dataset/NetConfigQA2.csv
```

---

## 🤝 관련 프로젝트

- **[core-batfish](../Make_Dataset/src/core_batfish/)**: Batfish 분석 라이브러리 (L4-L7 Analyzer)
- **[NetConfigQA](../README.md)**: 네트워크 구성 QA 벤치마크 데이터셋 생성

---

## 📝 로드맵

- [x] Verification Dashboard (v2.0)
- [x] 하이브리드 분석 엔진 (Batfish + LLM)
- [x] SSE 스트리밍 채팅
- [x] PNETLab 좌표 동기화 (토폴로지 위치 가져오기)
- [x] 도달성 오버레이 (Reachability Overlay - 통신 가능 경로 색상 표시)
- [x] 장비 상세 정보 패널 (Device Detail Panel)
- [x] Multi-language Support (EN/KO)
- [ ] Multi-Snapshot 비교 분석

---

## 📜 라이선스

This project is licensed under the MIT License.

---

<div align="center">

**NetAlly - Your Intelligent Network Ally** 🚀

*복잡한 네트워크, 똑똑한 비서와 함께라면 간단해집니다.*

</div>
