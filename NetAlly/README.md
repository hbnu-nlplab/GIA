# NetAlly

네트워크 설정 분석을 위한 Multi-Agent System.
LLM이 Batfish/NSO/PNETLab 도구를 호출하여 네트워크 질문에 근거 기반 답변을 제공합니다.

```
사용자: "P1에서 PE3까지 경로는?"
  → LLM이 batfish_traceroute 도구 자동 호출
  → Batfish 분석 결과를 해석하여 답변
  → 토폴로지 맵에서 경로 실시간 하이라이트
```

---

## 핵심 기능

- **SSE 채팅**: `planning → tool_call → tool_output → answer` 실시간 스트리밍
- **16개 MCP 도구**: Batfish (traceroute, reachability, BGP, ACL) + NSO (config, interfaces, routing)
- **토폴로지 시각화**: React Flow 기반 맵 + LLM 답변 연동 하이라이트 (경로 애니메이션, 포커스 글로우)
- **PNETLab LabFS**: 쿠키 없이 `.unl` 직접 파싱으로 안정적 토폴로지 복제
- **실험 평가**: NetConfigQA2.0 벤치마크 배치 실행기 내장

---

## 빠른 시작 (로컬 개발)

### 요구사항

| 소프트웨어 | 버전 | 용도 |
|-----------|------|------|
| Python | ≥3.10 (권장 3.12+) | 백엔드 |
| uv | latest | Python 패키지 관리 |
| Node.js | ≥18 | 프론트엔드 |
| Docker | latest | Batfish 컨테이너 |

### 1단계: 의존성 설치

```bash
cd NetAlly

# Python 백엔드
uv sync --extra dev

# React 프론트엔드
cd frontend && npm ci && cd ..
```

### 2단계: 환경 설정

```bash
# .env 생성 (Tailscale 분산 구성 기준)
cp .env.tailscale .env
```

`.env` 필수 설정:

```bash
# ── LLM (택 1) ──
# OpenAI API:
NETALLY_EXECUTOR_LLM_BACKEND=openai
NETALLY_EXECUTOR_LLM_MODEL=gpt-4o-mini
OPENAI_API_KEY=sk-xxx

# 또는 로컬 vLLM:
# NETALLY_EXECUTOR_LLM_BACKEND=vllm
# VLLM_BASE_URL=http://localhost:8000/v1

# ── Batfish (로컬 Docker) ──
BATFISH_HOST=localhost:9997
BATFISH_SNAPSHOT=LabB_NCN_Basic_SP_20nodes
BATFISH_NETWORK=LabB_NCN_Basic_SP_20nodes
AUTO_INIT_BATFISH=true

# ── PNETLab (Tailscale 경유) ──
PNETLAB_SSH_HOST=100.85.92.121
PNETLAB_LAB_NAME=LabB_NCN_Basic_SP

# ── NSO (PNETLab 내 Docker 노드) ──
NSO_BASE_URL=http://10.10.10.100:8080/restconf

# ── 에이전트 런타임 ──
NETALLY_AGENT_BACKEND=single_executor
NETALLY_TOOL_BACKEND=mcp
NETALLY_MCP_ALLOW_MUTATIONS=false
```

### 3단계: Batfish 컨테이너 시작

```bash
docker run -d -p 9997:9997 -p 9996:9996 --name batfish batfish/batfish
```

### 4단계: Config 파일 배치

```bash
# Config Generator 출력물을 Batfish 스냅샷 디렉토리에 복사
mkdir -p ../Data/Pnetlab/LabB_NCN_Basic_SP_20nodes/configs
cp ../Make_Dataset/config_generator/output/LabB_NCN_Basic_SP_20nodes/configs/*.cfg \
   ../Data/Pnetlab/LabB_NCN_Basic_SP_20nodes/configs/
```

### 5단계: 실행

```bash
# 원클릭 (백엔드 :8111 + 프론트엔드 :3000)
./scripts/demo_up_local.sh

# 또는 수동 (터미널 2개)
# 터미널 1:
uv run python main.py

# 터미널 2:
cd frontend && npm run dev
```

### 6단계: 브라우저 접속

```
http://localhost:3000
```

1. **Topology 탭** → 네트워크 맵 확인 (노드 호버 시 툴팁)
2. **Chat 탭** → 질문 입력
3. 맵에서 도구 호출 결과 실시간 하이라이트 확인

---

## 시각화 기능

### LLM 답변 연동 하이라이트

| 모드 | 트리거 | 시각 효과 |
|------|--------|----------|
| **Path** (녹색) | traceroute, reachability 도구 | 경로 노드/엣지 녹색 글로우 + dash flow 애니메이션 |
| **Focus** (주황) | 장비 조회, 인터페이스 쿼리 | 대상 노드 주황 pulse 글로우 |

- **호버 툴팁**: 노드 위에 마우스 → hostname, IP, 타입, 하이라이트 이유 표시
- **범례**: 좌하단에 현재 하이라이트 모드/제목 표시 + 클리어 버튼
- **SSE 연동**: `tool_call` → 대상 노드 하이라이트 → `tool_output` → 경로 완성 → 애니메이션

### 시각화 시나리오 예시

```
질문: "P1에서 PE3까지 traceroute 해줘"
  → batfish_traceroute(src=P1, dst=PE3) 호출
  → 결과: P1 → P3 → P5 → PE3
  → 맵: 해당 경로 녹색 dash flow 애니메이션
  → 나머지 노드: dim 처리

질문: "P3-P5 링크 장애 시 영향은?"
  → batfish_snapshot_diff(failure: P3-P5) 호출
  → 장애 링크: 빨간 X 표시
  → 대체 경로: 녹색 애니메이션
```

---

## 에이전트 아키텍처

```
User → Frontend (React :3000)
  → POST /api/chat (SSE)
  → main.py (FastAPI)
    → SingleExecutorRuntime
      → LLM.ainvoke(messages + tools)
        → tool_calls 추출
        → _invoke_tool() ← 타이밍 로그 (TOOL_OK/TOOL_FAIL)
          → MCP Server (localhost:8811)
            → batfish_traceroute() → Batfish Docker
            → nso_get_interfaces() → NSO RESTCONF
        → tool_output → LLM 재호출
      → answer 생성
    → SSE 스트리밍 (planning/tool_call/tool_output/tool_error/answer/complete)
  → Frontend: 채팅 표시 + 토폴로지 맵 하이라이트
```

### 런타임 모드

| 환경변수 | 값 | 용도 |
|---------|---|------|
| `NETALLY_AGENT_BACKEND` | `single_executor` (기본) | LLM + 도구 직접 호출 |
| | `legacy_graph` | LangGraph Orchestrator→Executor |
| | `team_multi_adapter` | 외부 Multi-Agent |
| `NETALLY_TOOL_BACKEND` | `mcp` (기본) | MCP 서버 경유 16개 도구 |
| | `legacy` | LangChain in-process 도구 |
| | `none` | 도구 없음 (Pure MAS / Exp.4용) |

### MCP 도구 카탈로그 (16개)

**Batfish (8개):**
`batfish_reachability`, `batfish_traceroute`, `batfish_bgp_sessions`,
`batfish_route_table`, `batfish_advanced_verify`, `batfish_snapshot_diff`,
`batfish_snapshot_create`, `batfish_apply_config`

**NSO (5개):**
`nso_list_devices`, `nso_get_device_info`, `nso_get_interfaces`,
`nso_get_routing`, `nso_get_logs`

**Lab (3개):**
`lab_show_inventory`, `lab_get_status`, `lab_export_configs`

---

## 실험 평가 (IEEE TNSM)

NetConfigQA2.0 벤치마크 실험용 도구가 내장되어 있습니다.

### 실험 구성

| 실험 | 도구 | 런타임 | 실행 방법 |
|------|------|--------|----------|
| **Exp.2** (Single LLM) | `run_eval_vllm_offline.py` | vLLM 배치 | .cfg context 직접 주입 |
| **Exp.4** (Pure MAS) | `eval/experiment_runner.py` | `TOOL_BACKEND=none` | 도구 없이 MAS 구조만 |
| **Exp.5** (NetAlly MAS) | `eval/experiment_runner.py` | `TOOL_BACKEND=mcp` | 16개 도구 활용 |

### 실험 실행

```bash
# Exp.4: Pure MAS (도구 없음)
NETALLY_TOOL_BACKEND=none python -m eval.experiment_runner \
  --dataset ../Data/Pnetlab/LabB_.../Dataset/dataset.csv \
  --output results/exp4_pure_mas.json

# Exp.5: NetAlly MAS (도구 포함)
NETALLY_TOOL_BACKEND=mcp python -m eval.experiment_runner \
  --dataset ../Data/Pnetlab/LabB_.../Dataset/dataset.csv \
  --output results/exp5_netally_mas.json
```

### 채점 + 시각화

```bash
# TA-Acc 채점 (analyze_results.py와 호환)
cd ../Experiment/code/NetConfigQA2_2/
python analyze_results.py results/exp5_netally_mas.json
python make_figure.py results_analyzed_*.json
```

---

## Lab 배포 (Config Generator Labs)

Config Generator로 생성한 .cfg를 PNETLab에 자동 배포하는 스크립트:

```bash
cd ../Make_Dataset/src

# Step 1: Telnet으로 .cfg 자동 Push (20개 장비 ~5분)
python -m deploy.1_push_configs

# Step 2: 연결 + 프로토콜 검증
python -m deploy.2_verify

# Step 3: NSO RESTCONF 등록
python -m deploy.3_register_nso
```

설정: `Data/Pnetlab/LabB_NCN_Basic_SP_20nodes/device_info.json`

---

## 테스트

```bash
# 백엔드 단위 테스트
uv run pytest -q tests

# 프론트엔드 E2E
cd frontend && npx playwright install --with-deps && npm run test:e2e

# 데모 전 점검
./scripts/demo_precheck.sh
```

---

## 환경변수 레퍼런스

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `OPENAI_API_KEY` | (필수) | LLM API 키 |
| `NETALLY_AGENT_BACKEND` | `single_executor` | 에이전트 런타임 |
| `NETALLY_TOOL_BACKEND` | `mcp` | 도구 백엔드 (`mcp`/`legacy`/`none`) |
| `NETALLY_MCP_ALLOW_MUTATIONS` | `false` | 변경 도구 차단 |
| `BATFISH_HOST` | `localhost:9997` | Batfish 주소 |
| `BATFISH_SNAPSHOT` | - | Batfish 스냅샷 이름 |
| `AUTO_INIT_BATFISH` | `true` | 채팅 시 자동 스냅샷 초기화 |
| `NSO_BASE_URL` | - | NSO RESTCONF URL |
| `PNETLAB_SSH_HOST` | - | PNETLab VM IP (Tailscale) |
| `PNETLAB_LAB_NAME` | - | PNETLab 랩 이름 |
| `PNETLAB_INVENTORY_BACKEND` | `labfs_ssh` | 토폴로지 소스 |
| `PNETLAB_DEVICE_INFO_AUTOGEN` | `false` | 자동 온보딩 비활성화 |

---

## 프로젝트 구조

```
NetAlly/
├── main.py                    # FastAPI 엔드포인트 + SSE 채팅
├── agent/
│   ├── runtime.py             # 에이전트 런타임 (SingleExecutor/LegacyGraph/TeamMulti)
│   ├── graph.py               # LangGraph 상태 그래프 (lazy init)
│   ├── mcp_server.py          # MCP 도구 카탈로그 (16 core + 6 compat)
│   ├── mcp_client.py          # MCP 클라이언트
│   ├── llm_provider.py        # LLM 백엔드 추상화 (OpenAI/vLLM/Ollama)
│   ├── onboarding.py          # scan_and_sync (deprecated → deploy 스크립트 사용)
│   ├── pnetlab_labfs.py       # PNETLab LabFS 파싱
│   └── clients/
│       ├── batfish.py          # Batfish API 클라이언트
│       ├── nso.py              # NSO RESTCONF 클라이언트
│       └── pnetlab.py          # PNETLab API 클라이언트
├── eval/
│   ├── experiment_runner.py    # Exp.4/5 배치 실행기
│   ├── runner.py               # 기본 평가 러너
│   ├── scorer.py               # 런타임 경량 채점
│   └── dataset_adapter.py      # NetConfigQA2 어댑터
├── frontend/
│   └── src/components/
│       ├── ChatPanel.tsx        # SSE 채팅 + viz 연동
│       ├── TopologyPanel.tsx    # React Flow 토폴로지 맵 + 범례
│       ├── DeviceNode.tsx       # 장비 노드 (호버 툴팁)
│       └── InterfaceEdge.tsx    # 엣지 (경로 애니메이션)
├── tests/
├── scripts/
│   ├── demo_up_local.sh        # 원클릭 실행
│   └── demo_precheck.sh        # 데모 전 점검
└── docs/
```

---

## 트러블슈팅

| 증상 | 원인 | 해결 |
|------|------|------|
| 앱 시작 안 됨 | API 키 미설정 | `.env`에 `OPENAI_API_KEY` 확인 |
| 도구 호출 실패 | Batfish 미실행 | `docker ps \| grep batfish` 확인 |
| 맵에 노드 없음 | 스냅샷 미초기화 | `AUTO_INIT_BATFISH=true` + configs/ 확인 |
| "Snapshot not initialized" | .cfg 파일 없음 | Step 4(Config 배치) 확인 |
| 하이라이트 안 됨 | tool_backend 설정 | `NETALLY_TOOL_BACKEND=mcp` 확인 |
| mutation 차단 | 읽기 전용 모드 | `NETALLY_MCP_ALLOW_MUTATIONS=false` 의도적 |
| NSO 연결 실패 | NSO 미시작 | PNETLab에서 NSO 노드 시작 + `ncs` 실행 |

---

## 라이선스

MIT License
