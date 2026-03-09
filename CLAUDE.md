# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Summary

GIA는 두 가지 핵심 산출물로 구성된 네트워크 연구 프로젝트입니다:

1. **NetConfigQA2.0** — LLM의 네트워크 설정 이해 능력을 평가하는 벤치마크 데이터셋 (1,128 QA, L1~L5 난이도, 127 메트릭)
2. **NetAlly** — Batfish/NSO/PNETLab 도구를 호출하는 Multi-Agent System (FastAPI + LangGraph + MCP)

논문 목표: IEEE TNMS. 핵심 질문은 "LLM이 .cfg 파일로부터 네트워크 동작을 추론(Behavioral Inference)할 수 있는가?"

## Active Directories

- `Make_Dataset/` — QA 데이터셋 생성 파이프라인 (Batfish 기반)
- `NetAlly/` — Multi-Agent System 웹 애플리케이션
- `Data/Pnetlab/` — 토폴로지별 configs/datasets (Research_Institute_Internal_DC가 주력)
- `docs/` — 난이도 철학, 메트릭 분석, TA-Acc 등 프로젝트 문서
- `NetAlly/docs/IEEE/` — 논문 준비 문서 허브 (README.md가 인덱스)

**무시할 디렉토리**: `NetConfigQA1/`, `NetConfigQA3/`, `MultiAgent/`, `Evaluation/`, `Experiment/` — 레거시, 사용 안함

## Build & Run Commands

### Dataset Generation (Make_Dataset)
```bash
# 전체 L1-L5 데이터셋 생성 (Batfish 컨테이너 실행 필수)
python Make_Dataset/src/main_batfish.py \
  --lab-path Data/Pnetlab/Research_Institute_Internal_DC \
  --policies Make_Dataset/policies.json

# 데이터 준비 순서 (PNETLab 환경에서)
python Make_Dataset/src/1-SSH_Enable.py       # PNETLab 장비 SSH 활성화
python Make_Dataset/src/2-NSO_Register.py     # NSO 장비 등록
python Make_Dataset/src/3-Config_Export_Batfish.py  # Config 추출→Batfish 스냅샷
```

### NetAlly (Multi-Agent System)
```bash
# 의존성 설치
cd NetAlly && uv sync --extra dev
cd frontend && npm ci && cd ..

# 로컬 실행
./scripts/demo_up_local.sh    # Backend :8111 + Frontend :3000

# Docker
cd NetAlly && docker compose build netally && docker compose up -d

# 테스트
cd NetAlly && uv run pytest -q tests                          # 백엔드 전체
cd NetAlly && uv run pytest tests/test_chat_sse_contract.py   # 단일 테스트
cd NetAlly/frontend && npx playwright install --with-deps && npm run test:e2e  # E2E

# 데모 전 점검
cd NetAlly && ./scripts/demo_precheck.sh
```

### Batfish (필수 인프라)
```bash
docker run -d -p 9997:9997 -p 9996:9996 --name batfish batfish/batfish
```

## Architecture

### Dataset Pipeline (Dual-Path)
```
.cfg files → UniversalParser (Batfish static analysis) → Static Facts JSON
  ├─ Path A (L1-L3): RuleBasedGenerator + policies.json → Scope Expansion → BuilderCore.compute()
  └─ Path B (L4-L6): BatfishBuilder → l4_analyzer (traceroute) / l5_analyzer (fork_snapshot) / l6_analyzer (fault injection)
→ Dataset Assembler → CSV + JSON
```

Key files:
- `Make_Dataset/src/main_batfish.py` — 진입점 (735 lines)
- `Make_Dataset/src/core_batfish/builder_core.py` — L1-L3 핵심 로직 (2148 lines)
- `Make_Dataset/src/core_batfish/l4_analyzer.py` — Batfish traceroute/reachability
- `Make_Dataset/src/core_batfish/l5_analyzer.py` — fork_snapshot + differentialReachability
- `Make_Dataset/policies.json` — 127개 메트릭 정의 (카테고리, 레벨, 질문 템플릿, scope)

### NetAlly Architecture
```
User → Frontend (React+Vite :3000) → POST /api/chat (SSE) →
  main.py (FastAPI, 2483 lines) →
    agent/runtime.py (런타임 선택: single_executor | team_multi_adapter | legacy_graph) →
      Orchestrator (질문 분석, 스킬 선택) →
        Executor (도구 호출) →
          agent/clients/batfish.py  (Batfish API)
          agent/clients/nso.py     (NSO RESTCONF)
          agent/clients/pnetlab.py (PNETLab API / LabFS)
```

- `agent/mcp_server.py` — MCP 도구 카탈로그 (16 core + 6 compat wrappers)
- `agent/graph.py` — LangGraph 상태 그래프
- `agent/onboarding.py` — scan_and_sync (PNETLab→NSO 자동 온보딩)
- `agent/pnetlab_labfs.py` — 쿠키 없는 LabFS 토폴로지 파싱
- SSE 이벤트 흐름: `planning → tool_call → tool_output → answer → complete`

### Data Layout
```
Data/Pnetlab/
  Research_Institute_Internal_DC/  ← 주력 토폴로지 (10 nodes: 4 Leaf + 4 P + 2 PE)
    configs/*.cfg                  ← Cisco IOS 설정 파일
    Dataset/                       ← 생성된 데이터셋 (CSV/JSON + facts + verification)
  L2VPN/                           ← 2번째 토폴로지 (8 nodes, 확장 후보)
```

## Environment Variables (NetAlly)

| Variable | Purpose | Default |
|---|---|---|
| `OPENAI_API_KEY` | LLM API | required |
| `BATFISH_HOST` | Batfish 주소 | `batfish` (compose) / `localhost` |
| `NSO_BASE_URL` | NSO RESTCONF | `http://host.docker.internal:8080/restconf` |
| `NETALLY_AGENT_BACKEND` | 런타임 모드 | `single_executor` |
| `NETALLY_TOOL_BACKEND` | 도구 백엔드 | `mcp` |
| `NETALLY_MCP_ALLOW_MUTATIONS` | 변경 작업 허용 | `false` |
| `PNETLAB_INVENTORY_BACKEND` | 토폴로지 소스 | `labfs_local` |

## Difficulty Levels (NetConfigQA2.0)

| Level | Cognitive Ability | Engine | Example |
|---|---|---|---|
| L1 | Fact extraction | Config parsing | "PE1의 hostname은?" |
| L2 | Aggregation | Facts traversal | "SSH 활성화 장비 수?" |
| L3 | Cross-comparison | BuilderCore | "iBGP full-mesh 완성?" |
| L4 | Simulation | Batfish traceroute | "10.0.0.1→192.168.1.1 경로?" |
| L5 | What-If | fork_snapshot + diff | "P1-P2 다운 시 영향?" |
| L6 | Diagnosis | Fault injection | 확장 항목 (논문 범위 외) |

## Evaluation Metric: Type-Aware Accuracy (TA-Acc)

BERTScore는 네트워크 데이터에서 변별력이 없음 (모든 레벨에서 0.9+). TA-Acc는 answer_type별 맞춤 비교:
- `set_str` → F1 Score (순서 무관)
- `path` → Ordered Exact Match
- `scalar_str/int` → 정규화 후 Exact Match
- `bool` → 정규화 비교
- `map_str_int` → Key-Value F1

## Language

프로젝트 문서와 코드 주석은 한국어가 기본입니다. 논문 본문과 Abstract은 영어.
