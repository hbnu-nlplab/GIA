# NetAlly Agent: Evidence-First Network Analysis

NetAlly is a next-generation network management agent that combines LLM reasoning with formal verification (Batfish) and automation (NSO) to provide an **Evidence-First** analytical experience.

---

## 📚 Documentation
- [**Architecture**](docs/architecture.md): System design, agent workflows, and data pipelines.
- [**Frontend Specification**](docs/frontend.md): UI/UX design (Zinc/Emerald), Zustand state, and React Flow.
- [**Backend API**](docs/backend_api.md): SSE Chat streaming and Topology API.
- [**Setup & Deployment**](docs/setup_guide.md): Docker installation and environment configuration.

---

## ⚡ Core Features
- **Evidence Dashboard**: Real-time capture of tool verification results.
- **Interactive Topology**: Live L3 visualization powered by React Flow and Batfish.
- **Multi-Agent reasoning**: Orchestrator-Executor logic for complex problem solving.
- **Hybrid Onboarding**: Automatic synchronization between PNETLab and NSO.
1,300+ QA pairs)

## 🚀 Quick Start

### 1. 설치 및 가상환경 설정 (uv 권장)

LangGraph Studio는 Python 3.11 이상이 필요합니다. `uv`를 사용하면 편리하게 관리할 수 있습니다.

```bash
cd NetAlly
# Python 3.12 가상환경 생성 및 활성화
uv venv --python 3.12
. .venv/bin/activate

# 의존성 설치
uv pip install -e .
uv pip install -U "langgraph-cli[inmem]"
```

### 2. 환경 설정

```bash
cp .env.example .env
# .env 파일에서 API 키 설정
```

### 3. LangGraph Studio 실행

```bash
# 가상환경 활성화 (필요시)
. .venv/bin/activate

# Studio 실행
langgraph dev
```

브라우저에서 `http://localhost:8000`으로 접속하면 LangGraph Studio UI를 볼 수 있습니다.

### 4. 평가 실행

```bash
# 샘플 10개로 빠른 테스트
python -m eval.runner --dataset ../Data/Dataset/NetConfigQA2.csv --sample 10

# 전체 평가
python -m eval.runner --dataset ../Data/Dataset/NetConfigQA2.csv

# 특정 레벨만 평가
python -m eval.runner --dataset ../Data/Dataset/NetConfigQA2.csv --levels L1 L2

# vLLM 백엔드 사용
python -m eval.runner --dataset ../Data/Dataset/NetConfigQA2.csv --backend vllm --model gpt-oss-20b
```

## 📁 프로젝트 구조

```
NetAlly/
├── langgraph.json          # LangGraph Studio 설정
├── pyproject.toml          # 프로젝트 설정
├── .env.example            # 환경변수 예시
│
├── agent/                  # 에이전트 모듈
│   ├── __init__.py
│   ├── graph.py            # LangGraph 에이전트 그래프
│   ├── tools.py            # MCP 도구 (network_query, network_verify, lab_manage)
│   ├── llm_provider.py     # 하이브리드 LLM (OpenAI, vLLM, Ollama)
│   └── state.py            # AgentState 정의
│
├── eval/                   # 평가 모듈
│   ├── __init__.py
│   ├── dataset_adapter.py  # NetConfigQA2.csv 어댑터
│   ├── scorer.py           # Type-aware 채점기
│   └── runner.py           # 평가 실행기
│
└── results/                # 평가 결과 저장
```

## 🛠️ 지원 LLM 백엔드

| 백엔드 | 모델 예시 | 설정 |
|--------|----------|------|
| **OpenAI API** | gpt-4o-mini, gpt-4o | `OPENAI_API_KEY` |
| **vLLM** | gpt-oss-20b | `VLLM_BASE_URL` |
| **Ollama** | qwen2.5:32b | `OLLAMA_API_URL` |

## 📊 평가 메트릭

- **Overall Accuracy**: 전체 정확도
- **By Level**: L1-L5 레벨별 정확도
- **By Answer Type**: text, numeric, set, map, boolean 타입별 정확도
- **Latency**: 평균 응답 시간

## 🔧 MCP 도구

| 도구 | 설명 | 연동 |
|------|------|------|
| `network_query` | NSO에서 장비 설정 조회 | NetConfigQA3 |
| `network_verify` | Batfish로 네트워크 속성 검증 | NetConfigQA3 |
| `lab_manage` | PNETLab 실험실 관리 | NetConfigQA3 |

## 📚 관련 프로젝트

- [NetConfigQA2.0](../README.md) - Q&A 데이터셋 생성
- [NetConfigQA3](../NetConfigQA3/README.md) - MCP 도구 및 에이전트

## 📝 TODO

- [ ] NetConfigQA3 MCP 서버 연동
- [ ] Topology 스케일 테스트 (8/16/32대)
- [ ] LangSmith 트레이싱 연동 확인
- [ ] 결과 분석 스크립트 추가
