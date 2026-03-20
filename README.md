# NetConfigQA2

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/hbnu-kilab/GIA) [![2025HCLT](https://img.shields.io/badge/2025-HCLT-blue)](https://sites.google.com/view/hclt-2025/) [![PnetLab](https://img.shields.io/badge/PnetLab-blue)](https://pnetlab.com/pages/main) [![Batfish](https://img.shields.io/badge/Batfish-Network%20Analysis-green)](https://www.batfish.org/)

네트워크 장비 설정(Configuration)으로부터 **Q&A 데이터셋을 자동 생성**하고, **Batfish 기반 네트워크 검증 질문**을 포함한 다층 난이도(L1-L5) 데이터셋을 구축하는 연구 프로젝트입니다.

---

- **자동화된 Ground Truth 생성**: Batfish 네트워크 분석 엔진을 활용하여 100% 재현 가능한 정답 생성
- **다층 난이도 체계 (L1-L5)**: 단순 설정 조회부터 장애 시나리오 추론까지 5단계 복잡도
- **하이브리드 분석 엔진**: 규칙 기반(Regex) 파서 + Batfish 시뮬레이션 결합
- **구조화된 정답 형식**: JSON 기반 정답으로 정확한 자동 채점 가능

---

## 🔧 사전 요구사항 (Prerequisites)

본 프로젝트를 실행하기 위해서는 다음 환경 설정이 필요합니다.

| 구성 요소       | 설명                                  | 비고                                |
| --------------- | ------------------------------------- | ----------------------------------- |
| **PnetLab**     | 가상 네트워크 토폴로지 구성 환경      | [공식 사이트](https://pnetlab.com/) |
| **Cisco NSO**   | 네트워크 장비 설정 수집 및 동기화     | Docker 컨테이너 권장                |
| **Batfish**     | 네트워크 설정 분석 및 시뮬레이션 엔진 | Docker 컨테이너 필수                |
| **Python 3.9+** | 데이터셋 생성 스크립트 실행 환경      | `uv` 권장 (`pip` 호환)             |
| **Node.js**     | 프론트엔드 실행 환경 (NetAlly)       | `npm` 사용                         |

### Batfish 설치 (Docker)

```bash
docker pull batfish/batfish
docker run -d -p 9997:9997 -p 9996:9996 --name batfish batfish/batfish
```

### NSO 설치 (Docker)

```bash
docker pull cisco-nso-dev:latest
docker run -d -p 8080:8080 -p 8888:8888 --name cisco-nso-dev cisco-nso-dev
```

---

## 🚀 빠른 시작 (Quick Start)

### 1. 환경 설정

```bash
# Repo Clone
git clone https://github.com/hbnu-kilab/GIA.git
cd GIA

# 1. Python 환경 구축 (uv 권장)
# uv가 없다면: curl -LsSf https://astral.sh/uv/install.sh | sh
uv venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
uv pip install -r requirements.txt

# 2. Frontend 환경 구축 (Node.js)
cd NetAlly/frontend
npm install
```

### 2. 데이터 준비

두 가지 방식이 있습니다:

#### 방식 A: Config Generator (Lab-B/C/D — 권장)

```bash
# Config 자동 생성
python Make_Dataset/config_generator/generator.py \
  --topology Make_Dataset/config_generator/topologies/lab_b_20nodes.yaml

# PNETLab에 자동 배포 (telnet push + 검증 + NSO 등록)
cd Make_Dataset/src
python -m deploy.1_push_configs    # .cfg 자동 적용
python -m deploy.2_verify          # OSPF/BGP/MPLS 검증
python -m deploy.3_register_nso    # NSO RESTCONF 등록
```

> 상세: [Config Generator 배포 가이드](Make_Dataset/config_generator/docs/deployment_guide.md)

#### 방식 B: 수동 (Lab-A — 기존 방식)

```bash
cd Make_Dataset/src
python 1-SSH_Enable.py             # PnetLab 장비 SSH 활성화
python 2-NSO_Register.py           # NSO 장비 등록 (deprecated → deploy/3 권장)
python 3-Config_Export_Batfish.py  # Config 추출
```

### 3. 데이터셋 생성

```bash
# Lab-A (10 nodes)
python Make_Dataset/src/main_batfish.py \
  --lab-path Data/Pnetlab/Research_Institute_Internal_DC \
  --policies Make_Dataset/policies.json

# Lab-B (20 nodes)
python Make_Dataset/src/main_batfish.py \
  --lab-path Data/Pnetlab/LabB_NCN_Basic_SP_20nodes \
  --policies Make_Dataset/policies.json

# Lab-C (30 nodes)
python Make_Dataset/src/main_batfish.py \
  --lab-path Data/Pnetlab/LabC_NCN_Security_L2VPN_30nodes \
  --policies Make_Dataset/policies.json

# Lab-D (40 nodes)
python Make_Dataset/src/main_batfish.py \
  --lab-path Data/Pnetlab/LabD_NCN_MultiAS_Complex_40nodes \
  --policies Make_Dataset/policies.json
```

**출력**: `Data/Pnetlab/[LabName]/Dataset/<timestamp>/`

| 파일 | 내용 |
|------|------|
| `*_dataset_batfish_*.csv` | 전체 Q&A 데이터셋 (question_type 컬럼 포함) |
| `*_dataset_batfish_*.json` | 구조화 데이터셋 (JSON) |
| `*_quality_report.md` | 품질 게이트 리포트 |
| `*_statistics.md` | 통계 요약 |
| `*_batfish_facts_*.json` | 파싱된 네트워크 팩트 |

---

## 📊 난이도 체계 (Metric Levels)

| Level  | 정의                | 분석 엔진             | 예시 질문                                |
| ------ | ------------------- | --------------------- | ---------------------------------------- |
| **L1** | 단일 장비 설정 조회 | Regex + Batfish       | "R1의 호스트네임은?"                     |
| **L2** | 복수 장비 설정 집계 | Python Logic          | "SSH가 활성화된 장비 목록은?"            |
| **L3** | 장비 간 정합성 비교 | Cross-Device          | "iBGP Full-Mesh가 완성되었는가?"         |
| **L4** | 패킷 도달성 분석    | Batfish Traceroute    | "10.0.0.1에서 10.0.0.5로 도달 가능한가?" |
| **L5** | 장애 시나리오 추론  | Batfish Snapshot Fork | "R2-R3 링크 다운 시 우회 경로는?"        |

자세한 메트릭 정의는 [METRIC_LEVEL_ANALYSIS.md](docs/METRIC_LEVEL_ANALYSIS.md) 참조.

---

## 📁 프로젝트 구조

```text
GIA/
├── Make_Dataset/                   # 데이터셋 생성 파이프라인
│   ├── src/
│   │   ├── main_batfish.py         # 메인 생성 스크립트
│   │   ├── core_batfish/           # Batfish 분석 엔진 (L1-L5)
│   │   │   ├── builder_core.py     # L1-L3 정답 생성
│   │   │   ├── l4_analyzer.py      # L4 traceroute/reachability
│   │   │   └── l5_analyzer.py      # L5 fork_snapshot/what-if
│   │   └── deploy/                 # PNETLab 자동 배포 (Lab-B/C/D)
│   │       ├── 1_push_configs.py   # Telnet config push
│   │       ├── 2_verify.py         # 연결/프로토콜 검증
│   │       └── 3_register_nso.py   # NSO RESTCONF 등록
│   ├── config_generator/           # Config 자동 생성
│   │   ├── generator.py            # YAML → .cfg 생성
│   │   ├── topologies/             # Lab-B/C/D YAML 정의
│   │   └── docs/                   # 배포 가이드, 토폴로지 시각화
│   └── policies.json               # 127개 메트릭 정의 (question_type 포함)
├── Data/Pnetlab/                   # 실험 데이터
│   ├── Research_Institute_Internal_DC/  # Lab-A (10 nodes)
│   ├── LabB_NCN_Basic_SP_20nodes/       # Lab-B (20 nodes)
│   ├── LabC_NCN_Security_L2VPN_30nodes/ # Lab-C (30 nodes)
│   └── LabD_NCN_MultiAS_Complex_40nodes/# Lab-D (40 nodes)
├── NetAlly/                        # Multi-Agent System (FastAPI + React)
│   ├── agent/runtime.py            # 에이전트 런타임
│   ├── agent/mcp_server.py         # MCP 도구 16개
│   ├── eval/experiment_runner.py   # Exp.4/5 배치 실행기
│   └── frontend/                   # React + React Flow 토폴로지
├── MultiAgent/agents_v2/           # 토론 기반 MAS (팀원 설계)
│   ├── debate1.py                  # Collector/Verifier/Synthesizer
│   ├── debate2.py                  # Supporter/Skeptic
│   └── main_netconfig.py           # NetConfigQA 실행
├── Experiment/code/NetConfigQA2_2/ # 평가 도구
│   ├── run_eval_vllm_offline.py    # Exp.2 vLLM 배치 평가
│   ├── analyze_results.py          # TA-Acc 채점 (1,211줄)
│   └── make_figure.py              # 논문 Figure 4종
└── docs/                           # 문서
```

---

## 📚 문서 (Documentation)

| 문서                                                               | 설명                              |
| ------------------------------------------------------------------ | --------------------------------- |
| [NetConfigQA 상세 문서 (KR)](docs/NetConfigQA_Documentation_KR.md) | 전체 파이프라인 및 평가 방법론    |
| [메트릭 레벨 분석](docs/METRIC_LEVEL_ANALYSIS.md)                  | L1-L5 메트릭 정의 및 구현 상세    |
| [데이터셋 형식](docs/Dataset_Format.md)                            | 출력 데이터셋 스키마 및 필드 설명 |
| [학술적 근거](docs/ACADEMIC_FOUNDATION.md)                         | 관련 논문 및 이론적 배경          |
| [정책 파일 가이드](docs/Policies.md)                               | policies.json 작성 가이드         |
| [고난도 질문 설계](docs/HARD_QUESTIONS.md)                         | L4/L5 질문 설계 원칙              |
| [L4-L5 상세](docs/L4-5.md)                                         | Batfish 기반 분석 상세            |

### NetAlly (Multi-Agent System)

| 문서 | 설명 |
| --- | --- |
| [NetAlly README](NetAlly/README.md) | 아키텍처, 빠른 시작, 환경변수, 트러블슈팅 |
| [배포 가이드](Make_Dataset/config_generator/docs/deployment_guide.md) | PNETLab 배포 절차 (배선 체크시트 포함) |
| [Deploy 스크립트](Make_Dataset/src/deploy/README.md) | Lab-B/C/D 자동 배포 3단계 |

### 실험 (Experiments)

| 문서 | 설명 |
| --- | --- |
| [실험 설계](NetAlly/docs/IEEE/experiment_design.md) | Exp.2/4/5 설계, 평가 메트릭 |
| [Lab-B 토폴로지](Make_Dataset/config_generator/docs/Lab-B-topology.html) | 인터랙티브 토폴로지 시각화 |
| [수정 계획](/.planning/) | NetAlly Fix, Experiment Gap, Dataset Fix 계획 |
