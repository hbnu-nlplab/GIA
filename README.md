# NetConfigQA2

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/hbnu-kilab/GIA) [![2025HCLT](https://img.shields.io/badge/2025-HCLT-blue)](https://sites.google.com/view/hclt-2025/) [![PnetLab](https://img.shields.io/badge/PnetLab-blue)](https://pnetlab.com/pages/main) [![Batfish](https://img.shields.io/badge/Batfish-Network%20Analysis-green)](https://www.batfish.org/)

네트워크 장비 설정(Configuration)으로부터 **Q&A 데이터셋을 자동 생성**하고, **Batfish 기반 네트워크 검증 질문**을 포함한 다층 난이도(L1-L5) 데이터셋을 구축하는 연구 프로젝트입니다.

---


## 📌 주요 특징

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
| **Python 3.9+** | 데이터셋 생성 스크립트 실행 환경      | `requirements.txt` 참조             |

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
git clone https://github.com/hbnu-kilab/GIA.git
cd GIA
pip install -r requirements.txt
```

### 2. 데이터 준비 (PnetLab → NSO → Batfish)

```bash
cd Make_Dataset/src

# Step 1: SSH 활성화 (PnetLab 장비)
python 1-SSH_Enable.py

# Step 2: NSO 장비 등록
python 2-NSO_Register.py

# Step 3: Config 추출 (Batfish 스냅샷 생성)
python 3-Config_Export_Batfish.py
```

### 3. 데이터셋 생성

```bash
# L1-L5 전체 데이터셋 생성
python main_batfish.py --lab-path ../../Data/Pnetlab/Research_Institute_Internal_DC
```

**출력 결과**: `Data/Pnetlab/[LabName]/Dataset/` 폴더에 다음 파일이 생성됩니다.

- `dataset.csv`: 전체 Q&A 데이터셋
- `facts.json`: 파싱된 네트워크 팩트 정보

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

```
GIA/
├── Make_Dataset/           # 데이터셋 생성 파이프라인
│   └── src/
│       ├── core_batfish/   # Batfish 분석 엔진 (L4/L5)
│       ├── main_batfish.py # 메인 실행 스크립트
│       └── 1-SSH_Enable.py # PnetLab SSH 설정
├── Data/                   # 실험 데이터
│   └── Pnetlab/
│       └── [LabName]/      # 실험 토폴로지별 데이터
├── Experiment/             # LLM 평가 실험
│   └── run_evaluation.py   # 평가 스크립트
└── docs/                   # 문서
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
