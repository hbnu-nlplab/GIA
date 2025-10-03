# NetConfigQA

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/hbnu-kilab/GIA) [![2025HCLT](https://img.shields.io/badge/2025-HCLT-blue)](https://sites.google.com/view/hclt-2025/) [![PnetLab](https://img.shields.io/badge/PnetLab-blue)](https://pnetlab.com/pages/main)

[![Notion](https://img.shields.io/badge/Notion-white)](https://www.notion.so/kilab/25_Network-Management-Agent-21c495df00ee806ca3d8e21e9c526cc5)


네트워크 장비 설정(XML)로부터 질의응답(Q&A) 데이터셋을 자동 생성하고, 생성된 데이터로 RAG 기반 네트워크 관리 에이전트를 학습·평가하기 위한 연구용 프로젝트입니다. HBNU-KILAB에서 진행 중인 **"NetConfigQA: 네트워크설정 해석 능력 평가를 위한 질의응답데이터셋"**(HCLT 2025) 실험 코드와 데이터 준비 파이프라인이 포함되어 있습니다.


### 바로가기 문서
- 실행 가이드: [docs/Getting_Started.md](docs/Getting_Started.md)
- 정책/카테고리 설명: [docs/Policies.md](docs/Policies.md)
- 메트릭 참조: [docs/Metrics.md](docs/Metrics.md)
- 데이터 구조 및 필드 설명: [docs/Dataset_Format.md](docs/Dataset_Format.md)

---

## 1. 프로젝트 전체 개요

### 1.1 무엇을 해결하려고 했나?
- 수천 대 네트워크 장비의 XML 설정에서 “BGP AS 65001 장비는?”, “sample9의 VRF Route-Target은?” 같은 질문에 답하기는 까다롭습니다.
- 규칙 기반 시스템은 유연성이 없고, 일반 LLM에게 직접 묻자니 도메인 환각(hallucination) 문제가 있습니다.
- 연구 목표는 **고품질 네트워크 Q&A 데이터셋 자동 생성**과 **RAG 파이프라인 구축**입니다.

### 1.2 구성요소 한눈에 보기
| 구성 | 파일/폴더 | 설명 |
| --- | --- | --- |
| XML 파서 | `Make_Dataset/src/core/parser.py` | 장비별 XML을 로딩해 구조화된 facts로 변환 |
| Rule 기반 생성기 | `Make_Dataset/src/core/rule_based_generator.py` | `policies.json`을 읽고 DSL(질문 템플릿 목록) 생성 |
| 정답 계산 엔진 | `Make_Dataset/src/core/builder_core.py` | DSL을 평가하여 ground truth, 증거 파일 등을 계산 |
| 실행 스크립트 | `Make_Dataset/src/main.py` | end-to-end 실행 (facts 저장 → DSL 확장 → 후처리 → JSON/CSV 저장) |
| 정책 정의 | `Make_Dataset/policies.json` | 카테고리, 메트릭, 난이도 정책 |
| 문서 | `docs/*.md` | 빠른 시작 / 정책 / 데이터 포맷 정리 |
| 참고 자료 | `Paper/HCLT/*` | HCLT 발표용 아키텍처/슬라이드/요약 |

### 1.3 파이프라인 흐름
1. **XML Facts 추출** : `UniversalParser`가 장비별 설정을 JSON 형태로 변환 ↴ `facts_YYYYMMDD_HHMMSS.json`
2. **DSL 컴파일** : 정책(`policies.json`)에서 카테고리별 질문 템플릿을 생성
3. **DSL 확장 & 정답 계산** : `BuilderCore.expand_from_dsl`이 스코프별 질문·정답·증거 파일을 계산
4. **후처리/중복 제거** : 질문 정렬/ID 재구성/ground_truth & explanation 생성/답변 형식 가이드 부착/`ground_truth_raw` 보관
5. **데이터셋 저장** : JSON(`dataset_logic_only_*.json`)과 CSV 동시 출력, train/val/test는 기본적으로 정렬된 순서를 유지하지만 `--shuffle` 옵션으로 랜덤화 가능

---

## 2. 빠르게 실행해 보기

```bash
# Python 3.9+ 권장, 추가 패키지 불필요
python Make_Dataset/src/main.py \
  --xml-dir Data/Pnetlab/Net1 \
  --output-dir output/net1_run \
  --verbose
```

실행하면 다음 파일이 생성됩니다.
- `output/net1_run/facts_YYYYMMDD_HHMMSS.json` : 파싱된 장비 facts
- `output/net1_run/dataset_logic_only_YYYYMMDD_HHMMSS.json` : train/validation/test 분할된 질문 목록 (각 항목에 `ground_truth_raw` 포함)
- `output/net1_run/dataset_logic_only_YYYYMMDD_HHMMSS.csv` : 동일 데이터를 CSV로 저장

### 주요 CLI 옵션
| 옵션 | 설명 |
| --- | --- |
| `--categories` | 생성할 카테고리 지정 (기본: policies.json 전체) |
| `--basic-per-category` | 카테고리별 최대 질문 수 제한 (0이면 제한 없음) |
| `--no-split` | train/val/test로 나누지 않고 단일 JSON 리스트로 저장 |
| `--shuffle` | train/val/test 분할 시 순서를 랜덤 셔플 (기본은 정렬 순서 유지) |
| `--policies` | 다른 정책 파일로 교체 |
| `--verbose` | 중간정보 출력 (DSL 항목 수, facts 저장 경로 등) |

> 안내: 정렬된 순서 그대로 분할하면 카테고리 편향이 생길 수 있습니다. 실험 목적이면 `--shuffle`을 켜는 것을 권장합니다.

---

## 3. 데이터 구조

각 질문 항목은 JSON에서 다음 키를 포함합니다.
| 키 | 설명 |
| --- | --- |
| `id` | `{METRIC}_{번호}` 형식의 고유 ID |
| `category`, `answer_type`, `level` | 정책에서 정의한 메타데이터 |
| `question` | 자연어 질문 + `[답변 형식: …]` 힌트 |
| `ground_truth` | 사람이 읽기 쉬운 문자열 (예: `host1, host2` / `키=값`) |
| `ground_truth_raw` | 리스트/딕셔너리 등 원본 자료형 (채점 자동화용) |
| `explanation` | 어떤 메트릭·스코프에서 계산했는지 요약 |
| `evidence_hint` | `metric`, `scope` 정보 (디버깅/추적용) |
| `source_files` | 실제 참고한 XML 파일 목록 |

세부 포맷은 `docs/Dataset_Format.md`를 참조하세요.

---

## 4. 정책(policies.json) 이해하기

- `defaults.scenarios` : 발표자료(HCLT)에서 정의한 시나리오 이름 (라벨 용도로만 사용)
- `defaults.min_per_category` : 카테고리당 최소 생성 수 (현재 파이프라인에서는 제한을 두지 않지만 참고용)
- `policies` 배열 : 각 카테고리별로 `goal`, `targets`, `primary_metric` 등을 지정
  - 예: `VRF_Consistency` → `vrf_rd_map`, `vrf_without_rt_pairs` 등 메트릭 사용
  - 모든 메트릭은 `utils/builder_core.py`에 계산 로직이 구현되어 있습니다.

정책 수정 시 주의 사항:
1. `primary_metric`을 추가하면 `BuilderCore._answer_for_metric`에서 지원되는지 확인하세요.
2. 새로운 카테고리/메트릭을 추가할 때는 문자열 ID가 중복되지 않도록 관리하세요.
3. 불필요한 질문이 많다면 `--basic-per-category`로 제한하거나, 정책에서 타깃 스코프를 조정하세요.

---

## 5. Command_Generation (명령어) 질문의 특징
- LLM이 바로 답하지 못하도록 질문에는 장비 이름만 제공하고, 정답은 관리용 IP를 포함합니다. (예: “CE1 장비에 SSH 접속하는 명령어?” → `ssh admin@172.16.1.40`)
- `scope.params`에 `hosts` 정보를 유지해 검증/디버깅 시 실제 장비 IP를 추적할 수 있습니다.
- 관련 소스 파일은 명령어에 참여한 장비들만 포함하도록 필터링했습니다.
