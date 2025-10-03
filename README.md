# NetConfigQA

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/hbnu-kilab/GIA) [![2025HCLT](https://img.shields.io/badge/2025-HCLT-blue)](https://sites.google.com/view/hclt-2025/) [![PnetLab](https://img.shields.io/badge/PnetLab-blue)](https://pnetlab.com/pages/main)

[![Notion](https://img.shields.io/badge/Notion-white)](https://www.notion.so/kilab/25_Network-Management-Agent-21c495df00ee806ca3d8e21e9c526cc5)

---

NetConfigQA는 네트워크 설정(XML)로부터 질문·정답(QA) 데이터셋을 생성하는 도구입니다. 본 README는 “평가(Evaluation)” 내용을 제외하고, 데이터셋 생성만 안내합니다. 현재 메인 파이프라인은 LLM을 사용하지 않고, 규칙(로직) 기반으로만 질문을 생성합니다.

- 빠른 시작: [docs/Getting_Started.md](docs/Getting_Started.md)
- 정책/카테고리: [docs/Policies.md](docs/Policies.md)
- 데이터 형식: [docs/Dataset_Format.md](docs/Dataset_Format.md)

## 개요

- 입력: 네트워크 설정 XML(예: Cisco IOS-XR/IOS)
- 처리: 정책(policy) → DSL 컴파일 → DSL 확장(정답 계산) → 데이터셋 분할
- 출력: train/validation/test로 분할된 JSON 데이터셋

구성요소 요약
- 파서: `Make_Dataset/src/parsers/universal_parser.py`
- 규칙 기반 생성기: `Make_Dataset/src/generators/rule_based_generator.py`
- 정답 계산 엔진: `Make_Dataset/src/utils/builder_core.py`
- 실행 스크립트(메인): `Make_Dataset/src/main.py`

## 빠른 실행 예시

요구 사항
- Python 3.9+
- 외부 패키지 없이 동작(LLM 미사용 경로)

샘플 데이터로 실행
- 예시 XML: `Data/Pnetlab/Net1`

명령어
- `python Make_Dataset/src/main.py --xml-dir Data/Pnetlab/Net1 --output-dir output/logic_only --verbose`

주요 옵션
- `--categories` 생성할 카테고리 지정(미지정 시 `policies.json`의 전체 카테고리 자동 사용)
- `--basic-per-category` 카테고리별 최대 항목 수 제한(0=무제한)
- `--policies` 정책 파일 경로(기본값: `Make_Dataset/policies.json`)

상세 사용법은 아래 문서를 참고하세요.
- [docs/Getting_Started.md](docs/Getting_Started.md)
- [docs/Policies.md](docs/Policies.md)
- [docs/Dataset_Format.md](docs/Dataset_Format.md)

## 참고 사항

- LLM 기반 심화 생성기는 코드(`Make_Dataset/src/generators/enhanced_llm_generator.py`)만 보존되고, 메인 실행 경로에서는 사용하지 않습니다.
- 평가(Evaluation)와 관련된 설명은 본 README에서 제외했습니다.

