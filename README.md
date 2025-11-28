# NetConfigQA

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/hbnu-kilab/GIA) [![2025HCLT](https://img.shields.io/badge/2025-HCLT-blue)](https://sites.google.com/view/hclt-2025/) [![PnetLab](https://img.shields.io/badge/PnetLab-blue)](https://pnetlab.com/pages/main)

네트워크 장비 설정(XML)으로부터 **Q&A 데이터셋을 자동 생성**하고, **Batfish 기반 네트워크 검증 질문**을 포함한 다층 레벨(L1-L5) 데이터셋을 구축하는 연구 프로젝트입니다.



## 빠른 시작

### 실행 (L1-L3)

```bash
python main.py --lab-path Data/Pnetlab/[실험실 이름] --enable-batfish
---



- 제일 우선 `device_info.json` 을 작성하여서 실험실 장비들의 정보를 준비해야합니다.
- [실험실 이름] 하위 디렉토리에는 `xml/`, `cfg/` 폴더가 준비되어야합니다.
- 

## 레벨 체계

| Level | 설명 | 엔진 |
|-------|------|------|
| **L1** | 단일 장비 설정값 조회 | JSON 파싱 |
| **L2** | 복수 장비 설정값 집계 | JSON 파싱 |
| **L3** | 복수 장비 + 계산/비교 | JSON 파싱 |
| **L4** | 네트워크 도달성 분석 | Batfish |
| **L5** | What-If / Differential 분석 | Batfish |

---

## 문서

- [실행 가이드](docs/Getting_Started.md)
- [메트릭 레벨 분석](docs/METRIC_LEVEL_ANALYSIS.md)
- [데이터셋 형식](docs/Dataset_Format.md)
- [학술적 근거](docs/ACADEMIC_FOUNDATION.md)

---
