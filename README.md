# NetConfigQA

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/hbnu-kilab/GIA) [![2025HCLT](https://img.shields.io/badge/2025-HCLT-blue)](https://sites.google.com/view/hclt-2025/) [![PnetLab](https://img.shields.io/badge/PnetLab-blue)](https://pnetlab.com/pages/main)

네트워크 장비 설정(XML)으로부터 **Q&A 데이터셋을 자동 생성**하고, **Batfish 기반 네트워크 검증 질문**을 포함한 다층 레벨(L1-L5) 데이터셋을 구축하는 연구 프로젝트입니다.

---

## 주요 특징

- **L1-L3**: XML 설정 파싱 기반 질문 (단일/복수 장비, 비교 분석)
- **L4-L5**: Batfish 기반 네트워크 검증 질문 (도달성, What-If 분석)
- **학술적 근거**: HSA, VeriFlow, Minesweeper, Config2Spec, DNA 논문 기반 설계
- **현업 실무 질문**: 비대칭 경로, SPOF 탐지, ACL 차단 분석 등

---

## 빠른 시작

### 기본 실행 (L1-L3)
```bash
python Make_Dataset/src/main.py \
  --xml-dir Data/Pnetlab/L2VPN/xml \
  --output-dir output/dataset
```

### Batfish 포함 실행 (L1-L5)
```bash
# Batfish 서버 실행 (Docker)
docker run -d -p 9996:9996 -p 9997:9997 batfish/allinone

# 데이터셋 생성
python Make_Dataset/src/main.py \
  --xml-dir Data/Pnetlab/L2VPN/xml \
  --output-dir output/dataset \
  --enable-batfish \
  --snapshot-path Data/Pnetlab/L2VPN
```

---

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
