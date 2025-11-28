# NetConfigQA

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/hbnu-kilab/GIA) [![2025HCLT](https://img.shields.io/badge/2025-HCLT-blue)](https://sites.google.com/view/hclt-2025/) [![PnetLab](https://img.shields.io/badge/PnetLab-blue)](https://pnetlab.com/pages/main)

네트워크 장비 설정(XML)으로부터 **Q&A 데이터셋을 자동 생성**하고, **Batfish 기반 네트워크 검증 질문**을 포함한 다층 레벨(L1-L5) 데이터셋을 구축하는 연구 프로젝트입니다.

## 데이터 준비 과정 (간단 가이드)

PnetLab 실험실 데이터를 NSO/Batfish 형식으로 변환하고 데이터셋을 생성하는 단계입니다. `Data/Pnetlab/[LabName]` (e.g., `L2VPN`, `Basic`) 디렉토리를 기준으로 설명합니다.

### 1. `device_info.json` 작성
실험실 장비 정보를 JSON으로 준비합니다. 예시 (`Data/Pnetlab/L2VPN/device_info.json`):
```json
{
    "global_settings": {
        "pnetlab_vm_ip": "100.66.240.82",
        "gateway_ip": "10.10.10.1",
        "enable_password": "123",
        "admin_password": "123",
        "domain_name": "mylab.local",
        "nso_authgroup": "L2VPN",
        "nso_ned_id": "cisco-ios-cli-6.110"
    },
    "devices": [
        {"name": "CE01", "oob_ip": "10.10.10.101", "telnet_port": 30031},
        // ... 기타 장비
    ]
}
```
- `pnetlab_vm_ip`: PnetLab VM IP.
- `devices`: 각 장비의 OOB IP와 Telnet 포트 (PnetLab 콘솔에서 확인).

### 2. SSH 활성화 (`1-SSH_Enable.py`)
```bash
cd Make_Dataset/src
python 1-SSH_Enable.py
```
- Telnet으로 각 장비에 SSH, hostname, admin user, RSA key 등을 설정.
- 성공 장비 목록을 확인 후 `successful_devices.json` 생성 (1 스크립트가 자동 저장하지 않으므로 수동으로 device_info.json 복사/편집).

### 3. NSO 장비 등록 (`2-NSO_Register.py`)
```bash
python 2-NSO_Register.py
```
- Docker NSO (`cisco-nso-dev`)에 장비 등록 및 sync-from.
- SSH 호스트 키 fetch 포함.

### 4. Config/XML Export (`3-Config_Export_Batfish.py`)
```bash
python 3-Config_Export_Batfish.py
```
- NSO에서 `show running-config` → `configs/[device].cfg` (Batfish snapshot).
- NSO XML config → `xml/[device].xml`.

이제 `Data/Pnetlab/[LabName]`에 `configs/`, `xml/` 폴더가 준비됩니다.

## 데이터셋 생성

### 빠른 시작 (L1-L5 전체)
```bash
cd Make_Dataset/src
python main.py --lab-path ../../Data/Pnetlab/L2VPN --enable-batfish
```
- **L1-L3**: XML 파싱 → facts → rule-based Q&A (policies.json 기반).
- **L4-L5**: Batfish snapshot으로 도달성/What-If 분석 질문 생성.
- 출력: `Data/Pnetlab/L2VPN/Dataset/`에 `facts.json`, `dataset.json` (train/val/test), `dataset.csv`.

#### 옵션 예시
```bash
python main.py --lab-path ../../Data/Pnetlab/Basic --enable-batfish --l1-sample-ratio 0.8 --categories Routing OSPF --verbose
```

## 레벨 체계

| Level | 설명 | 엔진 |
|-------|------|------|
| **L1** | 단일 장비 설정값 조회 | JSON 파싱 |
| **L2** | 복수 장비 설정값 집계 | JSON 파싱 |
| **L3** | 복수 장비 + 계산/비교 | JSON 파싱 |
| **L4** | 네트워크 도달성 분석 | Batfish |
| **L5** | What-If / Differential 분석 | Batfish |

## 문서
- [실행 가이드](docs/Getting_Started.md)
- [메트릭 레벨 분석](docs/METRIC_LEVEL_ANALYSIS.md)
- [데이터셋 형식](docs/Dataset_Format.md)
- [학술적 근거