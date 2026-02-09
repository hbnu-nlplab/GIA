---
name: lab_bootstrap
description: PNETLab 장비 초기화 및 NSO 등록 파이프라인
priority: 7
tags: [lab, onboarding, ssh, nso]
enabled: true
requires_tools: [lab_bootstrap]
---

# Lab Bootstrap Skill

## 용도
PNETLab 장비 초기화부터 NSO 등록까지의 파이프라인을 실행합니다.
- Telnet으로 SSH 활성화
- 기본 경로/도메인/계정 설정
- NSO authgroup 생성 및 장비 등록
- sync-from 수행

## 도구 사용법
```
lab_bootstrap(action="enable_ssh")
lab_bootstrap(action="register_nso")
lab_bootstrap(action="check_connectivity", params={"device": "P1"})
lab_bootstrap(action="sync_from", params={"devices": ["P1", "P2"]})
lab_bootstrap(action="detect_changes")
lab_bootstrap(action="sync_changed")
lab_bootstrap(action="diff_report")
lab_bootstrap(action="generate_device_info")
lab_bootstrap(action="refresh_onboard")
lab_bootstrap(action="full")
lab_bootstrap(action="discover_nso", params={"node_name": "NSO"})
```

## 선택 장비 필터
```
lab_bootstrap(action="enable_ssh", params={"devices": ["P1", "P2"]})
lab_bootstrap(action="register_nso", params={"devices": ["P1", "P2"]})
lab_bootstrap(action="sync_from", params={"devices": ["P1", "P2"]})
lab_bootstrap(action="detect_changes", params={"devices": ["P1", "P2"]})
lab_bootstrap(action="sync_changed", params={"devices": ["P1", "P2"]})
lab_bootstrap(action="diff_report", params={"devices": ["P1", "P2"]})
lab_bootstrap(action="generate_device_info", params={"config_path": "Data/Pnetlab/device_info.json"})
lab_bootstrap(action="refresh_onboard")
```
