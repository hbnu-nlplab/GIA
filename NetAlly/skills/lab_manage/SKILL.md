---
name: lab_manage
description: PNETLab 실험실 관리
priority: 6
tags: [lab, pnetlab, inventory]
enabled: true
requires_tools: [lab_manage]
---

# Lab Manage Skill

## 용도
PNETLab 실험실 환경을 관리합니다.
- 장비 목록 조회
- 장비 상태 확인
- 설정 파일 내보내기

## 도구 사용법
```
lab_manage(action="show_inventory")
lab_manage(action="get_status", params={"device": "p1"})
lab_manage(action="export_configs")
```
