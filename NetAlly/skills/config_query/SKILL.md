---
name: config_query
description: 장비 설정 정보 조회 (NSO/Batfish)
priority: 8
tags: [query, config, device]
enabled: true
requires_tools: [network_query]
---

# Config Query Skill

## 용도
장비의 설정 정보를 조회할 때 사용합니다.
- hostname, version, users
- 인터페이스 설정 (IP, status)
- 라우팅 설정 (OSPF, BGP, static)
- 보안 설정 (ACL, AAA)

## 도구 사용법
```
network_query(category="device", device="p1", field="hostname")
network_query(category="interface", device="p1")
network_query(category="routing", device="p1", field="ospf")
```
