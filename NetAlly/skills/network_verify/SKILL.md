---
name: network_verify
description: 네트워크 속성 검증 (Batfish)
priority: 8
tags: [verify, reachability, batfish]
enabled: true
requires_tools: [network_verify]
---

# Network Verify Skill

## 용도
Batfish를 사용하여 네트워크 속성을 검증합니다.
- Reachability (A→B 도달 가능 여부)
- Traceroute (경로 추적)
- BGP 세션 상태
- 라우팅 테이블 분석

## 도구 사용법
```
network_verify(test_type="reachability", params={"src": "10.1.1.1", "dst": "10.2.2.2"})
network_verify(test_type="traceroute", params={"src": "p1", "dst": "10.3.3.3"})
network_verify(test_type="bgp_session", params={"device": "p1"})
```
