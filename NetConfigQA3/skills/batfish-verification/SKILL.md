---
name: batfish_playbook
description: Batfish 네트워크 분석 도구 사용법
priority: 8
tags:
  - batfish
  - verification
  - reachability
  - troubleshooting
enabled: true
requires_tools:
  - network_verify
  - lab_manage
---

# Batfish Tool Playbook

네트워크 분석 도구 Batfish의 올바른 사용법을 안내합니다.

## 1. 사전 요구사항

Batfish를 사용하기 전에 스냅샷이 초기화되어 있어야 합니다:

```python
# 1. NSO에서 설정 추출
lab_manage("export_configs", {"output_dir": "./batfish_snapshot"})

# 2. Batfish 스냅샷 초기화
lab_manage("init_batfish", {"snapshot_path": "./batfish_snapshot"})
```

## 2. 사용 가능한 테스트

| 테스트 유형 | 용도 | 필수 파라미터 |
|------------|-----|-------------|
| `reachability` | A→B 도달 가능 여부 | src, dst |
| `traceroute` | 경로 추적 | src, dst |
| `bgp_session` | BGP 세션 상태 | device (선택) |
| `route_table` | 라우팅 테이블 | device, vrf (선택) |

## 3. 상황별 사용 가이드

| 사용자 질문 | 사용할 테스트 |
|------------|-------------|
| "A에서 B로 통신 되나요?" | `reachability` |
| "A에서 B까지 어떤 경로로 가나요?" | `traceroute` |
| "BGP 세션 상태가 어떤가요?" | `bgp_session` |
| "PE1의 라우팅 테이블 보여줘" | `route_table` |

## 4. 파라미터 형식

### src/dst 형식
```python
# IP 주소
{"src": "10.1.1.1", "dst": "10.2.2.2"}

# 프로토콜 지정
{"src": "10.1.1.1", "dst": "10.2.2.2", "protocol": "tcp", "dst_port": 443}
```

## 5. 결과 해석

### 성공
```
reachable: true
disposition: ACCEPTED
```
→ 패킷이 목적지에 도달함

### 실패
```
reachable: false
disposition: DENIED_IN
```
→ ACL에 의해 차단됨

```
reachable: false
disposition: NO_ROUTE
```
→ 라우팅 테이블에 경로 없음

## 6. 흔한 오류

### "Batfish not initialized"
1. `lab_manage("export_configs", {"output_dir": "./snapshot"})` 실행
2. `lab_manage("init_batfish", {"snapshot_path": "./snapshot"})` 실행
