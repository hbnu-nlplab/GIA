---
name: bgp_troubleshooting
description: BGP 세션 장애 진단 및 해결 절차
priority: 7
tags: [bgp, routing, troubleshooting, domain]
enabled: true
requires_tools: [network_query, network_verify]
---

# BGP Troubleshooting Skill

## When to Use

다음 상황에서 이 Skill을 사용합니다:

- BGP 세션이 Down 상태
- BGP 경로가 학습되지 않음
- BGP neighbor가 Established 되지 않음
- AS-PATH가 이상함

---

## Diagnosis Steps

### 1. BGP 설정 확인

```python
network_query(
    category="routing",
    device="PE1",
    params={"protocol": "bgp"}
)
```

**확인 사항**:
- BGP router-id 설정 여부
- Neighbor statement 존재 여부
- AS 번호 정확성
- Update-source 설정

---

### 2. BGP Neighbor 상태 확인

```python
# NSO에서 neighbor 상태 조회
network_query(
    category="routing",  
    device="PE1",
    params={"protocol": "bgp", "detail": "neighbors"}
)
```

**Expected Output**:
```
Neighbor: 10.0.1.2
  State: Established
  Uptime: 01:23:45
  PfxRcd: 100
```

**Troubleshooting**:
- State != Established → 연결 문제
- PfxRcd = 0 → 경로 광고 문제

---

### 3. Batfish로 BGP 세션 검증

```python
network_verify(
    test_type="bgp_session",
    params={"device": "PE1"}
)
```

Batfish는 설정 레벨에서 BGP 세션이 Established 가능한지 분석합니다.

---

### 4. 도달성 확인

```python
network_verify(
    test_type="reachability",
    params={
        "src": "PE1",
        "dst": "10.0.1.2",  # Neighbor IP
        "protocol": "tcp",
        "dst_port": 179     # BGP Port
    }
)
```

**분석**:
- Unreachable → 라우팅 또는 ACL 문제
- Reachable → BGP 설정 문제

---

## Common Issues

### Issue 1: Missing Neighbor Statement

**증상**:
```
% No BGP neighbor configured
```

**해결**:
```python
network_change(
    action="dry_run",
    device="PE1",
    config_path="router/bgp/neighbor",
    config_value={
        "neighbor_ip": "10.0.1.2",
        "remote_as": 65001
    }
)
```

---

### Issue 2: Wrong AS Number

**증상**:
```
%BGP-3-NOTIFICATION: sent to neighbor 10.0.1.2 (AS 65002) 2/2 (Open Message Error/Bad Peer AS)
```

**해결**:
1. 상대방 AS 번호 확인
2. neighbor remote-as 수정

---

### Issue 3: No Route to Neighbor

**증상**:
```
%BGP-3-NOTIFICATION: (Active) neighbor 10.0.1.2
```

**해결**:
```python
# 1. 라우팅 테이블 확인
network_query(
    category="routing",
    device="PE1",
    params={"dest": "10.0.1.2"}
)

# 2. Static route 추가 필요시
network_change(
    action="dry_run",
    device="PE1",
    config_path="ip/route",
    config_value="10.0.1.0 255.255.255.0 10.0.0.1"
)
```

---

### Issue 4: ACL Blocking BGP

**증상**:
- BGP 포트 179 차단됨

**해결**:
```python
# 1. ACL 확인
network_query(
    category="security",
    device="PE1",
    params={"interface": "GigabitEthernet0/0"}
)

# 2. Batfish로 검증
network_verify(
    test_type="reachability",
    params={
        "src": "PE1",
        "dst": "10.0.1.2",
        "protocol": "tcp",
        "dst_port": 179
    }
)
```

---

## Verification Checklist

변경 후 다음을 확인합니다:

```python
# 1. BGP Session State
network_query("routing", device="PE1", params={"protocol": "bgp"})
# Expected: State = Established

# 2. BGP Routes Received
network_query("routing", device="PE1", params={"protocol": "bgp", "detail": "routes"})
# Expected: PfxRcd > 0

# 3. Batfish 검증
network_verify("bgp_session", {"device": "PE1"})
# Expected: All sessions = Established
```

---

## Example: Complete Diagnosis

**Task**: "PE1과 PE2 간 BGP 세션이 Down입니다. 원인을 찾아주세요."

**Steps**:

```
1. network_query("routing", device="PE1", params={"protocol": "bgp"})
   → Result: Neighbor 10.0.1.2, State: Idle

2. network_verify("reachability", {
       "src": "PE1",
       "dst": "10.0.1.2",
       "protocol": "tcp",
       "dst_port": 179
   })
   → Result: Blocked by ACL on GigabitEthernet0/0

3. network_query("security", device="PE1", params={"interface": "Gi0/0"})
   → ACL: deny tcp any any eq 179

4. network_change("dry_run", 
                  device="PE1",
                  config_path="ip/access-list/extended/ACL_IN",
                  config_value="permit tcp host 10.0.1.1 host 10.0.1.2 eq 179")
   → Simulation: OK

5. approval_request(
       action="commit",
       reason="ACL 규칙 추가하여 BGP 포트 179 허용",
       impact="low"
   )

6. [사용자 승인 후]
   network_change("commit", ...)

7. network_query("routing", device="PE1", params={"protocol": "bgp"})
   → State: Established ✅
```

---

**참고 문서**:
- RFC 4271 - BGP-4
- Cisco BGP Configuration Guide
