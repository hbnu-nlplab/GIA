---
name: nso_playbook
description: NSO 장비 관리 및 설정 변경 도구 사용법
priority: 8
tags:
  - nso
  - configuration
  - device
  - change
  - registration
  - sync
enabled: true
requires_tools:
  - network_query
  - network_change
  - approval_request
---

# NSO Tool Playbook

Cisco NSO를 통한 장비 관리 및 설정 변경 방법을 안내합니다.

## 1. 조회 작업 (Read-Only)

모든 조회 작업은 `network_query()` 도구를 사용합니다.

### 장비 목록 조회
```python
network_query("device", {"operation": "list"})
```

### 특정 장비 설정 조회
```python
network_query("device", {
    "operation": "get_config",
    "device": "PE1",
    "config_path": "interface/GigabitEthernet"
})
```

### 사용 가능한 query_type
| query_type | 용도 |
|-----------|-----|
| `device` | 장비 정보 조회 |
| `interface` | 인터페이스 상태 조회 |
| `routing` | 라우팅 테이블 조회 |
| `service` | NSO 서비스 목록 조회 |

## 2. 장비 라이프사이클

### 2.1 장비 등록
```python
network_change("register_device", device_info={
    "name": "NewRouter",
    "oob_ip": "192.168.1.100",  # 관리 IP (필수)
    "port": 22,                   # SSH 포트
    "authgroup": "default",       # 인증 그룹
    "ned_id": "cisco-ios-cli-6.110",  # NED ID
    "protocol": "ssh"
})
```

### 2.2 SSH 호스트 키 가져오기
```python
network_change("fetch_host_keys", device="NewRouter")
```

### 2.3 설정 동기화
```python
network_change("sync_from", device="NewRouter")
```

### 2.4 장비 등록 해제 (⚠️ 승인 권장)
```python
network_change("delete_device", device="OldRouter")
```

## 3. 설정 변경 작업

### ⚠️ 주의: 변경 작업은 승인이 필요합니다

### 3.1 변경 흐름
```
1. network_change("dry_run", ...) → 시뮬레이션
2. approval_request() → 사용자 승인 요청
3. [승인 후] network_change("commit", ...) → 실제 적용
```

### 3.2 설정 차이 확인
```python
network_change("diff", device="PE1", config_path="interface/GigabitEthernet")
```

### 3.3 Dry-Run (시뮬레이션)
```python
network_change("dry_run", 
    device="PE1",
    config_path="interface/GigabitEthernet[name='0/1']",
    config_value={"description": "WAN Link"}
)
```

### 3.4 승인 요청
```python
approval_request(
    action_type="commit",
    description="PE1 인터페이스 설명 변경",
    affected_devices=["PE1"],
    risk_assessment="low"
)
```

## 4. 롤백 (Rollback)

### 4.1 롤백 요청 (승인 필요)
```python
network_change("rollback", 
    device="PE1", 
    rollback_id="12345"
)
```

## 5. 장비 등록 워크플로우 (전체)

```python
# 1. 장비 등록
network_change("register_device", device_info={
    "name": "NewRouter",
    "oob_ip": "192.168.1.100"
})

# 2. SSH 키 가져오기
network_change("fetch_host_keys", device="NewRouter")

# 3. 설정 동기화
network_change("sync_from", device="NewRouter")

# 4. 등록 확인
network_query("device", {"device": "NewRouter"})
```

## 6. 흔한 오류

### "Device not found"
→ `network_query("device")` 로 등록된 장비 목록 확인

### "NSO connection failed"
→ 환경변수 확인:
- `NSO_BASE_URL`
- `NSO_USER`
- `NSO_PASS`

### "Sync-from failed"
1. 장비가 켜져 있는지 확인
2. SSH 연결 가능한지 확인
3. `fetch_host_keys` 먼저 실행

### "NED not found"
→ NSO에 해당 NED 패키지가 설치되어 있는지 확인

### "Commit failed"
→ `dry_run` 먼저 실행하여 오류 확인
