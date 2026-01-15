---
name: device_lifecycle_playbook
description: 장비 전체 라이프사이클 관리 워크플로우
priority: 9
tags:
  - device
  - lifecycle
  - creation
  - deletion
  - registration
  - connection
enabled: true
requires_tools:
  - lab_manage
  - network_change
  - network_query
  - approval_request
---

# Device Lifecycle Playbook

장비 생성부터 삭제까지 전체 라이프사이클을 관리하는 워크플로우입니다.

## 1. 전체 라이프사이클 개요

```mermaid
graph LR
    A[장비 생성] --> B[클라우드 연결]
    B --> C[NSO 등록]
    C --> D[SSH 키 가져오기]
    D --> E[설정 동기화]
    E --> F[운영]
    F --> G[NSO 등록해제]
    G --> H[장비 삭제]
```

## 2. 장비 생성 (PNETLab)

### 새 장비 추가
```python
lab_manage("add_node", {
    "name": "NewRouter",
    "template": "vios",  # vios, csr1000v, xrv9k 등
    "left": 400,  # X 좌표
    "top": 300    # Y 좌표
})
```

### 장비 시작
```python
lab_manage("start_node", {"name": "NewRouter"})
```

## 3. 클라우드 연결

### 네트워크(Cloud) 추가 (필요시)
```python
lab_manage("add_network", {
    "name": "Mgmt-Cloud",
    "net_type": "pnet2"  # pnet2 = Cloud2
})
```

### 인터페이스 연결
```python
lab_manage("connect_interface", {
    "device_name": "NewRouter",
    "interface_id": 0,        # Gi0/0 = 0, Gi0/1 = 1 ...
    "network_name": "Cloud1"  # 연결할 네트워크 이름
})
```

## 4. NSO 등록

### 장비 등록
```python
network_change("register_device", device_info={
    "name": "NewRouter",
    "oob_ip": "192.168.1.100",
    "port": 22,
    "authgroup": "default",
    "ned_id": "cisco-ios-cli-6.110",
    "protocol": "ssh"
})
```

### SSH 호스트 키 가져오기
```python
network_change("fetch_host_keys", device="NewRouter")
```

### 설정 동기화
```python
network_change("sync_from", device="NewRouter")
```

## 5. 장비 삭제 워크플로우

> ⚠️ 삭제 작업은 역순으로 진행해야 합니다!

### 5.1 NSO 등록 해제
```python
network_change("delete_device", device="OldRouter")
```

### 5.2 인터페이스 연결 해제
```python
lab_manage("disconnect_interface", {
    "device_name": "OldRouter",
    "interface_id": 0
})
```

### 5.3 장비 중지 및 삭제
```python
lab_manage("stop_node", {"name": "OldRouter"})
lab_manage("delete_node", {"name": "OldRouter"})
```

## 6. 승인이 필요한 작업

| 작업 | 위험도 | 승인 필요 |
|-----|--------|---------|
| `add_node` | Low | ❌ |
| `delete_node` | High | ✅ 권장 |
| `register_device` | Medium | ❌ |
| `delete_device` | High | ✅ 권장 |
| `connect_interface` | Low | ❌ |
| `disconnect_interface` | Medium | ❌ |

## 7. 흔한 오류

### "Node not found"
→ `lab_manage("show_inventory")` 로 정확한 장비 이름 확인

### "Device already exists"
→ 장비가 이미 NSO에 등록됨. `network_query("device")` 로 확인

### "Sync-from failed"
1. 장비가 시작되었는지 확인: `lab_manage("get_status", {"device": "..."})`
2. SSH 연결 가능한지 확인
3. `network_change("fetch_host_keys", device="...")` 먼저 실행

### "Connection refused"
→ 장비가 아직 부팅 중일 수 있음. 1-2분 대기 후 재시도
