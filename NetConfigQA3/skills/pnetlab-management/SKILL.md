---
name: pnetlab_playbook
description: PNETLab 토폴로지 관리 도구 사용법
priority: 7
tags:
  - pnetlab
  - topology
  - lab
  - node
  - network
  - connection
enabled: true
requires_tools:
  - lab_manage
---

# PNETLab Tool Playbook

PNETLab 가상 네트워크 환경 관리 방법을 안내합니다.

## 1. 조회 작업

### 토폴로지 목록 조회
```python
lab_manage("show_inventory")
```

### 특정 장비 상태 조회
```python
lab_manage("get_status", {"device": "PE1"})
```

### 콘솔 접속 링크 조회
```python
lab_manage("get_console_link", {"device": "PE1"})
```

## 2. 장비 관리

### 장비 추가
```python
lab_manage("add_node", {
    "name": "NewRouter",
    "template": "vios",   # vios, csr1000v, xrv9k 등
    "left": 400,          # X 좌표
    "top": 300            # Y 좌표
})
```

### 장비 시작/중지
```python
lab_manage("start_node", {"name": "NewRouter"})
lab_manage("stop_node", {"name": "NewRouter"})
```

### 장비 삭제 (⚠️ 주의)
```python
# 먼저 장비 중지 권장
lab_manage("stop_node", {"name": "OldRouter"})
lab_manage("delete_node", {"name": "OldRouter"})
```

## 3. 네트워크(Cloud) 관리

### 네트워크 추가
```python
lab_manage("add_network", {
    "name": "Mgmt-Cloud",
    "net_type": "pnet2",  # pnet2 = Cloud2
    "left": 300,
    "top": 150
})
```

### 네트워크 타입
| net_type | 설명 |
|----------|-----|
| `bridge` | 내부 브릿지 |
| `ovs` | Open vSwitch |
| `pnet0` | Cloud0 (NAT) |
| `pnet1` | Cloud1 |
| `pnet2` | Cloud2 (관리용 권장) |
| `pnet3`~`pnet9` | Cloud3~9 |

### 네트워크 삭제
```python
lab_manage("delete_network", {"name": "Mgmt-Cloud"})
```

## 4. 연결 관리

### 인터페이스 → 네트워크 연결
```python
lab_manage("connect_interface", {
    "device_name": "Router1",
    "interface_id": 0,         # Gi0/0 = 0, Gi0/1 = 1 ...
    "network_name": "Cloud1"
})
```

### 인터페이스 연결 해제
```python
lab_manage("disconnect_interface", {
    "device_name": "Router1",
    "interface_id": 0
})
```

## 5. Batfish 연동

### NSO에서 설정 추출
```python
lab_manage("export_configs", {
    "output_dir": "./batfish_snapshot",
    "devices": ["PE1", "PE2"]  # 선택적, 없으면 전체
})
```

### Batfish 스냅샷 초기화
```python
lab_manage("init_batfish", {
    "snapshot_path": "./batfish_snapshot"
})
```

## 6. 인터페이스 ID 매핑

| interface_id | 인터페이스 |
|--------------|-----------|
| 0 | GigabitEthernet0/0 |
| 1 | GigabitEthernet0/1 |
| 2 | GigabitEthernet0/2 |
| 3 | GigabitEthernet0/3 |

## 7. 흔한 오류

### "Node not found"
→ `lab_manage("show_inventory")` 로 정확한 장비 이름 확인

### "Network not found"
→ `lab_manage("show_inventory")` 로 네트워크 이름 확인

### "PNETLab connection failed"
→ 환경변수 확인:
- `PNETLAB_BASE_URL`
- `PNETLAB_USER`
- `PNETLAB_PASS`

### "Node not started"
→ `lab_manage("start_node", ...)` 로 노드 시작 후 재시도
