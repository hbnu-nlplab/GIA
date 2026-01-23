# PNETLab API Reference

## 개요
PNETLab REST API를 사용한 토폴로지 자동화 가이드입니다.

---

## 1. 인증 방법

### 1.1 브라우저 쿠키 기반 인증 (권장)
PNETLab은 JWT 토큰이 아닌 **세션 쿠키** 기반 인증을 사용합니다.

```python
from clients.pnetlab import PnetlabClient

client = PnetlabClient("http://YOUR_PNETLAB_IP")

# 브라우저 개발자 도구(F12)에서 쿠키 복사
client.set_session_from_browser(
    token="your-token-value",
    session="your-session-value", 
    xsrf="your-xsrf-token-value"
)
```

### 1.2 필요한 쿠키
| 쿠키명 | 설명 |
|--------|------|
| `token` | JWT 토큰 |
| `_session` | 세션 ID |
| `XSRF-TOKEN` | CSRF 보호 토큰 |

---

## 2. 워크플로우

```
┌─────────────────────────────────────────────────────────┐
│  1. 인증 설정 (set_session_from_browser)                 │
│         ↓                                                │
│  2. 토폴로지 조회 (get_session_topology)                 │
│         ↓                                                │
│  3. 노드/네트워크 정보 추출                              │
│         ↓                                                │
│  4. 원하는 작업 수행                                     │
│     ├─ 노드 생성/삭제                                    │
│     ├─ 네트워크 생성/삭제                                │
│     └─ 인터페이스 연결/해제                              │
│         ↓                                                │
│  5. 결과 확인 (토폴로지 재조회)                          │
└─────────────────────────────────────────────────────────┘
```

---

## 3. API 엔드포인트

### 3.1 토폴로지 조회
```http
GET /api/labs/session/topology
```

### 3.2 노드 관리

#### 노드 생성
```http
POST /api/labs/session/nodes/add
Content-Type: application/json

{
  "template": "vios",
  "type": "qemu",
  "name": "vIOS1",
  "image": "vios-adventerprisek9-m.vmdk.SPA.157-3.M3",
  "ethernet": 4,
  "ram": 1024,
  "cpu": 1,
  "left": 400,
  "top": 300
}
```

#### 노드 삭제
```http
POST /api/labs/session/nodes/delete
Content-Type: application/json

{"id": "11"}
```

#### 노드 시작/중지
```http
POST /api/labs/session/nodes/{node_id}/start
POST /api/labs/session/nodes/{node_id}/stop
```

### 3.3 네트워크 관리

#### 네트워크 생성
```http
POST /api/labs/session/networks/add
Content-Type: application/json

{
  "name": "Mgmt-Cloud",
  "type": "pnet2",
  "left": 300,
  "top": 150
}
```

#### 네트워크 삭제
```http
POST /api/labs/session/networks/delete
Content-Type: application/json

{"id": "2"}
```

### 3.4 인터페이스 연결

#### 연결/해제
```http
POST /api/labs/session/interfaces/edit
Content-Type: application/json

# 연결
{"node_id": "1", "data": {"0": "1"}}

# 해제 (network_id = 빈 문자열)
{"node_id": "1", "data": {"0": ""}}
```

**페이로드 구조**:
- `node_id`: 문자열 (예: "1")
- `data`: `{인터페이스ID: 네트워크ID}` 형식
  - 인터페이스 ID: "0"=Gi0/0, "1"=Gi0/1
  - 네트워크 ID: "1", "2" 또는 "" (해제)

---

## 4. SDK 사용 예시

### 4.1 기본 사용법
```python
from clients.pnetlab import PnetlabClient
from config.settings import settings

# 클라이언트 초기화
client = PnetlabClient(settings.pnetlab.base_url)
client.set_session_from_browser(token, session, xsrf)

# 토폴로지 조회
topology = client.get_session_topology()
nodes = client.get_nodes_from_topology(topology)

# 노드 이름으로 ID 찾기
def get_node_by_name(name):
    for n in nodes:
        if n["name"] == name:
            return n
    return None

node = get_node_by_name("vIOS1")
node_id = int(node["id"])
```

### 4.2 장비 생성
```python
result = client.add_node(
    name="vIOS10",
    template="vios",
    left=100,
    top=500
)
# result = {"node_id": 18, "full_response": {...}}
```

### 4.3 인터페이스 연결
```python
# vIOS1의 Gi0/0을 Network 1에 연결
success = client.connect_node_interface(
    node_id=1,
    interface_id=0,  # Gi0/0
    network_id=1
)

# 연결 해제
client.connect_node_interface(node_id=1, interface_id=0, network_id=0)
```

### 4.4 네트워크 생성
```python
result = client.add_network(
    name="CloudA",
    net_type="pnet2",  # Cloud2
    left=300,
    top=150
)
```

---

## 5. 주의사항

1. **노드 ID vs 이름**: 생성 응답에서 ID 추출보다 **토폴로지 조회 후 이름으로 검색** 권장
2. **인터페이스 연결**: 노드가 **실행 중**이어도 연결 가능
3. **문자열 ID**: API 페이로드에서 ID는 **문자열**로 전송 (`"1"`, `"2"`)
4. **세션 만료**: 쿠키 세션은 시간이 지나면 만료됨, 재발급 필요

---

## 6. 테스트 스크립트

| 파일 | 설명 |
|------|------|
| `tests/pnetlab/test_topology_integration.py` | 전체 CRUD 통합 테스트 |
| `tests/pnetlab/test_pnetlab_api_functions.py` | API 기능 검증 테스트 |
| `tests/pnetlab/automate_topology_api.py` | 토폴로지 자동 연결 |
