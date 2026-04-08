# Deploy Scripts (Lab-B/C/D)

Config Generator로 생성한 .cfg 파일을 PNETLab에 배포하는 3단계 파이프라인.

## 전체 흐름

```
[Config Generator] → .cfg 파일 생성
        ↓
[Step 1] 1_push_configs.py   — Telnet 콘솔로 .cfg 밀어넣기 (5분)
        ↓
[Step 2] 2_verify.py          — Ping + OSPF/BGP/MPLS 검증 (2분)
        ↓
[Step 3] 3_register_nso.py    — NSO RESTCONF 장비 등록 + sync-from (3분)
        ↓
[main_batfish.py]             — 데이터셋 생성
```

## 사전 준비

1. `device_info.json`의 `telnet_port` 채우기 (PNETLab UI에서 확인)
2. PNETLab VM에서 `ip addr add 10.10.10.1/24 dev pnet0` (관리망 접근)
3. `pip install telnetlib3 requests`

## 사용법

```bash
cd Make_Dataset/src

# Step 1: Config Push
python -m deploy.1_push_configs                    # 전체
python -m deploy.1_push_configs --dry-run          # 파싱만 확인
python -m deploy.1_push_configs --only P2,P3       # 특정 장비만

# Step 2: Verify
python -m deploy.2_verify                          # 전체 검증
python -m deploy.2_verify --ping-only              # ping만

# Step 3: NSO Register
python -m deploy.3_register_nso                    # 전체 등록+sync
python -m deploy.3_register_nso --status           # 현재 상태 확인
python -m deploy.3_register_nso --no-sync          # 등록만
```

## device_info.json 설정

`Data/Pnetlab/<LabName>/device_info.json` 파일을 준비해야 합니다.

```json
{
  "global_settings": {
    "pnetlab_vm_ip": "100.85.92.121",   // PNETLab VM의 Tailscale IP
    "gateway_ip": "10.10.10.1",
    "enable_password": "",
    "admin_password": "admin",
    "nso_ip": "10.10.10.100",           // NSO Docker 노드의 Cloud0 IP
    "nso_port": 8080,
    "nso_authgroup": "LabB_NCN_Basic_SP",
    "nso_ned_id": "cisco-ios-cli-6.110",
    "nso_username": "admin",
    "nso_password": "admin"
  },
  "devices": [
    { "name": "P1", "oob_ip": "10.10.10.11", "oob_intf": "GigabitEthernet0/7",
      "device_group": "LabB", "telnet_port": 32769 }
  ]
}
```

### telnet_port 확인 방법

PNETLab UI에서 노드 우클릭 → 정보 → Console Port 확인. 또는:

```bash
# PNETLab VM에서
find /opt/unetlab/tmp -name "*.lock" -exec sh -c 'echo "$(dirname {}): $(cat {})"' \;
```

## NSO 사전 설정

NSO Docker 노드가 PNETLab에서 실행 중이어야 합니다.

```bash
# NSO 노드에 텔넷 접속 후:
sudo -i
source /home/NSO/nso-5.3/ncsrc
cd /home/NSO/ncs-run && ncs

# NSO eth2를 Cloud0(관리망)에 연결, IP 설정:
ifconfig eth2 10.10.10.100/24
```

> NSO의 eth2가 Cloud0에 연결되어 있어야 장비 SSH 접근 가능.
> 상세: [deployment_guide.md](../../config_generator/docs/deployment_guide.md)

## 트러블슈팅

| 증상 | 원인 | 해결 |
|------|------|------|
| `CONN_FAIL` | telnet_port 불일치 | PNETLab UI에서 포트 재확인 |
| Ping 실패 | pnet0에 IP 없음 | `ip addr add 10.10.10.1/24 dev pnet0` |
| NSO 연결 실패 | NSO 미시작 또는 eth2 미연결 | NSO `ncs` 실행 + Cloud0 연결 확인 |
| SSH key 수집 실패 | 장비 SSH 미설정 | Step 1 재실행 후 Step 3 재시도 |
| `NO_CFG` | .cfg 파일 없음 | `--configs-dir` 경로 확인 |

## vs 기존 스크립트 (Lab-A용)

| 기존 (Lab-A) | 용도 | 신규 (Lab-B/C/D) | 비고 |
|-------------|------|-----------------|------|
| 1-SSH_Enable.py | SSH 활성화 | ❌ 불필요 | .cfg에 SSH 포함 |
| 2-NSO_Register.py | NSO 등록 (docker exec) | 3_register_nso.py | RESTCONF 방식 |
| 3-Config_Export_Batfish.py | NSO→Batfish | ❌ 불필요 | .cfg 직접 사용 |
| ❌ 없음 | Config 적용 | 1_push_configs.py | 신규 |
| 3-Check_Connectivity.py | 연결 확인 | 2_verify.py | 통합 |
