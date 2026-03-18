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

## vs 기존 스크립트 (Lab-A용)

| 기존 (Lab-A) | 용도 | 신규 (Lab-B/C/D) | 비고 |
|-------------|------|-----------------|------|
| 1-SSH_Enable.py | SSH 활성화 | ❌ 불필요 | .cfg에 SSH 포함 |
| 2-NSO_Register.py | NSO 등록 (docker exec) | 3_register_nso.py | RESTCONF 방식 |
| 3-Config_Export_Batfish.py | NSO→Batfish | ❌ 불필요 | .cfg 직접 사용 |
| ❌ 없음 | Config 적용 | 1_push_configs.py | 신규 |
| 3-Check_Connectivity.py | 연결 확인 | 2_verify.py | 통합 |
