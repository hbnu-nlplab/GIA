# PNETLab Multi-Lab Deployment Runbook

이 문서는 `LabA`, `LabC`, `LabD`를 PNETLab + WSL NSO 환경에서 운영할 때 필요한 실제 작업 순서를 정리한 운영 가이드다.

대상 독자:
- 현재 작업을 이어받는 다른 AI
- 나중에 다시 보는 본인

핵심 결론:
- NSO는 랩별로 분리한다.
- 관리망 IP는 현재 `10.10.10.0/24`를 재사용하므로, 장비는 한 번에 한 랩만 켠다.
- PNETLab UI에서 다른 랩을 껐더라도 `pnet0` 브리지에 예전 `vunl*` 인터페이스가 남을 수 있다. 이 경우 `%IP-4-DUPADDR`와 NSO SSH host-key mismatch가 발생한다.
- Config push / verify는 `Make_Dataset/src/deploy` 파이프라인을 사용한다.
- NSO 등록은 원칙적으로 `deploy.3_register_nso`가 최신이지만, 현재 WSL Docker NSO에서는 RESTCONF가 `400 Bad Request`를 반환하므로 `2-NSO_Register.py --nso-container ...`를 fallback으로 사용한다.

## 1. 현재 환경의 운영 원칙

현재 구조에서는 다음 원칙을 지켜야 한다.

1. `LabA`, `LabC`, `LabD`는 모두 관리 IP 대역으로 `10.10.10.0/24`를 사용한다.
2. 따라서 `P1 = 10.10.10.11` 같은 주소가 랩마다 중복된다.
3. 중복 IP 때문에 여러 랩 장비를 동시에 켜두면 안 된다.
4. NSO inventory 충돌을 막기 위해 NSO는 랩별로 분리한다.
5. NSO를 랩별로 분리해도 PNETLab의 `Cloud0` / `pnet0` L2 관리망은 자동으로 분리되지 않는다.
6. 따라서 PNETLab UI 기준으로 장비를 껐더라도, VM의 `pnet0`에 잔여 `vunl*` 인터페이스가 남아 있으면 같은 문제가 다시 발생한다.

권장 운영 방식:

- `LabB` 작업 시: `LabB` 장비만 켬 + `cisco-nso-dev`
- `LabA` 작업 시: `LabA` 장비만 켬 + `cisco-nso-laba`
- `LabC` 작업 시: `LabC` 장비만 켬 + `cisco-nso-labc`
- `LabD` 작업 시: `LabD` 장비만 켬 + `cisco-nso-labd`

즉, 장비는 순차 실행이고, NSO는 병렬로 분리 가능하다.

랩 전환 전에는 반드시 `pnet0` 상태를 확인한다.

```bash
brctl show pnet0
bridge fdb show br pnet0
```

정상 원칙:

- 현재 작업 랩의 OOB 인터페이스만 `pnet0`에 붙어 있어야 한다.
- 이전 랩의 `vunl*` 인터페이스가 남아 있으면 IP 충돌 가능성이 있다.
- 콘솔에 `%IP-4-DUPADDR`가 보이면 NSO sync를 계속하지 말고 먼저 중복 MAC을 찾아야 한다.

## 2. LabA에서 실제로 확인된 사항

LabA를 살리면서 확인된 중요한 포인트는 다음과 같다.

1. `deploy` 파이프라인이 최신이다.
2. `deploy.1_push_configs`는 `device_info.json`의 `oob_intf`를 사용해 SSH를 여는 방식이 아니라, `.cfg` 내용을 텔넷 콘솔로 그대로 넣는다.
3. 따라서 실제 관리 인터페이스는 `device_info.json`보다 `.cfg`와 PNETLab 배선이 더 중요하다.
4. LabA는 처음에 `device_info.json`의 `oob_intf`를 `GigabitEthernet0/7`로 봤지만, 실제 LabA `.cfg`와 topology 문서는 `GigabitEthernet0/2` 또는 `GigabitEthernet0/3`를 관리 인터페이스로 사용했다.
5. PNETLab에서 Cloud0 배선을 `.cfg`와 맞춘 뒤 `deploy.2_verify`에서 `Ping 10/10 OK`가 나왔고, 그 상태가 정상 상태다.

LabA에서 성공 기준:

- `deploy.1_push_configs`: `Config Push 10/10 OK`
- `deploy.1_push_configs`: `RSA Keys 10/10 OK`
- `deploy.2_verify`: `Ping 10/10 OK`

## 3. PNETLab 호스트 필수 설정

PNETLab VM에서 관리망 접근을 위해 아래가 필요하다.

```bash
ip addr show pnet0
sudo ip addr add 10.10.10.1/24 dev pnet0
ip route | grep 10.10.10
```

정상 예시:

```bash
10.10.10.0/24 dev pnet0 proto kernel scope link src 10.10.10.1
```

Tailscale subnet route도 PNETLab VM에서 광고되어 있어야 한다.

```bash
sudo tailscale set --advertise-routes=10.10.10.0/24
```

그리고 Tailscale Admin에서 해당 route가 승인되어 있어야 한다.

## 4. NSO 컨테이너 분리 방식

기존 NSO:

```bash
cisco-nso-dev -> :8080
```

LabA 전용 NSO:

```bash
docker run -d --name cisco-nso-laba \
  -p 18080:8080 -p 12022:2022 -p 12024:2024 \
  cisco-nso-dev:6.6-ssh-rsa
```

LabC 전용 NSO:

```bash
docker run -d --name cisco-nso-labc \
  -p 28080:8080 -p 22022:2022 -p 22024:2024 \
  cisco-nso-dev:6.6-ssh-rsa
```

LabD 전용 NSO:

```bash
docker run -d --name cisco-nso-labd \
  -p 38080:8080 -p 32022:2022 -p 32024:2024 \
  cisco-nso-dev:6.6-ssh-rsa
```

상태 확인:

```bash
docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
```

## 5. 사용해야 하는 스크립트

### 5.1 Config Push / Verify

최신 파이프라인:

- `Make_Dataset/src/deploy/1_push_configs.py`
- `Make_Dataset/src/deploy/2_verify.py`

실행 위치:

```bash
cd /home/sdlab08/projects/GIA/Make_Dataset/src
```

### 5.2 NSO Register

원칙적 최신 스크립트:

- `Make_Dataset/src/deploy/3_register_nso.py`

하지만 현재 WSL Docker NSO에서는 다음 문제가 있다.

- `http://127.0.0.1:8080/restconf/...` -> `400 Bad Request`
- `http://127.0.0.1:18080/restconf/...` -> `400 Bad Request`

즉, RESTCONF 등록이 현재 환경에서 동작하지 않는다.

따라서 현재는 다음 fallback 스크립트를 쓴다.

- `Make_Dataset/src/2-NSO_Register.py`

이 스크립트는 이미 `--device-info`, `--nso-container`를 지원하도록 수정되어 있다.

## 6. 랩별 공통 작업 순서

### 6.1 사전 원칙

1. 작업 대상 랩만 PNETLab에서 켠다.
2. 다른 랩 장비는 전부 끈다.
3. 해당 랩 전용 NSO 컨테이너를 사용한다.
4. PNETLab VM에서 `pnet0`에 예전 랩 `vunl*` 인터페이스가 남아 있지 않은지 확인한다.

확인 명령:

```bash
brctl show pnet0
bridge fdb show br pnet0
```

중복 IP 로그가 이미 보이면, 상대 MAC을 기준으로 원인 인터페이스를 찾는다.

예시:

```text
*Apr 24 01:44:19.495: %IP-4-DUPADDR: Duplicate address 10.10.10.21 on GigabitEthernet0/7, sourced by 50ba.bd00.3e03
```

MAC 변환:

```text
50ba.bd00.3e03 -> 50:ba:bd:00:3e:03
```

PNETLab VM에서 원인 인터페이스 찾기:

```bash
bridge fdb show br pnet0 | egrep -i '50:ba:bd:00:3e:03'
```

예시 결과:

```text
50:ba:bd:00:3e:03 dev vunl62_3 master pnet0
```

임시 차단:

```bash
ip link set vunl62_3 down
```

주의:

- `ip link set vunl*_x down`은 런타임 임시 조치다.
- 근본적으로는 PNETLab UI에서 해당 예전 노드/랩을 완전히 stop해야 한다.
- 그래도 급한 NSO sync 복구에는 해당 `vunl*` down이 가장 빠르다.

### 6.2 Step 1: Config Push

예시: LabA

```bash
cd /home/sdlab08/projects/GIA/Make_Dataset/src

python3 -m deploy.1_push_configs \
  --device-info /home/sdlab08/projects/GIA/Data/Pnetlab/LabA_Research_Institute_DC_10nodes/device_info.json \
  --configs-dir /home/sdlab08/projects/GIA/Data/Pnetlab/LabA_Research_Institute_DC_10nodes/configs
```

예시: LabC

```bash
cd /home/sdlab08/projects/GIA/Make_Dataset/src

python3 -m deploy.1_push_configs \
  --device-info /home/sdlab08/projects/GIA/Data/Pnetlab/LabC_NCN_Security_L2VPN_30nodes/device_info.json \
  --configs-dir /home/sdlab08/projects/GIA/Data/Pnetlab/LabC_NCN_Security_L2VPN_30nodes/configs
```

예시: LabD

```bash
cd /home/sdlab08/projects/GIA/Make_Dataset/src

python3 -m deploy.1_push_configs \
  --device-info /home/sdlab08/projects/GIA/Data/Pnetlab/LabD_NCN_MultiAS_Complex_40nodes/device_info.json \
  --configs-dir /home/sdlab08/projects/GIA/Data/Pnetlab/LabD_NCN_MultiAS_Complex_40nodes/configs
```

### 6.3 Step 2: Verify

예시: LabC

```bash
cd /home/sdlab08/projects/GIA/Make_Dataset/src

python3 -m deploy.2_verify \
  --device-info /home/sdlab08/projects/GIA/Data/Pnetlab/LabC_NCN_Security_L2VPN_30nodes/device_info.json
```

성공 기준:

- `Ping: N/N OK`
- 주요 프로토콜 출력이 일부라도 정상적으로 보임

### 6.4 Step 3: NSO Registe

현재 권장 방식은 fallback CLI 스크립트다.

예시: LabA

```bash
cd /home/sdlab08/projects/GIA

python3 Make_Dataset/src/2-NSO_Register.py \
  --device-info Data/Pnetlab/LabA_Research_Institute_DC_10nodes/device_info.json \
  --nso-container cisco-nso-laba
```

예시: LabC

```bash
cd /home/sdlab08/projects/GIA

python3 Make_Dataset/src/2-NSO_Register.py \
  --device-info Data/Pnetlab/LabC_NCN_Security_L2VPN_30nodes/device_info.json \
  --nso-container cisco-nso-labc
```

예시: LabD

```bash
cd /home/sdlab08/projects/GIA

python3 Make_Dataset/src/2-NSO_Register.py \
  --device-info Data/Pnetlab/LabD_NCN_MultiAS_Complex_40nodes/device_info.json \
  --nso-container cisco-nso-labd
```

## 7. LabA에서 중요한 예외

LabA는 `device_info.json`만 보고 판단하면 안 된다.

이유:

- LabA의 topology 문서와 `.cfg`는 장비별 관리 인터페이스가 `GigabitEthernet0/2` 또는 `GigabitEthernet0/3` 기준이다.
- 따라서 PNETLab에서 Cloud0 배선도 그 기준과 맞아야 한다.
- `device_info.json`의 `oob_intf`를 `GigabitEthernet0/7`로 두더라도, `.cfg`가 `Gi0/2/3`에 관리 IP를 넣고 있으면 실제 SSH는 `Gi0/2/3` 쪽으로 열리게 된다.

LabA는 반드시 다음을 확인한다.

1. Cloud0 배선이 `.cfg`와 실제로 맞는지
2. `deploy.2_verify`에서 `Ping 10/10 OK`가 나오는지
3. 그 후에 NSO 등록을 진행하는지

## 8. LabC / LabD에서 `device_info.json` 수정 포인트

현재 `LabC`, `LabD`의 `device_info.json`은 기본 골격은 맞지만, 실제 사용 전에는 반드시 아래를 수정해야 한다.

### 8.1 공통 수정 항목

반드시 확인/수정:

1. `global_settings.pnetlab_vm_ip`
2. `global_settings.gateway_ip`
3. `global_settings.domain_name`
4. `global_settings.admin_password`
5. 각 장비의 `telnet_port`
6. 각 장비의 `oob_intf`

### 8.2 telnet_port

현재 `LabC`, `LabD`는 거의 모든 장비가 `telnet_port: 0`이다.

이 값은 반드시 실제 PNETLab 콘솔 포트로 바꿔야 한다.

확인 방법:

- PNETLab UI에서 노드 우클릭 -> 정보 -> Console Port 확인
- 또는 PNETLab VM에서:

```bash
find /opt/unetlab/tmp -name "*.lock" -exec sh -c 'echo "$(dirname {}): $(cat {})"' \;
```

`telnet_port`를 안 채우면 `deploy.1_push_configs`와 `deploy.2_verify`가 제대로 동작하지 않는다.

### 8.3 oob_intf

`LabC`, `LabD`는 현재 `oob_intf: GigabitEthernet0/7`로 되어 있다.

이 값은 다음 조건일 때만 유지한다.

- 실제 PNETLab 배선에서 모든 장비의 Cloud0 management 포트가 `Gi0/7`일 때

만약 실제 배선이 다르면, 반드시 실제 포트 번호로 수정해야 한다.

즉:

- 문서/CFG/PNETLab 배선이 모두 `Gi0/7`이면 그대로 사용
- 하나라도 다르면 `device_info.json`과 PNETLab 배선을 다시 맞춘다

### 8.4 nso 관련 값

현재 파일의 `nso_ip`, `nso_port`는 PNETLab 내부 NSO 기준 값이 들어 있다.

현재 운영은 WSL Docker NSO를 쓰므로 실제 등록 때는 `2-NSO_Register.py --nso-container ...`를 쓰고, `deploy.3_register_nso`는 사용하지 않는다.

따라서 당장 중요한 값은 다음이다.

- `nso_authgroup`
- `nso_ned_id`
- `nso_username`
- `nso_password`

권장 값:

- `nso_username`: `admin`
- `nso_password`: `admin`
- `nso_ned_id`: `cisco-ios-cli-6.110`

주의:

- `LabA`에는 한때 `cisco-ios-cli-6.110:cisco-ios-cli-6.110` 형태가 들어 있었는데, 일반적으로는 `cisco-ios-cli-6.110` 단일 값이 더 안전하다.

## 9. LabC / LabD용 권장 체크리스트

### 9.1 LabC 시작 전

1. `LabA`, `LabB`, `LabD` 장비 전부 OFF
2. `LabC` 장비만 ON
3. `device_info.json`에서 `telnet_port` 전부 수정
4. `oob_intf`가 실제 Cloud0 포트와 맞는지 확인
5. `cisco-nso-labc` 실행

### 9.2 LabC 실행

```bash
cd /home/sdlab08/projects/GIA/Make_Dataset/src

python3 -m deploy.1_push_configs \
  --device-info /home/sdlab08/projects/GIA/Data/Pnetlab/LabC_NCN_Security_L2VPN_30nodes/device_info.json \
  --configs-dir /home/sdlab08/projects/GIA/Data/Pnetlab/LabC_NCN_Security_L2VPN_30nodes/configs

python3 -m deploy.2_verify \
  --device-info /home/sdlab08/projects/GIA/Data/Pnetlab/LabC_NCN_Security_L2VPN_30nodes/device_info.json
```

그 다음:

```bash
cd /home/sdlab08/projects/GIA

python3 Make_Dataset/src/2-NSO_Register.py \
  --device-info Data/Pnetlab/LabC_NCN_Security_L2VPN_30nodes/device_info.json \
  --nso-container cisco-nso-labc
```

### 9.3 LabD 시작 전

1. `LabA`, `LabB`, `LabC` 장비 전부 OFF
2. `LabD` 장비만 ON
3. `device_info.json`에서 `telnet_port` 전부 수정
4. `oob_intf`가 실제 Cloud0 포트와 맞는지 확인
5. `cisco-nso-labd` 실행

### 9.4 LabD 실행

```bash
cd /home/sdlab08/projects/GIA/Make_Dataset/src

python3 -m deploy.1_push_configs \
  --device-info /home/sdlab08/projects/GIA/Data/Pnetlab/LabD_NCN_MultiAS_Complex_40nodes/device_info.json \
  --configs-dir /home/sdlab08/projects/GIA/Data/Pnetlab/LabD_NCN_MultiAS_Complex_40nodes/configs

python3 -m deploy.2_verify \
  --device-info /home/sdlab08/projects/GIA/Data/Pnetlab/LabD_NCN_MultiAS_Complex_40nodes/device_info.json
```

그 다음:

```bash
cd /home/sdlab08/projects/GIA

python3 Make_Dataset/src/2-NSO_Register.py \
  --device-info Data/Pnetlab/LabD_NCN_MultiAS_Complex_40nodes/device_info.json \
  --nso-container cisco-nso-labd
```

## 10. 장애 시 빠른 판단 기준

### 10.1 `deploy.1_push_configs`는 성공했는데 ping 실패

원인 후보:

- Cloud0 배선이 `.cfg`의 관리 인터페이스와 다름
- PNETLab VM의 `pnet0`에 `10.10.10.1/24`가 없음
- 다른 랩 장비가 켜져 있어 IP 충돌 발생

### 10.2 `deploy.2_verify` ping은 성공했는데 NSO 등록 실패

원인 후보:

- WSL Docker NSO에서 장비 SSH 접속 불가
- NED ID 문제
- authgroup 계정 정보 불일치
- PNETLab `pnet0`에 같은 OOB IP를 가진 잔여 `vunl*` 인터페이스가 남아 있어 NSO가 다른 장비의 SSH key를 받음

우선 확인:

```bash
python3 - <<'PY'
import socket
s = socket.socket()
s.settimeout(5)
try:
    s.connect(("10.10.10.11", 22))
    print("OK")
except Exception as e:
    print("FAIL:", e)
finally:
    s.close()
PY
```

### 10.3 `%IP-4-DUPADDR` 또는 NSO host-key mismatch

대표 증상:

```text
%IP-4-DUPADDR: Duplicate address 10.10.10.21 on GigabitEthernet0/7, sourced by 50ba.bd00.3e03
Could not verify `ssh-rsa` host key with fingerprint ... for `10.10.10.21`
```

의미:

- 같은 관리 IP를 가진 장비가 `pnet0`에 둘 이상 붙어 있다.
- NSO가 대상 장비가 아닌 다른 장비의 SSH host key를 저장했을 수 있다.
- 이 상태에서 `ssh fetch-host-keys`를 반복하면 NSO host-key 캐시가 더 꼬인다.

해결 순서:

1. 중복 MAC을 Cisco 형식에서 Linux 형식으로 바꾼다.
2. PNETLab VM에서 해당 MAC이 붙은 `vunl*` 인터페이스를 찾는다.
3. 해당 인터페이스를 down하거나 PNETLab UI에서 해당 노드를 완전히 stop한다.
4. 중복 IP 로그가 더 이상 나오지 않는지 확인한다.
5. NSO에 잘못 저장된 host key를 지우고 다시 fetch한다.
6. 해당 장비만 `sync-from` 재시도한다.

명령 예시:

```bash
bridge fdb show br pnet0 | egrep -i '50:ba:bd:00:3e:03|50:21:86:00:40:03'
ip link set vunl62_3 down
ip link set vunl64_3 down
```

NSO host-key 정리 예시:

```bash
docker exec cisco-nso-labc bash -lc '
cd ~/ncs-instance && source ~/nso-6.6/ncsrc &&
ncs_cli -C -u admin <<EOF
config
no devices device Leaf1 ssh host-key ssh-rsa
no devices device PE1 ssh host-key ssh-rsa
commit
exit
devices device Leaf1 ssh fetch-host-keys
devices device PE1 ssh fetch-host-keys
devices device Leaf1 sync-from
devices device PE1 sync-from
EOF
'
```

### 10.4 Cisco IOS NED `show vtp password` / `show running-config` timeout

대표 증상:

```text
External error in the NED implementation: read timeout after 0 seconds when waiting for \Qshow vtp password\E
External error in the NED implementation: read timeout after 0 seconds when waiting for \Qshow running-config\E
```

판단:

- 먼저 `%IP-4-DUPADDR`가 없는지 확인한다.
- host-key mismatch가 있으면 먼저 host-key를 정리한다.
- 중복 IP와 host-key 문제가 없는데도 timeout이 반복되면 IOSv/NED 세션이 느리거나 꼬인 상태다.

대응:

```bash
docker exec cisco-nso-labc bash -lc '
cd ~/ncs-instance && source ~/nso-6.6/ncsrc &&
ncs_cli -C -u admin <<EOF
config
devices device Leaf1 read-timeout 180
devices device Leaf3 read-timeout 180
devices device Leaf4 read-timeout 180
devices device PE1 read-timeout 180
commit
exit
devices device Leaf1 disconnect
devices device Leaf3 disconnect
devices device Leaf4 disconnect
devices device PE1 disconnect
devices device Leaf1 sync-from
devices device Leaf3 sync-from
devices device Leaf4 sync-from
devices device PE1 sync-from
EOF
'
```

그래도 안 되면 해당 장비만 PNETLab에서 stop/start 후 2~3분 기다리고 다시 `sync-from`한다. 이때 wipe는 하지 않는다.

### 10.5 `deploy.3_register_nso`에서 NSO 연결 실패

현재 환경에서는 RESTCONF 400 문제일 가능성이 높다.

대응:

- `deploy.3_register_nso`는 중단
- `2-NSO_Register.py --nso-container ...` 사용

## 11. 지금 시점의 가장 안전한 실무 규칙

다른 AI가 바로 이해해야 하는 한 줄 요약:

> 지금 환경은 `deploy`로 config push/verify를 하고, NSO 등록만 `2-NSO_Register.py --nso-container`로 우회한다. 각 랩은 별도 NSO를 쓰지만, 관리 IP는 중복이므로 장비는 한 번에 한 랩만 켠다.

추가 운영 규칙:

> 한 랩만 켰다고 생각해도 PNETLab VM의 `pnet0`에 예전 `vunl*` 인터페이스가 남아 있으면 같은 OOB IP가 충돌한다. `%IP-4-DUPADDR` 또는 NSO host-key mismatch가 나오면 `device_info.json`보다 먼저 `bridge fdb show br pnet0`로 중복 MAC의 실제 `vunl*` 인터페이스를 찾는다.
