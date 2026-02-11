# NetAlly PNETLab 배포 가이드

이 문서는 NetAlly 시스템을 PNETLab 환경에서 Docker 노드로 배포하고, 웹 인터페이스에 쉽게 접속할 수 있도록 설정하는 방법을 안내합니다.

문서 허브: `docs/README_ko.md`

실제 데모 운영 기준(스크린샷 기반 설정값, NetAlly-NSO-Chromebook 배선, `docker_options` 완성값)은
`docs/pnetlab_wiring_runbook_ko.md`를 함께 참고하세요.

## 📋 개요

NetAlly는 프론트엔드(React)와 백엔드(FastAPI)가 통합된 Docker 이미지로 제공됩니다. PNETLab의 **Docker Node** 기능을 사용하여 VPCS 없이 단독 장비처럼 구동할 수 있으며, 마우스 클릭으로 웹 UI에 바로 접속할 수 있습니다.

---

## 🚀 1. Docker 이미지 준비

먼저 PNETLab 서버에 NetAlly 도커 이미지가 있어야 합니다.

### 방법 A: Docker Hub에서 Pull (권장)
이미지가 Docker Hub에 올라가 있다면 PNETLab 서버의 터미널(SSH)에서 아래 명령어를 실행합니다.
```bash
docker pull <your-registry>/netally:latest
```

### 방법 B: 직접 빌드 및 전송
로컬에서 빌드한 이미지를 PNETLab 서버로 전송합니다.
```bash
# 로컬 개발 환경에서 이미지 저장
docker save -o netally.tar netally:latest

# SCP 등을 통해 PNETLab 서버로 전송
scp netally.tar root@<PNETLAB_IP>:/root/

# PNETLab 서버에서 이미지 로드
docker load -i netally.tar
```

---

## 🛠️ 2. PNETLab에 노드 추가 (Add Docker Node)

1.  **PNETLab 웹 UI**에 접속하여 실습 Lab을 엽니다.
2.  빈 공간 우클릭 -> **Node** 선택.
3.  **Docker** 아이콘(보통 고래 모양)을 선택합니다.
4.  설정 창에서 다음 항목을 입력합니다:

| 항목 | 설정값 | 설명 |
|---|---|---|
| **Image** | `netally:latest` | 현재 운영 기준 이미지 |
| **Name** | `NetAlly-Controller` | 식별하기 쉬운 이름 |
| **Icon** | `Server.png` 또는 `Desktop.png` | 어울리는 아이콘 선택 |
| **CPU/RAM** | 1024 / 2048 | 최소 2GB RAM 권장 |
| **Console Type** | **`http`** | **중요!** 클릭 시 웹으로 연결 |
| **Console Port** | **`8000`** | NetAlly 웹 서비스 포트 |

> **팁**: `Console Type`을 `http`로 설정하는 것이 핵심입니다. 이 설정을 통해 아이콘을 클릭했을 때 Telnet 대신 웹 브라우저가 열립니다.

### 2.1 Docker Options 실전 입력 예시

초기에는 `--privileged`만 넣어도 컨테이너는 뜨지만, 데모 안정성을 위해 아래 옵션까지 한 번에 넣는 것을 권장합니다.

```bash
--privileged -v /opt/unetlab:/opt/unetlab:ro --add-host=host.docker.internal:host-gateway -e PNETLAB_INVENTORY_BACKEND=labfs_local -e PNETLAB_LAB_NAME=test_nso -e NSO_BASE_URL=http://10.10.10.100:8080/restconf -e BATFISH_HOST=host.docker.internal:9997 -e BATFISH_SNAPSHOT=test_nso -e AUTO_INIT_BATFISH=true -e NETALLY_TOOL_BACKEND=mcp -e NETALLY_MCP_ALLOW_MUTATIONS=true
```

설명:
- `PNETLAB_INVENTORY_BACKEND=labfs_local`: 쿠키 없이 `.unl` 기반 토폴로지 복제
- `NSO_BASE_URL`: NSO RESTCONF 엔드포인트 고정
- `BATFISH_HOST`: 호스트에서 띄운 Batfish 컨테이너 접속
- `AUTO_INIT_BATFISH=true`: Prepare 버튼으로 스냅샷 초기화 자동 시도

---

## 🌐 3. 네트워크 구성 (권장)

NetAlly가 PNETLab 내부의 다른 라우터/스위치와 통신하려면 적절한 네트워크에 연결되어야 합니다.

*   **Management Network**: `Cloud0` (ManagementCloud)에 연결하여 외부(사용자 PC)에서 UI 접속 가능하게 합니다.
*   **Internal Network**: Lab 내부 장비들과 같은 Bridge(예: `pnet2`)에 연결하여 장비들을 제어(Telnet/SSH)합니다.

> **중요**: NetAlly가 장비 Telnet 포트에 접근하려면 **장비들도 동일한 관리망(Cloud0/Cloud2 또는 OOB 스위치)**에 연결되어 있어야 합니다.  
> NetAlly만 관리망에 연결하고 장비들은 미연결이면, Telnet 접근이 실패할 수 있습니다.

### 3.1 NetAlly-NSO-Chromebook 배선 기준

권장 배선:
- NetAlly Docker Node `eth1` → Management Cloud
- NSO Node `eth2` → 동일 Management Cloud
- NSO Node `eth1` ↔ Chromebook `eth1` (관리자 LAN, 예: `192.168.1.0/24`)

이렇게 구성하면:
- NetAlly는 NSO/Batfish/장비 관리망을 처리
- Chromebook은 운영자 웹 접속(NSO UI/관리 페이지)에 집중

---

## 🗺️ 3.5 PNETLab 토폴로지 "쿠키 없이" 복제하기 (권장: LabFS)

PNETLab 웹/API는 CAPTCHA/XSRF 때문에 쿠키 자동화가 불안정할 수 있습니다.  
NetAlly는 토폴로지 맵 복제를 위해 **PNETLab 파일 시스템(LabFS)** 를 읽는 경로를 지원합니다:

- `.unl`: 노드 위치(left/top), 아이콘, 네트워크/연결 메타데이터
- `/opt/unetlab/tmp/*/*/wrapper.txt`: 실행 중 노드의 콘솔 포트(best-effort)

### 핵심: 컨테이너에 `/opt/unetlab`을 read-only로 바인드 마운트

NetAlly가 PNETLab VM 내부에서 Docker 컨테이너로 실행되더라도, 기본적으로는 호스트의 `/opt/unetlab`을 볼 수 없습니다.  
따라서 **컨테이너에 `/opt/unetlab:/opt/unetlab:ro` 마운트가 필요**합니다.

PNETLab UI의 Docker Node 설정에서 volume/host path mapping 기능이 있다면:
- Host: `/opt/unetlab`
- Container: `/opt/unetlab`
- Mode: `ro` (read-only 권장)

만약 UI에서 마운트를 지원하지 않는 환경이라면, PNETLab 호스트에서 `docker run -v /opt/unetlab:/opt/unetlab:ro ...` 형태로 실행하는 방식이 더 확실합니다.

### 권장 환경 변수

토폴로지 복제는 PNETLab API 인증 없이도 가능합니다.

```bash
PNETLAB_INVENTORY_BACKEND=labfs_local
PNETLAB_LAB_NAME=test_nso          # 또는 PNETLAB_LAB_PATH=/opt/unetlab/labs/test_nso.unl
```

> 참고: 위 설정이 되어 있으면 NetAlly의 `/api/topology/pnetlab`가 쿠키 없이도 동작합니다.

---

## 🧭 4. 내부망 기반 자동 등록 파이프라인 (권장 흐름)

NetAlly를 PNETLab 내부 Docker 노드로 실행하면, 다음 파이프라인으로 자동 등록이 가능합니다.

1. **PNETLab 내부망 연결**
   - NetAlly 노드 + 장비 노드를 **같은 관리망(Cloud/OOB)**에 연결
2. **Telnet 접근 가능 상태 확인**
   - 장비 콘솔 포트가 PNETLab VM IP + Telnet 포트로 접근 가능해야 함
3. **lab_bootstrap 실행**
   - SSH 활성화 → NSO 등록 → sync-from

### 사용 예시
```
lab_bootstrap(action="enable_ssh")
lab_bootstrap(action="register_nso")
lab_bootstrap(action="full")
```

> `device_info.json`은 **PNETLab API로 자동 생성**됩니다.  
> 내부망 기준에서는 `oob_ip` 없이도 동작하도록 구성되어 있습니다.

### 자동 생성 / Refresh 시나리오
```
lab_bootstrap(action="generate_device_info")
lab_bootstrap(action="refresh_onboard")  # 신규 장비만 부트스트랩
```

---

## 🖱️ 5. 접속 및 사용

### 아이콘 더블 클릭
설정이 정확하다면, PNETLab 토폴로지 맵에서 NetAlly 아이콘을 **더블 클릭**하는 순간 새 브라우저 탭이 열리며 NetAlly 대시보드(`http://<NODE_IP>:8000`)로 접속됩니다.

### 수동 접속
만약 아이콘 클릭이 작동하지 않는다면:
1.  PNETLab 내에서 NetAlly 노드의 IP를 확인합니다. (보통 부팅 시 콘솔 로그에 뜨거나, `Cloud0` DHCP로 할당됨)
2.  브라우저 주소창에 `http://<PNETLAB_BOX_IP>:<MAPPED_PORT>` 또는 (PNETLab 내부망 접근 시) `http://<NODE_IP>:8000`을 직접 입력합니다.

### 로컬 브라우저에서 NSO + NetAlly 같이 접속하는 방법

현재처럼 NSO/NetAlly 컨테이너에 host port publish가 없을 때는 **SSH 터널**이 가장 간단합니다.

```bash
# 로컬 PC에서 실행
ssh -N \
  -L 18080:10.10.10.100:8080 \
  -L 18111:172.17.0.20:8000 \
  root@<PNETLAB_VM_IP>
```

> `172.17.0.20`은 예시입니다. 실제 NetAlly 컨테이너 IP로 바꿔야 합니다.  
> 확인 명령: `docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' <netally_container_name>`

접속:
- NSO: `http://127.0.0.1:18080`
- NetAlly: `http://127.0.0.1:18111`

대안:
- NetAlly Docker Options에 `-p 18111:8000`을 넣어 포트를 직접 노출할 수도 있습니다.

### Refresh 버튼 (부트스트랩)
상단의 **Refresh** 버튼은 신규 장비만 자동 부트스트랩합니다.
- 내부적으로 `lab_bootstrap(action="refresh_onboard")`가 실행됨
- `device_info.json`이 없으면 PNETLab API로 자동 생성
- **Settings > Bootstrap Overrides**에서 OOB 인터페이스/그룹/게이트웨이 등을 입력하면 생성 시 반영됨

### Batfish 서버 점검(데모 필수)
NetAlly Docker Node에서 Batfish까지 실제로 쓰려면, PNETLab 호스트에 Batfish 컨테이너가 떠 있어야 합니다.

```bash
# PNETLab 호스트(root)에서 1회 실행
docker run -d --name netally-batfish --restart unless-stopped \
  -p 9996:9996 -p 9997:9997 batfish/allinone:latest

# 헬스 확인 (/v2는 이미지에 따라 404일 수 있어 /v2/version 권장)
curl -fsS http://127.0.0.1:9996/v2/version
```

NetAlly Docker Node `docker_options`에는 아래를 권장합니다.
- `--add-host=host.docker.internal:host-gateway`
- `-e BATFISH_HOST=host.docker.internal:9997`
- `-e AUTO_INIT_BATFISH=true`

### Prepare 버튼 (Batfish 준비)
상단의 **Prepare** 버튼은 Batfish 상태를 점검합니다.
- `/api/lab/prepare` 호출
- 상태가 `ready/loaded/initialized`면 분석 가능

### PNETLab API 인증 (선택)
NetAlly의 일부 기능(예: `device_info.json` 자동 생성/부트스트랩)은 PNETLab API 접근이 필요할 수 있습니다.

- **Auto Login**: Settings에서 계정/비밀번호 입력 후 활성화
- **Cookies**: 자동로그인이 실패하면 쿠키를 입력하여 인증

반면, **토폴로지 맵 복제(`/api/topology/pnetlab`)는 LabFS 모드에서 쿠키 없이 동작**합니다.

---

## ❓ 문제 해결 (Troubleshooting)

### Q1. 아이콘을 눌러도 반응이 없거나 에러가 뜹니다.
*   PNETLab 버전에 따라 `http` 콘솔 타입을 지원하지 않을 수 있습니다. 이 경우 `Console Type`을 `vncp`로 두고, VNC로 접속하여 내부 브라우저(Firefox 등)를 띄우거나, 수동으로 IP를 확인해 접속해야 합니다.

### Q2. 접속은 되는데 "Connection Refused"가 뜹니다.
*   NetAlly 컨테이너가 정상적으로 실행 중인지(`docker ps`) 확인하세요.
*   NetAlly 애플리케이션이 `0.0.0.0`으로 바인딩되어 있는지 확인합니다. (현재 코드는 `0.0.0.0:8000`으로 설정 완료됨)

### Q3. 다른 장비에 Ping이 안 나갑니다.
*   NetAlly 노드가 올바른 vSwitch/Bridge에 연결되어 있는지 확인하세요.
*   Docker 컨테이너 내부의 IP 설정(`ifconfig` 등)이 Lab 네트워크 대역과 일치하는지 확인해야 합니다.
*   장비 노드도 동일한 관리망(Cloud/OOB)에 연결되어 있는지 확인하세요.

---

## 📚 관련 문서

- 문서 허브: `docs/README_ko.md`
- 실전 배선/운영: `docs/pnetlab_wiring_runbook_ko.md`
- 실행/테스트: `docs/testing_runbook_ko.md`
- API 계약: `docs/backend_api.md`
