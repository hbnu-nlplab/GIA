# NetAlly PNETLab 배포 가이드

이 문서는 NetAlly 시스템을 PNETLab 환경에서 Docker 노드로 배포하고, 웹 인터페이스에 쉽게 접속할 수 있도록 설정하는 방법을 안내합니다.

## 📋 개요

NetAlly는 프론트엔드(React)와 백엔드(FastAPI)가 통합된 Docker 이미지로 제공됩니다. PNETLab의 **Docker Node** 기능을 사용하여 VPCS 없이 단독 장비처럼 구동할 수 있으며, 마우스 클릭으로 웹 UI에 바로 접속할 수 있습니다.

---

## 🚀 1. Docker 이미지 준비

먼저 PNETLab 서버에 NetAlly 도커 이미지가 있어야 합니다.

### 방법 A: Docker Hub에서 Pull (권장)
이미지가 Docker Hub에 올라가 있다면 PNETLab 서버의 터미널(SSH)에서 아래 명령어를 실행합니다.
```bash
docker pull your-repo/netally:latest
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
| **Image** | `your-repo/netally:latest` | 방금 추가한 이미지 선택 |
| **Name** | `NetAlly-Controller` | 식별하기 쉬운 이름 |
| **Icon** | `Server.png` 또는 `Desktop.png` | 어울리는 아이콘 선택 |
| **CPU/RAM** | 1024 / 2048 | 최소 2GB RAM 권장 |
| **Console Type** | **`http`** | **중요!** 클릭 시 웹으로 연결 |
| **Console Port** | **`8000`** | NetAlly 웹 서비스 포트 |

> **팁**: `Console Type`을 `http`로 설정하는 것이 핵심입니다. 이 설정을 통해 아이콘을 클릭했을 때 Telnet 대신 웹 브라우저가 열립니다.

---

## 🌐 3. 네트워크 구성

NetAlly가 PNETLab 내부의 다른 라우터/스위치와 통신하려면 적절한 네트워크에 연결되어야 합니다.

*   **Management Network**: `Cloud0` (ManagementCloud)와 연결하여 외부(사용자 PC)에서 접속 가능하게 할 수도 있습니다.
*   **Internal Network**: Lab 내부 장비들과 같은 Bridge에 연결하여 장비들을 제어(Telnet/SSH/SNMP)합니다.

---

## 🖱️ 4. 접속 및 사용

### 아이콘 더블 클릭
설정이 정확하다면, PNETLab 토폴로지 맵에서 NetAlly 아이콘을 **더블 클릭**하는 순간 새 브라우저 탭이 열리며 NetAlly 대시보드(`http://<NODE_IP>:8000`)로 접속됩니다.

### 수동 접속
만약 아이콘 클릭이 작동하지 않는다면:
1.  PNETLab 내에서 NetAlly 노드의 IP를 확인합니다. (보통 부팅 시 콘솔 로그에 뜨거나, `Cloud0` DHCP로 할당됨)
2.  브라우저 주소창에 `http://<PNETLAB_BOX_IP>:<MAPPED_PORT>` 또는 (PNETLab 내부망 접근 시) `http://<NODE_IP>:8000`을 직접 입력합니다.

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
