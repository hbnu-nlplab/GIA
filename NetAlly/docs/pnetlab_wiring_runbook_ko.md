# NetAlly PNETLab 실전 배선/운영 런북 (KO)

이 문서는 현재 실습 환경처럼 **NetAlly가 PNETLab VM 내부 Docker Node로 실행**될 때,
`NetAlly ↔ NSO ↔ Chromebook ↔ 네트워크 노드`를 어떻게 연결하고 검증하는지에 집중한 실전 가이드입니다.

문서 허브: `docs/README_ko.md`

---

## 1. 현재 기준 런타임 상태 예시

PNETLab 호스트에서 아래처럼 보이면 정상적인 기준 상태입니다.

```bash
docker ps
```

예시:
- `netally-batfish` (`batfish/allinone:latest`, `9996-9997` publish)
- `docker15` (NetAlly 컨테이너)
- `docker10` (NSO 컨테이너)
- `docker9` (Chromebook 컨테이너)

### 1.1 현재 환경 스냅샷 (사용자 제공)

```text
CONTAINER ID   IMAGE                        ...   NAMES
b374e0e232b0   batfish/allinone:latest      ...   netally-batfish
6d749a2eec7d   97d2d44b05c2                 ...   docker15
ffd3e7b71977   pnetlab/pnet-chrome:latest   ...   docker9
41b98ac14cfa   ptthanh1511/nso:latest       ...   docker10
```

해석:
- `docker15`: NetAlly 앱 컨테이너
- `docker10`: NSO 컨테이너
- `docker9`: Chromebook 컨테이너
- `netally-batfish`: Batfish 서버 컨테이너

주의:
- `docker15`, `docker10`, `docker9` 이름은 노드 ID에 따라 달라질 수 있습니다.
- 문서에서는 이해를 위해 위 이름을 예시로 사용합니다.

이름 확인(실행 전):
```bash
docker ps --format 'table {{.Names}}\t{{.Image}}'
```
`<netally_container_name>` 자리는 여기서 확인한 실제 컨테이너 이름으로 바꿔서 실행하세요.

---

## 2. PNETLab 노드 배선 (가장 중요)

아래 연결이 맞아야 NetAlly 데모가 안정적으로 동작합니다.

| 구성요소 | 인터페이스 | 연결 대상 | 목적 |
|---|---|---|---|
| NetAlly Docker Node | `eth1` | Management Cloud | NSO/장비 관리망 접근 |
| NSO Node | `eth2` | 동일 Management Cloud | NetAlly와 RESTCONF 통신 |
| NSO Node | `eth1` | Admin LAN (`192.168.1.0/24`) | 관리자/Chromebook 웹 접근 |
| Chromebook Node | `eth1` | Admin LAN (`192.168.1.0/24`) | NSO 웹 UI 접속 |
| 라우터/스위치 노드 | OOB/Mgmt 인터페이스 (예: `e0/0`) | Management Cloud | 온보딩/수집 대상 |

핵심 포인트:
- NetAlly와 NSO는 반드시 같은 관리망에서 서로 도달 가능해야 합니다.
- Chromebook은 운영자 브라우저 용도이며, NSO 관리망과만 연결되어도 충분합니다.

---

## 3. NetAlly Docker Node 템플릿 설정 (스크린샷 기준)

PNETLab Node 설정 화면에서 아래를 기준으로 맞춥니다.

| 항목 | 권장 값 |
|---|---|
| Image | `netally:latest` |
| Name | `NetAlly` |
| CPU | 최소 `1`, 권장 `2` |
| RAM | 최소 `1024MB`, 권장 `2048MB` 이상 |
| Ethernet | `4` |
| Console | `http` |
| Console Port | `8000` |
| Docker Options (초기) | `--privileged` |

### 3.1 리소스 가이드 (데모 안정성 기준)

- 최소 동작: `1 core / 1024MB`
- 데모 권장: `2 core / 2048MB`
- 안정 여유: `2 core / 3072~4096MB`

설명:
- `1 core / 256MB`는 데모 중 응답 지연/재시작 위험이 큽니다.
- Batfish를 호스트에서 별도 컨테이너로 돌리더라도, NetAlly 자체에 최소 1GB는 권장합니다.
- VM 총 메모리는 `NSO + NetAlly + Batfish` 합계를 기준으로 계산해야 합니다.

---

## 4. Docker Options 완성 값 (복붙용)

`Docker Options` 입력창은 한 줄 입력이 안정적입니다.

```bash
--privileged -v /opt/unetlab:/opt/unetlab:ro --add-host=host.docker.internal:host-gateway -e PNETLAB_INVENTORY_BACKEND=labfs_local -e PNETLAB_LAB_NAME=test_nso -e PNETLAB_NSO_NODE=NSO -e BATFISH_HOST=host.docker.internal:9997 -e BATFISH_SNAPSHOT=test_nso -e AUTO_INIT_BATFISH=true -e NETALLY_TOOL_BACKEND=mcp -e NETALLY_MCP_ALLOW_MUTATIONS=true
```

설명:
- `-v /opt/unetlab:/opt/unetlab:ro`: 쿠키 없이 LabFS 토폴로지 복제
- `PNETLAB_INVENTORY_BACKEND=labfs_local`: VM 내부 실행 최적 경로
- `PNETLAB_NSO_NODE=NSO`: NSO 노드 이름으로 관리 IP를 자동 탐색해 RESTCONF URL을 구성
- `BATFISH_HOST=host.docker.internal:9997`: 호스트 Batfish 연결
- `AUTO_INIT_BATFISH=true`: Prepare 시 자동 초기화 시도

대체(NSO 주소를 명시해야 할 때):
- 자동 탐색이 어려우면 `-e NSO_BASE_URL=http://<REACHABLE_NSO_IP>:8080/restconf`를 직접 지정합니다.
- `<REACHABLE_NSO_IP>`는 NetAlly 컨테이너에서 실제로 닿는 주소를 사용합니다(예: `10.10.10.100` 또는 `192.168.1.1`).

---

## 5. NSO/Chromebook 연결 기준

### 5.1 NSO

- NetAlly가 NSO RESTCONF에 접근해야 하므로 아래 중 하나가 성공해야 합니다.
  - `http://<NSO_MGMT_IP>:8080/restconf`
  - `http://<NSO_ADMIN_IP>:8080/restconf`
  - `http://<NSO_CONTAINER_NAME>:8080/restconf` (임시)

중요:
- 현재 `docker ps` 출력에서 NSO(`docker10`)는 호스트 포트 publish가 없습니다.
- `NSO_BASE_URL`을 비워두면 NetAlly는 `PNETLAB_NSO_NODE`(기본값 `NSO`) 이름으로 NSO IP를 자동 탐색합니다.

간단 점검(호스트에서):
```bash
docker exec -it <netally_container_name> sh -lc 'python - << "PY"
import urllib.request, urllib.error
urls = [
    "http://10.10.10.100:8080/restconf",
    "http://192.168.1.1:8080/restconf",
    "http://docker10:8080/restconf",
]
for u in urls:
    try:
        r = urllib.request.urlopen(u, timeout=3)
        print(u, r.status)
    except Exception as e:
        print(u, "ERR", e)
PY'
```

### 5.2 Chromebook

Chromebook은 “운영자 브라우저” 역할입니다.

- NSO 웹 접속: `http://<NSO_ADMIN_IP>:8080/login.html`  
  예: `http://192.168.1.1:8080/login.html`
- NetAlly 접속:
  - 가장 쉬운 방식: PNETLab 캔버스에서 NetAlly 노드 더블클릭(http console)
  - 직접 IP 접속은 라우팅/망분리가 맞아야 합니다.

Chromebook 접속 참고:
- `docker ps` 기준 `docker9`는 `30009->3389`가 열려 있으므로, 호스트에서 원격 콘솔 경유 접근이 가능합니다.
- 단, 실제 운영 흐름에서는 PNETLab 캔버스에서 직접 콘솔을 여는 방식이 더 직관적입니다.

---

## 6. NetAlly/NSO 접속 방법 정리

질문 요약:
- “Admin Chromebook 노드만 열어서 접속해야 하나?”
- “내 로컬 브라우저에서 NSO/NetAlly 둘 다 접속 가능한가?”

답변:
- **네, Chromebook으로 접속해도 됩니다.**
- **로컬 브라우저에서도 가능합니다.** 단, 현재처럼 포트 publish가 없으면 **SSH 터널**이 가장 빠르고 안전합니다.

### 6.1 방법 A: PNETLab UI(노드 더블클릭) / Chromebook 사용

- NetAlly: PNETLab 캔버스에서 NetAlly 노드 더블클릭(http console)
- NSO: Admin Chromebook 노드에서 `http://<NSO_ADMIN_IP>:8080/login.html` 접속

장점:
- 설정이 단순
- 데모 중 가장 직관적

문제 해결:
- 더블클릭했는데 웹 대신 터미널만 뜨면 `Console Type`이 `linux`일 가능성이 큽니다.
- Node Edit에서 `Console Type=http`, `Console Port=8000`으로 변경 후 재시작하세요.

### 6.2 방법 B: 로컬 브라우저 + SSH 터널 (권장)

현재 `docker ps`에서 NSO/NetAlly는 host port publish가 없으므로, 아래처럼 터널링하면 로컬 브라우저에서 바로 접속할 수 있습니다.

전제:
- 로컬 PC에서 PNETLab VM SSH 가능 (`root@<PNETLAB_VM_IP>`)

예시:
```bash
# 로컬 PC에서 실행
ssh -N \
  -L 18080:10.10.10.100:8080 \
  -L 18111:127.0.0.1:8111 \
  root@192.168.50.60
```

설명:
- `18080 -> NSO(10.10.10.100:8080)`
- `18111 -> NetAlly 백엔드(예: host에서 8111로 노출된 경우)`

주의:
- NetAlly가 host에 8111로 안 떠 있다면, NetAlly 컨테이너 IP로 터널링해야 합니다.

컨테이너 IP 확인:
```bash
docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' <netally_container_name>
```

컨테이너 IP가 `172.17.0.20`이라면:
```bash
ssh -N -L 18111:172.17.0.20:8000 root@192.168.50.60
```

로컬 브라우저 접속:
- NSO: `http://127.0.0.1:18080`
- NetAlly: `http://127.0.0.1:18111`

### 6.3 방법 C: NetAlly Docker Options에 포트 공개

지속적으로 로컬 접속이 필요하면 `docker_options`에 포트 publish를 추가할 수 있습니다.

예시:
```bash
-p 18111:8000
```

그 후 로컬에서:
- `http://<PNETLAB_VM_IP>:18111`

주의:
- 포트 충돌/보안 이슈를 피하려면 데모용으로만 사용하고, 운영망에서는 SSH 터널 방식을 우선 권장합니다.

---

## 7. 적용 순서 (실수 방지)

1. NetAlly Docker Node `docker_options` 저장
2. 해당 노드 Stop/Start
3. PNETLab 호스트에서 컨테이너 상태 확인
```bash
docker ps
```
4. NetAlly 컨테이너에 환경변수 반영 확인
```bash
docker exec -it <netally_container_name> env | egrep 'PNETLAB_INVENTORY_BACKEND|PNETLAB_LAB_NAME|PNETLAB_NSO_NODE|NSO_BASE_URL|BATFISH_HOST|AUTO_INIT_BATFISH|NETALLY_MCP_ALLOW_MUTATIONS'
```
5. Batfish 준비 상태 확인
```bash
curl -fsS http://127.0.0.1:9996/v2/version
```
6. UI에서 `Prepare` 클릭 후 Map View 확인
  - `🧪 Lab` (PNETLab 좌표 기반)
  - `🔬 Batfish` (논리 토폴로지)

추가 검증(권장):
```bash
docker exec -it <netally_container_name> curl -fsS http://127.0.0.1:8000/api/health
docker exec -it <netally_container_name> curl -fsS -X POST http://127.0.0.1:8000/api/lab/prepare -H 'Content-Type: application/json' -d '{"auto_init_batfish": true}'
```

### 7.1 로컬 코드 수정 후 재배포 절차 (이미지 재생성 필요할 때)

다음은 **코드를 바꾼 경우에만** 필요합니다.

1. 로컬에서 이미지 빌드
```bash
cd /home/yujin/Desktop/Projects/GIA
docker build -f NetAlly/Dockerfile -t netally:latest .
```
2. 이미지 tar로 내보내기
```bash
docker save -o netally.tar netally:latest
```
3. PNETLab VM으로 전송
```bash
scp netally.tar root@192.168.50.60:/root/
```
4. PNETLab VM에서 로드
```bash
ssh root@192.168.50.60 'docker load -i /root/netally.tar'
```
5. PNETLab에서 NetAlly 노드 Stop/Start

중요:
- **Settings/API 값만 바꿀 때는 이미지 재빌드가 필요 없습니다.**
- `Settings > API Connections` 또는 `POST /api/settings`로 런타임 반영 가능합니다.
- 자동화 스크립트 사용 시:
```bash
cd NetAlly
PNETLAB_VM_IP=192.168.50.60 ./scripts/deploy_to_pnetlab.sh
```

---

## 8. "docker15 IP/route 영구 반영" 의미 정리

- "영구 반영"은 PNETLab 노드 설정(`docker_options`/`config_data`)에 네트워크 명령을 넣어, 컨테이너 재시작 후에도 동일 IP/route가 자동 적용되게 만드는 것을 뜻합니다.
- 이 문서의 권장값은 **고정 IP 주입이 아니라** `PNETLAB_NSO_NODE` 기반 자동 탐색 또는 `NSO_BASE_URL` 명시값 사용입니다.
- 실험 중 `ip route add`/`ifconfig`로 넣는 값은 **임시 런타임 변경**이며, 컨테이너 재시작 시 사라집니다.

---

## 9. 네트워크 변경 후 SSH 단절 시 복구 체크

PNETLab VM 콘솔에서:

```bash
ip -4 a
ip route
systemctl status ssh || systemctl status sshd
ss -lntp | egrep ':(22|80|443)\b'
```

필요 시:
```bash
systemctl restart ssh || systemctl restart sshd
systemctl restart networking
```

핵심:
- 같은 대역 IP라도 방화벽/서비스 다운이면 SSH는 timeout 됩니다.
- `ping`과 `ssh(22)`를 반드시 같이 점검해야 원인을 빠르게 분리할 수 있습니다.

---

## 10. 다중 실험실 운영 시 주의사항

실험실을 여러 개 운영할 때 가장 큰 리스크는 "같은 NetAlly 인스턴스에서 설정이 섞이는 문제"입니다.

문제 포인트:
- 같은 인스턴스를 공유하면 `PNETLAB_LAB_NAME`, `BATFISH_SNAPSHOT`이 덮어써져 결과가 혼선될 수 있습니다.
- 런타임 설정 파일을 공용으로 쓰면 실험실 A의 NSO/PNETLab/OpenAI 값이 실험실 B에 남을 수 있습니다.
- 운영 중 실수로 잘못된 랩에 `register/sync`를 실행할 가능성이 커집니다.

권장:
1. 실험실당 NetAlly 인스턴스 1개를 권장합니다.
1. 실험실별로 최소 아래 값을 고유하게 유지합니다.
   - `PNETLAB_LAB_NAME`
   - `BATFISH_SNAPSHOT`
   - `NETALLY_RUNTIME_SETTINGS_PATH` (예: `/data/netally/lab-a.settings.json`)
1. 같은 인스턴스를 꼭 공유해야 하면, 작업 시작 전에 `POST /api/settings`로 해당 랩 프로필을 강제 적용한 뒤 진행합니다.

---

## 11. 함께 보면 좋은 문서

- 전체 문서 입구: `docs/README_ko.md`
- 실행/테스트 방법: `docs/testing_runbook_ko.md`
- API 계약: `docs/backend_api.md`
