# NetAlly 인수 + 셋업 가이드 (leehj 전용)

> **이 문서의 목적**: 기존 운영자(kilab_pyj)가 셋업한 NetAlly + 4-NSO Docker 환경을 leehj가 인수받아 실험을 바로 돌릴 수 있게 만든다.
>
> **인수 시점**: 2026-05-11
> **대상 머신**: A5000 ubuntu (`kilab-A5000`)
> **현재 active lab**: LabD_NCN_MultiAS_Complex_40nodes
>
> **읽는 순서**: 이 문서 → `02_EXPERIMENT_GUIDE.md` (실험 운영) → `README.html` (그림 설명서)

---

## 0. 한 줄 요약

> NSO Docker는 lab마다 분리해서 4개 떠있고, **현재 LabD(38080)에만 device 40개가 등록되어 in-sync 상태**. leehj가 자기 폴더에서 `.env`만 갱신하고 백엔드 재기동하면 즉시 LabD 실험 가능. LabA/B/C로 전환할 땐 그 lab을 PNETLab에 띄우고 한 줄로 등록.

---

## 1. 환경 개요

### 1.1 네트워크 토폴로지

```
┌──────────────────────── A5000 ubuntu (192.168.0.80) ────────────────────────┐
│                                                                             │
│  ┌────────────────────┐    ┌─────────────────┐    ┌──────────────────────┐  │
│  │ NetAlly Backend    │    │ NSO 4 컨테이너  │    │ Batfish              │  │
│  │ FastAPI :8111      │◄──►│ laba :18080     │    │ batfish-allinone     │  │
│  │ Frontend Vite :3000│    │ labb :8080      │    │ :9996                │  │
│  └────────────────────┘    │ labc :28080     │    └──────────────────────┘  │
│             │              │ labd :38080  ★  │                              │
│             │              └────────┬────────┘                              │
│             │                       │ SSH 22 (NED)                          │
│             │              ┌────────▼────────┐                              │
│             │              │ vmnet8 NAT      │                              │
│             │              │ 192.168.110.0/24│                              │
│             ▼              └────────┬────────┘                              │
│  팀원 브라우저                       │                                       │
│  http://192.168.0.80:3000           │                                       │
│                              ┌──────▼─────────┐                             │
│                              │ PNETLab VM     │ 192.168.110.132             │
│                              │ (VMware)       │ Tailscale: 100.85.92.121    │
│                              │ pnet0:         │                             │
│                              │  10.10.10.1/24 │ ← OOB management            │
│                              └──────┬─────────┘                             │
│                                     │                                       │
│                              ┌──────▼─────────┐                             │
│                              │ Lab 장비 N개   │ 10.10.10.11~                │
│                              │ (LabD 40 nodes)│                             │
│                              └────────────────┘                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 1.2 주요 IP / 포트

| 항목 | 값 | 비고 |
|---|---|---|
| A5000 LAN | `192.168.0.80` | **팀원 접속 IP** |
| A5000 Tailscale | `100.67.63.77` | 외부 원격 접속용 |
| PNETLab VM (vmnet8) | `192.168.110.132` | **NSO/NetAlly가 부르는 IP** |
| PNETLab Tailscale | `100.85.92.121` | 안 씀 (전환 완료) |
| OOB 서브넷 | `10.10.10.0/24` | lab 모든 device의 management IP |
| NetAlly 백엔드 | `:8111` | FastAPI + SSE |
| NetAlly 프론트엔드 | `:3000` | Vite dev server |
| Batfish | `:9996` | 기존 컨테이너 그대로 |

### 1.3 NSO 컨테이너 4개

| 컨테이너 이름 | 포트 (RESTCONF) | 담당 Lab | 현재 상태 |
|---|---|---|---|
| `cisco-nso-laba` | `18080` | LabA_Research_Institute_DC_10nodes | 빈 NSO |
| `cisco-nso-labb` | `8080` | LabB_NCN_Basic_SP_20nodes | 빈 NSO |
| `cisco-nso-labc` | `28080` | LabC_NCN_Security_L2VPN_30nodes | 빈 NSO |
| **`cisco-nso-labd`** | **`38080`** | **LabD_NCN_MultiAS_Complex_40nodes** | **40 nodes 등록 + in-sync** ✅ |

### 1.4 데이터 마운트 (호스트 디렉토리)

```
/home/kilab_pyj/codespace/cisco-nso-docker/
├── ncs-instance              ← LabD CDB (954MB, 진짜 데이터)
├── ncs-instance-laba         ← LabA용 빈 CDB
├── ncs-instance-labb         ← LabB용 빈 CDB
├── ncs-instance-labc         ← LabC용 빈 CDB
└── ncs-instance.bak-20260509 ← 안전망 백업 (2.9GB)
```

→ NSO 컨테이너를 stop/rm해도 데이터는 호스트에 남아있다. **다시 같은 디렉토리를 마운트하면 부활.**

### 1.5 PNETLab 안의 lab 파일

```
/opt/unetlab/labs/Lab/
├── LabA_Research.unl
├── LabB_NCN_Basic_SP.unl
├── LabC.unl
└── LabD.unl       ← 현재 active
```

---

## 2. 왜 이렇게 분리했는가 (운영 원칙)

이 환경의 핵심 제약 하나를 알아두면 모든 운영 결정이 자연스럽다:

> **모든 lab의 OOB(management) IP가 `10.10.10.11~`로 동일하다.**

이 때문에:

1. **한 번에 하나의 lab만 PNETLab에서 켤 수 있다** (IP 충돌)
2. **NSO inventory도 lab마다 분리한다** (같은 device 이름·IP가 lab마다 다른 config을 가리키므로)
3. **lab을 전환할 땐 ① PNETLab UI에서 이전 lab stop → ② 새 lab start → ③ `.env` 두 줄 수정 → ④ NetAlly 재기동** 순서를 지킨다.
4. PNETLab에서 lab을 stop해도 `pnet0` 브리지에 잔여 `vunl*` 인터페이스가 남으면 IP 충돌이 계속될 수 있다. 의심 시 `bridge fdb show br pnet0`로 확인.

자세한 운영 원칙은 `docs/PNETLAB_MULTI_LAB_DEPLOYMENT_RUNBOOK.md` §1, §10 참고.

---

## 3. 인수 절차 (3 step)

leehj 자기 셸 (`/home/leehj/network/GIA/`)에서 차례로 실행.

### Step 1 — 기존 NetAlly 백엔드 정리

```bash
# 본인이 띄운 uvicorn이 있으면 종료
ps -ef | grep 'uvicorn main:app' | grep "$USER" | grep -v grep | awk '{print $2}' | xargs -r kill
sleep 3

# 확인 — 본인 uid 아래엔 비어야 함
ps -ef | grep uvicorn | grep -v grep
```

### Step 2 — 레포 최신화 + `.env` 작성

```bash
# git ownership 경고 끄기 (kilab_pyj 폴더가 다른 사용자라면)
git config --global --add safe.directory /home/leehj/network/GIA

cd /home/leehj/network/GIA && git pull
cd NetAlly

# 기존 .env 백업
[ -f .env ] && mv .env .env.bak-$(date +%Y%m%d)

# 새 .env 작성 — §4 양식 그대로 붙여넣고 API 키만 본인 거로 교체
nano .env
```

### Step 3 — 의존성 + 백엔드 재기동

```bash
# .venv 갱신 (의존성 추가됐을 수 있음)
uv sync --extra dev

# .env 환경변수 셸에 로드 후 백엔드 백그라운드 기동
set -a; source .env; set +a
nohup uv run uvicorn main:app --host 0.0.0.0 --port 8111 \
  > /tmp/netally-backend.log 2>&1 &
disown

# 프론트엔드도 띄우려면 (선택)
cd frontend
nohup npm run dev -- --host 0.0.0.0 --port 3000 \
  > /tmp/netally-frontend.log 2>&1 &
disown
cd ..

# 15초 대기 후 헬스체크
sleep 15
curl -s http://localhost:8111/api/health | python3 -m json.tool | head -8
curl -s -u admin:admin "http://localhost:38080/restconf/data/tailf-ncs:devices?fields=device(name)" \
  | grep -c '<name>'
# 마지막 줄이 40 이면 LabD 정상 ✅
```

---

## 4. `.env` 양식 (그대로 복사 + API 키만 교체)

```bash
# ── 네트워크 (vmnet8 LAN 직통) ──
PNETLAB_TAILSCALE_IP=192.168.110.132
UBUNTU_TAILSCALE_IP=100.67.63.77

# ── 공통 ──
OPENAI_API_KEY=__leehj_본인_키__
OPENROUTER_API_KEY=__leehj_본인_키__
PORT=8111
NETALLY_RUNTIME_SETTINGS_PATH=.runtime/settings.runtime.json
NETALLY_CACHE_DIR=.tmp/cache

# ── NSO (현재 LabD = 38080) ──
NSO_BASE_URL=http://localhost:38080/restconf
NSO_USERNAME=admin
NSO_PASSWORD=admin
NSO_AUTHGROUP=default

# ── PNETLab (vmnet8 직통) ──
PNETLAB_INVENTORY_BACKEND=labfs_ssh
PNETLAB_LAB_NAME=LabD_NCN_MultiAS_Complex_40nodes
PNETLAB_UNETLAB_ROOT=/opt/unetlab
PNETLAB_URL=http://192.168.110.132
PNETLAB_SSH_HOST=192.168.110.132
PNETLAB_SSH_USER=root
PNETLAB_SSH_PORT=22
PNETLAB_SSH_KEY_PATH=~/.ssh/id_rsa
PNETLAB_VM_IP=192.168.110.132
PNETLAB_EXCLUDE_NODE_NAMES=NSO,Docker,NetAlly,Admin
PNETLAB_GATEWAY_IP=10.10.10.1
PNETLAB_DOMAIN_NAME=ncn.go.kr
PNETLAB_ADMIN_PASSWORD=admin
PNETLAB_DEVICE_INFO_AUTOGEN=true

# ── Batfish ──
BATFISH_HOST=localhost:9997
BATFISH_SNAPSHOT=LabD
BATFISH_NETWORK=LabD
BATFISH_EXPORT_DIR=./snapshot/LabD_configs/
AUTO_INIT_BATFISH=true
AUTO_PREPARE_ON_CHAT=false

# ── NetAlly 런타임 ──
NETALLY_TOOL_BACKEND=mcp
NETALLY_AGENT_BACKEND=team_multi_adapter
NETALLY_TEAM_MULTI_MODULE=agents_netally.main_netally
NETALLY_TEAM_MULTI_ROOT=/home/leehj/network/GIA/NetAlly
NETALLY_MCP_SERVER_URL=http://127.0.0.1:8811/mcp
NETALLY_MCP_ALLOW_MUTATIONS=true

# ── LLM ──
NETALLY_EXECUTOR_LLM_BACKEND=openai
NETALLY_EXECUTOR_LLM_MODEL=mistralai/ministral-8b-2512
OPENAI_API_BASE=https://openrouter.ai/api/v1
```

> **주의**: `.env`는 `.gitignore`에 포함되어 있다. 절대 commit하지 말 것.

---

## 5. Lab 전환 절차 (LabD → LabA / B / C)

### 5.1 lab별 매핑 한눈

| Lab | PNETLab .unl | NSO 컨테이너 | 포트 | device_info.json | authgroup |
|---|---|---|---|---|---|
| LabA | `Lab/LabA_Research.unl` | `cisco-nso-laba` | 18080 | `LabA_Research_Institute_DC_10nodes` | `Research_Institute_Internal_DC` |
| LabB | `Lab/LabB_NCN_Basic_SP.unl` | `cisco-nso-labb` | 8080 | `LabB_NCN_Basic_SP_20nodes` | `default` |
| LabC | `Lab/LabC.unl` | `cisco-nso-labc` | 28080 | `LabC_NCN_Security_L2VPN_30nodes` | `LabC_NCN_Security_L2VPN` |
| **LabD** | `Lab/LabD.unl` | `cisco-nso-labd` | **38080** | `LabD_NCN_MultiAS_Complex_40nodes` | `LabD_NCN_MultiAS_Complex` |

### 5.2 전환 절차 (예: LabD → LabA)

#### (a) PNETLab GUI에서 lab 교체
1. 브라우저에서 `http://192.168.110.132` 접속 (또는 `http://100.85.92.121` Tailscale)
2. **LabD의 모든 노드 stop** (Topology → Stop All Nodes)
3. **LabA 열기**: `Lab/LabA_Research.unl`
4. **LabA의 모든 노드 start**
5. 콘솔로 1~2개 노드 접속해서 IOS 부팅 완료 확인 (`Press RETURN to get started` 뜰 때까지)

#### (b) (해당 lab 처음 1회만) NSO에 device 등록

```bash
cd /home/leehj/network/GIA

python3 Make_Dataset/src/2-NSO_Register.py \
  --device-info Data/Pnetlab/LabA_Research_Institute_DC_10nodes/device_info.json \
  --nso-container cisco-nso-laba
```

> 두 번째 이후 전환부터는 이 단계 생략. 이미 NSO CDB에 device가 등록되어 있다.

#### (c) `.env` 두 줄 + 재기동

```bash
cd /home/leehj/network/GIA/NetAlly

# NSO 포트와 Batfish lab 이름 교체
sed -i 's|^NSO_BASE_URL=.*|NSO_BASE_URL=http://localhost:18080/restconf|' .env
sed -i 's|^BATFISH_SNAPSHOT=.*|BATFISH_SNAPSHOT=LabA|' .env
sed -i 's|^BATFISH_NETWORK=.*|BATFISH_NETWORK=LabA|' .env
sed -i 's|^PNETLAB_LAB_NAME=.*|PNETLAB_LAB_NAME=LabA_Research_Institute_DC_10nodes|' .env

# 백엔드 재기동
pkill -f 'uvicorn main:app' && sleep 3
set -a; source .env; set +a
nohup uv run uvicorn main:app --host 0.0.0.0 --port 8111 \
  > /tmp/netally-backend.log 2>&1 &
disown
```

#### (d) 검증

```bash
# LabA의 device 수 (= 10이어야 함)
curl -s -u admin:admin "http://localhost:18080/restconf/data/tailf-ncs:devices?fields=device(name)" \
  | grep -c '<name>'

# 전체 sync 검증
curl -s -u admin:admin -X POST \
  -H "Content-Type: application/yang-data+json" \
  'http://localhost:18080/restconf/operations/tailf-ncs:devices/check-sync' \
  | python3 -m json.tool | head -20
```

### 5.3 lab별 포트/숫자 cheat sheet

| 전환 대상 | NSO 포트 | device 수 | BATFISH_SNAPSHOT |
|---|---|---|---|
| → LabA | 18080 | 10 | LabA |
| → LabB | 8080  | 20 | LabB |
| → LabC | 28080 | 30 | LabC |
| → LabD | 38080 | 40 | LabD |

---

## 6. 트러블슈팅

### 6.1 `ssh-rsa host key` 검증 실패 (특정 device sync error)

증상:
```
Could not verify `ssh-rsa` host key with fingerprint ... for `10.10.10.X`
```

원인: NSO가 캐시한 SSH host key와 device의 실제 key가 다르다 (device 재시작 후 흔함).

해결:
```bash
PORT=38080         # 해당 lab 포트
DEV=P1             # 에러난 device 이름

curl -s -u admin:admin -X POST \
  -H "Content-Type: application/yang-data+json" \
  "http://localhost:$PORT/restconf/data/tailf-ncs:devices/device=$DEV/ssh/fetch-host-keys"

curl -s -u admin:admin -X POST \
  -H "Content-Type: application/yang-data+json" \
  "http://localhost:$PORT/restconf/data/tailf-ncs:devices/device=$DEV/sync-from"
```

### 6.2 `8111` 포트 점유

```bash
sudo ss -tlnp | grep ':8111'
# 본인 프로세스만 종료
pkill -u $USER -f 'uvicorn main:app'
```

### 6.3 OOB(`10.10.10.x`) ping 안 됨

```bash
# 라우팅 — vmnet8 보여야 함
ip route show 10.10.10.0/24

# iptables MASQUERADE 룰 살아있나
sudo iptables -t nat -L POSTROUTING -n | grep '10.10.10'

# systemd 라우트 서비스
sudo systemctl status pnetlab-oob-route.service
```

PNETLab VM이 stop된 경우 vmnet8 자체가 사라진다 — **VMware Workstation에서 PNETLab VM 먼저 start**.

### 6.4 IP 중복 (`%IP-4-DUPADDR`) / host-key mismatch

증상 (console log):
```
%IP-4-DUPADDR: Duplicate address 10.10.10.21 on GigabitEthernet0/7, sourced by 50ba.bd00.3e03
```

원인: PNETLab `pnet0`에 이전 lab의 `vunl*` 인터페이스가 남아 있다.

해결:
```bash
# PNETLab VM에서 (SSH)
# Cisco MAC 50ba.bd00.3e03 → Linux 50:ba:bd:00:3e:03
bridge fdb show br pnet0 | grep -i '50:ba:bd:00:3e:03'

# 출력 예: 50:ba:bd:00:3e:03 dev vunl62_3 master pnet0
ip link set vunl62_3 down
```

근본 해결: PNETLab UI에서 해당 노드를 완전히 stop.

자세한 절차는 `docs/PNETLAB_MULTI_LAB_DEPLOYMENT_RUNBOOK.md` §10.3.

### 6.5 NSO 컨테이너가 죽었다

```bash
docker ps -a | grep cisco-nso
docker start cisco-nso-labd
docker logs --tail 30 cisco-nso-labd
```

CDB는 호스트 마운트라 데이터는 무사. 컨테이너만 다시 띄우면 끝.

### 6.6 authgroup 누락 (LabA/C 처음 등록 시)

LabA는 authgroup `Research_Institute_Internal_DC`를 요구하지만 빈 NSO에는 `default`만 있다. `2-NSO_Register.py`가 자동 생성하지 않으면 수동으로:

```bash
docker exec cisco-nso-laba /root/nso-6.6/bin/ncs_cli -u admin -C <<'EOF'
config
devices authgroups group Research_Institute_Internal_DC default-map remote-name admin remote-password admin
commit
EOF
```

대안: `device_info.json`의 `nso_authgroup`을 `default`로 통일하고 다시 등록.

---

## 7. 일상 운영 명령 모음

### 7.1 NSO 4개 상태 한눈
```bash
docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' | grep cisco-nso
```

### 7.2 각 lab의 device 수
```bash
for port in 38080 18080 8080 28080; do
  count=$(curl -s -u admin:admin "http://localhost:$port/restconf/data/tailf-ncs:devices?fields=device(name)" | grep -c '<name>')
  echo "port $port: $count devices"
done
```

### 7.3 현재 active lab의 전체 sync 검증
```bash
PORT=38080   # 현재 active lab의 포트
curl -s -u admin:admin -X POST \
  -H "Content-Type: application/yang-data+json" \
  "http://localhost:$PORT/restconf/operations/tailf-ncs:devices/check-sync" \
  > /tmp/sync.json

python3 - <<'PY'
import json
from collections import Counter
d = json.load(open('/tmp/sync.json'))
results = d.get("tailf-ncs:output", {}).get("sync-result", [])
print(f"총 {len(results)}개 device")
print(Counter(r.get("result") for r in results))
for r in results:
    if r.get("result") != "in-sync":
        print(f"  {r.get('device')}: {r.get('result')} — {(r.get('info') or '')[:120]}")
PY
```

### 7.4 NetAlly 헬스
```bash
curl -s http://localhost:8111/api/health | python3 -m json.tool | head -10
```

### 7.5 백엔드 한 줄 재기동
```bash
pkill -f 'uvicorn main:app' && sleep 3 && \
  cd /home/leehj/network/GIA/NetAlly && set -a && source .env && set +a && \
  nohup uv run uvicorn main:app --host 0.0.0.0 --port 8111 > /tmp/netally-backend.log 2>&1 &
```

---

## 8. 변경 이력 (이번 인계로 적용된 것)

| 일자 | 항목 |
|---|---|
| 2026-05-09 | NSO 컨테이너 1개 → 4개 분할 (`cisco-nso-{laba,labb,labc,labd}`) |
| 2026-05-09 | PNETLab 통신 Tailscale → vmnet8 LAN 직통 전환 |
| 2026-05-09 | A5000 정적 라우트 영구화 (`systemd: pnetlab-oob-route.service`) |
| 2026-05-09 | A5000 iptables MASQUERADE 영구화 (`/etc/iptables/rules.v4`) |
| 2026-05-09 | PNETLab VM SNAT 룰 + ICMP redirect 비활성 (영구) |
| 2026-05-09 | LabD 40 nodes 전부 in-sync 검증 완료 (P1은 ssh-rsa fetch-host-keys 후 정상화) |
| 2026-05-09 | NetAlly CORS에 `192.168.0.80` 허용 추가 |

---

## 9. 다음 단계

이 문서로 환경 인수가 끝났으면:

1. **`02_EXPERIMENT_GUIDE.md`** 읽기 — NetAlly 평가 파이프라인 돌리는 법과 결과 보는 법
2. **`README.html`** 열기 — 환경 구조를 그림으로 한 번 더 이해

질문은 슬랙/메신저로 kilab_pyj에게.
