# PNETLab 배포 가이드

> Config Generator로 생성한 .cfg 파일을 PNETLab에 배포하고, 데이터셋 파이프라인까지 연결하는 전 과정을 기술한다.
>
> **대상**: Lab-B (20 nodes), Lab-C (30 nodes), Lab-D (40 nodes)
> **관련 문서**: [lab_scalability_design.md](../../../NetAlly/docs/IEEE/lab_scalability_design.md)
> **NetAlly 배포**: [pnetlab_wiring_runbook_ko.md](../../../NetAlly/docs/pnetlab_wiring_runbook_ko.md)

---

## 0. Quick Start

```
Step 1. Config 생성     → python generator.py --topology topologies/lab_b_20nodes.yaml
Step 2. PNETLab 랩 생성  → UI에서 노드 추가 + 배선 (부록 A 참조)
Step 3. Config 적용      → Import Startup Configuration (txt/ 폴더) 또는 수동 복붙
Step 4. 검증             → OSPF/BGP/MPLS neighbor 확인
Step 5. NSO/NetAlly 연결 → (선택) NSO 등록 + NetAlly Docker Node 추가
Step 6. 파이프라인 실행   → main_batfish.py → 데이터셋 생성
```

| Lab | 노드 수 | 배선 수 | 예상 소요시간 |
|-----|---------|---------|-------------|
| Lab-B | 20 | 22 data + 1 mgmt | ~1.5시간 |
| Lab-C | 30 | 35 data + 1 mgmt | ~2.5시간 |
| Lab-D | 40 | 48 data + 1 mgmt | ~3.5시간 |

---

## 0.5 배포 진행 체크리스트 (Progress Tracker)

각 Lab 배포 시 현재 진행 상태를 추적한다. 완료된 항목에 `[x]` 표시.

### Lab-B (20 nodes)
```
Phase 1: 준비
  [ ] Config 생성 완료 (generator.py --topology lab_b_20nodes.yaml)
  [ ] output/LabB_NCN_Basic_SP_20nodes/configs/ 에 20개 .cfg 확인
  [ ] PNETLab 서버 RAM 16GB+ 확인

Phase 2: 랩 생성 + Config 적용
  [ ] PNETLab에서 "LabB_NCN_Basic_SP" 랩 생성
  [ ] IOSv 노드 20개 추가 (Ethernet: 8개 필수!)
  [ ] Cloud0 (Management) 네트워크 생성
  [ ] Import Startup Configuration 완료 (txt/ 폴더)
  [ ] Node ID remap 필요 시 완료

Phase 3: 배선 (가장 시간 소모적 — ~1시간)
  [ ] 관리망 배선: 20개 노드 e7 → Cloud0  (5분)
  [ ] Region 1 코어 배선: P1-P4, PE1-PE2 (15분)
  [ ] Region 1 액세스 배선: PE↔Leaf 4개 (5분)
  [ ] Inter-Region 배선: P3↔P5 (2분)
  [ ] Region 2 코어 배선: P5-P8, PE3-PE4 (15분)
  [ ] Region 2 액세스 배선: PE↔Leaf 4개 (5분)

Phase 4: 검증
  [ ] Start All → 모든 노드 부팅 (녹색 아이콘)
  [ ] 관리망 ping 확인 (10.10.10.11~38)
  [ ] SSH 접속 확인 (ssh admin@10.10.10.11)
  [ ] OSPF neighbor FULL 확인
  [ ] BGP VPNv4 세션 확인
  [ ] MPLS LDP neighbor 확인

Phase 5: 파이프라인 연결
  [ ] Data/Pnetlab/LabB_NCN_Basic_SP_20nodes/configs/ 에 .cfg 복사
  [ ] device_info.json 생성 (telnet_port 실제값 입력)
  [ ] Batfish 데이터셋 생성 (main_batfish.py)
```

> **팁**: Phase 3(배선)이 전체 작업의 60~70%를 차지한다. 아래 **섹션 2.5 효율적 배선 전략**을 반드시 참고할 것.

---

## 1. 사전 준비 (Prerequisites)

### 1.1 하드웨어 요구사항

| Lab | 노드 수 | 최소 RAM | 권장 RAM | CPU | 디스크 |
|-----|---------|---------|---------|-----|--------|
| Lab-B | 20 | 16 GB | 24 GB | 8 cores | 20 GB |
| Lab-C | 30 | 24 GB | 32 GB | 12 cores | 30 GB |
| Lab-D | 40 | 32 GB | 48 GB | 16 cores | 40 GB |

> IOSv VM 1대당 약 512 MB RAM 소모. Lab-D는 40 x 512 MB = 20 GB + PNETLab OS + Batfish/NSO/NetAlly 오버헤드.

### 1.2 소프트웨어

| 소프트웨어 | 용도 | 필수 여부 |
|-----------|------|----------|
| PNETLab 5.x+ | 가상 네트워크 랩 | 필수 |
| Cisco IOSv 이미지 (vios-adventerprisek9-m) | 라우터/스위치 VM | 필수 |
| Batfish Docker (`batfish/batfish`) | 설정 분석 + 데이터셋 생성 | 필수 |
| Cisco NSO | 장비 등록 + NetAlly 연동 | 선택 |

**IOSv 이미지 경로** (PNETLab 서버):
```
/opt/unetlab/addons/qemu/vios-adventerprisek9-m.SPA.xxx/
```

### 1.3 Config 생성 확인

```bash
# Lab-B (20 nodes)
python Make_Dataset/config_generator/generator.py \
  --topology Make_Dataset/config_generator/topologies/lab_b_20nodes.yaml

# Lab-C (30 nodes)
python Make_Dataset/config_generator/generator.py \
  --topology Make_Dataset/config_generator/topologies/lab_c_30nodes.yaml

# Lab-D (40 nodes)
python Make_Dataset/config_generator/generator.py \
  --topology Make_Dataset/config_generator/topologies/lab_d_40nodes.yaml
```

생성 확인:
```bash
ls Make_Dataset/config_generator/output/LabB_NCN_Basic_SP_20nodes/configs/ | wc -l    # → 20
ls Make_Dataset/config_generator/output/LabC_NCN_Security_L2VPN_30nodes/configs/ | wc -l  # → 30
ls Make_Dataset/config_generator/output/LabD_NCN_MultiAS_Complex_40nodes/configs/ | wc -l # → 40
```

---

## 2. PNETLab 랩 생성

### 2.1 새 랩 생성

PNETLab UI → **Add new lab** → 랩 이름 입력:
- Lab-B: `LabB_NCN_Basic_SP`
- Lab-C: `LabC_NCN_Security_L2VPN`

### 2.2 IOSv 노드 템플릿 설정 (핵심!)

**중요**: 기본 IOSv 템플릿은 인터페이스 4개(Gi0/0~Gi0/3)만 제공한다.
Lab-B/C는 **Gi0/7을 OOB 관리 인터페이스**로 사용하므로 반드시 **8개**로 변경해야 한다.

노드 추가 시 설정:
- **Template**: Cisco IOSv (vios)
- **Ethernet**: `8` (반드시 변경!)
- **RAM**: 512 MB (기본값)
- **CPU**: 1

### 2.3 노드 배치 (시각 레이아웃 가이드)

**공통 원칙:**
- **노드 이름은 YAML의 `name` 필드와 정확히 일치**시킬 것 (예: `P1`, `PE1`, `Leaf1`)
- Region별로 시각적 그룹핑 (색상/위치 구분)
- P 코어 라우터를 중앙에, PE를 그 주위에, Leaf(CE)를 가장자리에 배치
- Cloud0 (관리망)은 캔버스 상단 또는 하단에 별도 배치

#### Lab-B 배치 (20 nodes, 2 Regions)

```
╔═══════════════════════════════════╗    ╔═══════════════════════════════════╗
║         Region 1 (좌측)            ║    ║         Region 2 (우측)            ║
║         AS 65000, Area 0          ║    ║         AS 65000, Area 0          ║
║                                   ║    ║                                   ║
║  [Leaf1] [Leaf2]   [Leaf3] [Leaf4]║    ║  [Leaf5] [Leaf6]   [Leaf7] [Leaf8]║
║     \      /          \      /    ║    ║     \      /          \      /    ║
║     [PE1]              [PE2]      ║    ║     [PE3]              [PE4]      ║
║       |                  |        ║    ║       |                  |        ║
║     [P1]----[P2]   [P3]----[P4]   ║    ║     [P5]----[P6]   [P7]----[P8]  ║
║       \      /       |      /     ║    ║       \             /             ║
║        \    /        |     /      ║    ║        \           /              ║
║         \  /         |    /       ║    ║         \         /               ║
║          \/          |   /        ║    ║          \       /                ║
║                     [P3]==========║====║==========[P5]                     ║
║                  Inter-Region     ║    ║       Backbone Link               ║
╚═══════════════════════════════════╝    ╚═══════════════════════════════════╝

                        [ Cloud0 — 관리망 (10.10.10.0/24) ]
                          모든 20개 노드의 e7 연결
```

#### Lab-C 배치 (30 nodes, 3 Regions)

```
╔════════════════════╗  ╔════════════════════╗  ╔══════════════════════════════╗
║  Region 1 (좌측)    ║  ║  Region 2 (중앙)    ║  ║    Region 3 (우측)            ║
║  AS 65000, Area 0  ║  ║  AS 65000, Area 0  ║  ║    AS 65001, Area 1          ║
║                    ║  ║                    ║  ║                              ║
║  Leaf1~4           ║  ║  Leaf5~8           ║  ║  Leaf9~12                    ║
║   |    |           ║  ║   |    |           ║  ║   |    |                     ║
║  PE1  PE2          ║  ║  PE3  PE4          ║  ║  PE5  PE6 (HSRP on Leaf9)   ║
║   |    |           ║  ║   |    |           ║  ║   |    |                     ║
║  P1 P2 P3 P4      ║  ║  P5 P6 P7 P8      ║  ║  P9   P10                    ║
║        |           ║  ║  |       \    \    ║  ║  |    |                      ║
╚════════║═══════════╝  ╚══║════════║════║═══╝  ╚══║════║═════════════════════╝
         P3 ============= P5       P7===ASBR1=====P9   |
                                   P8===ASBR2===========P10
                              (eBGP Inter-AS)

                        [ Cloud0 — 관리망 (10.10.10.0/24) ]
                          모든 30개 노드의 e7 연결
```

#### Lab-D 배치 (40 nodes, 4 Regions)

```
╔════════════════════╗  ╔════════════════════╗
║  Region 1 (좌상)    ║  ║  Region 2 (우상)    ║
║  AS 65000, Area 0  ║  ║  AS 65000, Area 0  ║
║  Leaf1~4           ║  ║  Leaf5~8           ║
║  PE1  PE2          ║  ║  PE3  PE4          ║
║  P1 P2 P3 P4      ║  ║  P5 P6 P7 P8      ║
╚═════════╤══════════╝  ╚══╤═══════╤════╤═══╝
     P3===P5          P7===ASBR1   P8===ASBR2
     (Intra-AS)            │(eBGP)      │(eBGP)
╔═════════╧══════════╗  ╔══╧═══════╧════╧═══╗
║  Region 3 (좌하)    ║  ║  Region 4 (우하)    ║
║  AS 65001, Area 1  ║  ║  AS 65002, Area 2  ║
║  Leaf9~12          ║  ║  Leaf13~16         ║
║  PE5  PE6          ║  ║  PE7  PE8          ║
║  P9  P10           ║  ║  P11  P12          ║
║  ASBR1  ASBR2      ║  ║  FW1   FW2         ║
╚════════════════════╝  ╚════════════════════╝
     ASBR1===FW1 (eBGP, Inter-AS 65001↔65002)
     ASBR2===FW2 (eBGP, Inter-AS 65001↔65002)

        [ Cloud0 — 관리망 (10.10.10.0/24) ]
          모든 40개 노드의 e7 연결
```

> **PNETLab 배치 팁:**
> - 각 Region을 PNETLab 캔버스의 사분면에 배치하면 가독성이 좋다
> - Inter-Region/Inter-AS 링크가 Region 경계를 가로지르도록 배치
> - Cloud0는 캔버스 하단에 길게 배치하여 모든 노드의 e7과 연결
> - Lab-D의 경우 4개 Region을 2x2 격자로 배치 (좌상/우상/좌하/우하)

### 2.4 네트워크 배선

#### 2.4.1 관리 네트워크 (Management)

1. **Cloud0** (Type: `Management(Cloud0)`) 네트워크 1개 생성
2. **모든 노드**의 `e7` (= GigabitEthernet0/7)을 Cloud0에 연결
3. Cloud0 게이트웨이: `10.10.10.1/24`

> Cloud0는 PNETLab 호스트의 관리 브릿지에 매핑되어 외부 SSH 접근 가능.

#### 2.4.2 데이터 링크

각 point-to-point 링크마다 **별도의 네트워크(Bridge)**를 생성하고, 양쪽 노드의 해당 인터페이스를 연결한다.

**PNETLab 인터페이스 매핑 규칙:**
```
GigabitEthernet0/0 → e0  (PNETLab 슬롯 0)
GigabitEthernet0/1 → e1
GigabitEthernet0/2 → e2
  ...
GigabitEthernet0/7 → e7  (OOB Management → Cloud0)
```

배선 상세 테이블은 **부록 A.1** (Lab-B) / **부록 A.2** (Lab-C) 참조.

#### 2.4.3 Lab-C 특수 배선: HSRP 공유 서브넷

Lab-C에서 PE5와 PE6가 Leaf9의 172.18.1.0/24 서브넷에서 HSRP를 구성한다.
이 경우 **3개 인터페이스를 하나의 Bridge에 연결**해야 한다:

| Bridge 이름 | 연결 노드 | 인터페이스 |
|------------|----------|-----------|
| `net_hsrp_sec` | PE5 | e1 (Gi0/1, VRF_SEC, HSRP Active) |
| | PE6 | e4 (Gi0/4, VRF_SEC, HSRP Standby) |
| | Leaf9 | e0 (Gi0/0) |

### 2.5 효율적 배선 전략 (Wiring Strategy)

배선은 가장 시간이 많이 걸리는 단계다. 아래 전략을 따르면 실수를 최소화하고 속도를 높일 수 있다.

#### 2.5.1 배선 순서 원칙

**반드시 이 순서로 배선할 것:**

```
① 관리망 먼저 (Cloud0 ↔ 모든 노드 e7)
  → 이유: 배선 후 Start All하면 바로 SSH 접속 가능. config 오류 시 즉시 디버깅.

② Region별로 코어(P↔P, P↔PE) 먼저
  → 이유: OSPF neighbor가 먼저 올라와야 전체 토폴로지 동작 확인 가능.

③ 액세스(PE↔Leaf) 나중에
  → 이유: 코어가 안정되면 Leaf는 단순 연결. VRF 경로 전파도 코어 의존.

④ Inter-Region 링크 마지막
  → 이유: 각 Region이 독립적으로 동작하는 것을 먼저 확인.
```

#### 2.5.2 PNETLab Bridge 네이밍 컨벤션

PNETLab에서 각 point-to-point 링크마다 Bridge(네트워크)를 생성한다.
**네이밍이 일관되어야 나중에 디버깅이 쉽다.**

```
형식:  net_<NodeA>_<NodeB>
예시:  net_P1_PE1, net_P1_P2, net_PE1_Leaf1
관리망: net_mgmt (또는 Cloud0 자동 생성)
HSRP:  net_hsrp_sec (공유 Bridge)
```

> **주의**: PNETLab UI에서 네트워크 이름은 생성 후 변경 불가. 처음부터 명확하게 지을 것.

#### 2.5.3 Lab-B 배선 작업 체크시트 (22개 링크)

아래 순서대로 배선하면 약 40분에 완료 가능하다. 각 행을 체크하며 진행.

**Step 1 — 관리망 (5분)**
```
[ ] Cloud0 생성 (Type: Management)
[ ] P1~P8 (8개) e7 → Cloud0
[ ] PE1~PE4 (4개) e7 → Cloud0
[ ] Leaf1~Leaf8 (8개) e7 → Cloud0
```

**Step 2 — Region 1 코어 (15분, 링크 #1~#7)**
```
[ ] #1  net_P1_PE1:   P1(e0) ↔ PE1(e0)
[ ] #2  net_P1_P2:    P1(e1) ↔ P2(e0)
[ ] #3  net_P1_P3:    P1(e2) ↔ P3(e0)
[ ] #4  net_P2_PE2:   P2(e1) ↔ PE2(e0)
[ ] #5  net_P2_P4:    P2(e2) ↔ P4(e0)
[ ] #6  net_P3_P4:    P3(e1) ↔ P4(e1)
[ ] #7  net_P4_PE2:   P4(e2) ↔ PE2(e1)
```

**Step 3 — Region 1 액세스 (5분, 링크 #8~#11)**
```
[ ] #8  net_PE1_Leaf1: PE1(e1) ↔ Leaf1(e0)
[ ] #9  net_PE1_Leaf2: PE1(e2) ↔ Leaf2(e0)
[ ] #10 net_PE2_Leaf3: PE2(e2) ↔ Leaf3(e0)
[ ] #11 net_PE2_Leaf4: PE2(e3) ↔ Leaf4(e0)
```

**Step 4 — Inter-Region (2분, 링크 #12)**
```
[ ] #12 net_P3_P5:    P3(e2) ↔ P5(e2)   ← Inter-Region Backbone
```

**Step 5 — Region 2 코어 (15분, 링크 #13~#18)**
```
[ ] #13 net_P5_PE3:   P5(e0) ↔ PE3(e0)
[ ] #14 net_P5_P6:    P5(e1) ↔ P6(e0)
[ ] #15 net_P6_PE4:   P6(e1) ↔ PE4(e0)
[ ] #16 net_P6_P7:    P6(e2) ↔ P7(e0)
[ ] #17 net_P7_P8:    P7(e1) ↔ P8(e0)
[ ] #18 net_P8_PE4:   P8(e1) ↔ PE4(e1)
```

**Step 6 — Region 2 액세스 (5분, 링크 #19~#22)**
```
[ ] #19 net_PE3_Leaf5: PE3(e1) ↔ Leaf5(e0)
[ ] #20 net_PE3_Leaf6: PE3(e2) ↔ Leaf6(e0)
[ ] #21 net_PE4_Leaf7: PE4(e2) ↔ Leaf7(e0)
[ ] #22 net_PE4_Leaf8: PE4(e3) ↔ Leaf8(e0)
```

#### 2.5.4 배선 중 흔한 실수와 방지법

| 실수 | 증상 | 방지법 |
|------|------|--------|
| **e 슬롯 번호 착각** | OSPF neighbor 안 올라옴 | 배선 테이블의 Slot 열 대조 후 연결 |
| **Ethernet 4개만 설정** | e4~e7 슬롯이 안 보임 | 노드 생성 시 Ethernet=8 확인. 이미 만든 노드는 삭제 후 재생성 |
| **같은 Bridge에 3개 이상 연결** (의도치 않게) | broadcast storm 또는 예상치 못한 경로 | HSRP(#32) 외에는 반드시 1:1 point-to-point |
| **Cloud0에 e7 대신 다른 슬롯 연결** | 관리망 접속 불가 + 데이터 링크 깨짐 | 관리망은 **항상 e7 (Gi0/7)** |
| **노드 이름 불일치** (P01 vs P1) | config hostname과 불일치 → NSO 등록 실패 | YAML `name` 필드와 정확히 동일하게 |

> **실수 발견 시 복구**: PNETLab에서 배선은 자유롭게 삭제/재연결 가능. 잘못된 Bridge 삭제 → 재생성하면 된다.

---

## 3. Config 적용

### 3.1 방법 비교

| 방법 | 속도 (30 nodes) | 난이도 | 권장 |
|------|----------------|-------|------|
| **A: Import Startup Configuration** | ~5분 | 하 | **최우선** |
| B: Startup Config 에디터 (수동 복붙) | ~30분 | 하 | 대안 |
| C: SSH 파일시스템 직접 복사 | ~5분 | 중 | 고급 대안 |
| D: Console Telnet 복붙 | ~90분 | 하 | 비권장 |

> 생성된 .cfg에 SSH, OOB 관리 인터페이스, 기본 라우팅이 이미 포함되어 있으므로
> `1-SSH_Enable.py` 스크립트가 **불필요**하다.

### 3.2 방법 A: Import Startup Configuration (최우선 권장)

Config Generator가 생성한 `txt/` 폴더를 PNETLab의 Import 기능으로 한 번에 적용한다.

**전제 조건:**
- PNETLab에서 노드를 **YAML 순서대로** 생성했거나, 또는 `--remap`으로 txt를 재매핑한 상태

**절차:**

1. `txt/` 폴더 내 `.txt` 파일만 별도 폴더에 복사 (NODE_ID_MAP.md 제외)
   ```bash
   mkdir -p /tmp/lab_b_import
   cp output/LabB_NCN_Basic_SP_20nodes/txt/[0-9]*.txt /tmp/lab_b_import/
   ```
2. PNETLab UI → 랩 열기 → **More Actions** → **Import Startup Configuration**
3. 폴더 선택 → 자동으로 각 node_id에 맞는 config 적용
4. 노드 시작 (Start All) → config 자동 로드

**Node ID가 맞지 않을 때 (Remap):**
```bash
# PNETLab System Status에서 실제 node_id 확인 후 CSV 편집
cp remap_samples/lab_b_remap.csv my_remap.csv
# my_remap.csv에서 왼쪽 숫자를 PNETLab 실제 node_id로 수정

python generator.py --remap my_remap.csv --lab LabB_NCN_Basic_SP_20nodes
# → txt/ 폴더가 재매핑된 파일로 재생성됨
```

### 3.3 방법 B: Startup Config 에디터 (수동 복붙)

Import가 안 되는 환경이거나 소수 노드만 수정할 때 사용한다.

1. PNETLab UI 좌측 메뉴 → **Startup Config** (또는 랩 설정에서 접근)
2. 좌측 노드 목록에서 노드 선택 (예: `P1`)
3. 우측 텍스트 에디터에 해당 .cfg 파일 내용을 **전체 붙여넣기**
   - `output/LabB_NCN_Basic_SP_20nodes/configs/P1.cfg` 내용
4. 해당 노드의 스위치를 **ON** 으로 설정
5. 모든 노드에 대해 2~4 반복
6. **Set as Active** 클릭
7. 노드 시작 (Start All) → config 자동 적용

**주의사항:**
- 노드 이름이 YAML `name`과 일치해야 한다 (예: `P1`, 아닌 `P01`)
- `version 15.7` 행이 포함되어 있어도 무방 (IOSv가 자동 무시)
- 붙여넣기 전에 기존 기본 config 내용을 **전부 삭제**할 것

### 3.4 방법 C: SSH 파일시스템 직접 복사 (고급 대안)

PNETLab 서버에 SSH 접속이 가능한 경우, 노드의 startup-config 파일을 직접 교체할 수 있다.

```bash
# PNETLab 서버에 SSH 접속
ssh root@<PNETLAB_SERVER_IP>

# 랩 디렉토리 확인 (노드 생성 후에만 존재)
ls /opt/unetlab/tmp/0/

# 노드 ID 매핑 확인 (node_id는 PNETLab 내부 번호)
# PNETLab UI에서 노드 클릭 → URL에서 node_id 확인 가능

# 예시: node_id 1번 노드에 P1.cfg 복사
cp P1.cfg /opt/unetlab/tmp/0/<LAB_HASH>/1/startup-config

# 또는 일괄 복사 스크립트 (node_id ↔ hostname 매핑 필요)
for cfg in *.cfg; do
  hostname="${cfg%.cfg}"
  node_id=$(get_node_id "$hostname")  # 매핑 필요
  cp "$cfg" "/opt/unetlab/tmp/0/<LAB_HASH>/$node_id/startup-config"
done

# 파일 권한 설정
chown -R root:unl /opt/unetlab/tmp/0/<LAB_HASH>/*/startup-config
```

> node_id ↔ hostname 매핑은 PNETLab API 또는 `.unl` 파일에서 추출 가능.

### 3.5 방법 D: Console 복붙 (Fallback)

20+ 노드에서는 비권장. 필요한 경우:

1. PNETLab UI에서 노드 더블클릭 → Telnet 콘솔 열기
2. `enable` → `configure terminal`
3. .cfg 내용 복붙 (100줄 단위, 각 블록 사이 2초 대기)
4. `end` → `write memory`

---

## 4. device_info.json 생성

NSO 등록이나 기존 배포 스크립트 연동 시 `device_info.json`이 필요하다.

### 4.1 스키마

```json
{
  "global_settings": {
    "pnetlab_vm_ip": "<PNETLab 서버 IP>",
    "gateway_ip": "10.10.10.1",
    "enable_password": "",
    "admin_password": "admin",
    "domain_name": "ncn.go.kr",
    "nso_authgroup": "<Lab 이름>",
    "nso_ned_id": "cisco-ios-cli-6.110",
    "nso_username": "admin",
    "nso_password": "admin",
    "batfish_output_dir": "Data/Pnetlab/<Lab 디렉토리명>"
  },
  "devices": [
    {
      "name": "P1",
      "oob_ip": "10.10.10.11",
      "oob_intf": "GigabitEthernet0/7",
      "device_group": "<Lab 이름>",
      "telnet_port": 0
    }
  ]
}
```

### 4.2 필드 출처

| 필드 | 출처 | 자동 추출 |
|------|------|----------|
| `name` | YAML `nodes[].name` | O |
| `oob_ip` | YAML `nodes[].management_ip` (IP 부분) | O |
| `oob_intf` | `GigabitEthernet0/7` (고정, `management_intf_slot: 7`) | O |
| `telnet_port` | PNETLab 노드 생성 후 확인 필요 | X |
| `pnetlab_vm_ip` | PNETLab 서버 실제 IP | X |

**telnet_port 확인 방법:**
- PNETLab UI → 노드 우클릭 → 정보에서 Console Port 확인
- 또는 PNETLab 서버: `cat /opt/unetlab/tmp/0/<LAB_HASH>/*/wrapper.txt`

### 4.3 Lab-B device_info.json 템플릿

```json
{
  "global_settings": {
    "pnetlab_vm_ip": "YOUR_PNETLAB_IP",
    "gateway_ip": "10.10.10.1",
    "enable_password": "",
    "admin_password": "admin",
    "domain_name": "ncn.go.kr",
    "nso_authgroup": "LabB_NCN_Basic_SP",
    "nso_ned_id": "cisco-ios-cli-6.110",
    "nso_username": "admin",
    "nso_password": "admin",
    "batfish_output_dir": "Data/Pnetlab/LabB_NCN_Basic_SP_20nodes"
  },
  "devices": [
    { "name": "P1",    "oob_ip": "10.10.10.11", "oob_intf": "GigabitEthernet0/7", "device_group": "LabB", "telnet_port": 0 },
    { "name": "P2",    "oob_ip": "10.10.10.12", "oob_intf": "GigabitEthernet0/7", "device_group": "LabB", "telnet_port": 0 },
    { "name": "P3",    "oob_ip": "10.10.10.13", "oob_intf": "GigabitEthernet0/7", "device_group": "LabB", "telnet_port": 0 },
    { "name": "P4",    "oob_ip": "10.10.10.14", "oob_intf": "GigabitEthernet0/7", "device_group": "LabB", "telnet_port": 0 },
    { "name": "P5",    "oob_ip": "10.10.10.15", "oob_intf": "GigabitEthernet0/7", "device_group": "LabB", "telnet_port": 0 },
    { "name": "P6",    "oob_ip": "10.10.10.16", "oob_intf": "GigabitEthernet0/7", "device_group": "LabB", "telnet_port": 0 },
    { "name": "P7",    "oob_ip": "10.10.10.17", "oob_intf": "GigabitEthernet0/7", "device_group": "LabB", "telnet_port": 0 },
    { "name": "P8",    "oob_ip": "10.10.10.18", "oob_intf": "GigabitEthernet0/7", "device_group": "LabB", "telnet_port": 0 },
    { "name": "PE1",   "oob_ip": "10.10.10.21", "oob_intf": "GigabitEthernet0/7", "device_group": "LabB", "telnet_port": 0 },
    { "name": "PE2",   "oob_ip": "10.10.10.22", "oob_intf": "GigabitEthernet0/7", "device_group": "LabB", "telnet_port": 0 },
    { "name": "PE3",   "oob_ip": "10.10.10.23", "oob_intf": "GigabitEthernet0/7", "device_group": "LabB", "telnet_port": 0 },
    { "name": "PE4",   "oob_ip": "10.10.10.24", "oob_intf": "GigabitEthernet0/7", "device_group": "LabB", "telnet_port": 0 },
    { "name": "Leaf1", "oob_ip": "10.10.10.31", "oob_intf": "GigabitEthernet0/7", "device_group": "LabB", "telnet_port": 0 },
    { "name": "Leaf2", "oob_ip": "10.10.10.32", "oob_intf": "GigabitEthernet0/7", "device_group": "LabB", "telnet_port": 0 },
    { "name": "Leaf3", "oob_ip": "10.10.10.33", "oob_intf": "GigabitEthernet0/7", "device_group": "LabB", "telnet_port": 0 },
    { "name": "Leaf4", "oob_ip": "10.10.10.34", "oob_intf": "GigabitEthernet0/7", "device_group": "LabB", "telnet_port": 0 },
    { "name": "Leaf5", "oob_ip": "10.10.10.35", "oob_intf": "GigabitEthernet0/7", "device_group": "LabB", "telnet_port": 0 },
    { "name": "Leaf6", "oob_ip": "10.10.10.36", "oob_intf": "GigabitEthernet0/7", "device_group": "LabB", "telnet_port": 0 },
    { "name": "Leaf7", "oob_ip": "10.10.10.37", "oob_intf": "GigabitEthernet0/7", "device_group": "LabB", "telnet_port": 0 },
    { "name": "Leaf8", "oob_ip": "10.10.10.38", "oob_intf": "GigabitEthernet0/7", "device_group": "LabB", "telnet_port": 0 }
  ]
}
```

### 4.4 Lab-C device_info.json 템플릿

```json
{
  "global_settings": {
    "pnetlab_vm_ip": "YOUR_PNETLAB_IP",
    "gateway_ip": "10.10.10.1",
    "enable_password": "",
    "admin_password": "admin",
    "domain_name": "ncn.go.kr",
    "nso_authgroup": "LabC_NCN_Security_L2VPN",
    "nso_ned_id": "cisco-ios-cli-6.110",
    "nso_username": "admin",
    "nso_password": "admin",
    "batfish_output_dir": "Data/Pnetlab/LabC_NCN_Security_L2VPN_30nodes"
  },
  "devices": [
    { "name": "P1",     "oob_ip": "10.10.10.11", "oob_intf": "GigabitEthernet0/7", "device_group": "LabC", "telnet_port": 0 },
    { "name": "P2",     "oob_ip": "10.10.10.12", "oob_intf": "GigabitEthernet0/7", "device_group": "LabC", "telnet_port": 0 },
    { "name": "P3",     "oob_ip": "10.10.10.13", "oob_intf": "GigabitEthernet0/7", "device_group": "LabC", "telnet_port": 0 },
    { "name": "P4",     "oob_ip": "10.10.10.14", "oob_intf": "GigabitEthernet0/7", "device_group": "LabC", "telnet_port": 0 },
    { "name": "P5",     "oob_ip": "10.10.10.15", "oob_intf": "GigabitEthernet0/7", "device_group": "LabC", "telnet_port": 0 },
    { "name": "P6",     "oob_ip": "10.10.10.16", "oob_intf": "GigabitEthernet0/7", "device_group": "LabC", "telnet_port": 0 },
    { "name": "P7",     "oob_ip": "10.10.10.17", "oob_intf": "GigabitEthernet0/7", "device_group": "LabC", "telnet_port": 0 },
    { "name": "P8",     "oob_ip": "10.10.10.18", "oob_intf": "GigabitEthernet0/7", "device_group": "LabC", "telnet_port": 0 },
    { "name": "P9",     "oob_ip": "10.10.10.19", "oob_intf": "GigabitEthernet0/7", "device_group": "LabC", "telnet_port": 0 },
    { "name": "P10",    "oob_ip": "10.10.10.20", "oob_intf": "GigabitEthernet0/7", "device_group": "LabC", "telnet_port": 0 },
    { "name": "PE1",    "oob_ip": "10.10.10.21", "oob_intf": "GigabitEthernet0/7", "device_group": "LabC", "telnet_port": 0 },
    { "name": "PE2",    "oob_ip": "10.10.10.22", "oob_intf": "GigabitEthernet0/7", "device_group": "LabC", "telnet_port": 0 },
    { "name": "PE3",    "oob_ip": "10.10.10.23", "oob_intf": "GigabitEthernet0/7", "device_group": "LabC", "telnet_port": 0 },
    { "name": "PE4",    "oob_ip": "10.10.10.24", "oob_intf": "GigabitEthernet0/7", "device_group": "LabC", "telnet_port": 0 },
    { "name": "PE5",    "oob_ip": "10.10.10.43", "oob_intf": "GigabitEthernet0/7", "device_group": "LabC", "telnet_port": 0 },
    { "name": "PE6",    "oob_ip": "10.10.10.44", "oob_intf": "GigabitEthernet0/7", "device_group": "LabC", "telnet_port": 0 },
    { "name": "ASBR1",  "oob_ip": "10.10.10.41", "oob_intf": "GigabitEthernet0/7", "device_group": "LabC", "telnet_port": 0 },
    { "name": "ASBR2",  "oob_ip": "10.10.10.42", "oob_intf": "GigabitEthernet0/7", "device_group": "LabC", "telnet_port": 0 },
    { "name": "Leaf1",  "oob_ip": "10.10.10.31", "oob_intf": "GigabitEthernet0/7", "device_group": "LabC", "telnet_port": 0 },
    { "name": "Leaf2",  "oob_ip": "10.10.10.32", "oob_intf": "GigabitEthernet0/7", "device_group": "LabC", "telnet_port": 0 },
    { "name": "Leaf3",  "oob_ip": "10.10.10.33", "oob_intf": "GigabitEthernet0/7", "device_group": "LabC", "telnet_port": 0 },
    { "name": "Leaf4",  "oob_ip": "10.10.10.34", "oob_intf": "GigabitEthernet0/7", "device_group": "LabC", "telnet_port": 0 },
    { "name": "Leaf5",  "oob_ip": "10.10.10.35", "oob_intf": "GigabitEthernet0/7", "device_group": "LabC", "telnet_port": 0 },
    { "name": "Leaf6",  "oob_ip": "10.10.10.36", "oob_intf": "GigabitEthernet0/7", "device_group": "LabC", "telnet_port": 0 },
    { "name": "Leaf7",  "oob_ip": "10.10.10.37", "oob_intf": "GigabitEthernet0/7", "device_group": "LabC", "telnet_port": 0 },
    { "name": "Leaf8",  "oob_ip": "10.10.10.38", "oob_intf": "GigabitEthernet0/7", "device_group": "LabC", "telnet_port": 0 },
    { "name": "Leaf9",  "oob_ip": "10.10.10.39", "oob_intf": "GigabitEthernet0/7", "device_group": "LabC", "telnet_port": 0 },
    { "name": "Leaf10", "oob_ip": "10.10.10.40", "oob_intf": "GigabitEthernet0/7", "device_group": "LabC", "telnet_port": 0 },
    { "name": "Leaf11", "oob_ip": "10.10.10.45", "oob_intf": "GigabitEthernet0/7", "device_group": "LabC", "telnet_port": 0 },
    { "name": "Leaf12", "oob_ip": "10.10.10.46", "oob_intf": "GigabitEthernet0/7", "device_group": "LabC", "telnet_port": 0 }
  ]
}
```

> `telnet_port: 0`은 placeholder. PNETLab에서 노드 생성 후 실제 포트 번호로 교체 필요.

### 4.5 Lab-D device_info.json 템플릿

```json
{
  "global_settings": {
    "pnetlab_vm_ip": "YOUR_PNETLAB_IP",
    "gateway_ip": "10.10.10.1",
    "enable_password": "",
    "admin_password": "admin",
    "domain_name": "ncn.go.kr",
    "nso_authgroup": "LabD_NCN_MultiAS_Complex",
    "nso_ned_id": "cisco-ios-cli-6.110",
    "nso_username": "admin",
    "nso_password": "admin",
    "batfish_output_dir": "Data/Pnetlab/LabD_NCN_MultiAS_Complex_40nodes"
  },
  "devices": [
    { "name": "P1",     "oob_ip": "10.10.10.11", "oob_intf": "GigabitEthernet0/7", "device_group": "LabD", "telnet_port": 0 },
    { "name": "P2",     "oob_ip": "10.10.10.12", "oob_intf": "GigabitEthernet0/7", "device_group": "LabD", "telnet_port": 0 },
    { "name": "P3",     "oob_ip": "10.10.10.13", "oob_intf": "GigabitEthernet0/7", "device_group": "LabD", "telnet_port": 0 },
    { "name": "P4",     "oob_ip": "10.10.10.14", "oob_intf": "GigabitEthernet0/7", "device_group": "LabD", "telnet_port": 0 },
    { "name": "P5",     "oob_ip": "10.10.10.15", "oob_intf": "GigabitEthernet0/7", "device_group": "LabD", "telnet_port": 0 },
    { "name": "P6",     "oob_ip": "10.10.10.16", "oob_intf": "GigabitEthernet0/7", "device_group": "LabD", "telnet_port": 0 },
    { "name": "P7",     "oob_ip": "10.10.10.17", "oob_intf": "GigabitEthernet0/7", "device_group": "LabD", "telnet_port": 0 },
    { "name": "P8",     "oob_ip": "10.10.10.18", "oob_intf": "GigabitEthernet0/7", "device_group": "LabD", "telnet_port": 0 },
    { "name": "P9",     "oob_ip": "10.10.10.19", "oob_intf": "GigabitEthernet0/7", "device_group": "LabD", "telnet_port": 0 },
    { "name": "P10",    "oob_ip": "10.10.10.20", "oob_intf": "GigabitEthernet0/7", "device_group": "LabD", "telnet_port": 0 },
    { "name": "P11",    "oob_ip": "10.10.10.55", "oob_intf": "GigabitEthernet0/7", "device_group": "LabD", "telnet_port": 0 },
    { "name": "P12",    "oob_ip": "10.10.10.56", "oob_intf": "GigabitEthernet0/7", "device_group": "LabD", "telnet_port": 0 },
    { "name": "PE1",    "oob_ip": "10.10.10.21", "oob_intf": "GigabitEthernet0/7", "device_group": "LabD", "telnet_port": 0 },
    { "name": "PE2",    "oob_ip": "10.10.10.22", "oob_intf": "GigabitEthernet0/7", "device_group": "LabD", "telnet_port": 0 },
    { "name": "PE3",    "oob_ip": "10.10.10.23", "oob_intf": "GigabitEthernet0/7", "device_group": "LabD", "telnet_port": 0 },
    { "name": "PE4",    "oob_ip": "10.10.10.24", "oob_intf": "GigabitEthernet0/7", "device_group": "LabD", "telnet_port": 0 },
    { "name": "PE5",    "oob_ip": "10.10.10.43", "oob_intf": "GigabitEthernet0/7", "device_group": "LabD", "telnet_port": 0 },
    { "name": "PE6",    "oob_ip": "10.10.10.44", "oob_intf": "GigabitEthernet0/7", "device_group": "LabD", "telnet_port": 0 },
    { "name": "PE7",    "oob_ip": "10.10.10.53", "oob_intf": "GigabitEthernet0/7", "device_group": "LabD", "telnet_port": 0 },
    { "name": "PE8",    "oob_ip": "10.10.10.54", "oob_intf": "GigabitEthernet0/7", "device_group": "LabD", "telnet_port": 0 },
    { "name": "ASBR1",  "oob_ip": "10.10.10.41", "oob_intf": "GigabitEthernet0/7", "device_group": "LabD", "telnet_port": 0 },
    { "name": "ASBR2",  "oob_ip": "10.10.10.42", "oob_intf": "GigabitEthernet0/7", "device_group": "LabD", "telnet_port": 0 },
    { "name": "FW1",    "oob_ip": "10.10.10.51", "oob_intf": "GigabitEthernet0/7", "device_group": "LabD", "telnet_port": 0 },
    { "name": "FW2",    "oob_ip": "10.10.10.52", "oob_intf": "GigabitEthernet0/7", "device_group": "LabD", "telnet_port": 0 },
    { "name": "Leaf1",  "oob_ip": "10.10.10.31", "oob_intf": "GigabitEthernet0/7", "device_group": "LabD", "telnet_port": 0 },
    { "name": "Leaf2",  "oob_ip": "10.10.10.32", "oob_intf": "GigabitEthernet0/7", "device_group": "LabD", "telnet_port": 0 },
    { "name": "Leaf3",  "oob_ip": "10.10.10.33", "oob_intf": "GigabitEthernet0/7", "device_group": "LabD", "telnet_port": 0 },
    { "name": "Leaf4",  "oob_ip": "10.10.10.34", "oob_intf": "GigabitEthernet0/7", "device_group": "LabD", "telnet_port": 0 },
    { "name": "Leaf5",  "oob_ip": "10.10.10.35", "oob_intf": "GigabitEthernet0/7", "device_group": "LabD", "telnet_port": 0 },
    { "name": "Leaf6",  "oob_ip": "10.10.10.36", "oob_intf": "GigabitEthernet0/7", "device_group": "LabD", "telnet_port": 0 },
    { "name": "Leaf7",  "oob_ip": "10.10.10.37", "oob_intf": "GigabitEthernet0/7", "device_group": "LabD", "telnet_port": 0 },
    { "name": "Leaf8",  "oob_ip": "10.10.10.38", "oob_intf": "GigabitEthernet0/7", "device_group": "LabD", "telnet_port": 0 },
    { "name": "Leaf9",  "oob_ip": "10.10.10.39", "oob_intf": "GigabitEthernet0/7", "device_group": "LabD", "telnet_port": 0 },
    { "name": "Leaf10", "oob_ip": "10.10.10.40", "oob_intf": "GigabitEthernet0/7", "device_group": "LabD", "telnet_port": 0 },
    { "name": "Leaf11", "oob_ip": "10.10.10.45", "oob_intf": "GigabitEthernet0/7", "device_group": "LabD", "telnet_port": 0 },
    { "name": "Leaf12", "oob_ip": "10.10.10.46", "oob_intf": "GigabitEthernet0/7", "device_group": "LabD", "telnet_port": 0 },
    { "name": "Leaf13", "oob_ip": "10.10.10.47", "oob_intf": "GigabitEthernet0/7", "device_group": "LabD", "telnet_port": 0 },
    { "name": "Leaf14", "oob_ip": "10.10.10.48", "oob_intf": "GigabitEthernet0/7", "device_group": "LabD", "telnet_port": 0 },
    { "name": "Leaf15", "oob_ip": "10.10.10.49", "oob_intf": "GigabitEthernet0/7", "device_group": "LabD", "telnet_port": 0 },
    { "name": "Leaf16", "oob_ip": "10.10.10.50", "oob_intf": "GigabitEthernet0/7", "device_group": "LabD", "telnet_port": 0 }
  ]
}
```

---

## 5. 배포 검증 체크리스트

### 5.1 기본 연결

```
[ ] 모든 노드 부팅 완료 (PNETLab UI에서 녹색 아이콘)
[ ] Cloud0 관리망 연결: ping 10.10.10.11 ~ 10.10.10.46 (해당 Lab)
[ ] SSH 접속 확인: ssh admin@10.10.10.11 (패스워드: admin)
```

### 5.2 라우팅 프로토콜 (Lab-B, Lab-C 공통)

아무 P/PE 노드에 SSH 접속 후:

```cisco
! OSPF neighbor 확인 (모든 인접 라우터와 FULL 상태)
show ip ospf neighbor

! BGP VPNv4 세션 확인 (PE 노드에서)
show bgp vpnv4 unicast summary

! MPLS LDP neighbor 확인
show mpls ldp neighbor

! VRF 라우팅 테이블 확인 (PE 노드에서)
show ip route vrf VRF_GOV
show ip route vrf VRF_EDU
```

### 5.3 Lab-C 추가 검증 항목

```cisco
! eBGP 세션 (P7/P8 또는 ASBR1/ASBR2에서)
show ip bgp summary

! OSPF Multi-Area (ASBR에서 Area 0 + Area 1 확인)
show ip ospf

! L2VPN xconnect 상태
show xconnect all
! 정상: PE1↔PE5 (PW-100) = UP
! 오류: PE3↔PE6 (PW-200 vs 201) = DOWN (PWID 불일치)
! 오류: PE2 (PW-300) = DOWN (단방향)

! HSRP 상태 (PE5/PE6에서)
show standby brief
! PE5: Active (priority 110), PE6: Standby (priority 100)

! ACL 확인 (Leaf9~12에서)
show ip access-lists
! BLOCK_SSH_EXTERNAL: deny tcp any any eq 22, permit ip any any
```

### 5.4 Lab-D 추가 검증 항목

```cisco
! Region 4 (AS 65002) 관련

! eBGP 세션 (FW1/FW2 → ASBR1/ASBR2)
show ip bgp summary
! FW1: neighbor 10.0.40.0 (ASBR1) AS 65001 → Established
! FW2: neighbor 10.0.40.2 (ASBR2) AS 65001 → Established

! OSPF Multi-Area (FW1/FW2에서 Area 2 확인)
show ip ospf interface brief
! Region 4 인터페이스: Area 2

! QoS Policy (PE7/PE8에서)
show policy-map interface
! class VOICE: bandwidth percent 30
! class VIDEO: bandwidth percent 25
! class DATA:  bandwidth percent 20

! NetFlow (PE7/PE8에서)
show flow monitor FLOW_MONITOR_1 statistics
show flow exporter NETFLOW_EXPORT

! VRF 확인 (PE7/PE8에서)
show ip route vrf VRF_ISP
show ip route vrf VRF_CDN

! 의도적 오류 확인 (3가지)
! 1. VRF_ISP_BROKEN: RT 없음 → 경로 교환 실패
show ip bgp vpnv4 vrf VRF_ISP_BROKEN summary
! 2. PE7↔PE8 iBGP 비대칭 (PE8 → PE7 neighbor만 있음)
show ip bgp vpnv4 unicast summary    ! PE7에서: PE8 neighbor 없음
! 3. FW1↔PE7 OSPF cost 비대칭 (FW1:10, PE7:100)
show ip ospf interface GigabitEthernet0/2  ! cost 값 비교
```

### 5.5 검증 명령어 모음 (복사-붙여넣기용)

```cisco
show ip ospf neighbor
show bgp vpnv4 unicast summary
show mpls ldp neighbor
show ip route vrf VRF_GOV
show ip route vrf VRF_EDU
show ip route vrf VRF_RND
show xconnect all
show standby brief
show ip access-lists
show ip bgp summary
```

---

## 6. 파이프라인 연결

### 6.1 데이터 디렉토리 구성

```bash
# Lab-B 디렉토리 생성 + config 복사
mkdir -p Data/Pnetlab/LabB_NCN_Basic_SP_20nodes/configs
cp Make_Dataset/config_generator/output/LabB_NCN_Basic_SP_20nodes/configs/*.cfg \
   Data/Pnetlab/LabB_NCN_Basic_SP_20nodes/configs/

# Lab-C
mkdir -p Data/Pnetlab/LabC_NCN_Security_L2VPN_30nodes/configs
cp Make_Dataset/config_generator/output/LabC_NCN_Security_L2VPN_30nodes/configs/*.cfg \
   Data/Pnetlab/LabC_NCN_Security_L2VPN_30nodes/configs/

# Lab-D
mkdir -p Data/Pnetlab/LabD_NCN_MultiAS_Complex_40nodes/configs
cp Make_Dataset/config_generator/output/LabD_NCN_MultiAS_Complex_40nodes/configs/*.cfg \
   Data/Pnetlab/LabD_NCN_MultiAS_Complex_40nodes/configs/

# device_info.json 복사 (섹션 4에서 작성한 것)
cp device_info_labB.json Data/Pnetlab/LabB_NCN_Basic_SP_20nodes/device_info.json
cp device_info_labC.json Data/Pnetlab/LabC_NCN_Security_L2VPN_30nodes/device_info.json
cp device_info_labD.json Data/Pnetlab/LabD_NCN_MultiAS_Complex_40nodes/device_info.json
```

### 6.2 NSO 등록 (선택: NetAlly 데모 시 필요)

`2-NSO_Register.py`의 CONFIG_FILE 경로를 수정:

```python
# 기존 (Lab-A)
CONFIG_FILE = "Data/Pnetlab/Research_Institute_Internal_DC/device_info.json"

# Lab-B로 변경
CONFIG_FILE = "Data/Pnetlab/LabB_NCN_Basic_SP_20nodes/device_info.json"
```

### 6.3 Batfish 데이터셋 생성

```bash
# Batfish 컨테이너 실행 확인
docker ps | grep batfish
# 없으면: docker run -d -p 9997:9997 -p 9996:9996 --name batfish batfish/batfish

# Lab-B 데이터셋 생성
python Make_Dataset/src/main_batfish.py \
  --lab-path Data/Pnetlab/LabB_NCN_Basic_SP_20nodes \
  --policies Make_Dataset/policies.json

# Lab-C 데이터셋 생성
python Make_Dataset/src/main_batfish.py \
  --lab-path Data/Pnetlab/LabC_NCN_Security_L2VPN_30nodes \
  --policies Make_Dataset/policies.json

# Lab-D 데이터셋 생성
python Make_Dataset/src/main_batfish.py \
  --lab-path Data/Pnetlab/LabD_NCN_MultiAS_Complex_40nodes \
  --policies Make_Dataset/policies.json
```

### 6.4 Config Export (3-Config_Export_Batfish.py) 스킵

Lab-B/C는 Config Generator가 생성한 .cfg를 **직접** Batfish에 투입하므로,
NSO를 통한 config export 단계(`3-Config_Export_Batfish.py`)가 **불필요**하다.

> Batfish의 `main_batfish.py`는 `<lab-path>/configs/*.cfg` 파일을 직접 읽어 스냅샷을 생성한다.

---

## 7. NSO / NetAlly 연동 (선택)

Lab-B/C/D에서 NetAlly Multi-Agent System을 사용한 데이터셋 평가 실험(Exp.3)이나 데모를 수행할 때 필요하다.
Batfish 데이터셋 생성만 할 경우에는 이 섹션을 건너뛰어도 된다.

> **상세 문서**: 아래는 요약이며, 전체 절차는 NetAlly 문서를 참조한다.
> - [pnetlab_deployment_guide.md](../../../NetAlly/docs/pnetlab_deployment_guide.md) — NetAlly Docker Node 설정
> - [pnetlab_wiring_runbook_ko.md](../../../NetAlly/docs/pnetlab_wiring_runbook_ko.md) — 실전 배선/운영

### 7.1 전체 구성도

```
                    ┌─────────────────────────────────────────────────┐
                    │              PNETLab VM                          │
                    │                                                 │
                    │  ┌──────────┐  ┌──────────┐  ┌──────────────┐  │
                    │  │ NetAlly  │  │   NSO    │  │  Batfish     │  │
                    │  │ Docker   │  │ Docker   │  │  Docker      │  │
                    │  │ :8000    │  │ :8080    │  │  :9996/:9997 │  │
                    │  └────┬─────┘  └────┬─────┘  └──────────────┘  │
                    │       │             │                           │
                    │  ─────┴─────────────┴────── Cloud0 ──────────  │
                    │       │   Management Network (10.10.10.0/24)   │
                    │       │                                        │
                    │  ┌────┴───────────────────────────────────┐    │
                    │  │  Lab 노드들 (P/PE/Leaf/ASBR/FW)         │    │
                    │  │  각 노드 e7 → Cloud0                    │    │
                    │  └────────────────────────────────────────┘    │
                    └─────────────────────────────────────────────────┘
```

### 7.2 NetAlly Docker Node 추가

PNETLab UI에서 Docker 노드를 추가한다.

| 항목 | 설정값 |
|------|--------|
| Image | `netally:latest` |
| Name | `NetAlly` |
| CPU/RAM | 2 cores / 2048 MB |
| Console Type | `http` |
| Console Port | `8000` |
| Ethernet | `4` |
| 배선 | `eth1` → Cloud0 (관리망) |

**Docker Options** (한 줄 복붙):
```
--privileged -v /opt/unetlab:/opt/unetlab:ro --add-host=host.docker.internal:host-gateway -e PNETLAB_INVENTORY_BACKEND=labfs_local -e PNETLAB_LAB_NAME=<랩이름> -e PNETLAB_NSO_NODE=NSO -e BATFISH_HOST=host.docker.internal:9997 -e BATFISH_SNAPSHOT=<랩이름> -e AUTO_INIT_BATFISH=true -e NETALLY_TOOL_BACKEND=mcp -e NETALLY_MCP_ALLOW_MUTATIONS=true
```

| Lab | `PNETLAB_LAB_NAME` | `BATFISH_SNAPSHOT` |
|-----|--------------------|--------------------|
| Lab-B | `LabB_NCN_Basic_SP` | `LabB_NCN_Basic_SP` |
| Lab-C | `LabC_NCN_Security_L2VPN` | `LabC_NCN_Security_L2VPN` |
| Lab-D | `LabD_NCN_MultiAS_Complex` | `LabD_NCN_MultiAS_Complex` |

> **주의**: 실험실별로 NetAlly 인스턴스를 분리하는 것을 권장한다. 같은 인스턴스를 공유하면 `PNETLAB_LAB_NAME`, `BATFISH_SNAPSHOT`이 충돌할 수 있다.

### 7.3 NSO Docker Node 추가

NSO를 통한 장비 등록/sync-from이 필요한 경우에만 추가한다.

| 항목 | 설정값 |
|------|--------|
| Image | `ptthanh1511/nso:latest` |
| Name | `NSO` |
| 배선 | `eth2` → Cloud0 (관리망) |

NSO 등록:
```bash
# device_info.json 경로를 해당 Lab으로 수정 후 실행
python Make_Dataset/src/2-NSO_Register.py
```

### 7.4 Batfish Docker (호스트에서 실행)

Batfish는 PNETLab 호스트에서 별도 컨테이너로 실행한다.

```bash
# PNETLab 호스트(root)에서 1회 실행
docker run -d --name netally-batfish --restart unless-stopped \
  -p 9996:9996 -p 9997:9997 batfish/allinone:latest

# 헬스 확인
curl -fsS http://127.0.0.1:9996/v2/version
```

### 7.5 접속 방법

| 방법 | 용도 |
|------|------|
| PNETLab 캔버스에서 NetAlly 노드 더블클릭 | 가장 간단 (http console) |
| SSH 터널 (`ssh -N -L 18111:<NetAlly_IP>:8000 root@<PNETLab_IP>`) | 로컬 브라우저 접속 |
| Docker Options에 `-p 18111:8000` 추가 | 포트 직접 노출 (데모용) |

---

## 부록 A: Lab별 배선 상세 테이블

### A.1 Lab-B (20 Nodes) — 배선 테이블

**노드 목록 (20개)**

| # | Node | Role | Region | Loopback | Management IP |
|---|------|------|--------|----------|--------------|
| 1 | P1 | P Core | 1 | 10.255.0.1 | 10.10.10.11 |
| 2 | P2 | P Core | 1 | 10.255.0.2 | 10.10.10.12 |
| 3 | P3 | P Core | 1 | 10.255.0.3 | 10.10.10.13 |
| 4 | P4 | P Core | 1 | 10.255.0.4 | 10.10.10.14 |
| 5 | P5 | P Core | 2 | 10.255.0.5 | 10.10.10.15 |
| 6 | P6 | P Core | 2 | 10.255.0.6 | 10.10.10.16 |
| 7 | P7 | P Core | 2 | 10.255.0.7 | 10.10.10.17 |
| 8 | P8 | P Core | 2 | 10.255.0.8 | 10.10.10.18 |
| 9 | PE1 | PE | 1 | 10.255.0.11 | 10.10.10.21 |
| 10 | PE2 | PE | 1 | 10.255.0.12 | 10.10.10.22 |
| 11 | PE3 | PE | 2 | 10.255.0.21 | 10.10.10.23 |
| 12 | PE4 | PE | 2 | 10.255.0.22 | 10.10.10.24 |
| 13 | Leaf1 | Leaf | 1 | — | 10.10.10.31 |
| 14 | Leaf2 | Leaf | 1 | — | 10.10.10.32 |
| 15 | Leaf3 | Leaf | 1 | — | 10.10.10.33 |
| 16 | Leaf4 | Leaf | 1 | — | 10.10.10.34 |
| 17 | Leaf5 | Leaf | 2 | — | 10.10.10.35 |
| 18 | Leaf6 | Leaf | 2 | — | 10.10.10.36 |
| 19 | Leaf7 | Leaf | 2 | — | 10.10.10.37 |
| 20 | Leaf8 | Leaf | 2 | — | 10.10.10.38 |

**데이터 링크 (22개)**

| # | Node A | Slot A (eX) | Node B | Slot B (eX) | Subnet | 비고 |
|---|--------|------------|--------|------------|--------|------|
| 1 | P1 | e0 | PE1 | e0 | 10.0.1.0/31 | MPLS |
| 2 | P1 | e1 | P2 | e0 | 10.0.2.0/31 | MPLS |
| 3 | P1 | e2 | P3 | e0 | 10.0.3.0/31 | MPLS |
| 4 | P2 | e1 | PE2 | e0 | 10.0.4.0/31 | MPLS |
| 5 | P2 | e2 | P4 | e0 | 10.0.5.0/31 | MPLS |
| 6 | P3 | e1 | P4 | e1 | 10.0.6.0/31 | MPLS |
| 7 | P4 | e2 | PE2 | e1 | 10.0.7.0/31 | MPLS |
| 8 | PE1 | e1 | Leaf1 | e0 | 172.16.1.0/24 | VRF_GOV |
| 9 | PE1 | e2 | Leaf2 | e0 | 172.16.2.0/24 | VRF_EDU |
| 10 | PE2 | e2 | Leaf3 | e0 | 172.16.3.0/24 | VRF_RND |
| 11 | PE2 | e3 | Leaf4 | e0 | 172.16.4.0/24 | VRF_GOV |
| 12 | P3 | e2 | P5 | e2 | 10.0.20.0/31 | Inter-Region |
| 13 | P5 | e0 | PE3 | e0 | 10.0.11.0/31 | MPLS |
| 14 | P5 | e1 | P6 | e0 | 10.0.12.0/31 | MPLS |
| 15 | P6 | e1 | PE4 | e0 | 10.0.14.0/31 | MPLS |
| 16 | P6 | e2 | P7 | e0 | 10.0.15.0/31 | MPLS |
| 17 | P7 | e1 | P8 | e0 | 10.0.16.0/31 | MPLS |
| 18 | P8 | e1 | PE4 | e1 | 10.0.17.0/31 | MPLS |
| 19 | PE3 | e1 | Leaf5 | e0 | 172.17.1.0/24 | VRF_GOV |
| 20 | PE3 | e2 | Leaf6 | e0 | 172.17.2.0/24 | VRF_EDU |
| 21 | PE4 | e2 | Leaf7 | e0 | 172.17.3.0/24 | VRF_RND |
| 22 | PE4 | e3 | Leaf8 | e0 | 172.17.4.0/24 | VRF_GOV |

**관리 네트워크**: 모든 20개 노드의 `e7` → Cloud0 (`10.10.10.0/24`)

---

### A.2 Lab-C (30 Nodes) — 배선 테이블

**노드 목록 (30개)**

| # | Node | Role | Region | AS | Loopback | Management IP |
|---|------|------|--------|-----|----------|--------------|
| 1 | P1 | P Core | 1 | 65000 | 10.255.0.1 | 10.10.10.11 |
| 2 | P2 | P Core | 1 | 65000 | 10.255.0.2 | 10.10.10.12 |
| 3 | P3 | P Core | 1 | 65000 | 10.255.0.3 | 10.10.10.13 |
| 4 | P4 | P Core | 1 | 65000 | 10.255.0.4 | 10.10.10.14 |
| 5 | P5 | P Core | 2 | 65000 | 10.255.0.5 | 10.10.10.15 |
| 6 | P6 | P Core | 2 | 65000 | 10.255.0.6 | 10.10.10.16 |
| 7 | P7 | P Core | 2 | 65000 | 10.255.0.7 | 10.10.10.17 |
| 8 | P8 | P Core | 2 | 65000 | 10.255.0.8 | 10.10.10.18 |
| 9 | P9 | P Core | 3 | 65001 | 10.255.0.9 | 10.10.10.19 |
| 10 | P10 | P Core | 3 | 65001 | 10.255.0.10 | 10.10.10.20 |
| 11 | PE1 | PE | 1 | 65000 | 10.255.0.11 | 10.10.10.21 |
| 12 | PE2 | PE | 1 | 65000 | 10.255.0.12 | 10.10.10.22 |
| 13 | PE3 | PE | 2 | 65000 | 10.255.0.21 | 10.10.10.23 |
| 14 | PE4 | PE | 2 | 65000 | 10.255.0.22 | 10.10.10.24 |
| 15 | PE5 | PE | 3 | 65001 | 10.255.0.33 | 10.10.10.43 |
| 16 | PE6 | PE | 3 | 65001 | 10.255.0.34 | 10.10.10.44 |
| 17 | ASBR1 | ASBR | 3 | 65001 | 10.255.0.31 | 10.10.10.41 |
| 18 | ASBR2 | ASBR | 3 | 65001 | 10.255.0.32 | 10.10.10.42 |
| 19 | Leaf1 | Leaf | 1 | — | — | 10.10.10.31 |
| 20 | Leaf2 | Leaf | 1 | — | — | 10.10.10.32 |
| 21 | Leaf3 | Leaf | 1 | — | — | 10.10.10.33 |
| 22 | Leaf4 | Leaf | 1 | — | — | 10.10.10.34 |
| 23 | Leaf5 | Leaf | 2 | — | — | 10.10.10.35 |
| 24 | Leaf6 | Leaf | 2 | — | — | 10.10.10.36 |
| 25 | Leaf7 | Leaf | 2 | — | — | 10.10.10.37 |
| 26 | Leaf8 | Leaf | 2 | — | — | 10.10.10.38 |
| 27 | Leaf9 | Leaf | 3 | — | — | 10.10.10.39 |
| 28 | Leaf10 | Leaf | 3 | — | — | 10.10.10.40 |
| 29 | Leaf11 | Leaf | 3 | — | — | 10.10.10.45 |
| 30 | Leaf12 | Leaf | 3 | — | — | 10.10.10.46 |

**데이터 링크 (35개)**

Region 1 (AS 65000, OSPF Area 0):

| # | Node A | Slot A | Node B | Slot B | Subnet | 비고 |
|---|--------|--------|--------|--------|--------|------|
| 1 | P1 | e0 | PE1 | e0 | 10.0.1.0/31 | MPLS |
| 2 | P1 | e1 | P2 | e0 | 10.0.2.0/31 | MPLS |
| 3 | P1 | e2 | P3 | e0 | 10.0.3.0/31 | MPLS |
| 4 | P2 | e1 | PE2 | e0 | 10.0.4.0/31 | MPLS |
| 5 | P2 | e2 | P4 | e0 | 10.0.5.0/31 | MPLS |
| 6 | P3 | e1 | P4 | e1 | 10.0.6.0/31 | MPLS |
| 7 | P4 | e2 | PE2 | e1 | 10.0.7.0/31 | MPLS |
| 8 | PE1 | e1 | Leaf1 | e0 | 172.16.1.0/24 | VRF_GOV |
| 9 | PE1 | e2 | Leaf2 | e0 | 172.16.2.0/24 | VRF_EDU |
| 10 | PE2 | e2 | Leaf3 | e0 | 172.16.3.0/24 | VRF_RND |
| 11 | PE2 | e3 | Leaf4 | e0 | 172.16.4.0/24 | VRF_GOV |

Inter-Region 1 ↔ 2:

| # | Node A | Slot A | Node B | Slot B | Subnet | 비고 |
|---|--------|--------|--------|--------|--------|------|
| 12 | P3 | e2 | P5 | e2 | 10.0.20.0/31 | Inter-Region Backbone |

Region 2 (AS 65000, OSPF Area 0):

| # | Node A | Slot A | Node B | Slot B | Subnet | 비고 |
|---|--------|--------|--------|--------|--------|------|
| 13 | P5 | e0 | PE3 | e0 | 10.0.11.0/31 | MPLS |
| 14 | P5 | e1 | P6 | e0 | 10.0.12.0/31 | MPLS |
| 15 | P6 | e1 | PE4 | e0 | 10.0.14.0/31 | MPLS |
| 16 | P6 | e2 | P7 | e0 | 10.0.15.0/31 | MPLS |
| 17 | P7 | e1 | P8 | e0 | 10.0.16.0/31 | MPLS |
| 18 | P8 | e1 | PE4 | e1 | 10.0.17.0/31 | MPLS |
| 19 | PE3 | e1 | Leaf5 | e0 | 172.17.1.0/24 | VRF_GOV |
| 20 | PE3 | e2 | Leaf6 | e0 | 172.17.2.0/24 | VRF_EDU |
| 21 | PE4 | e2 | Leaf7 | e0 | 172.17.3.0/24 | VRF_RND |
| 22 | PE4 | e3 | Leaf8 | e0 | 172.17.4.0/24 | VRF_GOV |

Inter-Region 2 ↔ 3 (Inter-AS):

| # | Node A | Slot A | Node B | Slot B | Subnet | 비고 |
|---|--------|--------|--------|--------|--------|------|
| 23 | P7 | e2 | ASBR1 | e0 | 10.0.30.0/31 | Inter-AS (eBGP) |
| 24 | P8 | e2 | ASBR2 | e0 | 10.0.30.2/31 | Inter-AS (eBGP) |

Region 3 (AS 65001, OSPF Area 1):

| # | Node A | Slot A | Node B | Slot B | Subnet | 비고 |
|---|--------|--------|--------|--------|--------|------|
| 25 | ASBR1 | e1 | P9 | e0 | 10.0.31.0/31 | MPLS |
| 26 | ASBR1 | e2 | PE5 | e0 | 10.0.31.2/31 | MPLS |
| 27 | ASBR2 | e1 | P10 | e0 | 10.0.32.0/31 | MPLS |
| 28 | ASBR2 | e2 | PE6 | e0 | 10.0.32.2/31 | MPLS |
| 29 | P9 | e1 | P10 | e1 | 10.0.33.0/31 | MPLS |
| 30 | P9 | e2 | PE6 | e5 | 10.0.33.2/31 | MPLS |
| 31 | P10 | e2 | PE5 | e4 | 10.0.34.0/31 | MPLS |

Region 3 Access (VRF + HSRP + ACL):

| # | Node A | Slot A | Node B | Slot B | Subnet | 비고 |
|---|--------|--------|--------|--------|--------|------|
| 32 | PE5 e1 + PE6 e4 + Leaf9 e0 | (공유 Bridge) | | | 172.18.1.0/24 | **HSRP** VRF_SEC |
| 33 | PE5 | e2 | Leaf10 | e0 | 172.18.2.0/24 | VRF_MIL |
| 34 | PE6 | e1 | Leaf11 | e0 | 172.18.3.0/24 | VRF_SEC |
| 35 | PE6 | e2 | Leaf12 | e0 | 172.18.4.0/24 | VRF_MIL |

> Link #32는 HSRP 공유 서브넷: PE5(e1, Active), PE6(e4, Standby), Leaf9(e0)를 **하나의 Bridge**에 연결해야 한다.

L2VPN xconnect (논리적 Pseudowire — 물리 배선 불필요):

| PW | 송신 | 수신 | PWID | 상태 |
|----|------|------|------|------|
| PW-100 | PE1 (e3) | PE5 (e3) | 100 ↔ 100 | 정상 |
| PW-200/201 | PE3 (e3) | PE6 (e3) | 200 ↔ 201 | **PWID 불일치** (의도적) |
| PW-300 | PE2 (e4) | — | 300 | **단방향** (의도적) |

> xconnect 인터페이스(PE1 e3, PE2 e4, PE3 e3, PE5 e3, PE6 e3)는 PNETLab에서 **미연결 상태로 둬도** 무방. Pseudowire는 MPLS 코어를 통해 논리적으로 연결된다.

**관리 네트워크**: 모든 30개 노드의 `e7` → Cloud0 (`10.10.10.0/24`)

---

### A.3 Lab-D (40 Nodes) — 배선 테이블

**노드 목록 (40개)**

| # | Node | Role | Region | AS | OSPF Area | Loopback | Management IP |
|---|------|------|--------|-----|-----------|----------|---------------|
| 1 | P1 | P Core | 1 | 65000 | 0 | 10.255.0.1 | 10.10.10.11 |
| 2 | P2 | P Core | 1 | 65000 | 0 | 10.255.0.2 | 10.10.10.12 |
| 3 | P3 | P Core | 1 | 65000 | 0 | 10.255.0.3 | 10.10.10.13 |
| 4 | P4 | P Core | 1 | 65000 | 0 | 10.255.0.4 | 10.10.10.14 |
| 5 | P5 | P Core | 2 | 65000 | 0 | 10.255.0.5 | 10.10.10.15 |
| 6 | P6 | P Core | 2 | 65000 | 0 | 10.255.0.6 | 10.10.10.16 |
| 7 | P7 | P Core | 2 | 65000 | 0 | 10.255.0.7 | 10.10.10.17 |
| 8 | P8 | P Core | 2 | 65000 | 0 | 10.255.0.8 | 10.10.10.18 |
| 9 | P9 | P Core | 3 | 65001 | 1 | 10.255.0.9 | 10.10.10.19 |
| 10 | P10 | P Core | 3 | 65001 | 1 | 10.255.0.10 | 10.10.10.20 |
| 11 | P11 | P Core | 4 | 65002 | 2 | 10.255.0.51 | 10.10.10.55 |
| 12 | P12 | P Core | 4 | 65002 | 2 | 10.255.0.52 | 10.10.10.56 |
| 13 | PE1 | PE | 1 | 65000 | 0 | 10.255.0.11 | 10.10.10.21 |
| 14 | PE2 | PE | 1 | 65000 | 0 | 10.255.0.12 | 10.10.10.22 |
| 15 | PE3 | PE | 2 | 65000 | 0 | 10.255.0.21 | 10.10.10.23 |
| 16 | PE4 | PE | 2 | 65000 | 0 | 10.255.0.22 | 10.10.10.24 |
| 17 | PE5 | PE | 3 | 65001 | 1 | 10.255.0.33 | 10.10.10.43 |
| 18 | PE6 | PE | 3 | 65001 | 1 | 10.255.0.34 | 10.10.10.44 |
| 19 | PE7 | PE | 4 | 65002 | 2 | 10.255.0.43 | 10.10.10.53 |
| 20 | PE8 | PE | 4 | 65002 | 2 | 10.255.0.44 | 10.10.10.54 |
| 21 | ASBR1 | ASBR | 3 | 65001 | 0/1/2 | 10.255.0.31 | 10.10.10.41 |
| 22 | ASBR2 | ASBR | 3 | 65001 | 0/1/2 | 10.255.0.32 | 10.10.10.42 |
| 23 | FW1 | FW | 4 | 65002 | 2 | 10.255.0.41 | 10.10.10.51 |
| 24 | FW2 | FW | 4 | 65002 | 2 | 10.255.0.42 | 10.10.10.52 |
| 25-28 | Leaf1~4 | Leaf | 1 | — | — | — | 10.10.10.31~34 |
| 29-32 | Leaf5~8 | Leaf | 2 | — | — | — | 10.10.10.35~38 |
| 33-34 | Leaf9~10 | Leaf | 3 | — | — | — | 10.10.10.39~40 |
| 35-36 | Leaf11~12 | Leaf | 3 | — | — | — | 10.10.10.45~46 |
| 37-40 | Leaf13~16 | Leaf | 4 | — | — | — | 10.10.10.47~50 |

**데이터 링크 — Region 1 (AS 65000, OSPF Area 0)**

| # | Node A | Slot A | Node B | Slot B | Subnet | 비고 |
|---|--------|--------|--------|--------|--------|------|
| 1 | P1 | e0 | PE1 | e0 | 10.0.1.0/31 | MPLS |
| 2 | P1 | e1 | P2 | e0 | 10.0.2.0/31 | MPLS |
| 3 | P1 | e2 | P3 | e0 | 10.0.3.0/31 | MPLS |
| 4 | P2 | e1 | PE2 | e0 | 10.0.4.0/31 | MPLS |
| 5 | P2 | e2 | P4 | e0 | 10.0.5.0/31 | MPLS |
| 6 | P3 | e1 | P4 | e1 | 10.0.6.0/31 | MPLS |
| 7 | P4 | e2 | PE2 | e1 | 10.0.7.0/31 | MPLS |
| 8 | PE1 | e1 | Leaf1 | e0 | 172.16.1.0/24 | VRF_GOV |
| 9 | PE1 | e2 | Leaf2 | e0 | 172.16.2.0/24 | VRF_EDU |
| 10 | PE2 | e2 | Leaf3 | e0 | 172.16.3.0/24 | VRF_RND |
| 11 | PE2 | e3 | Leaf4 | e0 | 172.16.4.0/24 | VRF_GOV |

**Inter-Region 1 ↔ 2**

| 12 | P3 | e2 | P5 | e2 | 10.0.20.0/31 | Intra-AS Backbone |

**Region 2 (AS 65000, OSPF Area 0)**

| # | Node A | Slot A | Node B | Slot B | Subnet | 비고 |
|---|--------|--------|--------|--------|--------|------|
| 13 | P5 | e0 | PE3 | e0 | 10.0.11.0/31 | MPLS |
| 14 | P5 | e1 | P6 | e0 | 10.0.12.0/31 | MPLS |
| 15 | P6 | e1 | PE4 | e0 | 10.0.14.0/31 | MPLS |
| 16 | P6 | e2 | P7 | e0 | 10.0.15.0/31 | MPLS |
| 17 | P7 | e1 | P8 | e0 | 10.0.16.0/31 | MPLS |
| 18 | P8 | e1 | PE4 | e1 | 10.0.17.0/31 | MPLS |
| 19 | PE3 | e1 | Leaf5 | e0 | 172.17.1.0/24 | VRF_GOV |
| 20 | PE3 | e2 | Leaf6 | e0 | 172.17.2.0/24 | VRF_EDU |
| 21 | PE4 | e2 | Leaf7 | e0 | 172.17.3.0/24 | VRF_RND |
| 22 | PE4 | e3 | Leaf8 | e0 | 172.17.4.0/24 | VRF_GOV |

**Inter-Region 2 ↔ 3 (Inter-AS, eBGP)**

| # | Node A | Slot A | Node B | Slot B | Subnet | 비고 |
|---|--------|--------|--------|--------|--------|------|
| 23 | P7 | e2 | ASBR1 | e0 | 10.0.30.0/31 | eBGP 65000↔65001 |
| 24 | P8 | e2 | ASBR2 | e0 | 10.0.30.2/31 | eBGP 65000↔65001 |

**Region 3 (AS 65001, OSPF Area 1)**

| # | Node A | Slot A | Node B | Slot B | Subnet | 비고 |
|---|--------|--------|--------|--------|--------|------|
| 25 | ASBR1 | e1 | P9 | e0 | 10.0.31.0/31 | MPLS, Area 1 |
| 26 | ASBR1 | e2 | PE5 | e0 | 10.0.31.2/31 | MPLS, Area 1 |
| 27 | ASBR2 | e1 | P10 | e0 | 10.0.32.0/31 | MPLS, Area 1 |
| 28 | ASBR2 | e2 | PE6 | e0 | 10.0.32.2/31 | MPLS, Area 1 |
| 29 | P9 | e1 | P10 | e1 | 10.0.33.0/31 | MPLS |
| 30 | P9 | e2 | PE6 | e5 | 10.0.33.2/31 | MPLS |
| 31 | P10 | e2 | PE5 | e4 | 10.0.34.0/31 | MPLS |

**Region 3 Access (VRF + HSRP + ACL)**

| # | Node A | Slot A | Node B | Slot B | Subnet | 비고 |
|---|--------|--------|--------|--------|--------|------|
| 32 | PE5 e1 + PE6 e4 + Leaf9 e0 | (공유) | | | 172.18.1.0/24 | **HSRP** VRF_SEC |
| 33 | PE5 | e2 | Leaf10 | e0 | 172.18.2.0/24 | VRF_MIL |
| 34 | PE6 | e1 | Leaf11 | e0 | 172.18.3.0/24 | VRF_SEC |
| 35 | PE6 | e2 | Leaf12 | e0 | 172.18.4.0/24 | VRF_MIL |

**Inter-Region 3 ↔ 4 (Inter-AS, eBGP)**

| # | Node A | Slot A | Node B | Slot B | Subnet | 비고 |
|---|--------|--------|--------|--------|--------|------|
| 36 | ASBR1 | e3 | FW1 | e0 | 10.0.40.0/31 | eBGP 65001↔65002, Area 2 |
| 37 | ASBR2 | e3 | FW2 | e0 | 10.0.40.2/31 | eBGP 65001↔65002, Area 2 |

**Region 4 (AS 65002, OSPF Area 2)**

| # | Node A | Slot A | Node B | Slot B | Subnet | 비고 |
|---|--------|--------|--------|--------|--------|------|
| 38 | FW1 | e1 | PE7 | e0 | 10.0.41.0/31 | MPLS |
| 39 | FW1 | e2 | P11 | e0 | 10.0.43.2/31 | MPLS |
| 40 | FW2 | e1 | PE8 | e0 | 10.0.42.0/31 | MPLS |
| 41 | FW2 | e2 | P12 | e0 | 10.0.44.0/31 | MPLS |
| 42 | P11 | e1 | P12 | e0 | 10.0.43.0/31 | MPLS |
| 43 | P12 | e1 | PE8 | e1 | 10.0.44.1/31 | MPLS |
| 44 | P11 | e2 | PE7 | e3 | 10.0.43.3/31 | MPLS |

**Region 4 Access**

| # | Node A | Slot A | Node B | Slot B | Subnet | 비고 |
|---|--------|--------|--------|--------|--------|------|
| 45 | PE7 | e1 | Leaf13 | e0 | 172.19.1.0/24 | VRF_ISP |
| 46 | PE7 | e2 | Leaf14 | e0 | 172.19.2.0/24 | VRF_CDN + QoS + NetFlow |
| 47 | PE8 | e2 | Leaf15 | e0 | 172.19.3.0/24 | VRF_ISP_BROKEN (의도적 오류) |
| 48 | PE8 | e3 | Leaf16 | e0 | 172.19.4.0/24 | VRF_CDN |

**관리 네트워크**: 모든 40개 노드의 `e7` → Cloud0 (`10.10.10.0/24`)

**Lab-D 의도적 오류 3가지** (데이터셋 L6 진단 문제용):
1. **VRF_ISP_BROKEN** (PE8): RT import/export 없음 → 경로 교환 불가
2. **PE7↔PE8 iBGP 비대칭**: PE8→PE7 neighbor만 설정, PE7→PE8 미설정
3. **FW1↔PE7 OSPF cost 비대칭**: FW1 Gi0/2 cost=10, PE7 Gi0/2 cost=100

---

## 부록 B: Troubleshooting

### B.1 노드가 부팅되지 않음
- IOSv 이미지가 `/opt/unetlab/addons/qemu/` 에 올바르게 설치되었는지 확인
- PNETLab 서버 RAM이 충분한지 확인 (`free -h`)
- `virsh list --all`로 VM 상태 확인

### B.2 OSPF neighbor가 형성되지 않음
- 양쪽 인터페이스가 같은 OSPF area에 속하는지 확인 (`show ip ospf interface`)
- 인터페이스가 shutdown 상태가 아닌지 확인 (`show ip interface brief`)
- PNETLab에서 배선이 올바르게 연결되었는지 확인 (올바른 eX 슬롯)
- `show ip ospf neighbor` 에서 상태가 INIT이면 양방향 통신 문제

### B.3 Cloud0 관리망 연결 실패
- Cloud0가 `pnet0` (Management) 타입인지 확인
- 노드의 `e7`이 Cloud0에 연결되었는지 확인
- PNETLab 호스트에서 `brctl show` 로 브릿지 상태 확인
- 노드에서 `show ip interface GigabitEthernet0/7` 로 IP 할당 확인

### B.4 인터페이스 수 부족 (4개만 보임)
- 노드 생성 시 Ethernet 필드를 **8**로 설정했는지 확인
- 이미 생성된 노드는 삭제 후 재생성 (PNETLab은 인터페이스 수 변경 불가)
- `show ip interface brief`에서 Gi0/7이 보이지 않으면 인터페이스 부족

### B.5 Batfish snapshot 로드 실패
- Batfish Docker 컨테이너 실행 확인: `docker ps | grep batfish`
- configs 디렉토리에 .cfg 파일이 존재하는지 확인
- .cfg 파일명이 hostname과 일치하는지 확인 (예: `P1.cfg`의 `hostname P1`)
