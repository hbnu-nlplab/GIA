---
type: dev-note
date: 2026-01-21
project: LabMate
tags: [note, dev]
---
# LabMate 아키텍처 재정의 — 상세 분석

## 0) 한 단락 요약
LabMate는 SIGCOMM 2026을 목표로 NetConfigQA2.0 데이터셋에서 평가할 네트워크 Q&A 에이전트다. 원래 토폴로지 발견을 위해 UNL 파일 파싱을 계획했으나, **API-First + NSO 중심** 아키텍처로 전환했다. 이제 시스템은 PNETLab API로 실행 중인 노드를 탐색하고, NSO에 자동 등록하며, UNL XML 파싱 대신 CDP/LLDP를 통해 L1 토폴로지를 추출한다. 이 변경으로 v1 구현이 단순해지고, "실제 운영자" 경험에 부합하며, "Self-Driving Network Onboarding"을 연구 기여점으로 삼을 수 있게 되었다. 검증: `docker-compose up`으로 LabMate + Batfish가 `network_mode: host`로 뜨는지 확인. 위험: NSO 장애 시 주 워크플로우가 중단됨 (폴백 존재하나 기능 저하).

## 1) 맥락
- **문제**: 초기 아키텍처가 데이터 소스에 대해 모호했음. "Dual Ingestion (UNL vs Zip)"이 LabMate가 UNL 파일을 직접 파싱해야 하는지 API에 의존해야 하는지 혼란 야기.
- **왜 지금**: MCP 도구 연동(Phase 3) 완료 후, Phase 3.5 (Auto-Onboarding) 구현 전에 데이터 소스 전략 확정 필요.
- **성공 기준**: PNETLab → NSO → Agent로 이어지는 명확하고 문서화된 데이터 흐름, UNL 파싱은 v2로 연기.

## 2) 용어집
- **API-First**: REST API를 통해 모든 데이터를 가져오는 아키텍처 패턴 (파일 파싱 대신)
- **Single Source of Truth (SSOT)**: NSO가 장비 설정의 권위 있는 소스
- **Auto-Onboarding**: 수동 개입 없이 PNETLab에서 NSO로 장비 자동 등록
- **Design-to-Live Sync**: PNETLab(설계)과 NSO(실제)를 비교하고 누락 장비를 자동 등록하는 조정 워크플로우
- **CDP/LLDP**: Cisco Discovery Protocol / Link Layer Discovery Protocol - 물리 네트워크 토폴로지 발견 표준
- **Hybrid Mode**: 옵션 3 - PNETLab API(탐색)와 NSO(설정 소스)를 모두 사용하며 조정 로직 포함

## 3) 전후 비교
- **이전**: 
  - "Dual Ingestion (UNL 우선 + Zip 폴백)"으로 파일 기반 접근 암시
  - UNL XML 파싱을 위한 Collector/Normalizer 컴포넌트
  - NSO의 역할이 모호함 (선택적 vs 주요)
  
- **이후**:
  - "Data Ingestion Strategy (API-First + NSO)" with 명확한 3단계 워크플로우
  - PNETLab API Client + NSO Client (v1에서 파일 파싱 제거)
  - NSO가 SSOT, PNETLab API는 Discovery 전용
  - L1 토폴로지는 CDP/LLDP에서, UNL 아님 (v2에서 UNL 비교 추가 가능)

## 4) 상세 워크스루
1. Docker 스택이 `network_mode: host`로 시작 → LabMate 컨테이너가 `localhost` PNETLab/NSO API 접근 가능
2. Agent가 질문 수신 (예: "R1의 Gi0/1에 연결된 장비는?")
3. **Discovery 단계**: `lab_manage` 도구가 PNETLab API `/api/labs/{lab}/nodes` 호출 → 실행 중인 노드 목록 획득
4. **Reconciliation**: Agent가 `network_query` 도구 호출 → NSO API `/restconf/data/tailf-ncs:devices` → 등록된 장비 획득
5. **Diff 계산**: Agent가 PNETLab 노드 vs NSO 장비 비교 → R2, R3이 NSO에 없음 식별
6. **Auto-Onboarding 결정**: 정책(자동/수동)에 따라 Agent가 등록 여부 결정
7. **등록**: 누락된 각 장비에 대해 Agent가 PNETLab API의 Telnet 포트로 `nso_client.register_device(name, address, port)` 호출
8. **동기화**: Agent가 `nso_client.sync_from(device)` 실행 → NSO가 SSH/NETCONF로 running-config 가져옴
9. **L1 토폴로지 추출**: Agent가 NSO에서 모든 장비의 `show cdp neighbors detail` 실행
10. **토폴로지 생성**: CDP 출력 파싱 → 이웃 관계 추출 → `layer1_topology.json` 생성
11. **Batfish 분석**: 스냅샷(설정 + L1 토폴로지)을 Batfish에 로드
12. **답변 생성**: Batfish에 인터페이스 연결 쿼리 → "R1의 Gi0/1은 R2의 Gi0/0에 연결됨" 답변

## 5) 핵심 의사결정 (대안 포함)
- **결정 1: NSO를 SSOT vs UNL을 SSOT**
  - 선택 이유: 실제 네트워크는 정적 파일이 아닌 NSO를 통해 장비 관리. "Self-Driving Onboarding"의 연구 가치.
  - 고려한 대안: 토폴로지를 위한 UNL 파일 파싱 (옵션 1: File-Centric), 또는 L1 없이 Config만 (이전 계획의 옵션 A)
  - 대안을 선택하지 않은 이유: UNL 파싱은 복잡도만 높이고 실무 적용성 낮음. Config만으로는 L1 질문에 답변 불가.
  
- **결정 2: L1 토폴로지를 CDP/LLDP vs UNL**
  - 선택 이유: 실제 물리 연결 반영, 파일 마운트 불필요, 기존 NSO 기능 활용
  - 고려한 대안: UNL XML `<network>` 태그 파싱으로 케이블 정의 획득
  - 대안을 선택하지 않은 이유: UNL은 "설계 의도"를 나타내고, CDP/LLDP는 "실제 구성"을 나타냄. Q&A에서는 실제 상태가 더 가치 있음. 또한 v2에서 양쪽 비교 가능.
  
- **결정 3: Host Network vs Bridge Network**
  - 선택 이유: localhost 서비스 접근의 가장 간단한 방법 (PNETLab :80, NSO :8080)
  - 고려한 대안: `extra_hosts: host.docker.internal` 사용한 Bridge 네트워크
  - 대안을 선택하지 않은 이유: `host.docker.internal`은 Linux 특화 우회책, `network_mode: host`가 더 직접적.

## 6) 가정 / 전제조건
- PNETLab이 동일한 Docker 호스트에서 실행 중
- NSO가 동일한 Docker 호스트에서 실행 중 (또는 localhost로 접근 가능)
- PNETLab의 모든 네트워크 장비가 CDP 또는 LLDP 지원
- NSO에 장비 유형별 적절한 NED (Network Element Driver) 패키지 설치됨 (예: `cisco-ios-cli-6.x`)
- PNETLab API가 인증 불필요하거나 `.env`에 인증 정보 존재
- NSO RESTCONF API가 포트 8080에서 활성화됨

## 7) 실패 모드 / 주의사항
- **NSO 접근 불가**: 주 워크플로우 중단. "Export CFG" (zip 다운로드) 폴백 존재하지만 L1 토폴로지 및 자동 등록 기능 상실.
- **장비가 CDP/LLDP 미지원**: L1 토폴로지가 불완전함. v1에서 완화책 없음.
- **PNETLab API 변경**: 감지 어려움, 조용한 실패 유발. 버전 관리/계약 테스트 필요.
- **NED 불일치**: 장비 유형(예: IOS-XE 17.x)이 설치된 NED 버전과 맞지 않으면 `sync-from` 실패.
- **Telnet vs SSH 포트 혼동**: PNETLab API는 Telnet 포트 반환(콘솔 접근용), NSO는 SSH 포트 필요(NETCONF/CLI용). 매핑 필요.

## 8) 재현 / 검증 (미래 보장)
**단계**:
1. 2개 이상 Cisco 장비가 포함된 랩으로 PNETLab 실행 중 확인
2. `cisco-ios-cli` NED 설치된 NSO 실행 중 확인
3. `.env`에 환경 변수 설정:
   ```
   NSO_BASE_URL=http://localhost:8080/restconf
   PNETLAB_URL=http://localhost
   ```
4. LabMate 스택 시작: `docker-compose up -d`
5. 컨테이너 접속: `docker exec -it labmate_labmate_1 bash`
6. PNETLab API 테스트: `curl http://localhost/api/labs`
7. NSO API 테스트: `curl -u admin:admin http://localhost:8080/restconf/data/tailf-ncs:devices`
8. Python 테스트 실행:
   ```python
   from agent.tools import get_tools
   tools = get_tools()
   print([t.name for t in tools])  # 출력 예상: network_query, network_verify, lab_manage
   ```

**예상 출력**:
- PNETLab API가 `{"status": "success", "data": {...}}` JSON 반환
- NSO API가 장비 목록 반환 (처음엔 비어있을 수 있음)
- 도구가 에러 없이 로드됨

## 9) 증거
- `architecture.md` 재작성 (208줄 → 더 명확한 구조)
- `docker-compose.yml` 업데이트 (`network_mode: host` 및 Batfish 서비스)
- Phase 3 검증 통과: `Batfish Available: True`
- `task.md` Phase 3.5 작업으로 업데이트됨

## 10) 미해결 질문
- **Q1**: Telnet 전용 장비(오래된 랩 장비)는 어떻게 처리? NSO는 보통 SSH 필요.
  - 잠재적 답변: NSO의 serial/console NED 사용, 또는 v1에서 해당 장비 건너뜀.
- **Q2**: 반복적인 API 호출을 피하기 위해 PNETLab 노드 목록을 캐시해야 하나?
  - 잠재적 답변: 예, TTL 적용(예: 60초)하여 신선도와 성능 균형.
- **Q3**: PNETLab과 NSO가 장비 이름에 동의하지 않으면? (예: PNETLab "R1", NSO "router1")
  - 잠재적 답변: 노드 ID가 아닌 hostname을 매칭 키로 사용 (장비 설정에서 가져옴).

## 11) 다음 작업
- [ ] `agent/tools.py`에 `scan_and_sync` 액션 구현
- [ ] PNETLab→NSO 장비 매핑 유닛 테스트 작성
- [ ] CDP/LLDP 파서 작성 (NSO 출력 → Batfish `layer1_topology.json`)
- [ ] E2E 테스트: PNETLab 랩 시작, agent 실행, NSO가 장비 자동 등록하는지 검증
- [ ] 의존하는 PNETLab API 엔드포인트 문서화 (향후 API 변경 대비)
