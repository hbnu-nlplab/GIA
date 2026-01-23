# NetConfigQA3 로드맵

> **자동화된 네트워크 운영 에이전트를 향한 여정**

---

## 🎯 프로젝트 목표

**SIGCOMM 2026 논문 제출**: Task-based Network Operation Agent Benchmark

---

## 📅 Phase 1: PNETLab 연동 ✅ (완료 - 2026-01-08)

### 달성 내용

#### 1.1 PNETLab API 클라이언트

- ✅ JWT 토큰 인증 (3-cookie 방식)
- ✅ Topology 조회 API
- ✅ Node Status API
- ✅ Console Link API (Guacamole)
- ✅ Node 제어 API (start/stop)

#### 1.2 Inventory Builder

- ✅ PNETLab Topology → device_info.json 변환
- ✅ Lab 이름 자동 추출 (`labinfo['name']`)
- ✅ Telnet 포트 자동 추출 (Base64 디코딩)
- ✅ OOB IP 자동 할당 (10.10.10.0/24)
- ✅ Device Group 자동 설정

#### 1.3 사용자 경험 개선

- ✅ 쿠키 설정 간소화 (3줄 → 1줄)
- ✅ `PNETLAB_COOKIES` 환경변수 지원
- ✅ 명확한 로깅 및 디버깅
- ✅ JavaScript 쿠키 추출 도구

### 성과

- **완전 자동화**: 수동 설정 최소화
- **사용자 친화적**: 10초 만에 설정 완료
- **안정성**: 에러 핸들링 및 로깅

---

## ✅ Phase 2: NSO 자동 등록 (완료 - 2026-01-12)

### 목표

PNETLab 장비를 NSO에 자동으로 등록하여 중앙 관리 가능하도록 함

### 2.1 Day0 설정 자동화 ✅

**기존 스크립트**: `Make_Dataset/src/1-SSH_Enable.py`

**개선 완료**:

- ✅ Telnet 연결 자동화 (telnetlib3)
- ✅ SSH 설정 스크립트 실행
  - `conf t`
  - `hostname {device_name}`
  - `ip domain-name mylab.local`
  - `crypto key generate rsa modulus 2048`
  - `username admin privilege 15 secret admin`
  - `line vty 0 4`
  - `transport input ssh`
  - OOB 인터페이스 IP 설정
- ✅ 여러 장비 병렬 처리 (asyncio.gather)
- ✅ 진행 상황 표시 (구조화된 로깅)
- ✅ 에러 복구 로직 (재시도 메커니즘)

### 2.2 NSO 등록 자동화 ✅

**기존 스크립트**: `Make_Dataset/src/2-NSO_Register.py`

**개선 완료**:

- ✅ `device_info.json` 읽기
- ✅ NSO RESTCONF API 사용
  - Device 추가 (`PATCH /tailf-ncs:devices/device`)
  - Authgroup 설정
  - Device Type 및 NED 설정
  - SSH 알고리즘 설정
  - Device Group 설정
- ✅ SSH 호스트 키 가져오기 (`fetch-host-keys`)
- ✅ sync-from 실행
- ✅ 연결 테스트 (`check-sync`)
- ✅ 실패 시 재시도 로직

### 2.3 통합 워크플로우 ✅

**구현 완료**: `NetConfigQA3/automation/onboard.py`

```python
async def auto_onboard_lab(
    pnetlab_client,
    nso_client,
    lab_name: Optional[str] = None,
    skip_ssh: bool = False
) -> Dict[str, Any]:
    """PNETLab Lab을 NSO에 자동 등록"""
    # 1. Topology 조회
    topology = pnetlab_client.get_session_topology()

    # 2. Inventory 생성
    inventory = build_inventory_from_pnetlab(topology, lab_name)

    # 3. SSH 설정 (Day0) - 병렬 처리
    if not skip_ssh:
        ssh_enabler = SSHEnabler(inventory)
        ssh_results = await ssh_enabler.configure_all_devices()

    # 4. NSO 등록
    nso_onboarder = NSOOnboarder(inventory, nso_client)
    nso_results = nso_onboarder.register_all_devices()

    # 5. 검증
    verify_results = nso_onboarder.verify_all()

    return {
        "status": "completed",
        "ssh_results": ssh_results,
        "nso_results": nso_results,
        "verify_results": verify_results
    }
```

**사용법**:

```bash
python test_auto_onboard.py
```

### 실제 소요 시간

- **구현**: 3.5시간
- **테스트**: 진행 중

---

## ✅ Phase 3: MCP 아키텍처 및 통합 도구 (완료 - 2026-01-12)

### 목표

LLM 컨텍스트 효율을 극대화하고 독립적인 기능 확장이 가능한 MCP 기반 통합 도구 아키텍처 구축

### 3.1 MCP 서버 분리 ✅

- ✅ **NSO MCP 서버**: RESTCONF 래핑 및 Batfish용 cfg 추출 기능 통합
- ✅ **Batfish MCP 서버**: 기존 분석 엔진을 MCP 도구로 래핑 (Reachability, Traceroute 등)
- ✅ **PNETLab MCP 서버**: 실험실 자원 관리 및 상태 조회
- ✅ **Telemetry MCP 서버**: 로그/메트릭 조회를 위한 인터페이스 (Stub)

### 3.2 하이브리드 YANG 전략 ✅ (2026-01-12 완료)

**문제**: Batfish는 Native CLI, LLM은 YANG JSON, 연구는 표준 기반 확장성 필요

**해결**: 3가지 형식 동시 추출

```
NSO CDB → CLI 명령 → Native CLI (1.5 KB) → Batfish 자동 채점
       → XML 명령 → XML (5.8 KB)        → 레거시 호환
       → RESTCONF → YANG JSON (7.8 KB)  → LLM 쿼리 + Facts DB
```

**구현 세부사항**:

- ✅ NSO CDB 기반 추출 (live-status 대신) - 70% 시간 단축
- ✅ Docker CLI heredoc 방식으로 파이프 충돌 해결
- ✅ 인코딩 다중 시도 (UTF-8 → CP949 → ignore)
- ✅ Banner/프롬프트 자동 정제
- ✅ 20개 장비 × 3개 형식 = 60개 파일 (100% 성공률)

**연구 기여**:

- ✅ Batfish Verifier 자동 채점 준비 완료
- ✅ LLM Facts DB 구축 소스 확보
- ✅ 재현 가능한 스냅샷 기반 실험 환경

**참고 문서**: `Netconfiga3_docs/YANG_Hybrid_Strategy.md` (논문 작성용 상세 기록)

### 3.2 통합 도구 (7개 고정) ✅

- ✅ **Context 효율화**: 도구 스키마 토큰 53% 절감 (~3,000 → ~1,400)
- ✅ **라우팅 레이어**: `unified_tools.py`를 통해 요청을 적절한 MCP 서버로 전달
- ✅ **TDD 검증**: 104개 단위 테스트를 통한 안정성 확보

### 3.3 Ablation Study 및 설정 ✅

- ✅ **ToolConfig**: 11개 프리셋 (`full`, `no_batfish`, `eval_mode` 등) 지원
- ✅ **ToolProvider**: 에이전트에 필요한 도구만 동적으로 공급하는 인터페이스

---

## 🚧 Phase 4: LangGraph 기반 자율 운영 에이전트

### 목표

통합 도구를 사용하여 네트워크 장애를 스스로 진단하고 복구하는 에이전트 구현

### 4.1 Skills 모듈화 및 동적 로딩 (진행 중)

- [ ] **Core Policy**: 효율성, 예산, 금지 행동 수칙 정의
- [ ] **Runbook Skills**: 장애 진단 및 설정 변경 표준 절차 정의
- [ ] **Dynamic Loader**: 태스크에 필요한 스킬만 시스템 프롬프트에 주입

### 4.2 자율 진단 및 복구 루프

- [ ] **Diagnosis Node**: `telemetry.query` 및 `network.verify` 기반 원인 분석
- [ ] **Plan Node**: 수정안 작성 및 `network.change("dry_run")` 검증
- [ ] **Approval Gate**: `approval.request`를 통한 사용자 승인 인터페이스
- [ ] **Recovery Node**: `commit` 실행 및 최종 검증

### 4.3 E2E 벤치마크 환경 구축

- [ ] **Scenarios**: 도달성 장애, BGP 플래핑, ACL 오설정 등 고장 시나리오 라이브러리
- [ ] **Evaluator**: 정답지 기반의 Correctness, Safety, Efficiency 평가 엔진

---

## 🔮 Phase 5: 고급 기능 및 논문 준비 (2026-03 ~)

### 5.1 시각화 및 UI

- [ ] **Web UI**: 에이전트 추론 과정 및 네트워크 상태 실시간 대시보드
- [ ] **Diagram Sync**: NSO/Batfish 데이터를 활용한 네트워크 토폴로지 자동 시각화

### 5.2 다중 Lab 및 리소스 관리

- [ ] **IPAM**: 여러 Lab 간 IP 충돌 방지 및 자동 서브넷 할당
- [ ] **Multi-Lab Orchestrator**: 여러 실험실 환경의 병렬 관리

---

## 📊 마일스톤

| Phase         | 목표             | 예상 완료      | 상태       |
| ------------- | ---------------- | -------------- | ---------- |
| Phase 1       | PNETLab 연동     | 2026-01-08     | ✅ 완료    |
| Phase 2       | NSO 자동 등록    | 2026-01-12     | ✅ 완료    |
| Phase 3       | MCP & 통합 도구  | 2026-01-15     | ✅ 완료    |
| Phase 4       | 에이전트 고도화  | 2026-02-15     | 🚧 진행 중 |
| Phase 5       | 벤치마크 및 논문 | 2026-04-15     | 📝 계획    |
| **논문 제출** | **SIGCOMM 2026** | **2026-04-15** | 🎯 목표    |

---

## 🔥 우선순위

### 높음 (지금 당장)

1. ✅ PNETLab 연동
2. ✅ NSO 자동 등록
3. 🚧 Agent 통합

### 중간 (2-4주 후)

4. E2E 테스트
5. 성능 최적화

### 낮음 (필요 시)

6. 다중 Lab
7. IPAM
8. Batfish
9. 웹 UI

---

## 💡 아이디어 백로그

### 추가 기능

- [ ] Lab 템플릿 시스템
- [ ] 설정 백업/복원
- [ ] 네트워크 다이어그램 자동 생성
- [ ] 성능 모니터링 (CPU, 메모리)
- [ ] 이벤트 알림 (Slack, Email)
- [ ] CLI 인터페이스 (`netconfigqa lab sync`)

### 최적화

- [ ] 병렬 처리 (asyncio)
- [ ] 캐싱 (토폴로지, 장비 정보)
- [ ] 연결 풀링
- [ ] 재시도 로직 개선

### 개발자 경험

- [ ] 단위 테스트
- [ ] 통합 테스트
- [ ] CI/CD 파이프라인
- [ ] 코드 품질 도구 (pylint, mypy)
- [ ] 문서 자동 생성 (Sphinx)

---

## 📚 참고 자료

### PNETLab

- [PNETLab 공식 사이트](https://pnetlab.com/)
- [PNETLab 커뮤니티](https://community.pnetlab.com/)

### Cisco NSO

- [NSO Developer Hub](https://developer.cisco.com/site/nso/)
- [NSO Documentation](https://www.cisco.com/c/en/us/support/cloud-systems-management/network-services-orchestrator/tsd-products-support-series-home.html)

### LangGraph

- [LangGraph Documentation](https://langchain-ai.github.io/langgraph/)
- [LangGraph Examples](https://github.com/langchain-ai/langgraph/tree/main/examples)

---

**Last Updated**: 2026-01-12
**Next Review**: 2026-01-20

---

**Legend**:

- ✅ 완료
- 🚧 진행 중
- 📝 계획됨
- 🔮 미래 계획
- ⏸️ 보류
- ❌ 취소
