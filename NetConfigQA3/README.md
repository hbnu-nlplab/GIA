# NetConfigQA3 - PNETLab & NSO AI 통합 운영 시스템

> **PNETLab 실험실 환경을 NSO 및 Batfish와 자동 연동하는 AI 기반 네트워크 운영 프레임워크**

---

## 🎯 개요

NetConfigQA3는 PNETLab/EVE-NG 네트워크 실험실 환경을 Cisco NSO(Network Services Orchestrator) 및 Batfish와 자동으로 연동하여, 네트워크 장비 관리, 검증 및 설정을 자동화하는 시스템입니다. MCP(Model Context Protocol) 기반 아키텍처를 도입하여 LLM 에이전트가 효율적으로 네트워크를 관리할 수 있도록 설계되었습니다.

### 주요 기능

- ✅ **PNETLab API 완전 연동**: JWT 토큰 인증, 토폴로지 조회, 노드 제어
- ✅ **NSO 자동 등록**: SSH 설정 → NSO 등록 → sync-from 자동화
- ✅ **MCP 기반 아키텍처**: NSO, Batfish, PNETLab 서버를 독립적인 MCP 서버로 분리
- ✅ **통합 도구(7개) 시스템**: LLM 컨텍스트 효율을 극대화한 고정 도구 셋
- ✅ **네트워크 검증 (Batfish)**: 도달성, 경로 추적, BGP 세션 검증 자동화
- ✅ **Ablation Study 지원**: 11개 프리셋으로 컴포넌트별 효과 측정 지원
- ✅ **하이브리드 YANG 전략**: Native CLI + YANG JSON 동시 추출 (Batfish + LLM 통합)
- 🚧 **LangGraph Agent**: 자연어로 네트워크 운영 및 장애 대응 (진행 중)

---

## 🚀 빠른 시작

### 1. 의존성 설치

```bash
pip install -r requirements.txt
```

### 2. 환경 설정

```bash
# .env 파일 생성
cd NetConfigQA3/config
copy env_example.txt .env
```

### 3. PNETLab 쿠키 및 NSO 설정
`.env` 파일에 PNETLab 쿠키 문자열과 NSO 접속 정보를 입력합니다. (F12 → Network 탭에서 Cookie 복사)

### 4. 테스트 실행 (TDD 검증) 🎉

```bash
cd NetConfigQA3
python -m pytest tests/
```

**결과**: 100개 이상의 단위 테스트가 MCP 서버와 통합 도구의 정상 작동을 검증합니다.

---

## 📁 폴더 구조

```
NetConfigQA3/
├── mcp_servers/                # MCP 서버 (NSO, Batfish, PNETLab, Telemetry)
├── agent/                      # 에이전트 로직 및 통합 도구
│   ├── unified_tools.py        # 7개 통합 도구 정의
│   └── core.py                 # LangGraph 에이전트 (진행 중)
├── clients/                    # 하위 레벨 API 클라이언트 (NSO, PNETLab)
├── inventory/                  # 인벤토리 자동 생성
├── automation/                 # 자동 온보딩 워크플로우
├── config/                     # 설정 및 ToolConfig (Ablation 지원)
├── tests/                      # 100+ 단위 테스트 (pytest)
├── docs/                       # 시스템 설계 및 API 문서
└── requirements.txt
```

---

## 🛠️ 통합 도구 시스템 (Unified Tools)

LLM에게 노출되는 도구를 7개로 고정하여 컨텍스트 토큰을 50% 이상 절감합니다.

1. **`network_query`**: NSO 기반 설정 조회 (BGP, OSPF, Interface, VRF 등)
2. **`network_verify`**: Batfish 기반 네트워크 검증 (Reachability, Traceroute, BGP Session)
3. **`network_change`**: NSO 기반 설정 변경 (Dry-run, Commit, Rollback)
4. **`telemetry_query`**: 로그 및 메트릭 조회 (Stub 구현)
5. **`lab_manage`**: PNETLab 제어, Batfish용 설정 추출 및 스냅샷 초기화
6. **`approval_request`**: 위험 작업(Commit/Rollback) 승인 요청
7. **`help_guide`**: 도구 사용법 및 예시 안내

---

## 🔑 Ablation Study 프리셋

`config/tool_config.py`를 통해 실험 환경을 즉시 전환할 수 있습니다.
- `full`: 모든 기능 활성화
- `no_batfish`: Batfish 검증 도구 비활성화
- `no_cache`: 쿼리 캐시 비활성화
- `eval_mode`: Lab 관리 기능이 제한된 평가 모드

---

## 📊 워크플로우

```
1. PNETLab Lab 열기 및 쿠키 설정
   ↓
2. python test_auto_onboard.py (자동 온보딩)
   ↓
3. 통합 도구를 통한 운영 및 검증:
   - lab_manage("export_configs") → Batfish용 설정 추출
   - network_verify("reachability") → 장애 진단
   - network_change("dry_run") → 수정안 검증
   ↓
4. Agent를 통한 자연어 제어 (Phase 4 진행 중)
```

---

## 🎨 하이브리드 YANG 전략 (Phase 3 완료)

NetConfigQA3는 **3가지 형식을 동시 추출**하여 연구와 운영을 모두 지원합니다:

```
NSO CDB (저장소)
    ↓
├─> configs/      Native CLI (Cisco IOS)  → Batfish 자동 채점
├─> xml/          XML                     → 레거시 호환성
└─> yang/         YANG JSON               → LLM 실시간 쿼리 + Facts DB
```

### 핵심 기술

1. **NSO CDB 기반 안정적 추출**
   - live-status (실시간 SSH) 대신 CDB (저장소) 사용
   - 타임아웃 없음, 70% 시간 단축
   - 재현 가능한 스냅샷 기반 실험

2. **3가지 형식 동시 지원**
   ```bash
   # 20개 장비 × 3개 형식 = 60개 파일 (100% 성공률)
   python test_mcp_runtime.py
   
   # 결과:
   # - Native CLI: 1.5 KB/장비 (Batfish 입력)
   # - XML:        5.8 KB/장비 (레거시)
   # - YANG JSON:  7.8 KB/장비 (LLM 쿼리)
   ```

3. **연구 설계 요구사항 100% 충족**
   - ✅ Batfish Verifier 자동 채점 (Experimental_design.md)
   - ✅ Facts DB 구축 준비 (Netconfiga3_system.md)
   - ✅ 운영 안전성 확보 (Human_Approved.md)

### 상세 문서
📄 [YANG_Hybrid_Strategy.md](Netconfiga3_docs/YANG_Hybrid_Strategy.md) - 전체 구현 과정 및 논문 작성 가이드

---

## 🗺️ 로드맵

- **Phase 1**: PNETLab 연동 및 자동 인벤토리 ✅ 완료
- **Phase 2**: NSO 자동 등록 및 SSH 활성화 ✅ 완료
- **Phase 3**: MCP 아키텍처 + 하이브리드 YANG 전략 ✅ 완료
- **Phase 4**: LangGraph 기반 자율 운영 에이전트 🚧 진행 중
- **Phase 5**: SIGCOMM 2026 논문 제출을 위한 벤치마크 📅 계획

---

## 👤 작성자

**Yujin**
- 목표: SIGCOMM 2026 논문 제출
- 프로젝트: NetConfigQA3 - Task-based Network Operation Agent Benchmark

---

**Last Updated**: 2026-01-12
**Version**: 3.0.0 (MCP & Unified Tools 구현 완료)
