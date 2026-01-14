# 테스트 모음 및 자동화 가이드 (Test Suite & Automation Guide)

이 문서는 `tests/` 디렉토리에 위치한 테스트 및 자동화 스크립트의 구조와 사용법을 설명합니다.

## 디렉토리 구조

`tests/` 디렉토리는 네 가지 주요 카테고리로 구성되어 있습니다:

```text
tests/
├── integration/      # 통합 검증 테스트 (파일명: verify_*.py)
├── scripts/          # 운영 및 유지보수 스크립트 (파일명: 동사_*.py)
├── unit/             # 컴포넌트 단위 테스트 (파일명: unit_test_*.py)
└── legacy/           # 구형/아카이브된 자동화 스크립트
```

---

## 1. 통합 테스트 (`tests/integration/`)

이 스크립트들은 NSO, PNETLab 및 Agent 통합을 포함한 시스템의 End-to-End 기능을 검증합니다. 목적을 명확히 하기 위해 `verify_` 접두사를 사용합니다.

| 스크립트 이름 | 설명 |
| :--- | :--- |
| **`verify_nso_device_sync_status.py`** | 등록된 PNETLab 장비들이 지정된 NSO 인스턴스와 올바르게 동기화되었는지 확인합니다. |
| **`verify_pnetlab_api_connectivity.py`** | PNETLab 서버에 대한 인증 및 API 연결성을 검증하고 랩 토폴로지를 조회합니다. |
| **`verify_automated_device_onboarding.py`** | 신규 장비 온보딩의 전체 워크플로우(등록 -> 키 가져오기 -> 동기화)를 테스트합니다. |
| **`verify_nso_server_initialization.py`** | NSO 서버가 접근 가능하고 올바르게 초기화되었는지(RESTCONF API 체크) 검증합니다. |
| **`verify_inventory_builder_logic.py`** | PNETLab 토폴로지 데이터로부터 동적 인벤토리를 생성하는 로직을 테스트합니다. |
| **`verify_agent_capabilities.py`** | Agent가 정의된 도구/함수를 성공적으로 호출할 수 있는지 검증합니다. |
| **`verify_mcp_server_runtime.py`** | MCP(Model Context Protocol) 서버가 올바르게 시작되고 도구를 등록하는지 확인합니다. |
| **`verify_langsmith_integration.py`** | 관측성을 위해 트레이스와 로그가 LangSmith로 올바르게 전송되는지 검증합니다. |

### 사용 예시
```bash
# NSO 동기화 상태 검증
python3 tests/integration/verify_nso_device_sync_status.py
```

---

## 2. 유지보수 스크립트 (`tests/scripts/`)

이 유틸리티 스크립트들은 운영 작업, 문제 해결 또는 시스템 상태 감사를 위해 사용됩니다.

| 스크립트 이름 | 설명 |
| :--- | :--- |
| **`repair_nso_device_registration.py`** | **핵심 도구**. NSO 장비 등록 복구를 자동화합니다. 기존 항목을 삭제하고, 올바른 PNETLab Telnet 포트로 재등록한 후 동기화를 시도합니다. |
| **`audit_nso_ned_packages.py`** | NSO에 설치된 NED(Network Element Driver) 패키지 상태가 'up'이고 정상 작동 중인지 확인합니다. |
| **`maintenance_reload_nso_packages.py`** | NSO 패키지를 강제로 다시 로드합니다. 설치 후 NED가 멈추거나 보이지 않을 때 유용합니다. |
| **`util_get_pnetlab_auth_cookies.js`** | 브라우저 세션에서 PNETLab 인증 쿠키를 추출하는 JavaScript 헬퍼입니다 (수동 토큰 업데이트 필요 시). |

### 사용 예시
```bash
# NSO 등록 복구 (동기화 실패 시 실행)
python3 tests/scripts/repair_nso_device_registration.py
```

---

## 3. 단위 테스트 (`tests/unit/`)

이 테스트들은 주로 MCP 서버와 SDK 로직에 초점을 맞추어 개별 컴포넌트(클래스 및 메서드)를 격리된 상태에서 검증합니다.

- `unit_test_nso_server_logic.py`: `NSOServer` 클래스 메서드 테스트
- `unit_test_pnetlab_server_logic.py`: `PnetlabServer` 클래스 메서드 테스트
- `unit_test_unified_sdk_tools.py`: 통합 SDK를 감싸는 래퍼 로직 테스트

---

## 4. 레거시 스크립트 (`tests/legacy/`)

통합 SDK (`clients/nso.py`)에 의해 대체된 구형 자동화 스크립트들(`ssh_enabler.py`, `onboard.py` 등)을 포함합니다. 참고용으로 보존되지만, 실제 개발에는 사용하지 않는 것이 좋습니다.
