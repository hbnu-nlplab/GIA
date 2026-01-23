---
name: core_policy
description: 핵심 행동 규칙 및 안전성 원칙 (항상 적용)
priority: 10
tags:
  - core
  - policy
  - safety
enabled: true
requires_tools:
  - network_query
  - network_verify
  - approval_request
---

# Core Policy Skill

이 스킬은 **항상 적용**되며, 다른 모든 스킬보다 우선합니다.

## 1. Evidence Pack 규칙

### 상한 제한
- **Log Events**: 최대 30개
- **Metric Windows**: 최대 20개  
- **Facts Records**: 최대 40개
- **Batfish Results**: 결과 행 최대 50개

### 금지 행동
- ❌ 전체 테이블 덤프 요청 (예: 모든 장비의 모든 설정 조회)
- ❌ 필터 없는 대량 질의
- ❌ 같은 질의 반복 (캐시 사용 권장)

## 2. 승인 필요 작업

### High-Risk (승인 필수)
- `network_change(action="commit", ...)`
- `network_change(action="rollback", ...)`
- 5대 이상 장비 동시 변경

### Critical (절대 불허)
- ❌ `any-any permit` ACL
- ❌ 무단 default route 추가
- ❌ 전체 BGP clear/reset

### Low-Risk (자동 허용)
- 모든 읽기 질의 (network_query, telemetry_query)
- `network_verify()` (Batfish 분석)
- `lab_manage("show_inventory")` 등 조회 작업

## 3. 변경 작업 워크플로우

```python
# 1. 현재 상태 확인
network_query("device", device="PE1")

# 2. 영향 분석 (Batfish)
network_verify("reachability", {"src": "10.1.1.1", "dst": "10.2.2.2"})

# 3. 시뮬레이션 (dry-run)
network_change(
    action="dry_run",
    device="PE1",
    config_path="interface/GigabitEthernet0/0",
    config_value={"description": "WAN Link"}
)

# 4. 승인 요청
approval_request(
    action_type="commit",
    description="PE1 인터페이스 설명 변경",
    affected_devices=["PE1"],
    risk_assessment="low"
)

# 5. 승인 후 커밋
network_change(
    action="commit",
    device="PE1",
    config_path="interface/GigabitEthernet0/0",
    config_value={"description": "WAN Link"}
)

# 6. 사후 검증
network_verify("reachability", {"src": "10.1.1.1", "dst": "10.2.2.2"})
```

## 4. 오류 처리

- Batfish 미초기화 시: `lab_manage("export_configs", ...)` → `lab_manage("init_batfish", ...)` 순서로 실행
- NSO 연결 실패 시: 환경변수 확인 안내
- 장비 미등록 시: `network_query("device")` 로 목록 확인 안내
