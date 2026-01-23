# Lite-IRON End-to-End 테스트 가이드

## 개요

이 문서는 Lite-IRON 에이전트 아키텍처의 End-to-End 테스트 방법을 설명합니다.

---

## 테스트 구조

```
tests/lite_iron/
├── __init__.py
└── test_lite_iron_e2e.py    # 통합 테스트
```

---

## 사전 준비

### 1. Context 파일 생성 (최초 1회)

```bash
cd NetConfigQA3

# 기존 CFG 파일 사용 (테스트용)
python3 scripts/generate_context.py \
    --use-existing-configs ../Data/Pnetlab/Research_Institute_Internal_DC/configs

# 또는 NSO에서 직접 생성 (실제 운영 시)
python3 scripts/generate_context.py
```

### 2. 환경 확인

```bash
# NSO Docker 실행 여부 확인
docker ps | grep cisco-nso-dev

# 환경변수 확인
cat config/.env | grep NSO
```

---

## 테스트 실행

### 전체 테스트

```bash
cd NetConfigQA3
python3 tests/lite_iron/test_lite_iron_e2e.py
```

### Phase별 테스트

```bash
# Phase 1만 (Context Pipeline)
python3 tests/lite_iron/test_lite_iron_e2e.py --phase 1

# Phase 2만 (Human-in-the-Loop)
python3 tests/lite_iron/test_lite_iron_e2e.py --phase 2

# Phase 3만 (Commit Hook)
python3 tests/lite_iron/test_lite_iron_e2e.py --phase 3
```

### 상세 출력

```bash
python3 tests/lite_iron/test_lite_iron_e2e.py --verbose
```

---

## 테스트 항목

### Phase 1: Context Pipeline

| 테스트 | 설명 |
|--------|------|
| device_summary.json 존재 | Level 1 Summary 파일 확인 |
| device_facts.json 존재 | Level 2 Facts 파일 확인 |
| last_updated 타임스탬프 | 갱신 시간 기록 확인 |
| list_devices() | 장비 목록 조회 |
| search_context() | 장비별 상세 정보 검색 |

### Phase 2: Human-in-the-Loop

| 테스트 | 설명 |
|--------|------|
| ApprovalRequest 생성 | 승인 요청 객체 생성 |
| RiskLevel 평가 | 위험도 자동 평가 |
| CLI 프롬프트 생성 | Approve/Reject/Modify 옵션 |
| EvidencePack 구성 | 증거팩 데이터 수집 |
| RollbackTracker 기록 | Rollback ID 저장 |

### Phase 3: Commit Hook

| 테스트 | 설명 |
|--------|------|
| Hook 상태 조회 | polling_interval, last_check_time |
| Rollback 감지 | NSO rollback 파일 수 확인 |
| State 파일 | .commit_hook_state.json |

---

## 예상 출력

```
======================================================================
  🧪 Lite-IRON End-to-End Test Suite
======================================================================

======================================================================
  Phase 1: Context Pipeline Test
======================================================================

  ✅ PASS: device_summary.json 존재
  ✅ PASS: Summary 장비 수: 10개
  ✅ PASS: device_facts.json 존재 (10개 장비)
  ✅ PASS: list_devices(): 10개
  ✅ PASS: search_context('leaf1', 'interfaces'): 4개 인터페이스

======================================================================
  📊 Test Summary
======================================================================

  Total Tests: 15
  ✅ Passed: 15
  ❌ Failed: 0
  ⚠️  Warnings: 0
  Success Rate: 100.0%

  🎉 All tests passed!
```

---

## 트러블슈팅

### Context 파일 없음

```
❌ FAIL: device_summary.json 없음
```

**해결**: `generate_context.py` 실행

```bash
python3 scripts/generate_context.py --use-existing-configs ../Data/.../configs
```

### NSO Docker 미실행

```
⚠️ WARN: Rollback 감지 불가 - NSO Docker 미실행 가능
```

**해결**: NSO Docker 시작

```bash
docker start cisco-nso-dev
```

### 모듈 Import 오류

```
❌ FAIL: ContextManager 로드 실패
```

**해결**: PYTHONPATH 확인

```bash
cd NetConfigQA3
export PYTHONPATH=$(pwd):$PYTHONPATH
python3 tests/lite_iron/test_lite_iron_e2e.py
```

---

## 다음 단계

테스트 통과 후:

1. **에이전트 실행**: `python3 agent/core.py`
2. **Commit Hook 데몬**: `python3 scripts/nso_commit_hook.py --daemon`
3. **실제 시나리오 테스트**: 에이전트에게 "PE1의 BGP 설정 보여줘" 질문
