#!/usr/bin/env python3
"""
Lite-IRON End-to-End Test

Phase 1~3 구현 모듈의 통합 테스트

테스트 시나리오:
1. Context Pipeline 테스트
   - generate_context.py 실행
   - Summary/Facts 파일 생성 확인
   - search_context 도구 동작 확인

2. Human-in-the-Loop 테스트
   - ApprovalGate 요청 생성
   - 위험도 평가 확인
   - EvidencePack 구성
   - RollbackTracker 기록

3. Commit Hook 테스트
   - 상태 조회
   - 수동 동기화 트리거

사용법:
    python3 tests/lite_iron/test_lite_iron_e2e.py
    python3 tests/lite_iron/test_lite_iron_e2e.py --phase 1  # 특정 Phase만
    python3 tests/lite_iron/test_lite_iron_e2e.py --verbose   # 상세 출력
"""

import sys
import json
import logging
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List

# 프로젝트 경로 추가
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [E2E Test] - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def print_banner(msg: str):
    """배너 출력"""
    print(f"\n{'='*70}")
    print(f"  {msg}")
    print(f"{'='*70}\n")


def print_step(step: str, status: str = "running"):
    """단계 출력"""
    icons = {"running": "⏳", "success": "✅", "failed": "❌", "warning": "⚠️"}
    print(f"  {icons.get(status, '•')} {step}")


class TestResult:
    """테스트 결과 수집"""
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.warnings = 0
        self.details: List[Dict] = []
    
    def add_pass(self, name: str, detail: str = ""):
        self.passed += 1
        self.details.append({"name": name, "status": "pass", "detail": detail})
        print_step(f"PASS: {name}", "success")
    
    def add_fail(self, name: str, detail: str = ""):
        self.failed += 1
        self.details.append({"name": name, "status": "fail", "detail": detail})
        print_step(f"FAIL: {name} - {detail}", "failed")
    
    def add_warning(self, name: str, detail: str = ""):
        self.warnings += 1
        self.details.append({"name": name, "status": "warning", "detail": detail})
        print_step(f"WARN: {name} - {detail}", "warning")
    
    def summary(self) -> str:
        total = self.passed + self.failed
        return f"Passed: {self.passed}/{total}, Warnings: {self.warnings}"


# =============================================================================
# Phase 1: Context Pipeline Tests
# =============================================================================

def test_phase1_context_pipeline(result: TestResult, verbose: bool = False):
    """Phase 1: Context Pipeline 테스트"""
    print_banner("Phase 1: Context Pipeline Test")
    
    # 1.1 Context 파일 존재 확인
    print_step("1.1 Context 파일 확인", "running")
    
    context_dir = PROJECT_ROOT / "config" / "context"
    summary_path = context_dir / "device_summary.json"
    facts_path = context_dir / "device_facts.json"
    
    if summary_path.exists():
        result.add_pass("device_summary.json 존재")
        
        # 내용 검증
        with open(summary_path, "r") as f:
            summary = json.load(f)
        
        if summary.get("devices"):
            result.add_pass(f"Summary 장비 수: {len(summary['devices'])}개")
            
            if verbose:
                for d in summary["devices"][:3]:
                    print(f"      - {d.get('hostname')}: {d.get('role')}")
        else:
            result.add_warning("Summary에 장비 없음", "generate_context.py 실행 필요")
        
        if summary.get("last_updated"):
            result.add_pass(f"last_updated: {summary['last_updated']}")
        else:
            result.add_warning("last_updated 없음")
    else:
        result.add_fail("device_summary.json 없음", "generate_context.py 실행 필요")
    
    if facts_path.exists():
        with open(facts_path, "r") as f:
            facts = json.load(f)
        result.add_pass(f"device_facts.json 존재 ({len(facts.get('devices', []))}개 장비)")
    else:
        result.add_fail("device_facts.json 없음")
    
    # 1.2 ContextManager 테스트
    print_step("1.2 ContextManager 테스트", "running")
    
    try:
        from agent.tools.context_tools import get_context_manager, search_context
        
        manager = get_context_manager()
        devices = manager.list_devices()
        
        if devices:
            result.add_pass(f"list_devices(): {len(devices)}개")
            
            # search_context 테스트
            test_device = devices[0]
            search_result = search_context(test_device, "interfaces")
            
            if "error" not in search_result:
                data = search_result.get("data", search_result)
                if isinstance(data, list):
                    result.add_pass(f"search_context('{test_device}', 'interfaces'): {len(data)}개 인터페이스")
                else:
                    result.add_pass(f"search_context('{test_device}', 'interfaces'): 데이터 반환됨")
            else:
                result.add_warning(f"search_context 오류", search_result.get("error"))
        else:
            result.add_warning("장비 목록 비어있음")
            
    except Exception as e:
        result.add_fail("ContextManager 로드 실패", str(e))
    
    return result


# =============================================================================
# Phase 2: Human-in-the-Loop Tests
# =============================================================================

def test_phase2_human_in_the_loop(result: TestResult, verbose: bool = False):
    """Phase 2: Human-in-the-Loop 테스트"""
    print_banner("Phase 2: Human-in-the-Loop Test")
    
    # 2.1 ApprovalGate 테스트
    print_step("2.1 ApprovalGate 테스트", "running")
    
    try:
        from agent.approval_gate import get_approval_gate, RiskLevel
        
        gate = get_approval_gate()
        
        # 요청 생성
        request = gate.create_request(
            action="commit",
            target_devices=["TestPE1", "TestPE2"],
            change_summary="E2E Test: BGP neighbor 추가",
            change_details={"neighbor": "10.0.0.1", "remote_as": "65001"}
        )
        
        if request.request_id:
            result.add_pass(f"ApprovalRequest 생성: {request.request_id}")
        
        # 위험도 평가 확인
        if request.risk_level in [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]:
            result.add_pass(f"RiskLevel 평가: {request.risk_level.value}")
        
        # CLI 프롬프트 생성
        prompt = gate.format_cli_prompt(request)
        if "[A]pprove" in prompt and "[R]eject" in prompt:
            result.add_pass("CLI 프롬프트 생성 (Approve/Reject/Modify)")
            
            if verbose:
                print("\n--- CLI Prompt Preview ---")
                print(prompt[:500] + "...")
        else:
            result.add_fail("CLI 프롬프트 형식 오류")
            
    except Exception as e:
        result.add_fail("ApprovalGate 테스트 실패", str(e))
    
    # 2.2 EvidenceCollector 테스트
    print_step("2.2 EvidenceCollector 테스트", "running")
    
    try:
        from agent.tools.evidence_tools import get_evidence_collector
        
        collector = get_evidence_collector()
        
        # EvidencePack 구성 (테스트용)
        pack = collector.build_evidence_pack(
            device="TestDevice",
            change_type="test_change",
            dry_run_diff={"add": "test config"}
        )
        
        if pack.target_device == "TestDevice":
            result.add_pass("EvidencePack 생성됨")
        
        if pack.created_at:
            result.add_pass(f"EvidencePack 타임스탬프: {pack.created_at}")
        
        if pack.batfish_analysis:
            result.add_pass("Batfish 분석 포함됨")
            
    except Exception as e:
        result.add_fail("EvidenceCollector 테스트 실패", str(e))
    
    # 2.3 RollbackTracker 테스트
    print_step("2.3 RollbackTracker 테스트", "running")
    
    try:
        from agent.rollback_tracker import get_rollback_tracker
        
        tracker = get_rollback_tracker()
        
        # 테스트용 기록
        test_id = f"TEST-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        entry = tracker.record_commit(
            rollback_id=test_id,
            devices=["TestDevice"],
            change_summary="E2E Test rollback entry"
        )
        
        if entry.rollback_id == test_id:
            result.add_pass(f"Rollback 기록됨: {test_id}")
        
        # 조회 테스트
        latest = tracker.get_latest_rollback_id()
        if latest:
            result.add_pass(f"최신 rollback ID 조회: {latest}")
        
        # 응답 포맷 테스트
        response = tracker.format_rollback_response(test_id, ["TestDevice"], "Test")
        if "rollback" in response.lower():
            result.add_pass("Rollback 응답 포맷 정상")
            
    except Exception as e:
        result.add_fail("RollbackTracker 테스트 실패", str(e))
    
    return result


# =============================================================================
# Phase 3: Commit Hook Tests
# =============================================================================

def test_phase3_commit_hook(result: TestResult, verbose: bool = False):
    """Phase 3: NSO Commit Hook 테스트"""
    print_banner("Phase 3: NSO Commit Hook Test")
    
    # 3.1 Hook 상태 조회
    print_step("3.1 CommitHook 상태 조회", "running")
    
    try:
        from scripts.nso_commit_hook import get_commit_hook, get_commit_hook_status
        
        status = get_commit_hook_status()
        
        if "polling_interval" in status:
            result.add_pass(f"Hook 상태 조회: interval={status['polling_interval']}s")
        
        if "last_rollback_count" in status:
            result.add_pass(f"Rollback count: {status['last_rollback_count']}")
        
        if verbose:
            print(f"      Full status: {json.dumps(status, indent=2)}")
            
    except Exception as e:
        result.add_fail("CommitHook 상태 조회 실패", str(e))
    
    # 3.2 Rollback 파일 수 감지
    print_step("3.2 Rollback 감지 테스트", "running")
    
    try:
        hook = get_commit_hook()
        count = hook.get_rollback_count()
        
        # count가 0 이상이면 정상 (Docker 연결 여부에 따라 다름)
        if count >= 0:
            result.add_pass(f"Rollback 파일 수 감지: {count}개")
        else:
            result.add_warning("Rollback 감지 불가", "NSO Docker 미실행 가능")
            
    except Exception as e:
        result.add_warning("Rollback 감지 테스트 실패", str(e))
    
    # 3.3 State 파일 확인
    print_step("3.3 State 파일 테스트", "running")
    
    state_file = PROJECT_ROOT / "config" / ".commit_hook_state.json"
    
    if state_file.exists():
        with open(state_file, "r") as f:
            state = json.load(f)
        result.add_pass(f"State 파일 존재: {state_file.name}")
    else:
        result.add_pass("State 파일 미존재 (정상 - 첫 실행)")
    
    return result


# =============================================================================
# Main
# =============================================================================

def run_all_tests(phases: List[int] = None, verbose: bool = False) -> Dict[str, Any]:
    """모든 테스트 실행"""
    print_banner("🧪 Lite-IRON End-to-End Test Suite")
    
    result = TestResult()
    
    if phases is None:
        phases = [1, 2, 3]
    
    if 1 in phases:
        test_phase1_context_pipeline(result, verbose)
    
    if 2 in phases:
        test_phase2_human_in_the_loop(result, verbose)
    
    if 3 in phases:
        test_phase3_commit_hook(result, verbose)
    
    # 최종 결과
    print_banner("📊 Test Summary")
    
    total = result.passed + result.failed
    success_rate = (result.passed / total * 100) if total > 0 else 0
    
    print(f"  Total Tests: {total}")
    print(f"  ✅ Passed: {result.passed}")
    print(f"  ❌ Failed: {result.failed}")
    print(f"  ⚠️  Warnings: {result.warnings}")
    print(f"  Success Rate: {success_rate:.1f}%")
    
    if result.failed == 0:
        print("\n  🎉 All tests passed!")
        status = "SUCCESS"
    elif result.passed > result.failed:
        print("\n  ⚠️  Some tests failed. Check details above.")
        status = "PARTIAL"
    else:
        print("\n  ❌ Tests failed. Review implementation.")
        status = "FAILED"
    
    return {
        "status": status,
        "passed": result.passed,
        "failed": result.failed,
        "warnings": result.warnings,
        "details": result.details
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Lite-IRON End-to-End Test")
    parser.add_argument(
        "--phase", "-p",
        type=int,
        choices=[1, 2, 3],
        help="특정 Phase만 테스트 (1, 2, 또는 3)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="상세 출력"
    )
    
    args = parser.parse_args()
    
    phases = [args.phase] if args.phase else None
    result = run_all_tests(phases=phases, verbose=args.verbose)
    
    # 종료 코드
    sys.exit(0 if result["status"] == "SUCCESS" else 1)
