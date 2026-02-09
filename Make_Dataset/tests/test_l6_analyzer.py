"""
L6 Analyzer Test Suite

L6 Diagnostic QA 생성기의 기능을 검증하는 테스트 코드입니다.
Batfish 서버가 실행 중이어야 합니다.

실행 방법:
    python -m pytest tests/test_l6_analyzer.py -v --tb=short
    
또는 단독 실행:
    python tests/test_l6_analyzer.py
"""

import sys
import os
import json
import logging

# 프로젝트 루트를 path에 추가
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from typing import List, Dict, Any

# 로깅 설정
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def test_l6_link_failure_question_structure(questions: List[Dict[str, Any]]) -> bool:
    """Link Failure 문제의 구조 검증"""
    passed = True
    link_questions = [q for q in questions if q.get('id', '').startswith('DIAG_LINK_')]
    
    if not link_questions:
        logger.warning("No DIAG_LINK questions generated")
        return False
    
    for q in link_questions:
        # 필수 필드 확인
        required_fields = ['id', 'category', 'level', 'question', 'ground_truth', 'evidence_hint']
        for field in required_fields:
            if field not in q:
                logger.error(f"Missing field '{field}' in question {q.get('id', 'UNKNOWN')}")
                passed = False
        
        # 정답 형식 확인 (장비A - 장비B)
        gt = q.get('ground_truth', '')
        if ' - ' not in gt:
            logger.error(f"Ground truth format error: '{gt}' (expected 'NodeA - NodeB')")
            passed = False
        
        # 증상(symptom) 포함 확인
        evidence = q.get('evidence_hint', {})
        if 'symptom' not in evidence:
            logger.error(f"Missing 'symptom' in evidence_hint for {q.get('id')}")
            passed = False
    
    logger.info(f"Link Failure: {len(link_questions)} questions tested, {'PASSED' if passed else 'FAILED'}")
    return passed


def test_l6_node_failure_question_structure(questions: List[Dict[str, Any]]) -> bool:
    """Node Failure 문제의 구조 검증"""
    passed = True
    node_questions = [q for q in questions if q.get('id', '').startswith('DIAG_NODE_')]
    
    if not node_questions:
        logger.warning("No DIAG_NODE questions generated (might be expected if no path has intermediate nodes)")
        return True  # 경로가 직접 연결인 경우 없을 수 있음
    
    for q in node_questions:
        # 정답이 단일 노드명인지 확인
        gt = q.get('ground_truth', '')
        if ' - ' in gt:  # 링크 형식이 아니어야 함
            logger.error(f"Ground truth should be single node, got: '{gt}'")
            passed = False
        
        if not gt:
            logger.error(f"Empty ground_truth for {q.get('id')}")
            passed = False
    
    logger.info(f"Node Failure: {len(node_questions)} questions tested, {'PASSED' if passed else 'FAILED'}")
    return passed


def test_l6_bgp_mismatch_question_structure(questions: List[Dict[str, Any]]) -> bool:
    """BGP Mismatch 문제의 구조 검증"""
    passed = True
    bgp_questions = [q for q in questions if q.get('id', '').startswith('DIAG_BGP_')]
    
    if not bgp_questions:
        logger.info("No DIAG_BGP questions generated (might be expected if BGP is properly configured)")
        return True  # BGP 설정이 완벽하면 없을 수 있음
    
    valid_answers = ['ASN 불일치', '인증 불일치', 'Peer IP 누락', '설정 오류']
    for q in bgp_questions:
        gt = q.get('ground_truth', '')
        if gt not in valid_answers:
            logger.error(f"Unexpected BGP ground_truth: '{gt}' (expected one of {valid_answers})")
            passed = False
    
    logger.info(f"BGP Mismatch: {len(bgp_questions)} questions tested, {'PASSED' if passed else 'FAILED'}")
    return passed


def test_l6_ospf_mismatch_question_structure(questions: List[Dict[str, Any]]) -> bool:
    """OSPF Mismatch 문제의 구조 검증"""
    passed = True
    ospf_questions = [q for q in questions if q.get('id', '').startswith('DIAG_OSPF_')]
    
    if not ospf_questions:
        logger.info("No DIAG_OSPF questions generated (might be expected if OSPF is properly configured)")
        return True
    
    valid_answers = ['Area 불일치', 'Hello/Dead 타이머 불일치', 'Network Type 불일치', '설정 오류']
    for q in ospf_questions:
        gt = q.get('ground_truth', '')
        if gt not in valid_answers:
            logger.error(f"Unexpected OSPF ground_truth: '{gt}' (expected one of {valid_answers})")
            passed = False
    
    logger.info(f"OSPF Mismatch: {len(ospf_questions)} questions tested, {'PASSED' if passed else 'FAILED'}")
    return passed


def test_l6_acl_block_question_structure(questions: List[Dict[str, Any]]) -> bool:
    """ACL Block 문제의 구조 검증"""
    passed = True
    acl_questions = [q for q in questions if q.get('id', '').startswith('DIAG_ACL_')]
    
    if not acl_questions:
        logger.info("No DIAG_ACL questions generated (might be expected if no ACLs configured)")
        return True
    
    for q in acl_questions:
        gt = q.get('ground_truth', '')
        if not gt or gt == 'Unknown':
            logger.error(f"Invalid ACL ground_truth: '{gt}'")
            passed = False
        
        evidence = q.get('evidence_hint', {})
        if 'filter_name' not in evidence:
            logger.error(f"Missing 'filter_name' in evidence_hint for {q.get('id')}")
            passed = False
    
    logger.info(f"ACL Block: {len(acl_questions)} questions tested, {'PASSED' if passed else 'FAILED'}")
    return passed


def run_l6_integration_test(lab_path: str = None) -> bool:
    """
    L6 생성기 통합 테스트
    
    Args:
        lab_path: 테스트용 Lab 경로 (None이면 기본 경로 사용)
    
    Returns:
        True if all tests passed
    """
    from core_batfish.batfish_builder import BatfishBuilder
    
    # 기본 테스트 경로
    if lab_path is None:
        lab_path = os.path.join(
            os.path.dirname(__file__), '..', '..', 'Data', 'Pnetlab', 'Research_Institute_Internal_DC'
        )
        lab_path = os.path.abspath(lab_path)
    
    if not os.path.exists(lab_path):
        logger.error(f"Lab path not found: {lab_path}")
        return False
    
    logger.info(f"Testing L6 generation with lab: {lab_path}")
    
    # BatfishBuilder 초기화 (정확한 constructor 사용)
    try:
        network_name = os.path.basename(lab_path)
        logger.info(f"Initializing BatfishBuilder with network_name='{network_name}', snapshot_path='{lab_path}'")
        builder = BatfishBuilder(
            network_name=network_name,
            snapshot_path=lab_path
        )
        
        # Explicit initialization required
        if not builder.initialize():
            logger.error("builder.initialize() failed")
            return False

        # 초기화 상태 확인
        if not builder._initialized:
            logger.error("BatfishBuilder created but _initialized=False")
            logger.error("Check if Batfish server is running (default: localhost:9996)")
            logger.error("You can start Batfish with: docker run -d -p 9996:9996 -p 9997:9997 batfish/batfish")
            return False
        else:
            logger.info(f"BatfishBuilder initialized successfully. Nodes: {len(builder.nodes)}")
    except Exception as e:
        logger.error(f"Failed to initialize BatfishBuilder: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # L6 문제 생성
    logger.info("Generating L6 questions...")
    questions = builder.generate_l6_questions()
    
    if not questions:
        logger.warning("No L6 questions generated at all!")
        return False
    
    logger.info(f"Generated {len(questions)} L6 questions total")
    
    # 각 유형별 테스트 실행
    all_passed = True
    all_passed &= test_l6_link_failure_question_structure(questions)
    all_passed &= test_l6_node_failure_question_structure(questions)
    all_passed &= test_l6_bgp_mismatch_question_structure(questions)
    all_passed &= test_l6_ospf_mismatch_question_structure(questions)
    all_passed &= test_l6_acl_block_question_structure(questions)
    
    # 결과 요약
    if all_passed:
        logger.info("=" * 60)
        logger.info("✅ ALL L6 TESTS PASSED!")
        logger.info("=" * 60)
    else:
        logger.error("=" * 60)
        logger.error("❌ SOME L6 TESTS FAILED!")
        logger.error("=" * 60)
    
    # 샘플 출력
    logger.info("\n=== Sample L6 Questions ===")
    for q in questions[:3]:  # 처음 3개만 출력
        logger.info(f"\nID: {q.get('id')}")
        logger.info(f"Category: {q.get('category')}")
        logger.info(f"Question: {q.get('question')[:100]}...")
        logger.info(f"Ground Truth: {q.get('ground_truth')}")
    
    return all_passed


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Test L6 Diagnostic QA Generator')
    parser.add_argument('--lab-path', type=str, default=None, help='Path to lab directory')
    args = parser.parse_args()
    
    success = run_l6_integration_test(args.lab_path)
    sys.exit(0 if success else 1)
