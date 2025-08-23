"""
증거 기반 답변 생성 시스템 테스트
LLM이 세운 계획을 시스템이 실행하여 구체적인 증거를 찾고,
그 증거를 바탕으로 최종 답변을 생성하는 과정을 검증
"""

import json
from typing import Dict, Any

# 테스트용 더미 데이터
test_network_facts = {
    "devices": [
        {"name": "R1", "type": "router", "as": 65001, "ssh_enabled": True, "aaa_enabled": True},
        {"name": "R2", "type": "router", "as": 65001, "ssh_enabled": False, "aaa_enabled": False},
        {"name": "R3", "type": "router", "as": 65002, "ssh_enabled": True, "aaa_enabled": True},
        {"name": "SW1", "type": "switch", "ssh_enabled": True, "aaa_enabled": False}
    ],
    "bgp_peers": [
        {"local": "R1", "remote": "R2", "type": "ibgp"},
        {"local": "R1", "remote": "R3", "type": "ebgp"}
    ]
}

def test_evidence_collection():
    """증거 수집 테스트"""
    print("🧪 === 증거 기반 답변 생성 시스템 테스트 ===\n")
    
    from answer_agent import AnswerAgent
    
    # AnswerAgent 초기화
    agent = AnswerAgent(test_network_facts)
    
    # 테스트 케이스 1: 구체적인 reasoning_plan이 있는 경우
    print("📋 테스트 1: 구체적인 reasoning_plan 실행")
    
    test_question = "네트워크의 SSH 보안 설정 상태는 어떻습니까?"
    test_plan = [
        {
            "step": 1,
            "description": "SSH 설정이 누락된 장비 수 확인",
            "required_metric": "ssh_missing_count",
            "metric_params": {},
            "synthesis": "fetch"
        },
        {
            "step": 2,
            "description": "SSH가 활성화된 장비 목록 조회",
            "required_metric": "ssh_enabled_devices",
            "metric_params": {},
            "synthesis": "fetch"
        },
        {
            "step": 3,
            "description": "전체 SSH 활성화 상태 확인",
            "required_metric": "ssh_all_enabled_bool",
            "metric_params": {},
            "synthesis": "summarize"
        }
    ]
    
    print(f"질문: {test_question}")
    print("계획:", json.dumps(test_plan, indent=2, ensure_ascii=False))
    
    # 계획 실행 및 답변 생성
    result = agent.execute_plan(test_question, test_plan)
    
    print(f"\n🎯 **최종 답변:**")
    print(result)
    print(f"\n📊 **수집된 증거:**")
    print(json.dumps(agent.evidence, indent=2, ensure_ascii=False))
    
    print("\n" + "="*60 + "\n")
    
    # 테스트 케이스 2: 텍스트 기반 계획 (자동 메트릭 추론)
    print("📋 테스트 2: 텍스트 기반 계획 (자동 메트릭 추론)")
    
    test_question2 = "BGP 피어링 설정에 문제가 있나요?"
    test_plan2 = "BGP 피어링 상태를 확인하고 iBGP 풀메시 구성을 점검하여 문제점을 식별한다."
    
    print(f"질문: {test_question2}")
    print(f"계획: {test_plan2}")
    
    result2 = agent.execute_plan(test_question2, test_plan2)
    
    print(f"\n🎯 **최종 답변:**")
    print(result2)
    print(f"\n📊 **수집된 증거:**")
    print(json.dumps(agent.evidence, indent=2, ensure_ascii=False))
    
    print("\n" + "="*60 + "\n")
    
    # 테스트 케이스 3: 복합 분석 질문
    print("📋 테스트 3: 복합 분석 질문 (AAA + SSH)")
    
    test_question3 = "네트워크 접근 보안이 적절히 설정되어 있는지 종합적으로 평가해주세요."
    test_plan3 = [
        {
            "step": 1,
            "description": "AAA 인증이 활성화된 장비 목록 확인",
            "required_metric": "aaa_enabled_devices",
            "metric_params": {},
            "synthesis": "fetch"
        },
        {
            "step": 2,
            "description": "SSH 활성화된 장비 목록 확인",
            "required_metric": "ssh_enabled_devices",
            "metric_params": {},
            "synthesis": "fetch"
        },
        {
            "step": 3,
            "description": "SSH 미설정 장비 수 확인",
            "required_metric": "ssh_missing_count",
            "metric_params": {},
            "synthesis": "compare"
        }
    ]
    
    print(f"질문: {test_question3}")
    print("계획:", json.dumps(test_plan3, indent=2, ensure_ascii=False))
    
    result3 = agent.execute_plan(test_question3, test_plan3)
    
    print(f"\n🎯 **최종 답변:**")
    print(result3)
    print(f"\n📊 **수집된 증거:**")
    print(json.dumps(agent.evidence, indent=2, ensure_ascii=False))

def test_evidence_formatting():
    """증거 포맷팅 테스트"""
    print("\n🎨 === 증거 포맷팅 테스트 ===\n")
    
    from answer_agent import AnswerAgent
    
    agent = AnswerAgent(test_network_facts)
    
    # 테스트 증거 데이터
    agent.evidence = {
        'step_1_ssh_missing_count': 2,
        'step_2_ssh_enabled_devices': ['R1', 'R3', 'SW1'],
        'step_3_ssh_all_enabled_bool': False,
        'aaa_enabled_devices': ['R1', 'R3'],
        'ibgp_fullmesh_ok': True,
        'error_metric': 'error: Metric not found'
    }
    
    formatted = agent._format_evidence()
    print("포맷팅된 증거:")
    print(formatted)
    
    # 개별 값 포맷팅 테스트
    print("\n개별 값 포맷팅 테스트:")
    print(f"Boolean True: {agent._format_value(True)}")
    print(f"Boolean False: {agent._format_value(False)}")
    print(f"Zero: {agent._format_value(0)}")
    print(f"List: {agent._format_value(['R1', 'R2', 'R3'])}")
    print(f"Long List: {agent._format_value(['R1', 'R2', 'R3', 'R4', 'R5'])}")
    print(f"Error: {agent._format_value('error: Something went wrong')}")

if __name__ == "__main__":
    try:
        test_evidence_collection()
        test_evidence_formatting()
        print("\n🎉 모든 테스트 완료! 증거 기반 답변 생성 시스템이 정상 작동합니다.")
    except Exception as e:
        print(f"❌ 테스트 실패: {e}")
        import traceback
        traceback.print_exc()
