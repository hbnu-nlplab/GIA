from pathlib import Path
#!/usr/bin/env python3
"""
에이전트 기능 테스트 스크립트

실제로 어떤 도구들이 호출되는지 확인하고 로깅합니다.
"""

import sys
from pathlib import Path

# 프로젝트 루트 경로 추가
sys.path.insert(0, str(Path(__file__).parents[2]))

import logging
from agent.core import NetworkAgent

# 로깅 설정 (콘솔 + 파일)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/agent_test.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def test_agent_functionality():
    """에이전트 기능 테스트"""
    
    print("\n" + "="*80)
    print("🧪 SANOA Agent 기능 테스트")
    print("="*80)
    
    # 에이전트 초기화
    print("\n[Step 1] 에이전트 초기화...")
    agent = NetworkAgent()
    
    if not agent.initialize():
        print("❌ 에이전트 초기화 실패!")
        print("   환경변수를 확인하세요 (OPENAI_API_KEY, NSO, PNETLAB)")
        return
    
    print("✅ 에이전트 초기화 성공")
    
    # 테스트 시나리오
    test_scenarios = [
        {
            "name": "Scenario 1: 장비 목록 조회",
            "query": "네트워크에 어떤 장비가 있어?",
            "expected_tools": ["scan_network_devices"],
            "description": "NSO에서 장비 목록을 조회하는 기본 테스트"
        },
        {
            "name": "Scenario 2: PNETLab 실험실 조회",
            "query": "현재 실험실 정보를 보여줘",
            "expected_tools": ["lab_show_inventory"],
            "description": "PNETLab API로 실험실 정보 조회"
        },
        {
            "name": "Scenario 3: 특정 장비 정보",
            "query": "PE1 장비의 기본 정보를 알려줘",
            "expected_tools": ["get_device_info"],
            "description": "특정 장비의 상세 정보 조회"
        },
        {
            "name": "Scenario 4: IP 충돌 검사",
            "query": "네트워크에 IP 충돌이 있는지 확인해줘",
            "expected_tools": ["check_ip_conflicts"],
            "description": "전체 네트워크 IP 충돌 분석"
        }
    ]
    
    # 테스트 실행
    for i, scenario in enumerate(test_scenarios, 1):
        print("\n" + "-"*80)
        print(f"\n[{scenario['name']}]")
        print(f"설명: {scenario['description']}")
        print(f"질문: \"{scenario['query']}\"")
        print(f"예상 도구: {', '.join(scenario['expected_tools'])}")
        print()
        
        # 에이전트 호출
        print("🤖 에이전트가 생각 중...")
        logger.info(f"=== {scenario['name']} ===")
        logger.info(f"Query: {scenario['query']}")
        
        try:
            response = agent.chat(scenario['query'], thread_id=f"test_scenario_{i}")
            
            print("\n📤 에이전트 응답:")
            print("-" * 40)
            print(response)
            print("-" * 40)
            
            logger.info(f"Response: {response[:200]}...")
            
        except Exception as e:
            print(f"❌ 에러 발생: {e}")
            logger.error(f"Error in scenario {i}: {e}", exc_info=True)
        
        # 다음 테스트로 넘어가기 전 확인
        if i < len(test_scenarios):
            input("\nEnter를 누르면 다음 테스트로 계속...")
    
    print("\n" + "="*80)
    print("✅ 모든 테스트 완료!")
    print("="*80)
    print(f"\n📝 상세 로그: logs/agent_test.log")
    print(f"📝 감사 로그: logs/sanoa_audit.log")
    print()

if __name__ == "__main__":
    try:
        test_agent_functionality()
    except KeyboardInterrupt:
        print("\n\n⚠️  테스트 중단됨")
    except Exception as e:
        print(f"\n❌ 예상치 못한 에러: {e}")
        logger.exception("Unexpected error in test")
