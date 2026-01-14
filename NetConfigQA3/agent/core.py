"""
NetConfigQA3 Agent Core
LangGraph 기반 네트워크 운영 에이전트
"""

import sys
from pathlib import Path

# 상위 모듈 import를 위한 경로 설정
sys.path.insert(0, str(Path(__file__).parent.parent))

import logging
from typing import Optional

# LangGraph 관련 import
try:
    from langchain_openai import ChatOpenAI
    from langgraph.prebuilt import create_react_agent
    from langgraph.checkpoint.memory import MemorySaver
    LANGGRAPH_AVAILABLE = True
except ImportError:
    print("❌ LangGraph 설치 필요: pip install langgraph langchain-openai")
    LANGGRAPH_AVAILABLE = False

from config.settings import settings
from agent.tools import get_tools

# 로깅 설정
logging.basicConfig(
    filename=settings.log_file,
    level=getattr(logging, settings.log_level),
    format='%(asctime)s - [SANOA] - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# =============================================================================
# 시스템 프롬프트
# =============================================================================

SYSTEM_PROMPT = """
당신은 'SANOA(Self-Adaptive Network Orchestration Agent)'입니다.
PNETLab 실험실과 Cisco NSO를 연동하는 지능형 네트워크 운영 에이전트입니다.

## 당신의 역할
1. 네트워크 장비 정보 조회 및 분석
2. 설정 일관성 검증 및 문제 진단
3. PNETLab 실험실 ↔ NSO 자동 연동
4. 네트워크 연결성 테스트 (Ping, Traceroute)

## 핵심 행동 수칙
1. **효율성 우선**: 필요한 정보만 조회하세요. 전체 덤프 대신 특정 장비/설정만 요청하세요.
2. **검증 필수**: 설정이 있다고 끝이 아닙니다. 통신 문제라면 ping_test로 실제 확인하세요.
3. **안전 우선**: 변경 작업 전에는 반드시 현재 상태를 확인하세요.

## 도구 사용 가이드
- **scan_network_devices**: NSO에 등록된 장비 목록 조회
- **get_device_info**: 특정 장비의 기본 정보 조회
- **get_interfaces / get_interface_ips**: 인터페이스 정보 조회
- **get_routing_info**: BGP/OSPF 라우팅 설정 조회
- **compare_devices**: 두 장비 설정 비교
- **check_ip_conflicts**: IP 충돌 검사
- **ping_test / traceroute_test**: 연결성 테스트
- **lab_show_inventory**: PNETLab 실험실 장비 목록
- **lab_sync_to_nso**: 실험실 → NSO 자동 연동

## 답변 스타일
- 전문적인 네트워크 엔지니어처럼 답변하세요.
- 문제 발견 시 '현상 - 원인 - 해결책' 순서로 정리하세요.
- 한국어로 답변하되, 기술 용어(BGP, OSPF, VRF 등)는 영어로 유지하세요.
"""


# =============================================================================
# 에이전트 클래스
# =============================================================================

class NetworkAgent:
    """네트워크 운영 에이전트"""
    
    def __init__(self):
        self.agent = None
        self.memory = None
        self._initialized = False
    
    def initialize(self) -> bool:
        """에이전트 초기화"""
        if not LANGGRAPH_AVAILABLE:
            logger.error("LangGraph not available")
            return False
        
        if not settings.openai.api_key:
            logger.error("OpenAI API key not set")
            print("❌ OPENAI_API_KEY 환경변수를 설정하세요.")
            return False
        
        try:
            # LLM 초기화
            llm = ChatOpenAI(
                model=settings.openai.model,
                temperature=settings.openai.temperature,
                api_key=settings.openai.api_key
            )
            logger.info(f"LLM initialized: {settings.openai.model}")
            
            # 메모리 설정
            self.memory = MemorySaver()
            
            # 도구 로드
            tools = get_tools()
            logger.info(f"Loaded {len(tools)} tools")
            
            # ReAct 에이전트 생성
            self.agent = create_react_agent(
                llm,
                tools,
                checkpointer=self.memory
            )
            
            self._initialized = True
            logger.info("NetworkAgent initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Agent initialization failed: {e}")
            print(f"❌ 에이전트 초기화 실패: {e}")
            return False
    
    def chat(self, message: str, thread_id: str = "default") -> str:
        """사용자 메시지에 응답"""
        if not self._initialized:
            return "에이전트가 초기화되지 않았습니다. initialize()를 먼저 호출하세요."
        
        try:
            config = {"configurable": {"thread_id": thread_id}}
            
            response = self.agent.invoke(
                {"messages": [("system", SYSTEM_PROMPT), ("user", message)]},
                config=config
            )
            
            # 최종 응답 추출
            final_message = response["messages"][-1]
            return final_message.content
            
        except Exception as e:
            logger.error(f"Chat error: {e}")
            return f"오류가 발생했습니다: {e}"
    
    @property
    def is_initialized(self) -> bool:
        return self._initialized


# =============================================================================
# 메인 실행
# =============================================================================

def main():
    """메인 실행 함수"""
    print("\n" + "="*60)
    print("🌐 SANOA Network Agent v3.0")
    print("   PNETLab + NSO 통합 네트워크 운영 에이전트")
    print("="*60)
    
    # 에이전트 초기화
    agent = NetworkAgent()
    
    if not agent.initialize():
        print("\n⚠️  에이전트 초기화 실패")
        print("   환경변수를 확인하세요:")
        print("   - OPENAI_API_KEY")
        print("   - PNETLAB_BASE_URL, PNETLAB_USER, PNETLAB_PASS")
        print("   - NSO_BASE_URL, NSO_USER, NSO_PASS")
        return
    
    print("\n✅ 에이전트 준비 완료!")
    print("\n💡 사용 예시:")
    print("   - '네트워크에 어떤 장비가 있어?'")
    print("   - 'PE1의 인터페이스 IP를 보여줘'")
    print("   - '현재 실험실을 NSO에 연동해줘'")
    print("   - 'IP 충돌이 있는지 확인해줘'")
    print("\n'exit' 또는 'quit'으로 종료")
    print("-"*60 + "\n")
    
    # 대화 루프
    while True:
        try:
            user_input = input("You: ").strip()
            
            if not user_input:
                continue
            
            if user_input.lower() in ["exit", "quit", "q"]:
                print("\n👋 종료합니다.")
                break
            
            print("\n🤖 생각 중...")
            response = agent.chat(user_input)
            print(f"\nAgent: {response}\n")
            
        except KeyboardInterrupt:
            print("\n\n👋 사용자에 의해 중단되었습니다.")
            break
        except Exception as e:
            print(f"\n❌ 오류: {e}\n")


if __name__ == "__main__":
    main()

