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
from agent.unified_tools import get_unified_tools, get_filtered_tools
from agent.tools import get_pnetlab_client  # Keep for topology context
from agent.tracing import setup_langsmith, get_structured_logger
from agent.skill_loader import SkillLoader
from agent.planner import TaskPlanner
from agent.models import TaskPassage

# 로깅 설정
log_file_path = Path(settings.log_file)
log_file_path.parent.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    filename=str(log_file_path),
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
2. 설정 일관성 검증 및 문제 진단 (Batfish 활용)
3. PNETLab 실험실 ↔ NSO 자동 연동
4. 네트워크 연결성 검증 및 트러블슈팅

## 핵심 행동 수칙 (Core Policy)
1. **효율성 우선**: 필요한 정보만 조회하세요. 전체 Facts 덤프 금지.
2. **검증 필수**: 설정 변경 전 반드시 `network_verify`로 영향 분석.
3. **안전 우선**: `network_change("commit", ...)` 전에 반드시 `approval_request()` 사용.
4. **Evidence Pack 상한**: 한 번에 최대 30개 로그, 20개 메트릭, 40개 Facts 조회.

## 통합 도구 (7개)
1. **network_query** - NSO에서 설정 정보 조회
   - category: device, interface, routing, vrf, security, acl
   - 예: `network_query("routing", device="PE1", params={{"protocol": "bgp"}})`

2. **network_verify** - Batfish로 네트워크 속성 검증
   - test_type: reachability, traceroute, bgp_session, route_table
   - 예: `network_verify("reachability", {{"src": "10.1.1.1", "dst": "10.2.2.2"}})`

3. **network_change** - NSO를 통한 설정 변경 (⚠️ 주의)
   - action: dry_run, commit (승인필요), rollback (승인필요), diff
   - 예: `network_change("dry_run", "PE1", "acl/100", {{...}})`

4. **telemetry_query** - 로그/메트릭/플로우 조회
   - source: logs, metrics, flows
   - 예: `telemetry_query("logs", {{"device": "PE1", "severity": "error"}})`

5. **lab_manage** - PNETLab 실험실 관리
   - action: show_inventory, get_status, export_configs, init_batfish

6. **approval_request** - 위험 작업 승인 요청 (⚠️ 필수)
   - commit/rollback 전 반드시 호출

7. **help_guide** - 도구 사용법 조회
   - topic: tools, examples, troubleshooting, best_practices

## 금지 행동
❌ any-any permit ACL 추가
❌ default route 무단 추가  
❌ 전체 BGP clear/reset
❌ 승인 없이 commit 실행

## Task Analysis (Planner 결과)
{task_passage}

## 사용 가능한 도구
위 분석에서 선택된 도구만 사용할 수 있습니다.

## 답변 스타일
- 전문적인 네트워크 엔지니어처럼 답변하세요.
- 문제 발견 시 '현상 - 원인 - 해결책' 순서로 정리하세요.
- 한국어로 답변하되, 기술 용어(BGP, OSPF, VRF 등)는 영어로 유지하세요.

## 현재 네트워크 상태 (Context)
{context}

{skills_prompt}
"""


# =============================================================================
# 에이전트 클래스
# =============================================================================

class NetworkAgent:
    """
    2-Stage Network Agent
    
    Stage 1 (Planner): 사용자 요청을 분석하여 필요한 스킬/도구 결정
    Stage 2 (Executor): 선택된 스킬/도구로 작업 수행
    """
    
    def __init__(self, model: str = "gpt-4o-mini"):
        # LangSmith 트레이싱 활성화 (선택사항)
        setup_langsmith("NetConfigQA3-Agent")
        
        self.model = model
        self.planner = None
        self.skill_loader = None
        self.memory = None
        self._initialized = False
        self.topology_context = "초기화되지 않음"
    
    def _fetch_topology_context(self) -> str:
        """PNETLab에서 토폴로지 정보를 가져와 요약 텍스트 생성"""
        try:
            pnetlab = get_pnetlab_client()
            if not pnetlab.login():
                return "PNETLab 로그인 실패로 정보를 가져올 수 없습니다."
                
            topology = pnetlab.get_session_topology()
            if "error" in topology:
                return f"토폴로지 조회 실패: {topology['error']}"
                
            nodes = pnetlab.get_nodes_from_topology(topology)
            
            # 요약 정보 생성
            summary = [f"총 장비 수: {len(nodes)}대"]
            node_list = []
            for n in nodes:
                node_list.append(f"- {n['name']} ({n['type']})")
            
            summary.extend(node_list)
            return "\n".join(summary)
            
        except Exception as e:
            logger.error(f"Failed to fetch topology context: {e}")
            return "토폴로지 정보를 가져오는 중 오류 발생"

    def initialize(self) -> bool:
        """에이전트 초기화"""
        if not LANGGRAPH_AVAILABLE:
            logger.error("LangGraph not available")
            return False

        # 0. 토폴로지 컨텍스트 로드
        print("   ⏳ 초기 네트워크 컨텍스트 로딩 중...")
        self.topology_context = self._fetch_topology_context()
        logger.info(f"Topology context loaded: {len(self.topology_context)} chars")

        if not settings.openai.api_key:
            logger.error("OpenAI API key not set")
            print("❌ OPENAI_API_KEY 환경변수를 설정하세요.")
            return False
        
        try:
            # Planner 초기화 (Stage 1)
            print("   ⏳ Planner Agent 초기화 중...")
            self.planner = TaskPlanner(model=self.model)
            logger.info(f"Planner initialized: {self.model}")
            
            # SkillLoader 초기화
            self.skill_loader = SkillLoader()
            
            # 메모리 설정
            self.memory = MemorySaver()
            
            self._initialized = True
            logger.info("NetworkAgent initialized successfully (2-stage architecture)")
            print("   ✅ 2-Stage Agent 초기화 완료")
            return True
            
        except Exception as e:
            logger.error(f"Agent initialization failed: {e}")
            print(f"❌ 에이전트 초기화 실패: {e}")
            return False
    
    def chat(self, message: str, thread_id: str = "default") -> str:
        """
        2-Stage 처리로 사용자 메시지에 응답
        
        Stage 1: Planner가 요청 분석 → TaskPassage 생성
        Stage 2: Executor가 선택된 스킬/도구로 작업 수행
        """
        if not self._initialized:
            return "에이전트가 초기화되지 않았습니다. initialize()를 먼저 호출하세요."
        
        try:
            # =========================================
            # Stage 1: Planner - 요청 분석
            # =========================================
            logger.info(f"Stage 1: Planning for '{message[:50]}...'")
            passage = self.planner.plan(message)
            
            logger.info(f"Plan result: intent={passage.intent.value}, "
                       f"tools={passage.required_tools}, skills={passage.required_skills}")
            
            # =========================================
            # Stage 2: Executor - 작업 수행
            # =========================================
            logger.info("Stage 2: Executing with filtered tools")
            
            # 선택된 Skills만 로드
            skills = self.skill_loader.load_by_names(passage.required_skills)
            skills_prompt = self.skill_loader.build_system_prompt(skills) if skills else ""
            
            # 선택된 Tools만 바인딩
            tools = get_filtered_tools(passage.required_tools)
            logger.info(f"Filtered tools: {len(tools)} (vs 7 total)")
            
            # Executor LLM 생성 (동적 도구 바인딩)
            executor_llm = ChatOpenAI(
                model=self.model,
                temperature=0,
                api_key=settings.openai.api_key
            )
            
            # ReAct 에이전트 생성 (선택된 도구만)
            executor = create_react_agent(
                executor_llm,
                tools,
                checkpointer=self.memory
            )
            
            # 시스템 프롬프트 구성
            config = {"configurable": {"thread_id": thread_id}}
            formatted_system_prompt = SYSTEM_PROMPT.format(
                context=self.topology_context,
                task_passage=passage.to_prompt_context(),
                skills_prompt=skills_prompt
            )
            
            # Executor 실행
            response = executor.invoke(
                {"messages": [("system", formatted_system_prompt), ("user", message)]},
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

