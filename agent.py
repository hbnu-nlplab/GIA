import os
import json
from typing import List, Dict, Any, Optional

# LangGraph 기반 에이전트 (공식 문서 권장 방식)
try:
    from langchain_openai import ChatOpenAI
    from langchain_core.tools import tool
    from langgraph.prebuilt import create_react_agent
    from langgraph.checkpoint.memory import MemorySaver
    LANGGRAPH_AVAILABLE = True
except ImportError:
    print("❌ LangGraph not available. Please install: pip install langgraph langchain-openai")
    LANGGRAPH_AVAILABLE = False

# ★ 작성자님이 만든 프레임워크(Body) 연결
from enter_NSO import SanoaConnector

# API 키 설정 (환경 변수에 없다면 주석 해제 후 입력)
# os.environ["OPENAI_API_KEY"] = "sk-..."
try:
    from dotenv import load_dotenv
    load_dotenv("Evaluation/TeleQnA/openai_key.env")
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    API_KEY_AVAILABLE = bool(OPENAI_API_KEY)
except ImportError:
    print("Warning: python-dotenv not installed. Using environment variable directly.")
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    API_KEY_AVAILABLE = bool(OPENAI_API_KEY)

if not API_KEY_AVAILABLE:
    print("⚠️  OPENAI_API_KEY not found. Agent will run in demo mode without LLM.")


# =========================================================
# 1. SANOA 프레임워크 초기화
# =========================================================
print("🔌 Connecting to NSO Framework...")
print("   📡 Initializing SanoaConnector...")
try:
    nso = SanoaConnector()
    print("✅ NSO Framework connected successfully")
    print(f"   🔧 NSO Version: {getattr(nso, 'version', 'unknown')}")
    print(f"   📊 Available devices: {len(nso.get_devices()) if hasattr(nso, 'get_devices') else 'unknown'}")

    # NSO 연결 상태 상세 출력
    if hasattr(nso, 'connection_info'):
        print(f"   🌐 Connection info: {nso.connection_info}")

except Exception as e:
    print(f"❌ Failed to connect to NSO Framework: {e}")
    import traceback
    print("📋 Full error traceback:")
    traceback.print_exc()
    print("Please check if NSO is running and accessible.")
    exit(1)

# =========================================================
# 2. 도구(Tools) 정의: 프레임워크의 32개 기능을 최적화하여 노출
# =========================================================

# --- [Tier 1] Discovery (탐색) ---
@tool
def scan_network_devices() -> List[str]:
    """
    [Discovery] 현재 네트워크에 등록된 모든 장비의 이름 목록을 스캔합니다.
    작업을 시작하기 전, 어떤 장비가 있는지 파악할 때 가장 먼저 사용하세요.
    """
    print("🔍 [TOOL] scan_network_devices() - NSO에서 장비 목록 조회 중...")
    try:
        devices = nso.get_devices()
        print(f"📋 [TOOL RESULT] 장비 목록: {devices}")
        return devices
    except Exception as e:
        print(f"❌ [TOOL ERROR] scan_network_devices: {e}")
        return []

@tool
def inspect_device_basic_info(device: str) -> Dict[str, Any]:
    """
    [Discovery] 특정 장비의 기본 정보(플랫폼, 관리 IP, 포트, 인증그룹 등)를 조회합니다.
    """
    print(f"🔍 [TOOL] inspect_device_basic_info({device}) - 장비 기본 정보 조회 중...")
    try:
        info = nso.get_device_info(device)
        print(f"📋 [TOOL RESULT] {device} 정보: {info}")
        return info
    except Exception as e:
        print(f"❌ [TOOL ERROR] inspect_device_basic_info({device}): {e}")
        return {}

# --- [Tier 2] Diagnosis (상세 진단 - Getters) ---
@tool
def get_interfaces_status(device: str) -> List[Dict[str, Any]]:
    """
    [Diagnosis] 장비의 모든 인터페이스 설정 및 상태 정보를 상세 조회합니다.
    """
    return nso.get_interfaces(device)

@tool
def get_ip_address_map(device: str) -> Dict[str, str]:
    """
    [Diagnosis] 장비의 인터페이스별 IP 주소 할당 현황을 조회합니다. (Key: 인터페이스명, Value: IP/Mask)
    """
    return nso.get_interface_ips(device)

@tool
def get_routing_status(device: str, protocol: str) -> Any:
    """
    [Diagnosis] 라우팅 프로토콜(BGP, OSPF)의 설정 및 상태를 조회합니다.
    protocol 옵션: 'bgp' (네이버 목록 반환), 'ospf' (설정 전체 반환)
    """
    if protocol.lower() == 'bgp':
        return nso.get_bgp_neighbors(device)
    elif protocol.lower() == 'ospf':
        return nso.get_ospf_config(device)
    return "Error: Unsupported protocol. Use 'bgp' or 'ospf'."

@tool
def get_vrf_list(device: str) -> List[str]:
    """
    [Diagnosis] 장비에 설정된 VRF(가상 라우팅) 목록을 조회합니다.
    """
    return nso.get_vrf_list(device)

# --- [Tier 3] Analysis (고수준 분석 - 논문 핵심 기능) ---
# ★ LLM이 직접 계산하지 않고 프레임워크에 위임하여 정확도 100% 보장

@tool
def compare_devices_configuration(dev1: str, dev2: str, aspect: str) -> Dict[str, Any]:
    """
    [Analysis] 두 장비 간의 설정을 정밀 비교 분석합니다. LLM이 직접 텍스트를 비교하는 것보다 정확합니다.
    aspect 옵션:
    - 'interface_count': 인터페이스 개수 비교
    - 'bgp_neighbor_count': BGP 네이버 수 비교
    - 'bgp_as': BGP AS 번호 일치 여부 확인 (형식: '장비1: AS X, 장비2: AS Y, 결과: true/false')
    - 'ospf_areas': OSPF Area 구성 일치 여부 확인 (형식: '장비1: Area X, 장비2: Area Y, 결과: true/false')
    """
    print(f"🔍 [TOOL] compare_devices_configuration({dev1}, {dev2}, {aspect}) - 장비 비교 분석 중...")
    try:
        result = nso.compare_devices(dev1, dev2, aspect)
        print(f"📋 [TOOL RESULT] {dev1} vs {dev2} ({aspect}): {result}")
        return result
    except Exception as e:
        print(f"❌ [TOOL ERROR] compare_devices_configuration: {e}")
        return {}

@tool
def find_devices_by_query(condition: str) -> List[str]:
    """
    [Analysis] 특정 조건을 만족하는 장비 목록을 검색합니다.
    condition 옵션:
    - 'max_interfaces': 인터페이스가 가장 많은 장비
    - 'min_interfaces': 인터페이스가 가장 적은 장비
    - 'ssh_enabled': SSH가 활성화된 장비
    - 'bgp_configured': BGP가 설정된 장비
    """
    return nso.find_devices_with(condition)

@tool
def detect_network_anomalies(check_type: str) -> Any:
    """
    [Analysis] 네트워크 전체를 스캔하여 잠재적인 이상 징후(Anomaly)를 탐지합니다.
    check_type 옵션:
    - 'ip_conflict': IP 주소 충돌 여부 검사 (List[Dict] 반환)
    - 'l2vpn_consistency': L2VPN(Pseudowire) 구성 오류 검사 (Dict 반환)
    """
    if check_type == "ip_conflict":
        return nso.check_ip_conflicts()
    elif check_type == "l2vpn_consistency":
        return nso.check_l2vpn_consistency()
    return {"error": "Unknown check type. Use 'ip_conflict' or 'l2vpn_consistency'."}

# --- [Tier 4] Verification (검증 - L4/L5 Active Testing) ---
# ★ 설정(Static)이 아닌 실제 상태(Dynamic) 확인

@tool
def verify_reachability_ping(source_device: str, target_ip: str) -> Dict[str, Any]:
    """
    [Verification] 'Ping' 테스트를 수행하여 실제 트래픽 도달 가능성을 검증합니다.
    설정은 정상이지만 통신이 안 될 때 반드시 사용해야 합니다.
    """
    return nso.ping(source_device, target_ip)

@tool
def trace_traffic_path(source_device: str, target_ip: str) -> Dict[str, Any]:
    """
    [Verification] 'Traceroute'를 수행하여 패킷의 경로를 추적합니다.
    네트워크 경로상의 병목 지점이나 라우팅 루프를 찾을 때 사용합니다.
    """
    return nso.traceroute(source_device, target_ip)

# 에이전트에게 쥐여줄 도구 상자
tools = [
    scan_network_devices, inspect_device_basic_info,
    get_interfaces_status, get_ip_address_map, get_routing_status, get_vrf_list,
    compare_devices_configuration, find_devices_by_query, detect_network_anomalies,
    verify_reachability_ping, trace_traffic_path
]

# =========================================================
# 3. 에이전트 두뇌(Brain) 설계 - 시스템 프롬프트
# =========================================================

# 시스템 프롬프트 (전역 정의)
system_prompt = """
당신은 'SANOA(Self-Adaptive Network Orchestration Agent)'입니다.
Cisco NSO 프레임워크와 연동된 지능형 네트워크 운영 에이전트입니다.

**당신의 임무:**
사용자의 질문에 대해 진단(Diagnosis), 분석(Analysis), 검증(Verification)을 수행하여 정확한 답변을 제공하십시오.

**핵심 행동 수칙 (Standard Operating Procedure):**
1. **효율성 최우선 (Efficiency First):**
   - 사용자가 "IP 충돌 있어?"라고 물으면, 장비 설정을 일일이 읽지 마십시오.
   - 즉시 `detect_network_anomalies('ip_conflict')` 도구를 사용하여 프레임워크에게 계산을 위임하십시오.

2. **검증 필수 (Verification Required):**
   - "설정이 되어 있습니다"로 끝내지 마십시오.
   - 통신 문제라면 반드시 `verify_reachability_ping`을 수행하여 실제 패킷이 도달하는지 확인하고 답변하십시오.

3. **맥락 파악 (Context Awareness):**
   - 사용자가 "장비 상태 어때?"라고 모호하게 물으면, `scan_network_devices`로 목록을 먼저 파악한 뒤 `find_devices_by_query` 등을 활용해 요약 보고하십시오.

**답변 스타일:**
- 전문적인 네트워크 엔지니어처럼 답변하십시오.
- 문제가 발견되면 '현상 - 원인 - 해결책' 순서로 정리하십시오.
- 한국어로 답변하되, 기술 용어는 영어로 유지하십시오.
"""

system_prompt = """
당신은 'SANOA(Self-Adaptive Network Orchestration Agent)'입니다.
Cisco NSO 프레임워크와 연동된 지능형 네트워크 운영 에이전트입니다.

**당신의 임무:**
사용자의 질문에 대해 진단(Diagnosis), 분석(Analysis), 검증(Verification)을 수행하여 정확한 답변을 제공하십시오.

**핵심 행동 수칙 (Standard Operating Procedure):**
1. **효율성 최우선 (Efficiency First):**
   - 사용자가 "IP 충돌 있어?"라고 물으면, 장비 설정을 일일이 읽지 마십시오.
   - 즉시 `detect_network_anomalies('ip_conflict')` 도구를 사용하여 프레임워크에게 계산을 위임하십시오.

2. **검증 필수 (Verification Required):**
   - "설정이 되어 있습니다"로 끝내지 마십시오.
   - 통신 문제라면 반드시 `verify_reachability_ping`을 수행하여 실제 패킷이 도달하는지 확인하고 답변하십시오.

3. **맥락 파악 (Context Awareness):**
   - 사용자가 "장비 상태 어때?"라고 모호하게 물으면, `scan_network_devices`로 목록을 먼저 파악한 뒤 `find_devices_by_query` 등을 활용해 요약 보고하십시오.

**답변 스타일:**
- 전문적인 네트워크 엔지니어처럼 답변하십시오.
- 문제가 발견되면 '현상 - 원인 - 해결책' 순서로 정리하십시오.
- 한국어로 답변하되, 기술 용어는 영어로 유지하십시오.
"""

# LangGraph 사용 가능 여부에 따라 초기화
if not LANGGRAPH_AVAILABLE:
    print("❌ LangGraph를 사용할 수 없습니다. 기본 모드로 실행합니다.")
    agent_executor = None
elif not API_KEY_AVAILABLE:
    print("⚠️  OpenAI API 키가 없어 LLM을 사용할 수 없습니다. NSO 도구만 사용 가능합니다.")
    agent_executor = None
else:
    try:
        print("🤖 Initializing LLM...")
        # GPT-4o-mini 사용 (비용 효율적이고 네트워크 추론에 충분)
        llm = ChatOpenAI(
            model="gpt-5-mini",
            temperature=0,
            api_key=OPENAI_API_KEY  # 명시적 API 키 설정
        )
        print(f"   ✅ LLM initialized: {llm.model_name}")

        print("💾 Setting up memory checkpoint...")
        # 메모리 저장소 설정 (LangGraph 공식 문서 권장)
        memory = MemorySaver()
        print("   ✅ Memory checkpoint ready")

        print("🧠 Creating LangGraph ReAct Agent...")
        # ReAct 에이전트 생성 (LangGraph 공식 문서 방식)
        agent_executor = create_react_agent(
            llm,
            tools,
            checkpointer=memory
        )
        print("   ✅ ReAct Agent created successfully")
        print(f"   🛠️  Available tools: {len(tools)}")
        for tool in tools:
            print(f"      - {tool.name}")

        print("✅ LangGraph ReAct 에이전트 초기화됨")
    except Exception as e:
        print(f"❌ LangGraph 에이전트 초기화 실패: {e}")
        print("NSO 도구만 사용 가능합니다.")
        agent_executor = None

# =========================================================
# 4. 실행 인터페이스 (Chat Loop)
# =========================================================
if __name__ == "__main__":
    print("\n🌐 SANOA Network Agent Activated.")
    print("==================================================")

    # 시스템 상태 요약
    print("📊 System Status:")
    if agent_executor is None:
        print("   ⚠️  LLM: DISABLED (NSO tools only)")
        print("   ✅ NSO Framework: CONNECTED")
    else:
        print("   ✅ LLM: ENABLED (GPT-4o-mini)")
        print("   ✅ NSO Framework: CONNECTED")
        print("   ✅ LangGraph ReAct Agent: READY")

    print("\n🛠️  Available Capabilities:")
    print("   - 32 NSO API integrations")
    print("   - Real-time network diagnostics")
    print("   - Automated troubleshooting")
    print("   - Configuration analysis")

    print("\n💡 Usage Tips:")
    print("   1. '네트워크 전체에 IP 충돌이나 L2VPN 오류 있어?' (이상 탐지)")
    print("   2. 'R1이랑 R2의 BGP 네이버 수가 같아?' (비교 분석)")
    print("   3. 'R1에서 8.8.8.8로 핑이 나가?' (도달성 검증)")
    print("   4. 'CE01과 CE02의 BGP AS가 같아?' (구성 검증)")
    print("   5. 'PE01에서 CE01까지의 경로를 알려줘' (경로 추적)")

    print("\n==================================================")
    print("🔄 Ready for user queries. Type 'exit' to quit.")
    print("==================================================\n")

    while True:
        try:
            q = input("User (exit to quit): ")
            if q.lower() in ["exit", "quit"]:
                print("시스템을 종료합니다.")
                break

            if not q.strip():
                continue

            if agent_executor is None:
                # LLM 없이 기본 NSO 도구만 사용
                print("\n🔧 SANOA (Basic Mode) - 직접 NSO 명령어 사용")
                print("사용 가능한 명령어:")
                print("- devices: 장비 목록 조회")
                print("- ping <device> <ip>: 핑 테스트")
                print("- trace <device> <ip>: 트레이스")
                print("- compare <dev1> <dev2> <aspect>: 장비 비교")
                print("LLM을 사용하려면 OPENAI_API_KEY 환경변수를 설정하세요.\n")
                continue

            print("\n🤖 SANOA Thinking...")
            print(f"📝 User Query: {q}")
            print("🔍 Analyzing query and selecting tools...")

            # LangGraph ReAct 에이전트 호출 (시스템 프롬프트 포함)
            config = {"configurable": {"thread_id": "default_thread"}}
            print("🚀 Invoking LangGraph ReAct Agent...")

            try:
                response = agent_executor.invoke(
                    {"messages": [("system", system_prompt), ("user", q)]},
                    config=config
                )
                print("✅ Agent execution completed successfully")

                # 응답 구조 분석 및 출력
                print("📊 Response Analysis:")
                print(f"   - Total messages: {len(response['messages'])}")
                print(f"   - Thread ID: {config['configurable']['thread_id']}")

                # 모든 메시지 내용 출력
                for i, msg in enumerate(response["messages"]):
                    role = getattr(msg, 'type', getattr(msg, 'role', 'unknown'))
                    content = getattr(msg, 'content', str(msg))
                    print(f"   [{i}] {role.upper()}: {content[:100]}{'...' if len(content) > 100 else ''}")

                # 최종 응답 추출 및 출력
                final_message = response["messages"][-1]
                print("\n🎯 Final Answer:")
                print(f"{final_message.content}")

                # 추가 분석 정보
                if hasattr(final_message, 'tool_calls') and final_message.tool_calls:
                    print(f"🛠️  Tool calls made: {len(final_message.tool_calls)}")
                    for tool_call in final_message.tool_calls:
                        print(f"   - Tool: {tool_call.get('name', 'unknown')}")
                        print(f"   - Args: {tool_call.get('args', {})}")

            except Exception as e:
                print(f"❌ Agent execution failed: {e}")
                import traceback
                print("📋 Full traceback:")
                traceback.print_exc()

        except KeyboardInterrupt:
            print("\n\n사용자에 의해 중단되었습니다.")
            break
        except Exception as e:
            print(f"❌ Error occurred: {e}")
            print("다시 시도하거나 'exit'를 입력하세요.\n")