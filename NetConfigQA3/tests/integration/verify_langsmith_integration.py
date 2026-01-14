from pathlib import Path
#!/usr/bin/env python3
"""
LangSmith 트레이싱 데모

LangSmith를 사용하여 에이전트 실행을 추적합니다.

실행 전 준비:
1. https://smith.langchain.com 에서 무료 계정 생성
2. API 키 발급 (Settings > API Keys)
3. config/.env에 다음 추가:
   LANGCHAIN_TRACING_V2=true
   LANGCHAIN_API_KEY=ls-your-key-here
   LANGCHAIN_PROJECT=NetConfigQA3-Test
"""

import os
import sys
from pathlib import Path
from typing import Optional

# 프로젝트 루트 경로
sys.path.insert(0, str(Path(__file__).parents[2]))

# config.settings를 먼저 임포트하여 .env 로드
from config.settings import settings

def get_env_var(key_chain: str, key_smith: str) -> Optional[str]:
    """LANGCHAIN_ 또는 LANGSMITH_로 시작하는 환경변수 조회"""
    return os.getenv(key_chain) or os.getenv(key_smith)

# API 키 및 트레이싱 활성화 여부 확인
api_key = get_env_var("LANGCHAIN_API_KEY", "LANGSMITH_API_KEY")
tracing_enabled = get_env_var("LANGCHAIN_TRACING_V2", "LANGSMITH_TRACING")

# LangSmith 활성화 확인
if not api_key:
    print("="*70)
    print("⚠️  LangSmith API 키가 설정되지 않았습니다")
    print("="*70)
    print()
    print("LangSmith 무료 트레이싱을 사용하려면:")
    print()
    print("1. https://smith.langchain.com 에서 무료 계정 생성")
    print("2. Settings > API Keys 에서 API 키 발급")
    print("3. config/.env 에 다음 추가:")
    print()
    print("   LANGCHAIN_TRACING_V2=true")
    print("   LANGCHAIN_API_KEY=ls-your-key-here")
    print("   LANGCHAIN_PROJECT=NetConfigQA3-Test")
    print()
    print("="*70)
    print()
    response = input("API 키 없이 계속하시겠습니까? (y/N): ")
    if response.lower() != 'y':
        print("종료합니다.")
        sys.exit(0)
    print()
else:
    # 환경변수 정규화 (LANGSMITH_를 LANGCHAIN_으로 복사하여 SDK 호환성 확보)
    if not os.getenv("LANGCHAIN_API_KEY") and os.getenv("LANGSMITH_API_KEY"):
        os.environ["LANGCHAIN_API_KEY"] = os.environ["LANGSMITH_API_KEY"]
    if not os.getenv("LANGCHAIN_TRACING_V2") and os.getenv("LANGSMITH_TRACING"):
        os.environ["LANGCHAIN_TRACING_V2"] = os.environ["LANGSMITH_TRACING"]
    if not os.getenv("LANGCHAIN_PROJECT") and os.getenv("LANGSMITH_PROJECT"):
        os.environ["LANGCHAIN_PROJECT"] = os.environ["LANGSMITH_PROJECT"]
    if not os.getenv("LANGCHAIN_ENDPOINT") and os.getenv("LANGSMITH_ENDPOINT"):
        os.environ["LANGCHAIN_ENDPOINT"] = os.environ["LANGSMITH_ENDPOINT"]

from agent.core import NetworkAgent

def main():
    """LangSmith 트레이싱 데모"""
    
    print("\n" + "="*70)
    print("🔍 LangSmith 트레이싱 데모")
    print("="*70)
    
    # 에이전트 초기화
    print("\n[1] 에이전트 초기화...")
    agent = NetworkAgent()
    
    if not agent.initialize():
        print("❌ 에이전트 초기화 실패")
        return
    
    print("✅ 에이전트 초기화 성공")
    
    # LangSmith 상태 확인
    current_api_key = get_env_var("LANGCHAIN_API_KEY", "LANGSMITH_API_KEY")
    if current_api_key:
        print(f"\n✅ LangSmith 트레이싱 활성화됨")
        print(f"   프로젝트: {get_env_var('LANGCHAIN_PROJECT', 'LANGSMITH_PROJECT') or 'NetConfigQA3-Agent'}")
        print(f"   URL: https://smith.langchain.com")
    else:
        print(f"\n⚠️  LangSmith 비활성화 (로컬 로그만 사용)")
    
    # 테스트 시나리오
    scenarios = [
        {
            "name": "장비 목록 조회",
            "query": "네트워크에 어떤 장비가 있어?",
            "description": "NSO scan_network_devices 호출"
        },
        {
            "name": "PNETLab 실험실",
            "query": "현재 실험실 정보를 보여줘",
            "description": "PNETLab lab_show_inventory 호출"
        },
        {
            "name": "IP 충돌 검사",
            "query": "네트워크에 IP 충돌이 있는지 확인해줘",
            "description": "check_ip_conflicts 호출"
        }
    ]
    
    print("\n" + "="*70)
    print("테스트 시나리오 실행")
    print("="*70)
    
    for i, scenario in enumerate(scenarios, 1):
        print(f"\n[Scenario {i}] {scenario['name']}")
        print(f"설명: {scenario['description']}")
        print(f"질문: \"{scenario['query']}\"")
        print()
        
        try:
            # 에이전트 실행
            print("🤖 에이전트 실행 중...")
            response = agent.chat(scenario['query'], thread_id=f"demo_{i}")
            
            print("\n📤 응답:")
            print("-" * 50)
            print(response)
            print("-" * 50)
            
            if os.getenv("LANGCHAIN_API_KEY"):
                print(f"\n✅ LangSmith에서 이 실행을 확인하세요:")
                print(f"   https://smith.langchain.com")
            
        except Exception as e:
            print(f"\n❌ 에러: {e}")
        
        if i < len(scenarios):
            input("\nEnter를 눌러 다음 시나리오로...")
    
    print("\n" + "="*70)
    print("✅ 모든 시나리오 완료!")
    print("="*70)
    
    if os.getenv("LANGCHAIN_API_KEY"):
        print(f"\n📊 LangSmith에서 결과를 확인하세요:")
        print(f"   https://smith.langchain.com")
        print(f"\n다음 정보를 확인할 수 있습니다:")
        print(f"   - 모든 LLM 호출 내역")
        print(f"   - 도구 실행 타임라인")
        print(f"   - 토큰 사용량")
        print(f"   - 실행 시간 분석")
    else:
        print(f"\n💡 Tip: LangSmith를 활성화하면 더 상세한 분석이 가능합니다!")
        print(f"   https://smith.langchain.com에서 무료 계정을 만드세요")
    
    print(f"\n📝 로컬 로그:")
    print(f"   - logs/sanoa_audit.log (일반 로그)")
    print(f"   - logs/structured_events.jsonl (구조화 로그)")
    print()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  중단됨")
    except Exception as e:
        print(f"\n❌ 예외 발생: {e}")
        import traceback
        traceback.print_exc()
