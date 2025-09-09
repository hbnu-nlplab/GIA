#!/usr/bin/env python3
"""다중 API 키 테스트 스크립트"""

import os
import sys
import time

# 현재 디렉토리를 파이썬 경로에 추가
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

def test_config():
    """config.py의 다중 키 감지 테스트"""
    print("🔍 config.py 다중 키 설정 테스트...")
    try:
        from config import OPENAI_API_KEYS
        print(f"✅ {len(OPENAI_API_KEYS)}개 API 키 감지됨")
        for i, key in enumerate(OPENAI_API_KEYS, 1):
            masked_key = f"...{key[-8:]}" if len(key) >= 8 else "***"
            print(f"   🔑 Key {i}: {masked_key}")
        return True
    except Exception as e:
        print(f"❌ config.py 로딩 실패: {e}")
        return False

def test_multi_client():
    """MultiKeyOpenAIClient 테스트"""
    print("\n🔄 다중 키 클라이언트 테스트...")
    try:
        from config import OPENAI_API_KEYS
        from common.llm_utils import MultiKeyOpenAIClient
        
        if len(OPENAI_API_KEYS) < 2:
            print("⚠️ 단일 키 모드 (다중 키 테스트 건너뜀)")
            return True
        
        client = MultiKeyOpenAIClient(OPENAI_API_KEYS)
        
        # 간단한 테스트 호출
        print("   📞 테스트 API 호출 중...")
        response = client.chat_completions_create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": "Say 'test success' in one word"}],
            max_tokens=5
        )
        
        result = response.choices[0].message.content.strip()
        print(f"   ✅ 응답: {result}")
        
        # 통계 출력
        client.print_stats()
        return True
        
    except Exception as e:
        print(f"❌ 다중 키 클라이언트 테스트 실패: {e}")
        return False

def test_tracked_client():
    """TrackedOpenAIClient 테스트"""
    print("\n🎯 TrackedOpenAIClient 테스트...")
    try:
        from common.llm_utils import ExperimentLogger, TrackedOpenAIClient
        
        # 임시 로거 생성
        logger = ExperimentLogger("test", "/tmp/test_experiment")
        client = TrackedOpenAIClient(logger)
        
        # 테스트 호출
        print("   📞 추적 API 호출 중...")
        response = client.chat_completions_create(
            call_type="test",
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": "Hello"}],
            max_tokens=10
        )
        
        result = response.choices[0].message.content.strip()
        print(f"   ✅ 응답: {result}")
        
        # 요약 출력
        client.print_summary()
        return True
        
    except Exception as e:
        print(f"❌ TrackedOpenAIClient 테스트 실패: {e}")
        return False

def main():
    print("🧪 다중 API 키 시스템 통합 테스트")
    print("=" * 50)
    
    # config 로드로 .env 파일도 자동 로드됨
    try:
        from config import OPENAI_API_KEYS
        print(f"📋 .env에서 로드된 키: {len(OPENAI_API_KEYS)}개")
        for i, key in enumerate(OPENAI_API_KEYS, 1):
            print(f"   ✅ Key {i}: ...{key[-8:]}")
    except Exception as e:
        print(f"❌ config 로드 실패: {e}")
        return False
    
    if not OPENAI_API_KEYS:
        print("   ❌ API 키가 설정되지 않았습니다!")
        return False
    
    print(f"\n📊 총 {len(OPENAI_API_KEYS)}개 키 감지됨")
    print(f"📈 예상 처리량: {200_000 * len(OPENAI_API_KEYS):,} TPM")
    
    # 테스트 실행
    tests = [
        ("Config 로딩", test_config),
        ("다중 클라이언트", test_multi_client),
        ("추적 클라이언트", test_tracked_client),
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            success = test_func()
            results.append((test_name, success))
        except Exception as e:
            print(f"❌ {test_name} 테스트 중 예외 발생: {e}")
            results.append((test_name, False))
    
    # 결과 요약
    print("\n" + "=" * 50)
    print("📊 테스트 결과 요약:")
    
    all_passed = True
    for test_name, success in results:
        status = "✅ 통과" if success else "❌ 실패"
        print(f"   {test_name}: {status}")
        if not success:
            all_passed = False
    
    print("\n" + "=" * 50)
    if all_passed:
        print("🎉 모든 테스트 통과! 다중 키 시스템이 정상 작동합니다.")
        print("\n🚀 이제 실험을 실행할 수 있습니다:")
        print("   cd /workspace/Yujin/GIA")
        print("   ./Network-Management-System-main/pipeline_v2/run_full_experiment.sh 10")
    else:
        print("⚠️ 일부 테스트 실패. 설정을 확인해주세요.")
    
    return all_passed

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
