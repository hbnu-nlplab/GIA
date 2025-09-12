#!/usr/bin/env python3
"""
Basic Dataset만 생성하는 전용 스크립트
Rule-based 질문만으로 구성된 데이터셋을 빠르게 생성합니다.
"""

from integrated_pipeline import generate_basic_dataset_only

if __name__ == "__main__":
    print("📋 Basic Dataset 생성 스크립트")
    print("=" * 50)
    
    try:
        dataset = generate_basic_dataset_only()
        print("\n🎉 성공적으로 완료되었습니다!")
        
    except KeyboardInterrupt:
        print("\n⚠️  사용자에 의해 중단되었습니다.")
    except Exception as e:
        print(f"\n❌ 오류 발생: {e}")
        raise 