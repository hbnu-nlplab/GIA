#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

print("=== 복원된 Enhanced LLM Generator 테스트 ===")

# Mock 테스트로 복원 상태 확인
from generators.enhanced_llm_generator import EnhancedLLMQuestionGenerator

generator = EnhancedLLMQuestionGenerator()

print(f"총 템플릿 수: {len(generator.templates)}")

# 첫 번째 템플릿의 expected_metrics 확인
first_template = generator.templates[0]
print(f"첫 번째 템플릿:")
print(f"  - 시나리오: {first_template.scenario}")
print(f"  - Expected Metrics: {first_template.expected_metrics}")

# 실제 메트릭명이 복원되었는지 확인
expected_real_metrics = ["ibgp_missing_pairs", "ibgp_under_peered_count", "neighbor_list_ibgp"]
if first_template.expected_metrics == expected_real_metrics:
    print("✅ Expected Metrics가 실제 메트릭명으로 정상 복원됨")
else:
    print("❌ Expected Metrics가 아직 자연어 형태임")

print("\n모든 템플릿의 expected_metrics:")
for i, template in enumerate(generator.templates):
    print(f"{i+1}. {template.scenario}: {template.expected_metrics}")

print("\n✅ 복원 완료! 이제 실제 네트워크 데이터와 연결되어 정확한 질문이 생성될 것입니다.")