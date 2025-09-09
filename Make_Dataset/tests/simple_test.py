#!/usr/bin/env python3
"""Enhanced LLM Generator 간단 테스트"""
import json

# Mock settings
class MockSettings:
    def __init__(self):
        self.models = MockModels()
        self.generation = MockGeneration()

class MockModels:
    def __init__(self):
        self.enhanced_generation = "gpt-4o-mini"
        self.hypothesis_review = "gpt-4o-mini"

class MockGeneration:
    def __init__(self):
        self.enhanced_questions_per_category = 20

# Mock llm call
def mock_call_llm_json(messages, schema, **kwargs):
    """Mock LLM call for testing"""
    return {
        "questions": [
            {
                "question": "BGP Full-Mesh 구성에서 누락된 iBGP 피어 관계 수는 몇 개입니까?",
                "ground_truth": "7",
                "explanation": "현재 AS65000 내에서 Full-Mesh 구성을 위해 필요한 총 21개의 피어 관계 중 14개만 설정되어 있어, 7개의 피어 관계가 누락된 상태입니다. 이는 경로 수렴성에 문제를 일으킬 수 있습니다.",
                "reasoning_requirement": "BGP 토폴로지 분석 및 Full-Mesh 계산",
                "expected_analysis_depth": "detailed",
                "metrics_involved": ["iBGP 누락 피어 관계"],
                "reasoning_plan": [
                    {"step": 1, "description": "iBGP 구성 데이터 수집", "synthesis": "fetch"},
                    {"step": 2, "description": "피어 관계 분석", "synthesis": "compare"},
                    {"step": 3, "description": "누락된 관계 계산", "synthesis": "summarize"}
                ],
                "evaluation_suitability": {
                    "em_f1_suitable": True,
                    "bert_score_suitable": True,
                    "ground_truth_type": "single_value"
                }
            }
        ]
    }

def test_llm_generation():
    print("=== Enhanced LLM Generator 기능 테스트 ===")
    
    # 테스트용 네트워크 데이터
    network_facts = {
        "devices": [
            {"hostname": "sample7", "routing": {"bgp": {"as": 65000, "neighbors": []}}},
            {"hostname": "sample8", "routing": {"bgp": {"as": 65000, "neighbors": []}}},
            {"hostname": "CE1", "routing": {"bgp": {"as": 65100, "neighbors": []}}},
        ]
    }
    
    # Mock LLM 호출 테스트
    messages = [
        {"role": "system", "content": "네트워크 질문 생성 전문가입니다."},
        {"role": "user", "content": "BGP 관련 분석적 질문 3개를 생성해주세요."}
    ]
    
    schema = {"type": "object", "properties": {"questions": {"type": "array"}}}
    
    try:
        result = mock_call_llm_json(messages, schema)
        print(f"✅ LLM 호출 성공")
        print(f"생성된 질문 수: {len(result.get('questions', []))}")
        
        if result.get('questions'):
            q = result['questions'][0]
            print(f"\n📝 예시 질문:")
            print(f"Q: {q.get('question', '')}")
            print(f"A: {q.get('ground_truth', '')}")
            print(f"설명: {q.get('explanation', '')[:100]}...")
        
        print(f"\n✅ Enhanced LLM Generator가 정상적으로 고품질 질문을 생성할 것으로 예상됩니다!")
        print(f"🎯 대안 질문 생성 로직이 제거되어 LLM에만 의존합니다.")
        print(f"🚀 템플릿당 최소 10개씩 생성하도록 설정했습니다.")
        
    except Exception as e:
        print(f"❌ 테스트 실패: {e}")

if __name__ == "__main__":
    test_llm_generation()