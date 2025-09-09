#!/usr/bin/env python3
"""Boolean 정규화 테스트"""

from pipeline_v2.common.evaluation import normalize_boolean_text, calculate_exact_match

def test_boolean_normalization():
    print("🔧 Boolean 정규화 테스트")
    
    # 테스트 케이스들
    test_cases = [
        ("TRUE", "True"),
        ("FALSE", "False"), 
        ("true", "TRUE"),
        ("false", "FALSE"),
        ("Yes", "true"),
        ("No", "false"),
        ("1", "TRUE"),
        ("0", "FALSE"),
    ]
    
    print("\n📊 개별 정규화 테스트:")
    for case1, case2 in test_cases:
        norm1 = normalize_boolean_text(case1)
        norm2 = normalize_boolean_text(case2)
        match = norm1 == norm2
        print(f"  {case1:>5} vs {case2:>5} → {norm1:>5} vs {norm2:>5} → {'✅' if match else '❌'}")
    
    print("\n📊 Exact Match 테스트:")
    predictions = ["TRUE", "False", "true", "YES", "1"]
    ground_truths = ["True", "FALSE", "TRUE", "true", "TRUE"]
    
    em_score = calculate_exact_match(predictions, ground_truths)
    print(f"  Predictions: {predictions}")
    print(f"  Ground Truth: {ground_truths}")
    print(f"  Exact Match Score: {em_score:.4f} (예상: 1.0000)")

if __name__ == "__main__":
    test_boolean_normalization()
