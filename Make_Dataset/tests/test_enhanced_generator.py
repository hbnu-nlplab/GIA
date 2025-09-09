#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from generators.enhanced_llm_generator import EnhancedLLMQuestionGenerator, QuestionComplexity
from data_loader import NetworkFactsLoader

def test_enhanced_generator():
    print("Enhanced LLM Generator 테스트 시작...")
    
    # 데이터 로드
    loader = NetworkFactsLoader()
    facts = loader.load_network_facts("data/network_facts.json")
    print(f"네트워크 데이터 로드 완료: {len(facts.get('devices', []))}개 장비")
    
    # Enhanced Generator 초기화
    generator = EnhancedLLMQuestionGenerator()
    
    # 높은 복잡도 질문만 생성 테스트
    target_complexities = [QuestionComplexity.ANALYTICAL, QuestionComplexity.SYNTHETIC]
    
    print("LLM으로 질문 생성 중...")
    questions = generator.generate_enhanced_questions(
        facts, 
        target_complexities=target_complexities,
        questions_per_template=20
    )
    
    print(f"\n=== 결과 ===")
    print(f"총 생성된 질문 수: {len(questions)}")
    
    if questions:
        print(f"\n첫 번째 질문 예시:")
        print(f"Q: {questions[0].get('question', '')}")
        print(f"A: {questions[0].get('ground_truth', '')}")
        print(f"복잡도: {questions[0].get('complexity', '')}")
        print(f"페르소나: {questions[0].get('persona', '')}")
    
    print("\n테스트 완료!")

if __name__ == "__main__":
    test_enhanced_generator()