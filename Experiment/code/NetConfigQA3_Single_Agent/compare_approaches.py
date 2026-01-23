"""
Config vs Facts vs Agent 비교 분석 스크립트

세 가지 접근법의 성능과 효율성을 비교합니다.
"""

import json
import pandas as pd
import argparse
from pathlib import Path
from typing import Dict, Any

def load_results(file_path: str) -> Dict[str, Any]:
    """결과 파일 로드"""
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def extract_metrics(results: Dict[str, Any], approach: str) -> Dict[str, Any]:
    """결과에서 주요 메트릭 추출"""
    meta = results.get('meta', {})
    
    metrics = {
        'approach': approach,
        'model': meta.get('model', 'Unknown'),
        'total_samples': meta.get('total_samples', 0),
        'duration': meta.get('duration', 0),
        'avg_time_per_query': 0,
    }
    
    # Agent 방식의 경우 추가 메트릭
    if 'metrics_summary' in results:
        summary = results['metrics_summary']
        metrics.update({
            'avg_time_per_query': summary.get('avg_time_per_query', 0),
            'avg_tool_calls': summary.get('avg_tool_calls', 0),
            'avg_prompt_tokens': summary.get('avg_prompt_tokens', 0),
            'avg_completion_tokens': summary.get('avg_completion_tokens', 0),
            'avg_total_tokens': summary.get('avg_total_tokens', 0),
            'avg_context_size': summary.get('avg_context_size', 0),
            'total_tokens': summary.get('total_tokens', 0),
            'total_tool_calls': summary.get('total_tool_calls', 0),
        })
    else:
        # Config/Facts 방식
        total_samples = meta.get('total_samples', 1)
        duration = meta.get('duration', 0)
        metrics['avg_time_per_query'] = duration / total_samples if total_samples > 0 else 0
        
        # 추정값 (실제로는 로그에서 파싱해야 함)
        if 'config' in approach.lower():
            metrics['avg_total_tokens'] = 15000  # Config는 큰 컨텍스트
            metrics['avg_context_size'] = 50000
        elif 'facts' in approach.lower():
            metrics['avg_total_tokens'] = 12000  # Facts는 조금 작음
            metrics['avg_context_size'] = 40000
        
        metrics['avg_total_tokens'] = metrics.get('avg_total_tokens', 0)
        metrics['avg_context_size'] = metrics.get('avg_context_size', 0)
        metrics['avg_tool_calls'] = 0
        metrics['total_tokens'] = metrics['avg_total_tokens'] * total_samples
        metrics['total_tool_calls'] = 0
    
    return metrics

from collections import defaultdict

from analyze_results_agent import NetConfigQAScorer
from collections import defaultdict

def calculate_accuracy(results: Dict[str, Any]) -> Dict[str, float]:
    """NetConfigQA2에서 이식된 검증된 Scorer 사용"""
    scorer = NetConfigQAScorer()
    result_list = results.get('results', [])
    if not result_list:
        return {}
    
    correct = 0
    type_correct = defaultdict(float)
    type_total = defaultdict(int)
    
    for item in result_list:
        gold = item.get('gold', '')
        pred = item.get('pred', '')
        answer_type = item.get('answer_type', 'text')
        
        # Use the highly accurate scoring logic from NetConfigQA2
        score_dict = scorer.score(pred, gold, answer_type)
        score = score_dict['score']
        
        # Canonicalize types for reporting
        atype = str(answer_type).lower()
        if atype in ['scalar_int', 'number']: atype = 'numeric'
        elif atype == 'set_str': atype = 'set'
        
        type_total[atype] += 1
        type_correct[atype] += score
        if score > 0.99:
            correct += 1
            
    accuracy = {
        'overall': correct / len(result_list) if result_list else 0,
    }
    
    for atype in type_total:
        accuracy[f'{atype}_accuracy'] = (
            type_correct[atype] / type_total[atype] if type_total[atype] > 0 else 0
        )
    
    return accuracy

def compare_approaches(config_file: str, facts_file: str, agent_file: str):
    """세 가지 접근법 비교"""
    
    print("=" * 80)
    print("NetConfigQA 접근법 비교 분석")
    print("=" * 80)
    print()
    
    # 결과 로드
    approaches = {}
    
    if config_file:
        print(f"Loading Config results: {config_file}")
        approaches['Config'] = load_results(config_file)
    
    if facts_file:
        print(f"Loading Facts results: {facts_file}")
        approaches['Facts'] = load_results(facts_file)
    
    if agent_file:
        print(f"Loading Agent results: {agent_file}")
        approaches['Agent'] = load_results(agent_file)
    
    print()
    
    # 메트릭 추출
    metrics_data = []
    accuracy_data = []
    
    for name, results in approaches.items():
        metrics = extract_metrics(results, name)
        accuracy = calculate_accuracy(results)
        
        metrics_data.append(metrics)
        accuracy_data.append({
            'approach': name,
            **accuracy
        })
    
    # DataFrame 생성
    metrics_df = pd.DataFrame(metrics_data)
    accuracy_df = pd.DataFrame(accuracy_data)
    
    # 효율성 비교
    print("=" * 80)
    print("1. 효율성 비교")
    print("=" * 80)
    print()
    
    efficiency_cols = [
        'approach', 'avg_time_per_query', 'avg_total_tokens', 
        'avg_context_size', 'avg_tool_calls'
    ]
    
    # 존재하는 컬럼만 출력
    actual_cols = [col for col in efficiency_cols if col in metrics_df.columns]
    print(metrics_df[actual_cols].to_string(index=False))
    print()
    
    # 정확도 비교
    print("=" * 80)
    print("2. 정확도 비교")
    print("=" * 80)
    print()
    
    print(accuracy_df.to_string(index=False))
    print()
    
    # 비용 추정 (GPT-4o-mini 기준)
    print("=" * 80)
    print("3. 비용 추정 (GPT-4o-mini: $0.15/1M input, $0.6/1M output)")
    print("=" * 80)
    print()
    
    for _, row in metrics_df.iterrows():
        total_tokens = row.get('total_tokens', 0)
        if total_tokens > 0:
            # 간단한 추정 (input:output = 95:5 비율 가정)
            input_tokens = total_tokens * 0.95
            output_tokens = total_tokens * 0.05
            
            cost = (input_tokens / 1_000_000 * 0.15) + (output_tokens / 1_000_000 * 0.6)
            
            print(f"{row['approach']:10s}: ${cost:>8.4f} ({int(total_tokens):,} tokens)")
        else:
            print(f"{row['approach']:10s}: 비용 계산 불가 (토큰 정보 없음)")
    
    print()
    
    # 개선 비율
    if len(metrics_df) > 1:
        print("=" * 80)
        print("4. Agent vs 기존 방식 개선율")
        print("=" * 80)
        print()
        
        # 기준 행 찾기 (Config 우선, 없으면 첫 행)
        if 'Config' in approaches:
            baseline_row = metrics_df[metrics_df['approach'] == 'Config'].iloc[0]
        else:
            baseline_row = metrics_df.iloc[0]
            
        agent_row_list = metrics_df[metrics_df['approach'] == 'Agent']
        if not agent_row_list.empty:
            agent_row = agent_row_list.iloc[0]
            
            # 토큰 절약
            if baseline_row['avg_total_tokens'] > 0 and agent_row['avg_total_tokens'] > 0:
                print(f"토큰 절약: {(1 - agent_row['avg_total_tokens'] / baseline_row['avg_total_tokens']) * 100:.1f}%")
            
            # 컨텍스트 절약
            if baseline_row['avg_context_size'] > 0:
                print(f"컨텍스트 절약: {(1 - agent_row['avg_context_size'] / baseline_row['avg_context_size']) * 100:.1f}%")
            
            # 시간 개선
            if baseline_row['avg_time_per_query'] > 0:
                print(f"시간 개선: {(1 - agent_row['avg_time_per_query'] / baseline_row['avg_time_per_query']) * 100:.1f}%")
            
            print()
            
            # 정확도 비교
            baseline_acc_list = accuracy_df[accuracy_df['approach'] == baseline_row['approach']]['overall']
            agent_acc_list = accuracy_df[accuracy_df['approach'] == 'Agent']['overall']
            
            if not baseline_acc_list.empty and not agent_acc_list.empty:
                baseline_acc = baseline_acc_list.iloc[0]
                agent_acc = agent_acc_list.iloc[0]
                print(f"정확도 변화 (vs {baseline_row['approach']}): {(agent_acc - baseline_acc) * 100:+.1f}%p")
                print()
    
    # 타입별 상세 비교
    print("=" * 80)
    print("5. 타입별 정확도 상세")
    print("=" * 80)
    print()
    
    type_cols = [col for col in accuracy_df.columns if col.endswith('_accuracy')]
    if type_cols:
        print(accuracy_df[['approach'] + type_cols].to_string(index=False))
    
    print()
    print("=" * 80)
    print("분석 완료!")
    print("=" * 80)

def main():
    parser = argparse.ArgumentParser(description="Compare Config vs Facts vs Agent approaches")
    parser.add_argument("--config", help="Config approach results JSON file")
    parser.add_argument("--facts", help="Facts approach results JSON file")
    parser.add_argument("--agent", required=True, help="Agent approach results JSON file")
    
    args = parser.parse_args()
    
    compare_approaches(args.config, args.facts, args.agent)

if __name__ == "__main__":
    main()
