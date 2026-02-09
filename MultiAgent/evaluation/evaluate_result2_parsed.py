
import sys
import json
import os
import re
from collections import defaultdict

# Add the directory containing the scorer
sys.path.append("/home/leehj/network/GIA/Experiment/code/NetConfigQA2")

try:
    from analyze_results_netconfigqa import NetConfigQAScorer, canonical_answer_type
except ImportError as e:
    print(f"Error importing scorer: {e}")
    sys.exit(1)

# Copied from Experiment/code/NetConfigQA2/run_netconfigqa_eval_vllm.py
def extract_answer_from_raw(raw_text: str, answer_type: str) -> str:
    """
    GPT-OSS-20B와 같이 불필요한 텍스트를 출력하는 모델의 응답에서 답만 추출
    """
    if raw_text is None:
        return ""
        
    original_text = raw_text  # Keep for fallback
    
    # 1. </think> 태그 및 구분자 이후 텍스트 추출
    if '</think>' in raw_text:
        after_think = raw_text.split('</think>')[-1].strip()
    elif 'assistantfinal' in raw_text:
        # Handle multiple assistantfinal - take LAST one
        parts = raw_text.split('assistantfinal')
        after_think = parts[-1].strip()
        
        # Handle 'assistantfinal think' pattern
        if after_think.startswith('think'):
            after_think = after_think[5:].strip()
            
            # If long explanation without structured answer, extract from original
            if len(after_think) > 80 and not any(after_think.strip().startswith(c) for c in ['{', '[', '"']):
                # Look for last JSON object
                json_matches = list(re.finditer(r'\{[^{}]+:[^{}]+\}', original_text))
                if json_matches:
                    after_think = json_matches[-1].group(0)
                # Look for last JSON array
                elif re.search(r'\[[^\[\]]+\]', original_text):
                    array_matches = list(re.finditer(r'\[[^\[\]]+\]', original_text))
                    after_think = array_matches[-1].group(0)
                # Extract number from explanation
                elif len(after_think) > 100:
                    sentences = after_think.split('.')
                    if sentences:
                        last_sent = sentences[-1].strip()
                        num_match = re.search(r'\b(\d+)\b', last_sent)
                        if num_match:
                            after_think = num_match.group(1)
        
    elif '<think>' in raw_text:
        after_think = raw_text.split('<think>')[0].strip()
    else:
        after_think = raw_text.strip()
    
    # 2. 불필요한 태그 제거 (Facts JSON 응답에서 <p2> 같은 태그 제거)
    # Multiple passes to ensure complete removal
    for _ in range(3):  # Repeat 3 times to handle nested/multiple tags
        after_think = re.sub(r'<([^>]+)>', r'\1', after_think)  # <p2> → p2
        after_think = after_think.strip()
    
    # 3. 불필요한 프리픽스 제거
    prefixes_to_remove = [
        r'^analysis\s*',
        r'^we need to\s*',
        r'^we need\s*',
        r'^based on\s*',
        r'^the answer is\s*',
        r'^answer:\s*',
        r'^result:\s*',
        r'^\**answer\**:\s*',
        r'^json\s*',
        r'^set\s*',
        r'^map\s*',
        r'^text\s*',
        r'^device:\s*',
        r'^router:\s*',
        r'^hostname:\s*',
    ]
    
    cleaned = after_think
    for prefix in prefixes_to_remove:
        cleaned = re.sub(prefix, '', cleaned, flags=re.IGNORECASE)
    
    # 4. 첫 번째 라인만 추출 (여러 줄 설명이 있을 경우)
    lines = [l.strip() for l in cleaned.split('\n') if l.strip()]
    if not lines:
        return "null"
    
    first_line = lines[0]
    
    # 5. "We need to check..." 같은 설명문 감지 및 처리
    if first_line.lower().startswith('we ') and len(first_line) > 50:
        # JSON 값이나 숫자 추출 시도
        if answer_type in ["number", "numeric"]:
            num_match = re.search(r'\b(\d+\.?\d*)\b', first_line)
            if num_match:
                first_line = num_match.group(1)
        elif answer_type == "text":
            # 디바이스명이나 값 추출 (예: "We need OS version of p2" → "p2")
            device_match = re.search(r'of\s+(\w+)', first_line)
            if device_match:
                first_line = device_match.group(1)
    
    # 6. 타입별 특수 처리
    if answer_type == "set":
        # JSON 배열 파싱 시도
        match = re.search(r'\[.*?\]', first_line)
        if match:
            try:
                parsed = json.loads(match.group(0))
                return json.dumps(parsed)
            except:
                pass
        return "[]"
    
    elif answer_type == "map":
        # JSON 객체 파싱 시도
        match = re.search(r'\{.*?\}', first_line)
        if match:
            try:
                parsed = json.loads(match.group(0))
                return json.dumps(parsed)
            except:
                pass
        return "{}"
    
    elif answer_type in ["number", "numeric"]:
        # 숫자만 추출
        match = re.search(r'-?\d+\.?\d*', first_line)
        if match:
            return match.group(0)
        return "0"
    
    elif answer_type == "boolean":
        # true/false 추출
        lower = first_line.lower()
        if 'true' in lower or 'yes' in lower:
            return "true"
        elif 'false' in lower or 'no' in lower:
            return "false"
        return "false"
    
    else:  # text
        # 따옴표나 불필요한 문장 제거
        text = first_line.strip('"\'')
        # 문장 형태면 첫 단어/구문만 추출
        if len(text.split()) > 5:
            # 너무 긴 설명이면 첫 단어만
            text = text.split()[0]
        # Cisco-specific: 'login local' -> 'local'
        if text.lower() == 'login local':
            text = 'local'
        return text

def evaluate_file(file_path):
    print(f"Evaluating {file_path} using extracted parsing logic...")
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error reading file: {e}")
        return

    # Handle different json structures
    if isinstance(data, dict) and "results" in data:
        items = data["results"]
    elif isinstance(data, list):
        items = data
    else:
        print("Unknown JSON format")
        return

    scorer = NetConfigQAScorer()
    
    results = []
    print(f"Total items: {len(items)}")
    
    for idx, item in enumerate(items):
        question = item.get('question')
        gold = item.get('gold_answer')
        
        # We want to measure debate2_answer
        raw_pred = item.get('debate2_answer')
        if raw_pred is None:
            raw_pred = ""
            
        atype = item.get('answer_type')
        norm_type = canonical_answer_type(atype)
        
        # 1. Parse using extracting logic from run_netconfigqa_eval_vllm.py
        parsed_pred = extract_answer_from_raw(str(raw_pred), norm_type)
        
        # 2. Score using NetConfigQAScorer (which also does some cleaning)
        metrics = scorer.score(parsed_pred, str(gold), norm_type)
        prediction_score = metrics['score']
        
        results.append({
            'type': norm_type,
            'score': prediction_score,
            'gold': gold,
            'raw_pred': raw_pred,
            'parsed_pred': parsed_pred
        })

    # Aggregation
    by_type = defaultdict(lambda: {'sum': 0, 'count': 0})
    total_score = 0
    total_count = 0
    
    for r in results:
        t = r['type']
        s = r['score']
        by_type[t]['sum'] += s
        by_type[t]['count'] += 1
        total_score += s
        total_count += 1
        
    print("-" * 40)
    print(f"Overall Accuracy: {total_score/total_count*100:.2f}% ({total_count} samples)")
    print("-" * 40)
    print("Accuracy by Type:")
    for t in sorted(by_type.keys()):
        stats = by_type[t]
        avg = stats['sum'] / stats['count'] * 100
        print(f"  {t:<10}: {avg:.2f}% ({stats['count']} samples)")
    print("-" * 40)

if __name__ == "__main__":
    target_file = "/home/leehj/network/GIA/MultiAgent/data/debate_results/full_w_context4/netconfig_result2.json"
    if os.path.exists(target_file):
        evaluate_file(target_file)
    else:
        print(f"File not found: {target_file}")
