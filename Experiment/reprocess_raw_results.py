"""
기존에 생성된 raw 결과 파일에서 답변을 재추출하는 스크립트
GPT-OSS-20B처럼 불필요한 텍스트를 출력한 결과를 정제합니다.
"""

import json
import re
import argparse
from pathlib import Path


def extract_answer_from_raw(raw_text: str, answer_type: str) -> str:
    """
    Raw 응답에서 실제 답변만 추출
    
    전략:
    1. </think> 태그 이후의 첫 번째 유의미한 라인 추출
    2. "The answer is", "Based on", "Analysis" 등의 설명 텍스트 제거
    3. JSON 형식 답변 파싱 시도
    """
    # 1. </think> 태그 이후 텍스트 추출
    if '</think>' in raw_text:
        after_think = raw_text.split('</think>', 1)[-1].strip()
    else:
        after_think = raw_text.strip()
    
    # 2. 불필요한 프리픽스 제거
    prefixes_to_remove = [
        r'^analysis\s*',
        r'^we need to\s*',
        r'^based on\s*',
        r'^the answer is\s*',
        r'^answer:\s*',
        r'^result:\s*',
        r'^\**answer\**:\s*',
        r'^to answer this\s*',
        r'^looking at\s*',
    ]
    
    cleaned = after_think
    for prefix in prefixes_to_remove:
        cleaned = re.sub(prefix, '', cleaned, flags=re.IGNORECASE)
    
    # 3. 첫 번째 라인만 추출 (여러 줄 설명이 있을 경우)
    lines = [l.strip() for l in cleaned.split('\n') if l.strip()]
    if not lines:
        return "null"
    
    first_line = lines[0]
    
    # 4. 타입별 특수 처리
    if answer_type == "set":
        # JSON 배열 파싱 시도
        match = re.search(r'\[.*?\]', first_line)
        if match:
            try:
                parsed = json.loads(match.group(0))
                return json.dumps(parsed, ensure_ascii=False)
            except:
                pass
        return "[]"
    
    elif answer_type == "map":
        # JSON 객체 파싱 시도
        match = re.search(r'\{.*?\}', first_line, re.DOTALL)
        if match:
            try:
                parsed = json.loads(match.group(0))
                return json.dumps(parsed, ensure_ascii=False)
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
        return text


def reprocess_results(input_file: str, output_file: str = None):
    """
    Raw 결과 파일을 읽어서 답변을 재추출하고 저장
    """
    print(f"📂 Loading: {input_file}")
    
    with open(input_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    results = data.get('results', [])
    total = len(results)
    
    print(f"📊 Processing {total} samples...")
    
    # 재처리
    cleaned_count = 0
    for i, entry in enumerate(results):
        raw_pred = entry.get('raw_pred', '')
        answer_type = entry.get('answer_type', 'text')
        
        # 기존 pred가 없거나 raw_pred와 같으면 재추출
        if 'pred' not in entry or entry['pred'] == raw_pred:
            cleaned_pred = extract_answer_from_raw(raw_pred, answer_type)
            entry['pred'] = cleaned_pred
            cleaned_count += 1
        
        if (i + 1) % 100 == 0:
            print(f"  ⏳ Progress: {i+1}/{total}")
    
    print(f"✅ Cleaned {cleaned_count} predictions")
    
    # 출력 파일명 결정
    if output_file is None:
        input_path = Path(input_file)
        output_file = str(input_path.parent / f"{input_path.stem}_cleaned.json")
    
    # 저장
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    
    print(f"💾 Saved to: {output_file}")
    print(f"\n🎯 다음 명령어로 재분석하세요:")
    print(f"   python analyze_results.py \"{output_file}\"")


def main():
    parser = argparse.ArgumentParser(
        description="기존 raw 결과 파일에서 답변을 재추출"
    )
    parser.add_argument(
        "input_file",
        help="입력 JSON 파일 경로 (예: results_raw_20251228_180256.json)"
    )
    parser.add_argument(
        "--output",
        help="출력 JSON 파일 경로 (기본: {input}_cleaned.json)",
        default=None
    )
    
    args = parser.parse_args()
    
    reprocess_results(args.input_file, args.output)


if __name__ == "__main__":
    main()

