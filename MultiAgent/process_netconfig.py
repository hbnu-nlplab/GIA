import json
import os

# 경로 설정
original_file = '/home/leehj/network/GIA/MultiAgent/data/passages/full_w_context/netconfig_en.json'
output_file = '/home/leehj/network/GIA/MultiAgent/data/passages/full_w_context/netconfig_en2.json'

# 데이터 로드
with open(original_file, 'r', encoding='utf-8') as f:
    original_data = json.load(f)

result = []
total_count = len(original_data)

for i in range(total_count):
    orig_item = original_data[i]
    
    formatted_item = {
        "id": i,
        "question": orig_item.get('question', ''),
        "gold_answer": str(orig_item.get('gold_answer', '')),
        "passage": orig_item.get('level', ''), 
        "answer_type": orig_item.get('answer_type', ''),
        "answer_status": orig_item.get('answer_status', '')
    }
    result.append(formatted_item)

# 결과 저장
os.makedirs(os.path.dirname(output_file), exist_ok=True)
with open(output_file, 'w', encoding='utf-8') as f:
    json.dump(result, f, indent=4, ensure_ascii=False)

print(f"✅ 순차 병합 완료!")
print(f"📊 총 {len(result)}개의 아이템이 저장되었습니다.")