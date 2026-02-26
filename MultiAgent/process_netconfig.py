import json
import os

# 경로 설정
original_file = '/home/leehj/network/GIA/MultiAgent/data/original/telequad.json'
existing_passage_file = '/home/leehj/network/GIA/MultiAgent/data/passages/full_w_context/telequad_passages.json'
output_file = '/home/leehj/network/GIA/MultiAgent/data/passages/full_w_context/telequad_passage_final.json'

# 데이터 로드
with open(original_file, 'r', encoding='utf-8') as f:
    original_data = json.load(f)

with open(existing_passage_file, 'r', encoding='utf-8') as f:
    existing_passages = json.load(f)

# 데이터 병합 (두 리스트의 인덱스를 맞춤)
result = []
# 두 리스트 중 더 짧은 길이를 기준으로 반복 (인덱스 에러 방지)
total_count = min(len(original_data), len(existing_passages))

for i in range(total_count):
    orig_item = original_data[i]
    pass_item = existing_passages[i]
    
    formatted_item = {
        "id": i,
        "question": orig_item.get('question', ''),
        "gold_answer": str(orig_item.get('gold_answer', '')),
        "passage": pass_item.get('passage', ''), # 매칭 없이 같은 순서의 passage를 가져옴
        "context": orig_item.get('gold_context', '')
    }
    result.append(formatted_item)

# 결과 저장
os.makedirs(os.path.dirname(output_file), exist_ok=True)
with open(output_file, 'w', encoding='utf-8') as f:
    json.dump(result, f, indent=4, ensure_ascii=False)

print(f"✅ 순차 병합 완료!")
print(f"📊 총 {len(result)}개의 아이템이 저장되었습니다.")