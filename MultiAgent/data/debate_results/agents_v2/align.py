import json

# file_path="/home/leehj/network/GIA/MultiAgent/data/debate_results/agents_v2/full_w_context6/netbench/netbench_result.json"
file_path="/home/leehj/network/GIA/MultiAgent/data/debate_results/agents_v2/full_w_context6/netconfig/netconfig_result.json"

with open(file_path, 'r') as f:
    data = json.load(f)

# id가 int형이나 str형인 것에 대비해 처리
def get_id(x):
    try:
        return int(x.get('id', 0))
    except ValueError:
        return x.get('id', '')

data.sort(key=get_id)

with open(file_path, 'w') as f:
    json.dump(data, f, indent=4, ensure_ascii=False)

print('Sorted successfully.')

# Missing ID 찾기
ids = []
for item in data:
    val = get_id(item)
    if isinstance(val, int):
        ids.append(val)

if ids:
    min_id = min(ids)
    max_id = max(ids)
    expected = set(range(min_id, max_id + 1))
    actual = set(ids)
    missing = sorted(list(expected - actual))
    if missing:
        print(f"빠진 ID 개수: {len(missing)}개")
        print(f"빠진 ID 목록: {missing}")
    else:
        print("빠진 ID가 없습니다.")
else:
    print("정수형 ID를 찾을 수 없습니다.")
