import json

# 파일 로드
with open("../data/llm_answer_revised/llm_answer_merged.json", "r") as f:
    file1 = json.load(f)

with open("../data/llm_answer_revised/llm_answer_gpt5o-mini.json", "r") as f:
    file2 = json.load(f)

# with open("../data/llm_answer_revised/llm_answer_gpt5-mini.json", "r") as f:
#     file3 = json.load(f)

# question 기준으로 빠르게 접근할 수 있도록 dict로 변환
dict2 = {item["question"]: item["gpt-5-mini"] for item in file2}
# dict3 = {item["question"]: item["gpt-5-mini"] for item in file3}

merged_data = []

for item in file1:
    q = item["question"]

    data = {
        "question": q,
        "gold_answer": item["gold_answer"],
        "gpt-4o-mini": item["gpt-4o-mini"],
        "gpt-4o": item["gpt-4o"],
        "gpt-5-mini": dict2.get(q, None),
        # "gpt-5": dict2.get(q, None)
    }

    merged_data.append(data)

with open("../data/llm_answer_revised/llm_answer_merged.json", "w") as f:
    json.dump(merged_data, f, indent=2, ensure_ascii=False)