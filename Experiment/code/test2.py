import json
import re

INPUT_JSON = "../data/llm_answer_revised/llm_answer_netbench_gpt4o-mini.json"
OUTPUT_JSON = "../data/llm_answer_revised/llm_answer_netbench_gpt4o-mini.cleaned.json"


def remove_code_fence_anywhere(text):
    if not isinstance(text, str):
        return text

    text = re.sub(r"```[a-zA-Z]*\n?", "", text)
    text = re.sub(r"\n?```", "", text)

    return text.strip()


def preprocess_llm_output():
    with open(INPUT_JSON, "r", encoding="utf-8") as f:
        data = json.load(f)

    processed = []

    for item in data:
        new_item = {
            "question": item.get("question", ""),
            "gold_answer": item.get("gold_answer", "")
        }

        if "gpt-4o-mini" in item:
            new_item["gpt-4o-mini"] = remove_code_fence_anywhere(
                item["gpt-4o-mini"]
            )

        processed.append(new_item)

    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(processed, f, ensure_ascii=False, indent=2)

    print(f"[+] 전처리 완료: {OUTPUT_JSON}")


if __name__ == "__main__":
    preprocess_llm_output()