import json
import os
import re
import sys
import time
from pathlib import Path
from openai import OpenAI

PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_ROOT))

from config.load_env import load_api_key

CURRENT_DIR = Path(__file__).resolve().parent
DATA_PATH = CURRENT_DIR / "netconfig.json"
FINAL_OUTPUT_FILE = CURRENT_DIR / "netconfig_en.json"

MODEL = "gpt-4o-mini"

PROMPT_TEMPLATE = """
Your job is to translate the following Question and Answer from Korean into English.

Question: {question}
Answer: {answer}

Translation Format:
- Question: [Translated Question]
- Answer: [Translated Answer]
"""

def load_data():
    if not DATA_PATH.exists():
        raise FileNotFoundError(f"Data file not found at {DATA_PATH}")
    with open(DATA_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def parse_response(response_text):
    question_match = re.search(r'-\s*Question:\s*(.*)', response_text, re.IGNORECASE)
    answer_match = re.search(r'-\s*Answer:\s*(.*)', response_text, re.IGNORECASE)

    q_en = question_match.group(1).strip() if question_match else ""
    a_en = answer_match.group(1).strip() if answer_match else ""
    return q_en, a_en

def translate_item(client, question, answer):
    content = PROMPT_TEMPLATE.format(question=question, answer=answer)

    resp = client.chat.completions.create(
        model=MODEL,
        messages=[
            {"role": "system", "content": "You are a helpful assistant that translates technical content into English."},
            {"role": "user", "content": content}
        ],
        temperature=0.0,
        max_tokens=1000
    )

    return resp.choices[0].message.content

def process_all(client, data):
    final_items = []
    questions = data.get("questions", [])

    for idx, item in enumerate(questions, 1):
        question = item.get("question", "")
        answer = item.get("answer", "")
        item_id = item.get("id")

        if not question:
            final_items.append(item)
            continue

        print(f"[{idx}/{len(questions)}] Translating id={item_id}")

        try:
            response_text = translate_item(client, question, answer)
            q_en, a_en = parse_response(response_text)

            new_item = item.copy()
            new_item["question_en"] = q_en
            new_item["answer_en"] = a_en
            new_item["translation_raw"] = response_text

            final_items.append(new_item)

            time.sleep(0.2)  # rate limit 보호용 (필요 없으면 제거)

        except Exception as e:
            print(f"Failed id={item_id}: {e}")
            final_items.append(item)

    return {"questions": final_items}

def main():
    try:
        api_key = load_api_key()
    except Exception:
        api_key = os.getenv("OPENAI_API_KEY")

    if not api_key:
        print("OPENAI_API_KEY not set")
        return

    client = OpenAI(api_key=api_key)

    data = load_data()
    final_data = process_all(client, data)

    with open(FINAL_OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(final_data, f, ensure_ascii=False, indent=2)

    print(f"Saved: {FINAL_OUTPUT_FILE}")

if __name__ == "__main__":
    main()