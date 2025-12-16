import json
import sys
import os
from openai import OpenAI


sys.path.append('../')
from load_env import load_api_key

QUESTION_DIR = "../data/qa/qa_dataset.json"
OUTPUT_DIR = "../data/qa/paragraphs.json"

def gen_paragraph():
    api_key = load_api_key()

    if not api_key:
        print("API Key not found")
        return

    client = OpenAI(api_key=api_key)
    
    try:
        with open(QUESTION_DIR, 'r', encoding='utf-8') as f:
            qa_data = json.load(f)
    except FileNotFoundError:
        print(f"File not found: {QUESTION_DIR}")
        return

    results = []
    
    for item in qa_data[:5]:
        question = item.get('question', '')
        if not question:
            continue
            
        prompt = '''
        You are a network expert. Write a paragraph about the question based on your knowledge.
        Write [None] if you cannot write a factual passage.
        '''

        try:
            completion = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": prompt},
                    {"role": "user", "content": question}
                ]
            )
            
            answer = completion.choices[0].message.content
            print(f"Processed: {question}")
            
            results.append({
                "question": question,
                "paragraph": answer
            })
            
        except Exception as e:
            print(f"Error for '{question}': {e}")
            continue

    with open(OUTPUT_DIR, 'w', encoding='utf-8') as f:
        json.dump(results, f, ensure_ascii=False, indent=4)
    print(f"Done. Results saved to {OUTPUT_DIR}")

if __name__ == "__main__":
    gen_paragraph()