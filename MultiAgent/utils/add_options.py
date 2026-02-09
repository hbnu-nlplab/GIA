
import json
import os
from pathlib import Path

BASE_DIR = Path("/home/leehj/network/GIA/MultiAgent")
PASSAGE_FILE = BASE_DIR / "data" / "passages" / "full_w_context" / "teleqna_passage.json"
ORIGINAL_FILE = BASE_DIR / "data" / "original" / "teleqna_original.json"

def process_options(item):
    # Extract options keys like "option 1", "option 2", etc.
    raw_options = {k: v for k, v in item.items() if k.startswith("option")}
    # Sort them numerically
    sorted_keys = sorted(
        raw_options.keys(), 
        key=lambda x: int(x.split()[-1]) if x.split()[-1].isdigit() else 999
    )
    # Format: "option 1: Value"
    options_list = [f"{key}: {raw_options[key]}" for key in sorted_keys]
    return "\n".join(options_list)

def main():
    if not PASSAGE_FILE.exists():
        print(f"Error: {PASSAGE_FILE} does not exist.")
        return
    if not ORIGINAL_FILE.exists():
        print(f"Error: {ORIGINAL_FILE} does not exist.")
        return

    print("Loading files...")
    with open(PASSAGE_FILE, 'r', encoding='utf-8') as f:
        passage_data = json.load(f)

    with open(ORIGINAL_FILE, 'r', encoding='utf-8') as f:
        original_data = json.load(f)

    # Create a lookup map from question text to options string
    # original_data is a dict: {"question 0": {...}, "question 1": {...}}
    question_to_options = {}
    
    # Handle the structure of original_data
    items_to_process = []
    if isinstance(original_data, dict):
        items_to_process = original_data.values()
    elif isinstance(original_data, list):
        items_to_process = original_data
        
    for item in items_to_process:
        q_text = item.get('question', '').strip()
        if q_text:
            options_str = process_options(item)
            question_to_options[q_text] = options_str

    print(f"Loaded {len(question_to_options)} questions from original data.")

    # Update passage data
    updated_count = 0
    for entry in passage_data:
        q_text = entry.get('question', '').strip()
        if q_text in question_to_options:
            entry['options'] = question_to_options[q_text]
            updated_count += 1
        else:
            # Fallback for slight whitespace differences or encoding issues?
            # Try straightforward match first.
            pass
            
            # If strict match fails, we might warn, but let's assume strict match works for now.
    
    print(f"Updated {updated_count} entries out of {len(passage_data)}.")

    # Save back
    with open(PASSAGE_FILE, 'w', encoding='utf-8') as f:
        json.dump(passage_data, f, ensure_ascii=False, indent=4)
    print(f"Saved updated file to {PASSAGE_FILE}")

if __name__ == "__main__":
    main()
