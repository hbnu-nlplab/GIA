import json
import os

original_path = "/home/leehj/network/GIA/Experiment/data/telequad/telequad_original.json"
target_path = "/home/leehj/network/GIA/MultiAgent/data/original/telequad.json"

print(f"Loading {original_path}...")
with open(original_path, 'r', encoding='utf-8') as f:
    orig_data = json.load(f)

# Build question -> context map
q_to_ctx = {}
for entry in orig_data.get('data', []):
    for para in entry.get('paragraphs', []):
        context = para.get('context', '')
        for qa in para.get('qas', []):
            q_text = qa.get('question', '').strip()
            q_to_ctx[q_text] = context

print(f"Mapped {len(q_to_ctx)} questions to contexts.")

print(f"Loading {target_path}...")
with open(target_path, 'r', encoding='utf-8') as f:
    target_data = json.load(f)

updated_count = 0
for item in target_data:
    q_text = item.get('question', '').strip()
    if q_text in q_to_ctx:
        item['gold_context'] = q_to_ctx[q_text]
        updated_count += 1
    else:
        # Try fuzzy match or just leave strict?
        # User output suggests strict match is likely fine or we might miss some due to spacing.
        pass

print(f"Updated {updated_count} items with context.")

with open(target_path, 'w', encoding='utf-8') as f:
    json.dump(target_data, f, indent=4, ensure_ascii=False)

print("Done.")
