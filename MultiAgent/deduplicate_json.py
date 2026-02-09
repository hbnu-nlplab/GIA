import json
import os
import sys

file_path = '/home/leehj/network/GIA/MultiAgent/data/debate_results/full_w_context4/netconfig_result2.json'

if not os.path.exists(file_path):
    print(f"Error: File not found at {file_path}")
    sys.exit(1)

if os.stat(file_path).st_size == 0:
    print(f"Error: {file_path} is empty (0 bytes). Please save the file content first.")
    sys.exit(1)

print(f"Reading {file_path}...")
with open(file_path, 'r', encoding='utf-8') as f:
    try:
        data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error: Failed to decode JSON. {e}")
        sys.exit(1)

if not isinstance(data, list):
    print("Error: JSON root is not a list.")
    sys.exit(1)

seen_ids = set()
unique_data = []
duplicates_count = 0

# We use 'question' as the unique identifier. 
# If 'question' is not unique enough, we might need to look at other fields, 
# but for dataset results, usually the question is the key.
for item in data:
    # distinct key: try 'question', fallback to string representation of the object
    key = item.get('question')
    if key is None:
        key = json.dumps(item, sort_keys=True)
    
    if key not in seen_ids:
        seen_ids.add(key)
        unique_data.append(item)
    else:
        duplicates_count += 1
        # Removing duplicate (second occurrence)

print(f"Found {len(data)} items.")
print(f"Found {duplicates_count} duplicates.")
print(f"keeping {len(unique_data)} unique items.")

if duplicates_count > 0:
    print("Writing back to file...")
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(unique_data, f, ensure_ascii=False, indent=4)
    print("Done.")
else:
    print("No duplicates found. File left unchanged.")
