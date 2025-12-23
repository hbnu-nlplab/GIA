import json

# Load policies.json
with open('policies.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

metrics = data['metrics_metadata']

# Count by level
level_counts = {}
for key, value in metrics.items():
    level = value.get('level', 'unknown')
    if level not in level_counts:
        level_counts[level] = []
    level_counts[level].append(key)

print("=== Metrics Count by Level ===")
for level in ['L1', 'L2', 'L3', 'L4', 'L5']:
    count = len(level_counts.get(level, []))
    print(f"{level}: {count}개")
print(f"총 메트릭: {len(metrics)}개")

# Check description and verification quality
print("\n=== Quality Check ===")
short_desc = []
short_verif = []

for key, value in metrics.items():
    desc = value.get('description', '')
    verif = value.get('verification', '')
    
    if len(desc) < 100:
        short_desc.append(key)
    if len(verif) < 100:
        short_verif.append(key)

print(f"Description 짧음 (<100자): {len(short_desc)}개")
print(f"Verification 짧음 (<100자): {len(short_verif)}개")

if short_desc:
    print(f"\n=== Description 보강 필요 (처음 20개) ===")
    for i, key in enumerate(short_desc[:20], 1):
        desc_len = len(metrics[key].get('description', ''))
        print(f"{i}. {key} (level: {metrics[key]['level']}, length: {desc_len}자)")

if short_verif:
    print(f"\n=== Verification 보강 필요 (처음 20개) ===")
    for i, key in enumerate(short_verif[:20], 1):
        verif_len = len(metrics[key].get('verification', ''))
        print(f"{i}. {key} (level: {metrics[key]['level']}, length: {verif_len}자)")
