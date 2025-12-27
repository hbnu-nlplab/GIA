import json
from collections import defaultdict

# Load results
with open('Experiment/results/Qwen3-8B/results_analyzed_20251226_171545.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

# Filter text type
all_text = [r for r in data['results'] if r['type'] == 'text']
text_errors = [r for r in all_text if r['type_aware_score'] == 0.0]

print(f"Text Type Analysis")
print(f"Total: {len(all_text)}, Correct: {len(all_text)-len(text_errors)}, Wrong: {len(text_errors)}")
print(f"Accuracy: {(len(all_text)-len(text_errors))/len(all_text)*100:.1f}%")
print()

# Error by category
print("Errors by Category:")
error_cat = defaultdict(int)
for e in text_errors:
    error_cat[e['category']] += 1
for cat, count in sorted(error_cat.items(), key=lambda x: x[1], reverse=True):
    print(f"  {cat}: {count}")
print()

# Pattern analysis
print("Error Patterns:")
not_config_fail = sum(1 for e in text_errors if e['status'] == 'NOT_CONFIGURED' and e['pred'])
comparison_errors = sum(1 for e in text_errors if e['category'] == 'Comparison_Analysis')
print(f"  NOT_CONFIGURED handling fail: {not_config_fail}")
print(f"  Comparison_Analysis errors: {comparison_errors}")
print()

# Show samples
print("Sample Errors (first 5):")
for i, err in enumerate(text_errors[:5], 1):
    print(f"\n{i}. Q: {err['question'][:60]}")
    print(f"   Gold: '{err['gold_cleaned']}'")
    print(f"   Pred: '{err['pred']}'")
    print(f"   Token F1: {err.get('token_f1', 0):.2f}")
    print(f"   Category: {err['category']}")
