import json
import pandas as pd
import sys

def analyze_model_results(json_path, csv_path):
    print(f"--- Analysis Report ---")
    
    # 1. Load JSON results
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error loading JSON: {e}")
        return

    results = data.get('results', [])
    df_results = pd.DataFrame(results)

    # 2. Load CSV dataset for ground truth distribution
    try:
        df_csv = pd.read_csv(csv_path)
    except Exception as e:
        print(f"Error loading CSV: {e}")
        return

    # Filter for L5 Boolean
    l5_bool_results = df_results[(df_results['level'] == 'L5') & (df_results['type'] == 'boolean')]
    
    if not l5_bool_results.empty:
        print(f"\n[L5 Boolean Analysis]")
        print(f"Count: {len(l5_bool_results)}")
        print(f"Average Score: {l5_bool_results['type_aware_score'].mean():.2%}")
        print("Gold Value Distribution:")
        print(l5_bool_results['gold_cleaned'].value_counts())
        print("Pred Value Distribution:")
        print(l5_bool_results['pred'].value_counts())
    else:
        print("\nNo L5 Boolean results found in JSON.")

    # Filter for L1 Boolean for comparison
    l1_bool_results = df_results[(df_results['level'] == 'L1') & (df_results['type'] == 'boolean')]
    if not l1_bool_results.empty:
        print(f"\n[L1 Boolean Analysis (for comparison)]")
        print(f"Count: {len(l1_bool_results)}")
        print(f"Average Score: {l1_bool_results['type_aware_score'].mean():.2%}")
        print("Gold Value Distribution:")
        print(l1_bool_results['gold_cleaned'].value_counts())
    
    # Adjusted L5 Accuracy (Excluding Boolean)
    l5_non_bool = df_results[(df_results['level'] == 'L5') & (df_results['type'] != 'boolean')]
    if not l5_non_bool.empty:
        print(f"\n[L5 Non-Boolean Analysis]")
        print(f"Count: {len(l5_non_bool)}")
        print(f"Adjusted L5 Accuracy: {l5_non_bool['type_aware_score'].mean():.2%}")
    
    print("\n--- End of Report ---")

if __name__ == "__main__":
    json_p = r"c:\Users\Yujin\CodeSpace\GIA\Experiment\results\Qwen3-8B\results_analyzed_20251226_171545.json"
    csv_p = r"Data/Pnetlab/Research_Institute_Internal_DC/Dataset/Research_Institute_Internal_DC_dataset_batfish_20251224_012740.csv"
    analyze_model_results(json_p, csv_p)
