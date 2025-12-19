import pandas as pd
import json
import glob
import os
import sys

def check_csv(csv_path):
    print(f"Checking {csv_path}...")
    try:
        df = pd.read_csv(csv_path)
    except Exception as e:
        print(f"Error reading CSV: {e}")
        return

    # 1. Check for "정보없음"
    info_missing_count = df["answer"].astype(str).str.contains("정보없음").sum()
    print(f"[Check 1] '정보없음' count: {info_missing_count} (Expected: 0)")

    # 2. Check for numeric types stored as strings in JSON
    numeric_rows = df[df["answer_type"].isin(["numeric", "number", "integer"])]
    
    def is_bad_number(s):
        try:
            val = json.loads(s)
            # If valid number, type is int/float. If null, None.
            # Bad if type is str.
            return isinstance(val, str)
        except:
            return True

    bad_numerics = numeric_rows["answer"].apply(is_bad_number).sum()
    print(f"[Check 2] Numeric types stored as strings: {bad_numerics} (Expected: 0)")

    # 3. Check Status Distribution
    print("[Check 3] Status Distribution:")
    print(df["answer_status"].value_counts())
    
    # 4. Check for NOT_CONFIGURED
    nc_count = (df["answer_status"] == "NOT_CONFIGURED").sum()
    print(f"  -> NOT_CONFIGURED count: {nc_count}")

    # 5. Check Evidence
    # Should contain 'snapshot' key
    def has_evidence_keys(s):
        try:
            d = json.loads(s)
            return "snapshot" in d and "metric" in d
        except:
            return False

    valid_evidence = df["evidence"].apply(has_evidence_keys).sum()
    print(f"[Check 4] Valid Evidence (has snapshot/metric): {valid_evidence}/{len(df)}")
    
    if info_missing_count == 0 and bad_numerics == 0 and valid_evidence == len(df):
        print("\n✅ PASS: All checks passed!")
    else:
        print("\n❌ FAIL: Some checks failed.")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        csv_file = sys.argv[1]
    else:
        # Find latest CSV in known dir relative to current cwd
        # Try a few locations
        search_dirs = [
            r"Data\Pnetlab\Research_Institute_Internal_DC\Dataset",
             r"Dataset"
        ]
        csv_file = None
        for d in search_dirs:
            pattern = os.path.join(d, "*dataset_batfish*.csv")
            files = glob.glob(pattern)
            if files:
                csv_file = max(files, key=os.path.getctime)
                break
        
        if not csv_file:
            print("No CSV found automatically.")
            sys.exit(1)
    
    check_csv(csv_file)
