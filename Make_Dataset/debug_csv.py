import pandas as pd
import sys
import glob
import os

def debug_csv(csv_path):
    print(f"Inspecting {csv_path}...")
    df = pd.read_csv(csv_path)

    bad_metrics = [
        "system_timezone_text", 
        "logging_buffered_severity_text", 
        "vty_transport_input_text", 
        "vty_login_mode_text"
    ]
    
    for m in bad_metrics:
        rows = df[df["answer"].str.contains(m)] # Wait format is answer? No metric is in question?
        # df ID or Category does not have metric name directly.
        # But we can search by question text or just look at all rows.
        
        # Actually I suspect the Metric name is not in the CSV directly unless I put it in Evidence.
        # But I added Evidence! Let's check evidence.
        pass

    # Just look at rows where answer is "" or "null" or anything suspicious.
    print("\n--- Inspecting 'null' answers ---")
    null_rows = df[df["answer"] == "null"]
    print(f"Null rows: {len(null_rows)}")
    print(null_rows[["id", "answer_status", "answer", "evidence"]].head())

    print("\n--- Inspecting 'OK' rows with empty/suspicious string answers ---")
    # '""' or "[]"
    empty_str_rows = df[df["answer"] == '""']
    print(f"Empty String rows: {len(empty_str_rows)}")
    if not empty_str_rows.empty:
        print(empty_str_rows[["id", "answer_status", "answer"]].head())
        # Try to find which metric they belong to.
        # I'll modify main loop to output metric ID in CSV? No, I can't change CSV schema too much.
        # But 'id' column usually has the Rule ID.
    
    # Check Evidence content for the failed ones
    print("\n--- Inspecting Invalid Evidence ---")
    def is_bad_ev(s):
        import json
        try:
            d = json.loads(s)
            return "snapshot" not in d
        except:
            return True
    
    bad_ev_rows = df[df["evidence"].apply(is_bad_ev)]
    print(f"Bad Evidence rows: {len(bad_ev_rows)}")
    if not bad_ev_rows.empty:
        print(bad_ev_rows[["id", "evidence"]].head())

if __name__ == "__main__":
    search_dirs = [r"Data\Pnetlab\Research_Institute_Internal_DC\Dataset"]
    csv_file = None
    for d in search_dirs:
        pattern = os.path.join(d, "*dataset_batfish*.csv")
        files = glob.glob(pattern)
        if files:
            csv_file = max(files, key=os.path.getctime)
            break
    
    if csv_file:
        debug_csv(csv_file)
