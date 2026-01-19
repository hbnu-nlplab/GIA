import sys
import os
from pathlib import Path

# Add parent directory to sys.path to allow imports from config
current_dir = Path(__file__).resolve().parent
parent_dir = current_dir.parent
sys.path.append(str(parent_dir))

from gen_passage.gen_passage import merge_batch_results

if __name__ == "__main__":
    print("Running manual merge for telequad...")
    merge_batch_results('telequad')
