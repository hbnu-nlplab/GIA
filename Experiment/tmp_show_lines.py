from pathlib import Path
path = Path("code/External_dataset/Local/external_dataset_runner.py")
for i, line in enumerate(path.open(encoding="utf-8"), 1):
    if 20 <= i <= 120:
        print(f"{i}: {line.rstrip()}" )
