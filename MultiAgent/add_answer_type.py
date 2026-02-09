import json
from pathlib import Path

# Paths
base_dir = Path("/home/leehj/network/GIA/MultiAgent")
netconfig_path = base_dir / "data" / "original" / "netconfig" / "netconfig.json"
result_path = base_dir / "data" / "debate_results" / "full_w_context4" / "netconfig_result2.json"

def main():
    if not netconfig_path.exists():
        print(f"Error: {netconfig_path} does not exist.")
        return
    if not result_path.exists():
        print(f"Error: {result_path} does not exist.")
        return

    # Load original netconfig data
    print(f"Loading {netconfig_path}...")
    with open(netconfig_path, 'r', encoding='utf-8') as f:
        netconfig_data = json.load(f)

    # Create mapping: question -> answer_type
    question_to_type = {}
    if "questions" in netconfig_data:
        for item in netconfig_data["questions"]:
            q = item.get("question")
            a_type = item.get("answer_type")
            if q and a_type:
                question_to_type[q] = a_type
    else:
        print("Error: 'questions' key not found in netconfig.json")
        return
    
    print(f"Loaded {len(question_to_type)} question mappings.")

    # Load result data
    print(f"Loading {result_path}...")
    with open(result_path, 'r', encoding='utf-8') as f:
        result_data = json.load(f)

    # Update result data
    updated_count = 0
    for item in result_data:
        q = item.get("question")
        if q in question_to_type:
            item["answer_type"] = question_to_type[q]
            updated_count += 1
        else:
            # Try matching with stripped whitespace if exact match fails
            q_stripped = q.strip()
            found = False
            for map_q, map_type in question_to_type.items():
                if map_q.strip() == q_stripped:
                    item["answer_type"] = map_type
                    updated_count += 1
                    found = True
                    break
            if not found:
                 print(f"Warning: No answer_type found for question: {q}")

    print(f"Updated {updated_count} items with answer_type.")

    # Save updated data
    print(f"Saving to {result_path}...")
    with open(result_path, 'w', encoding='utf-8') as f:
        json.dump(result_data, f, indent=4, ensure_ascii=False)
    print("Done.")

if __name__ == "__main__":
    main()
