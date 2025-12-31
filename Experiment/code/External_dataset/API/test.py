import json

DATA_PATH = "../data/llm_answer_teleqna/llm_answer_gpt4o-mini.json"

# ✅ 수정 1: 실제 데이터에 맞는 키로 변경
target_keys = ["openai/gpt-4o-mini"]

try:
    with open(DATA_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
        print(f"✅ 파일을 읽었습니다. (총 {len(data)}개 항목)")

    cleaned_data = []

    for item in data:
        new_item = item.copy()
        
        for key in target_keys:
            if key in new_item:
                raw_text = new_item[key]
                
                # ✅ 수정 2: "Answer:" 접두어 제거 로직 추가
                # 대소문자 구분 없이 "answer:"로 시작하는지 확인
                if raw_text.strip().lower().startswith("answer:"):
                    # "Answer:" (7글자) 이후의 텍스트만 가져오고 양옆 공백 제거
                    raw_text = raw_text.strip()[7:].strip()

                # ✅ 수정 3: 백슬래시와 따옴표 제거 (기존 로직 유지)
                clean_text = raw_text.replace("\\", "").replace("\"", "")
                
                new_item[key] = clean_text
        
        cleaned_data.append(new_item)

    # JSON 저장
    output_json_str = json.dumps(cleaned_data, indent=4, ensure_ascii=False)

    with open(DATA_PATH, "w", encoding="utf-8") as f:
        f.write(output_json_str)
        
    print(f"✅ '{DATA_PATH}' 파일에 정제된 내용이 저장되었습니다.")
    
    # 결과 확인용 출력
    if cleaned_data:
        print("\n--- 변환 결과 예시 ---")
        for i in range(min(5, len(cleaned_data))): # 처음 5개만 확인
             val = cleaned_data[i].get("openai/gpt-4o-mini", "Key Missing")
             print(f"[{i}] {val}")

except FileNotFoundError:
    print(f"❌ 오류: '{DATA_PATH}' 경로에 파일이 없습니다.")
except Exception as e:
    print(f"❌ 오류 발생: {e}")