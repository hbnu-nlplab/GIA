import os
import re

# === 설정 ===
INPUT_XML_DIR = "../data/original/xml"           # 원본 XML 파일들이 있는 폴더
OUTPUT_TXT_FILE = "../data/original/netconfig_context.txt" # 결과가 저장될 텍스트 파일 경로

def minify_xml_content(content):
    """
    XML의 불필요한 공백과 줄바꿈을 제거하여 토큰을 절약합니다.
    """
    # 1. 태그 사이의 공백 제거 ( >   <  -> >< )
    content = re.sub(r'>\s+<', '><', content)
    # 2. 각 줄의 앞뒤 공백 제거 및 빈 줄 삭제
    lines = [line.strip() for line in content.splitlines() if line.strip()]
    return "".join(lines)

def merge_xmls_to_text():
    if not os.path.exists(INPUT_XML_DIR):
        print(f"Error: Directory not found - {INPUT_XML_DIR}")
        return

    all_files = sorted([f for f in os.listdir(INPUT_XML_DIR) if f.endswith('.xml')])
    
    if not all_files:
        print("No XML files found.")
        return

    print(f"Found {len(all_files)} XML files. Merging...")
    
    full_context = ""
    
    for xml_file in all_files:
        file_path = os.path.join(INPUT_XML_DIR, xml_file)
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                raw_content = f.read()
                minified = minify_xml_content(raw_content)
                # 파일명을 헤더로 붙여서 구분
                full_context += f"[{xml_file}]:{minified}\n"
        except Exception as e:
            print(f"Skipping {xml_file}: {e}")

    # 결과 저장
    os.makedirs(os.path.dirname(OUTPUT_TXT_FILE), exist_ok=True)
    with open(OUTPUT_TXT_FILE, "w", encoding="utf-8") as f:
        f.write(full_context)
    
    print(f"Success! Merged content saved to: {OUTPUT_TXT_FILE}")
    print(f"Total size: {len(full_context)} characters")

if __name__ == "__main__":
    merge_xmls_to_text()