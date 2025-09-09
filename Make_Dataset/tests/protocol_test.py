import xml.etree.ElementTree as ET

def detailed_check_forward_protocol(xml_file, device_name):
    """forward-protocol 설정 상세 확인"""
    try:
        with open(xml_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        print(f"\n=== {device_name} forward-protocol 상세 분석 ===")
        
        # 라인별로 forward-protocol 주변 확인
        lines = content.split('\n')
        in_forward_protocol = False
        start_line = None
        
        for i, line in enumerate(lines):
            if '<forward-protocol>' in line.lower():
                in_forward_protocol = True
                start_line = i
                print(f"Line {i+1}: {line.strip()}")
            elif '</forward-protocol>' in line.lower():
                print(f"Line {i+1}: {line.strip()}")
                in_forward_protocol = False
                
                # forward-protocol 섹션 내용 출력
                if start_line is not None:
                    print("forward-protocol 섹션 내용:")
                    for j in range(start_line, i+1):
                        print(f"  {j+1}: {lines[j]}")
                break
            elif in_forward_protocol:
                print(f"Line {i+1}: {line.strip()}")
                # nd 설정 확인
                if 'nd' in line.lower():
                    print(f"  *** ND 설정 발견! ***")
        
        # XML 파싱으로도 확인
        root = ET.fromstring(content)
        forward_protocols = root.findall('.//forward-protocol')
        
        print(f"\n파싱된 forward-protocol 요소 수: {len(forward_protocols)}")
        for i, fp in enumerate(forward_protocols):
            print(f"forward-protocol {i+1}:")
            print(f"  태그: {fp.tag}")
            print(f"  텍스트: '{fp.text}'")
            print(f"  속성: {fp.attrib}")
            
            # 자식 요소들 확인
            children = list(fp)
            print(f"  자식 요소 수: {len(children)}")
            for child in children:
                print(f"    - {child.tag}: '{child.text}' (속성: {child.attrib})")
                
                # nd 관련 확인
                if 'nd' in child.tag.lower() or (child.text and 'nd' in child.text.lower()):
                    print(f"      *** ND 관련 설정 발견! ***")
        
    except Exception as e:
        print(f"Error: {e}")

# CE1과 CE2 상세 분석
detailed_check_forward_protocol('data/raw/XML_Data/ce1.xml', 'CE1')
detailed_check_forward_protocol('data/raw/XML_Data/ce2.xml', 'CE2')