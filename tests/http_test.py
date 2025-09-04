import xml.etree.ElementTree as ET
import os

def check_http_server(xml_file):
    """HTTP 서버 설정 확인"""
    try:
        with open(xml_file, 'r', encoding='utf-8') as f:
            content = f.read()
        root = ET.fromstring(content)
        
        # HTTP 서버 설정 찾기
        http_server = root.find('.//http/server')
        if http_server is not None:
            return True
        
        # 다른 가능한 HTTP 설정 경로들도 확인
        http_configs = root.findall('.//http')
        for http in http_configs:
            if 'server' in http.tag or any('server' in child.tag for child in http):
                return True
                
        return False
    except Exception as e:
        print(f"Error reading {xml_file}: {e}")
        return False

def check_ip_forward_protocol(xml_file):
    """ip forward-protocol nd 설정 확인"""
    try:
        with open(xml_file, 'r', encoding='utf-8') as f:
            content = f.read()
        root = ET.fromstring(content)
        
        # ip forward-protocol 설정 찾기
        forward_protocols = root.findall('.//forward-protocol')
        for fp in forward_protocols:
            if fp.text and 'nd' in fp.text.lower():
                return True
                
        # 다른 가능한 경로들도 확인
        ip_configs = root.findall('.//ip')
        for ip in ip_configs:
            for child in ip:
                if 'forward' in child.tag.lower() and child.text and 'nd' in child.text.lower():
                    return True
                    
        return False
    except Exception as e:
        print(f"Error reading {xml_file}: {e}")
        return False

# 검토할 파일들
files_to_check = {
    'sample7': 'data/raw/XML_Data/sample7.xml',
    'sample8': 'data/raw/XML_Data/sample8.xml', 
    'sample9': 'data/raw/XML_Data/sample9.xml',
    'CE1': 'data/raw/XML_Data/ce1.xml',
    'CE2': 'data/raw/XML_Data/ce2.xml'
}

print("=== HTTP 서버 설정 검토 ===")
for device, file_path in [('sample7', files_to_check['sample7']), 
                         ('sample8', files_to_check['sample8']), 
                         ('sample9', files_to_check['sample9'])]:
    if os.path.exists(file_path):
        http_enabled = check_http_server(file_path)
        print(f"{device}: HTTP 서버 활성화 = {http_enabled}")
        
        # XML 내용에서 HTTP 관련 부분 직접 확인
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            if '<http>' in content.lower() or 'http-server' in content.lower():
                print(f"  -> XML에 HTTP 관련 설정 발견")
            else:
                print(f"  -> XML에 HTTP 관련 설정 없음")
    else:
        print(f"{device}: 파일을 찾을 수 없음")

print("\n=== IP Forward-Protocol ND 설정 검토 ===")
for device, file_path in [('CE1', files_to_check['CE1']), 
                         ('CE2', files_to_check['CE2'])]:
    if os.path.exists(file_path):
        forward_nd = check_ip_forward_protocol(file_path)
        print(f"{device}: ip forward-protocol nd = {forward_nd}")
        
        # XML 내용에서 forward-protocol 관련 부분 직접 확인
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            if 'forward-protocol' in content.lower():
                print(f"  -> XML에 forward-protocol 설정 발견")
                # 해당 부분 출력
                lines = content.split('\n')
                for i, line in enumerate(lines):
                    if 'forward-protocol' in line.lower():
                        print(f"     Line {i+1}: {line.strip()}")
            else:
                print(f"  -> XML에 forward-protocol 설정 없음")
    else:
        print(f"{device}: 파일을 찾을 수 없음")