"""
BatfishBuilder에서 node_vrfs 속성 확인 및 수정 방법 분석
"""
import re
from pathlib import Path

# batfish_builder.py 파일 읽기
builder_file = Path(r'c:\Users\Yujin\CodeSpace\GIA\Make_Dataset\src\core_batfish\batfish_builder.py')
content = builder_file.read_text(encoding='utf-8')

# __init__ 메서드에서 초기화되는 속성 찾기
print("=== BatfishBuilder.__init__에서 초기화되는 속성 ===")
init_match = re.search(r'def __init__\(self.*?\n(.*?)(?=\n    def )', content, re.DOTALL)
if init_match:
    init_body = init_match.group(1)
    # self.xxx 패턴 찾기
    attrs = re.findall(r'self\.(\w+)\s*=', init_body)
    for attr in sorted(set(attrs)):
        print(f"  - self.{attr}")

# node_ips가 어떻게 초기화되는지 확인
print("\n=== node_ips 초기화 방법 ===")
node_ips_init = re.search(r'self\.node_ips\s*=\s*(.+)', content)
if node_ips_init:
    print(f"  {node_ips_init.group(0)}")

# VRF 관련 메서드 찾기
print("\n=== VRF 관련 메서드 ===")
vrf_methods = re.findall(r'def (.*vrf.*)\(', content, re.IGNORECASE)
if vrf_methods:
    for method in vrf_methods:
        print(f"  - {method}")
else:
    print("  VRF 관련 메서드 없음")

# get_vrfs 메서드가 있는지 확인
print("\n=== get_vrfs() 메서드 확인 ===")
get_vrfs_match = re.search(r'def get_vrfs\(self\):(.*?)(?=\n    def |\nclass |\Z)', content, re.DOTALL)
if get_vrfs_match:
    print("  ✓ get_vrfs() 메서드 존재")
    print(f"  내용:\n{get_vrfs_match.group(0)[:200]}...")
else:
    print("  ✗ get_vrfs() 메서드 없음")

print("\n=== 해결 방법 ===")
print("1. node_vrfs 속성을 __init__에서 초기화")
print("2. 또는 get_vrfs()를 사용하여 VRF 목록 가져오기")
print("3. VRF 코드를 제거하거나 조건부로 실행")
