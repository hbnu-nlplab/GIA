from pybatfish.client.session import Session
from pybatfish.datamodel.flow import HeaderConstraints

# Batfish 세션 초기화
print("=== Batfish 분석 시작 ===\n")
bf = Session(host='localhost')

# 네트워크 및 스냅샷 설정
print("[1] 네트워크 초기화 중...")
bf.set_network('pnetlab')
print("[2] 스냅샷 로드 중...")
bf.init_snapshot('./pnetlab_snapshot', name='snapshot1', overwrite=True)
print("    [OK] 스냅샷 로드 완료!\n")

# 1. 노드 정보 확인
print("=" * 50)
print("[분석 1] 네트워크 장비 목록")
print("=" * 50)
nodes = bf.q.nodeProperties().answer().frame()
print(nodes[['Node']].to_string(index=False))
print()

# 2. 인터페이스 정보 확인
print("=" * 50)
print("[분석 2] 인터페이스 설정")
print("=" * 50)
interfaces = bf.q.interfaceProperties().answer().frame()
print(interfaces[['Interface', 'Active', 'Primary_Address']].to_string(index=False))
print()

# 3. 라우팅 테이블 확인
print("=" * 50)
print("[분석 3] 라우팅 테이블")
print("=" * 50)
routes = bf.q.routes().answer().frame()
print(routes[['Node', 'Network', 'Next_Hop_IP', 'Protocol']].head(20).to_string(index=False))
print()

# 4. 연결성 테스트 (CE01 -> CE02)
print("=" * 50)
print("[분석 4] 연결성 테스트: CE01 -> CE02 (172.16.1.2)")
print("=" * 50)
try:
    traceroute = bf.q.traceroute(
        startLocation='CE01',
        headers=HeaderConstraints(dstIps='172.16.1.2')
    ).answer().frame()
    print(traceroute.to_string(index=False))
except Exception as e:
    print(f"연결성 테스트 오류: {e}")

print("\n=== Batfish 분석 완료 ===")
