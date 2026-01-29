#!/usr/bin/env python3
"""
Batfish 초기화 스크립트
Research_Institute_Internal_DC 설정 파일로 Batfish 스냅샷 생성
"""

import sys
from pathlib import Path

# NetAlly agent path 추가
NETALLY_PATH = Path(__file__).parent
sys.path.insert(0, str(NETALLY_PATH))

from agent.clients.batfish import BatfishClient

def init_batfish_snapshot():
    """
    Research_Institute_Internal_DC 설정 파일로 Batfish 초기화
    """
    # 설정 파일 경로
    config_dir = Path("/home/kilab_pyj/codespace/GIA/Data/Pnetlab/Research_Institute_Internal_DC/configs")
    
    if not config_dir.exists():
        print(f"❌ Config directory not found: {config_dir}")
        return False
    
    # 모든 .cfg 파일 찾기
    config_files = list(config_dir.glob("*.cfg"))
    
    if not config_files:
        print(f"❌ No .cfg files found in {config_dir}")
        return False
    
    print(f"📁 Found {len(config_files)} configuration files")
    for f in config_files:
        print(f"  - {f.name}")
    
    # Batfish 클라이언트 생성
    batfish = BatfishClient(host="localhost")
    
    if not batfish.is_available:
        print("❌ Batfish is not available. Check if Batfish SDK is installed.")
        return False
    
    # 스냅샷 초기화
    print("\n🚀 Initializing Batfish snapshot...")
    
    result = batfish.init_snapshot(
        topology_name="Research_Institute_Internal_DC",
        configs=[str(f) for f in config_files],
        device_info={
            "source": "PNETLab",
            "topology": "Research Institute Internal DC",
            "timestamp": str(Path(config_files[0]).stat().st_mtime)
        }
    )
    
    if "error" in result:
        print(f"❌ Initialization failed: {result['error']}")
        return False
    
    print(f"✅ Batfish initialized successfully!")
    print(f"   - Topology: {result.get('topology')}")
    print(f"   - Nodes: {len(result.get('nodes', []))}")
    print(f"   - Saved files: {result.get('saved_files')}")
    
    # 간단한 테스트: layer3Edges 조회
    try:
        print("\n🔍 Testing L3 topology extraction...")
        bf = batfish._builder.bf
        l3_edges = bf.q.layer3Edges().answer().frame()
        print(f"✅ Found {len(l3_edges)} L3 edges")
        
        if not l3_edges.empty:
            print("\nSample edges:")
            for idx, row in l3_edges.head(3).iterrows():
                src = row.get("Interface", {})
                dst = row.get("Remote_Interface", {})
                print(f"  {src.get('hostname')}:{src.get('interface')} <-> {dst.get('hostname')}:{dst.get('interface')}")
    
    except Exception as e:
        print(f"⚠️ L3 edge test failed: {e}")
    
    return True


if __name__ == "__main__":
    print("=" * 60)
    print("NetAlly - Batfish Snapshot Initialization")
    print("=" * 60)
    
    success = init_batfish_snapshot()
    
    if success:
        print("\n✨ Batfish is ready! You can now:")
        print("   1. Start the backend: uvicorn main:app --reload --port 8111")
        print("   2. Access topology at: http://localhost:3000")
    else:
        print("\n❌ Initialization failed. Please check the errors above.")
        sys.exit(1)
