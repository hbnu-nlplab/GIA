#!/usr/bin/env python3
"""
Batfish 초기화 스크립트
NSO에서 설정을 Export하여 Batfish 스냅샷을 생성합니다.
"""

import os
import sys
from pathlib import Path

# NetAlly agent path 추가
NETALLY_PATH = Path(__file__).parent
sys.path.insert(0, str(NETALLY_PATH))

from dotenv import load_dotenv
load_dotenv()

from agent.clients.batfish import BatfishClient
from agent.clients.nso import NSOClient

def init_batfish_snapshot():
    """
    NSO Export 결과로 Batfish 초기화
    """
    snapshot_name = (
        os.getenv("BATFISH_SNAPSHOT")
        or os.getenv("BATFISH_NETWORK")
        or "default"
    )
    output_dir = os.getenv("BATFISH_EXPORT_DIR", "./snapshot")
    use_restconf = os.getenv("USE_RESTCONF_EXPORT", "false").lower() == "true"

    nso = NSOClient(
        base_url=os.getenv("NSO_BASE_URL", "http://localhost:8080/restconf"),
        username=os.getenv("NSO_USERNAME") or os.getenv("NSO_USER", "admin"),
        password=os.getenv("NSO_PASSWORD") or os.getenv("NSO_PASS", "admin"),
    )

    # Batfish 클라이언트 생성
    batfish = BatfishClient(host=os.getenv("BATFISH_HOST", "localhost"))
    
    if not batfish.is_available:
        print("❌ Batfish is not available. Check if Batfish SDK is installed.")
        return False
    
    # 1) NSO에서 configs export
    print("\n📦 Exporting configs from NSO...")
    export_result = nso.export_batfish_configs(
        output_dir=output_dir,
        export_xml=False,
        export_yang_json=False,
    )

    if "error" in export_result:
        print(f"⚠️ NSO export failed: {export_result.get('error')}")
        if not use_restconf:
            return False
    else:
        configs_dir = export_result.get("configs_dir")
        if not configs_dir:
            print("❌ NSO export returned no configs_dir.")
            return False
        config_dir = Path(configs_dir)
        config_files = list(config_dir.glob("*.cfg"))
        if not config_files:
            print(f"❌ No .cfg files found in {config_dir}")
            return False
        print(f"📁 Found {len(config_files)} configuration files")

    # 2) 스냅샷 초기화
    print("\n🚀 Initializing Batfish snapshot...")
    if "error" in export_result and use_restconf:
        device_names = nso.get_devices()
        if not device_names:
            print("❌ No devices found for RESTCONF export.")
            return False
        configs = {}
        for name in device_names:
            cfg = nso.get_native_config(name)
            if cfg:
                configs[name] = cfg
        if not configs:
            print("❌ RESTCONF export returned empty configs.")
            return False
        result = batfish.init_snapshot(
            topology_name=snapshot_name,
            configs=configs,
            device_info={"source": "NSO_RESTCONF", "topology": snapshot_name},
        )
    else:
        result = batfish.init_snapshot(
            topology_name=snapshot_name,
            configs=[str(f) for f in config_files],
            device_info={"source": "NSO", "topology": snapshot_name},
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
