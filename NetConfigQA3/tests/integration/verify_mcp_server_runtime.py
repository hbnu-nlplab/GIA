from pathlib import Path
import asyncio
from mcp_main import nso_get_devices, pnetlab_inventory, nso_export_configs

async def test_real_mcp_logic():
    print("=== 1. PNETLab 인벤토리 조회 테스트 ===")
    pnet_res = await pnetlab_inventory()
    print(f"Result: {pnet_res}\n")

    print("=== 2. NSO 장비 목록 조회 테스트 ===")
    nso_res = await nso_get_devices()
    print(f"Result: {nso_res}\n")

    print("=== 3. 장비 설정 추출 테스트 (NSO -> File) - 하이브리드 전략 ===")
    # PH1_L3VPN_GOLDEN 그룹 장비 목록
    # golden_devices = ["P1", "P2", "P3", "P4", "P5", "P6"]
    # output_dir = "Data/Pnetlab/PH1_L3VPN_GOLDEN"
    
    # 실제 장비가 등록되어 있어야 작동합니다.
    export_res = await nso_export_configs(
        output_dir="./test_export",
        export_xml=True,          # XML 추출 (선택)
        export_yang_json=True     # YANG JSON 추출 (향후 확장성)
    )
    print(f"Result: {export_res}\n")
    print("✅ 추출된 파일 위치:")
    print(f"  - configs/: Native CLI (Batfish용)")
    print(f"  - xml/: XML (레거시)")
    print(f"  - yang/: YANG JSON (향후 확장)")

if __name__ == "__main__":
    asyncio.run(test_real_mcp_logic())
