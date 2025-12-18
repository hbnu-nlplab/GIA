from __future__ import annotations
from pathlib import Path
from typing import Dict, Any, List

from . import batfish_parser

class UniversalParser:
    """
    Batfish 기반 파서 래퍼
    - 입력: XML 또는 Config 디렉토리
    - 출력: {"devices": [...]} JSON-호환 dict
    """
    def __init__(self):
        pass

    def parse_dir(self, xml_dir: str) -> Dict[str, Any]:
        """
        기존 인터페이스(xml_dir)를 유지하되, 내부적으로는 configs 폴더를 찾아서 Batfish에 넘깁니다.
        """
        # xml_dir: .../xml
        # Batfish는 .../configs 폴더가 필요함 (같은 레벨 가정)
        base_xml = Path(xml_dir)
        configs_dir = base_xml.parent / "configs"
        
        if not configs_dir.exists():
            # 만약 XML 디렉토리 자체가 configs라면?
            if base_xml.name == "configs":
                configs_dir = base_xml
            else:
                # Fallback: 그냥 xml_dir을 넘겨보거나 에러 처리
                # 하지만 Batfish는 .cfg가 필요하므로 configs를 찾아야 함
                print(f"[Warning] 'configs' directory not found near {xml_dir}. Trying to use {xml_dir} as configs.")
                configs_dir = base_xml

        # Dummy path list for signature compatibility
        return batfish_parser.parse_batfish_datamodel(configs_dir)
