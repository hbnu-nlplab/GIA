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

    def parse_dir(
        self,
        xml_dir: str,
        batfish_host: str = "localhost",
        fail_on_missing_config: bool = False,
    ) -> Dict[str, Any]:
        """
        xml_dir: Lab root or configs directory.
        """
        path = Path(xml_dir)
        
        # 1. 'configs' 폴더 찾기
        if path.name == "configs":
            configs_dir = path
        elif (path / "configs").exists():
            configs_dir = path / "configs"
        elif (path.parent / "configs").exists():
            configs_dir = path.parent / "configs"
        else:
            # 못 찾으면 현재 경로를 configs로 가정 (Batfish packaging error 가능성 높음)
            configs_dir = path

        print(f"[UniversalParser] Using configs_dir: {configs_dir}")
        return batfish_parser.parse_batfish_datamodel(
            configs_dir,
            batfish_host=batfish_host,
            fail_on_missing_config=fail_on_missing_config,
        )
