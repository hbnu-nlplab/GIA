from __future__ import annotations
from pathlib import Path
from typing import Dict, Any, List
import xml.etree.ElementTree as ET

from .vendor import xr_facts_parser

class UniversalParser:
    """
    벤더 자동 감지 및 파서 선택 (초기 버전: XR 우선, 실패 시 XR 시도로 폴백)
    - 입력: XML 파일들이 있는 디렉터리 경로
    - 출력: {"devices": [...]} JSON-호환 dict
    """
    def __init__(self):
        pass

    def parse_dir(self, xml_dir: str) -> Dict[str, Any]:
        base = Path(xml_dir)
        xmls: List[Path] = sorted([p for p in base.iterdir() if p.suffix.lower() == ".xml"], key=lambda x: x.name)
        # 간단: XR 파서로 통일 처리
        return xr_facts_parser.parse_files(xmls) 