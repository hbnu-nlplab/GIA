#!/usr/bin/env python3
"""
Context 자동 생성 스크립트

NSO에서 CFG를 export하고 Batfish로 파싱하여 
Level 1 Summary와 Level 2 Facts를 생성합니다.

Usage:
    python scripts/generate_context.py
    python scripts/generate_context.py --output-dir ./config/context
"""

import json
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional
import argparse
import logging

# 프로젝트 경로 설정
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.batfish_parser import parse_batfish_datamodel
from clients.nso import NSOClient
from config.settings import settings

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def infer_device_role(device_facts: Dict[str, Any]) -> str:
    """
    장비 설정을 기반으로 역할(Role)을 추론합니다.
    
    P (Provider): MPLS LDP 활성화, BGP 없음
    PE (Provider Edge): MPLS + BGP + VRF
    Leaf/CE: BGP 또는 정적 라우팅만
    """
    has_mpls = device_facts.get("services", {}).get("mpls", {}).get("ldp_enabled", False)
    has_bgp = bool(device_facts.get("routing", {}).get("bgp", {}).get("local_as"))
    has_vrf = bool(device_facts.get("services", {}).get("vrf", []))
    has_ospf = bool(device_facts.get("routing", {}).get("ospf", {}).get("process_ids", []))
    
    hostname = device_facts.get("system", {}).get("hostname", "").lower()
    
    # 이름 기반 추론 (우선)
    if hostname.startswith("pe"):
        return "PE"
    elif hostname.startswith("p") and not hostname.startswith("pe"):
        return "P"
    elif hostname.startswith("leaf"):
        return "Leaf"
    elif hostname.startswith("spine"):
        return "Spine"
    elif hostname.startswith("ce"):
        return "CE"
    
    # 설정 기반 추론 (폴백)
    if has_mpls and has_bgp and has_vrf:
        return "PE"
    elif has_mpls and has_ospf and not has_bgp:
        return "P"
    elif has_bgp:
        return "CE"
    else:
        return "Leaf"


def generate_summary(facts: Dict[str, Any]) -> Dict[str, Any]:
    """
    Level 2 Facts에서 Level 1 Summary를 추출합니다.
    
    Summary 구조:
    {
        "last_updated": "2026-01-16T01:00:00Z",
        "device_count": 10,
        "devices": [
            {"hostname": "pe1", "role": "PE", "mgmt_ip": "10.10.10.21", "interfaces_count": 5}
        ]
    }
    """
    summary = {
        "last_updated": datetime.utcnow().isoformat() + "Z",
        "device_count": len(facts.get("devices", [])),
        "devices": []
    }
    
    for device in facts.get("devices", []):
        hostname = device.get("system", {}).get("hostname", "unknown")
        
        # 관리 IP 추출 (OOB 인터페이스에서)
        mgmt_ip = None
        for iface in device.get("interfaces", []):
            # 10.10.10.x 대역을 관리 IP로 간주
            ipv4 = iface.get("ipv4", "")
            if ipv4 and "10.10.10." in ipv4:
                mgmt_ip = ipv4.split("/")[0]
                break
        
        device_summary = {
            "hostname": hostname,
            "role": infer_device_role(device),
            "mgmt_ip": mgmt_ip,
            "interfaces_count": device.get("num_interfaces", 0),
            "ospf": bool(device.get("routing", {}).get("ospf", {}).get("process_ids", [])),
            "bgp_as": device.get("routing", {}).get("bgp", {}).get("local_as"),
            "mpls": device.get("services", {}).get("mpls", {}).get("ldp_enabled", False)
        }
        summary["devices"].append(device_summary)
    
    return summary


def export_configs_from_nso(output_dir: Path) -> List[Path]:
    """
    NSO에서 CFG 파일을 export합니다.
    """
    logger.info("NSO에서 장비 설정 export 중...")
    
    client = NSOClient()
    devices = client.get_devices()
    
    if not devices:
        logger.warning("NSO에 등록된 장비가 없습니다.")
        return []
    
    device_names = [d.get("name") for d in devices if d.get("name")]
    logger.info(f"발견된 장비: {device_names}")
    
    # CFG 디렉토리 생성
    configs_dir = output_dir / "configs"
    configs_dir.mkdir(parents=True, exist_ok=True)
    
    # 각 장비 설정 export
    cfg_files = []
    for device_name in device_names:
        try:
            # Native CLI 형식으로 설정 가져오기
            config = client.get_config(device_name)
            if config:
                cfg_path = configs_dir / f"{device_name}.cfg"
                with open(cfg_path, "w", encoding="utf-8") as f:
                    if isinstance(config, dict):
                        # JSON 형식이면 CLI로 변환 필요 (간단한 처리)
                        f.write(f"! Config for {device_name}\n")
                        f.write(json.dumps(config, indent=2))
                    else:
                        f.write(config)
                cfg_files.append(cfg_path)
                logger.info(f"  ✓ {device_name}.cfg 저장됨")
        except Exception as e:
            logger.error(f"  ✗ {device_name} export 실패: {e}")
    
    return cfg_files


def main(output_dir: Optional[str] = None, use_existing_configs: Optional[str] = None):
    """
    Context 생성 메인 함수
    
    Args:
        output_dir: 출력 디렉토리 (기본: config/context)
        use_existing_configs: 기존 CFG 디렉토리 사용 (NSO export 건너뛰기)
    """
    output_path = Path(output_dir) if output_dir else PROJECT_ROOT / "config" / "context"
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Step 1: CFG 파일 준비
    if use_existing_configs:
        configs_dir = Path(use_existing_configs)
        logger.info(f"기존 CFG 디렉토리 사용: {configs_dir}")
    else:
        configs_dir = output_path / "configs"
        export_configs_from_nso(output_path)
    
    # CFG 파일 확인
    cfg_files = list(configs_dir.glob("*.cfg"))
    if not cfg_files:
        logger.error(f"CFG 파일이 없습니다: {configs_dir}")
        return None
    
    logger.info(f"총 {len(cfg_files)}개 CFG 파일 발견")
    
    # Step 2: Batfish로 파싱하여 Facts 생성
    logger.info("Batfish로 설정 파싱 중...")
    try:
        facts = parse_batfish_datamodel(configs_dir)
        logger.info(f"  ✓ {len(facts.get('devices', []))}개 장비 파싱 완료")
    except Exception as e:
        logger.error(f"Batfish 파싱 실패: {e}")
        return None
    
    # Step 3: Facts JSON 저장 (Level 2)
    facts["last_updated"] = datetime.utcnow().isoformat() + "Z"
    facts_path = output_path / "device_facts.json"
    with open(facts_path, "w", encoding="utf-8") as f:
        json.dump(facts, f, ensure_ascii=False, indent=2)
    logger.info(f"Level 2 Facts 저장: {facts_path}")
    
    # Step 4: Summary JSON 생성 (Level 1)
    summary = generate_summary(facts)
    summary_path = output_path / "device_summary.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    logger.info(f"Level 1 Summary 저장: {summary_path}")
    
    # 결과 출력
    print("\n" + "="*50)
    print("Context 생성 완료!")
    print("="*50)
    print(f"Level 1 Summary: {summary_path}")
    print(f"Level 2 Facts:   {facts_path}")
    print(f"장비 수: {summary['device_count']}")
    print(f"갱신 시간: {summary['last_updated']}")
    print("="*50)
    
    return {
        "summary_path": str(summary_path),
        "facts_path": str(facts_path),
        "device_count": summary["device_count"]
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Context 자동 생성 스크립트")
    parser.add_argument(
        "--output-dir", "-o",
        help="출력 디렉토리 (기본: config/context)"
    )
    parser.add_argument(
        "--use-existing-configs", "-c",
        help="기존 CFG 디렉토리 사용 (NSO export 건너뛰기)"
    )
    
    args = parser.parse_args()
    main(args.output_dir, args.use_existing_configs)
