"""Shared utilities for deploy scripts."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]  # GIA/
DEFAULT_DEVICE_INFO = ROOT / "Data/Pnetlab/LabB_NCN_Basic_SP_20nodes/device_info.json"


def add_common_args(parser):
    """Add --device-info and --only arguments shared by all deploy scripts."""
    parser.add_argument("--device-info", type=Path, default=DEFAULT_DEVICE_INFO,
                        help="Path to device_info.json")
    parser.add_argument("--only", type=str, default=None,
                        help="Comma-separated device names to include")


def load_and_filter_devices(args):
    """Load device_info.json and apply --only filter.

    Returns:
        (info, devices) where info is the full parsed JSON dict
        and devices is the filtered list.
    """
    with open(args.device_info, encoding="utf-8") as f:
        info = json.load(f)
    devices = info.get("devices", [])
    if args.only:
        only = set(args.only.split(","))
        devices = [d for d in devices if d["name"] in only]
    return info, devices
