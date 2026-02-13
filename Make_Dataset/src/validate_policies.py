#!/usr/bin/env python3
"""Validate NetConfigQA policy metadata and template contracts."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple

CANONICAL_TYPES = {"text", "number", "set", "map", "boolean"}
LEGACY_ALIASES = {
    "scalar_int",
    "set_str",
    "map_str_str",
    "map_str_int",
    "json",
    "enum",
    "bool",
    "path",
    "edge_set",
    "scalar_str",
    "numeric",
    "list",
}
ALLOWED_TYPES = CANONICAL_TYPES | LEGACY_ALIASES

REQUIRED_FIELDS = {
    "level",
    "category",
    "answer_type",
    "template",
    "description",
    "verification",
    "logic_ref",
}

STRUCTURED_COMPARE_METRICS = {
    "compare_bgp_neighbor_count",
    "compare_interface_count",
    "compare_vrf_count",
}
HANGUL_PATTERN = re.compile(r"[\uac00-\ud7a3]")


def _check_placeholder_syntax(template: str) -> Tuple[bool, str]:
    """Allow placeholders like {host}, and escaped braces {{...}}."""
    s = template.replace("{{", "").replace("}}", "")
    i = 0
    while i < len(s):
        c = s[i]
        if c == "{":
            j = s.find("}", i + 1)
            if j == -1:
                return False, "unclosed '{'"
            token = s[i + 1 : j].strip()
            if not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*", token):
                return False, f"invalid placeholder token '{{{token}}}'"
            i = j + 1
            continue
        if c == "}":
            return False, "orphan '}'"
        i += 1
    return True, ""


def _extract_placeholders(template: str) -> set[str]:
    s = template.replace("{{", "").replace("}}", "")
    return set(re.findall(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}", s))


def _validate_metric(
    name: str,
    meta: Dict[str, object],
    errors: List[str],
    warnings: List[str],
    require_template_en: bool = False,
    strict_template_en: bool = False,
) -> None:
    missing = sorted(REQUIRED_FIELDS - set(meta.keys()))
    if missing:
        errors.append(f"{name}: missing required fields: {', '.join(missing)}")

    answer_type = str(meta.get("answer_type", "")).strip().lower()
    if answer_type and answer_type not in ALLOWED_TYPES:
        errors.append(f"{name}: unsupported answer_type '{answer_type}'")

    deprecated = bool(meta.get("deprecated", False))
    submission_excluded = bool(meta.get("submission_excluded", False))
    if deprecated and not submission_excluded:
        errors.append(f"{name}: deprecated=true requires submission_excluded=true")

    template = str(meta.get("template", ""))
    if template:
        ok, why = _check_placeholder_syntax(template)
        if not ok:
            errors.append(f"{name}: template placeholder syntax error: {why}")

    template_en = str(meta.get("template_en", ""))
    if require_template_en and not template_en.strip():
        errors.append(f"{name}: missing required field 'template_en'")
    if template_en:
        ok_en, why_en = _check_placeholder_syntax(template_en)
        if not ok_en:
            errors.append(f"{name}: template_en placeholder syntax error: {why_en}")

        ko_placeholders = _extract_placeholders(template)
        en_placeholders = _extract_placeholders(template_en)
        if ko_placeholders != en_placeholders:
            errors.append(
                f"{name}: placeholder mismatch template vs template_en "
                f"(template={sorted(ko_placeholders)}, template_en={sorted(en_placeholders)})"
            )

        if HANGUL_PATTERN.search(template_en):
            msg = f"{name}: template_en contains Hangul characters"
            if strict_template_en:
                errors.append(msg)
            else:
                warnings.append(msg)

    if name in STRUCTURED_COMPARE_METRICS:
        if answer_type != "map_str_int":
            errors.append(f"{name}: answer_type must be map_str_int for structured L3 compare")
        contract_text = f"{meta.get('template', '')} {meta.get('verification', '')}".lower()
        for required_key in ("host1_count", "host2_count", "difference"):
            if required_key not in contract_text:
                errors.append(f"{name}: structured contract missing key '{required_key}'")

    if name == "ospf_compatibility_check":
        contract_text = f"{meta.get('template', '')} {meta.get('verification', '')}".lower()
        if "issues" not in contract_text:
            errors.append("ospf_compatibility_check: contract must include 'issues' key")

    if name.startswith("diagnostic_") and str(meta.get("level", "")).upper() == "L6":
        if submission_excluded:
            warnings.append(f"{name}: L6 metric is explicitly submission_excluded")


def validate_policies(
    policies_path: Path,
    require_template_en: bool = False,
    strict_template_en: bool = False,
) -> int:
    if not policies_path.exists():
        print(f"[ERROR] policy file not found: {policies_path}")
        return 2

    payload = json.loads(policies_path.read_text(encoding="utf-8"))
    errors: List[str] = []
    warnings: List[str] = []

    if str(payload.get("schema_version", "")) != "3.1":
        errors.append("top-level schema_version must be '3.1'")
    if str(payload.get("submission_scope", "")) != "L1-L5":
        errors.append("top-level submission_scope must be 'L1-L5'")

    metadata = payload.get("metrics_metadata")
    if not isinstance(metadata, dict) or not metadata:
        errors.append("metrics_metadata must be a non-empty object")
    else:
        for metric_name, metric_meta in metadata.items():
            if not isinstance(metric_meta, dict):
                errors.append(f"{metric_name}: metadata must be an object")
                continue
            _validate_metric(
                metric_name,
                metric_meta,
                errors,
                warnings,
                require_template_en=require_template_en,
                strict_template_en=strict_template_en,
            )

    if warnings:
        print("[WARN] policy warnings:")
        for w in warnings:
            print(f"  - {w}")

    if errors:
        print("[FAIL] policy validation failed:")
        for e in errors:
            print(f"  - {e}")
        return 1

    print(
        f"[OK] policy validation passed: {len(metadata)} metrics, "
        f"schema_version={payload.get('schema_version')}, submission_scope={payload.get('submission_scope')}"
    )
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate Make_Dataset/policies.json")
    parser.add_argument(
        "--policies",
        default=str(Path(__file__).resolve().parents[1] / "policies.json"),
        help="Path to policies.json",
    )
    parser.add_argument(
        "--require-template-en",
        action="store_true",
        help="Require template_en for every metric and validate placeholder parity.",
    )
    parser.add_argument(
        "--strict-template-en",
        action="store_true",
        help="Fail if template_en contains Hangul characters.",
    )
    args = parser.parse_args()
    code = validate_policies(
        Path(args.policies).resolve(),
        require_template_en=args.require_template_en,
        strict_template_en=args.strict_template_en,
    )
    raise SystemExit(code)


if __name__ == "__main__":
    main()
