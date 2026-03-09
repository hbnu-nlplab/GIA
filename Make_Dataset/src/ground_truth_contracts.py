#!/usr/bin/env python3
"""Helpers for metric contracts used by generation and verification.

This module adds a lightweight contract layer without forcing a full
policies.json rewrite up front. Contracts are inferred from existing
metadata and can be overridden per metric as the V2 migration proceeds.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, Iterable, Mapping


_CANONICAL_TYPE_ALIASES = {
    "numeric": "number",
    "scalar_int": "number",
    "int": "number",
    "integer": "number",
    "float": "number",
    "set_str": "set",
    "list": "set",
    "map_str_int": "map",
    "map_str_str": "map",
    "json": "map",
    "scalar_str": "text",
    "enum": "text",
    "bool": "boolean",
}

_TEXT_CONFIG_METRICS = {
    "system_hostname_text",
    "system_version_text",
    "system_timezone_text",
    "system_user_list",
    "system_user_count",
    "logging_buffered_severity_text",
    "ntp_server_list",
    "snmp_community_list",
    "syslog_server_list",
    "vty_login_mode_text",
    "vty_transport_input_text",
    "password_encryption_config",
    "enable_secret_type",
    "console_password_val",
    "console_password_config",
    "exec_timeout_val",
    "exec_timeout_config",
    "banner_motd_content",
    "banner_login_content",
    "banner_motd_config",
    "banner_login_config",
    "http_server_config",
    "cdp_config",
    "source_route_config",
    "ip_source_route_config",
    "name_servers_list",
    "acl_applied_interfaces_list",
    "acl_configured_count",
    "prefix_list_count",
    "route_map_count",
    "qos_class_maps_list",
    "netflow_monitors_list",
    "interfaces_missing_description_count",
    "rip_processes",
    "hsrp_groups_list",
    "multicast_routing_config",
}

_SCOPE_SCHEMA_OVERRIDES = {
    "all_devices_same_as": {},
    "bgp_as_distribution": {},
    "vrf_usage_statistics": {},
    "ibgp_fullmesh_ok": {"asn": "int"},
    "ibgp_missing_pairs": {"asn": "int"},
    "ibgp_missing_pairs_count": {"asn": "int"},
    "ibgp_under_peered_devices": {"asn": "int"},
    "ibgp_under_peered_count": {"asn": "int"},
    "compare_bgp_neighbor_count": {"host1": "hostname", "host2": "hostname"},
    "compare_interface_count": {"host1": "hostname", "host2": "hostname"},
    "compare_vrf_count": {"host1": "hostname", "host2": "hostname"},
}


@dataclass(frozen=True)
class MetricContract:
    metric: str
    level: str
    answer_type: str
    canonical_answer_type: str
    oracle_source: str
    null_policy: str
    scope_schema: Dict[str, str]
    logic_contract: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def canonical_answer_type(answer_type: str) -> str:
    value = str(answer_type or "").strip().lower()
    return _CANONICAL_TYPE_ALIASES.get(value, value or "text")


def infer_oracle_source(metric: str, level: str) -> str:
    level = str(level or "").upper()
    if level in {"L4", "L5"}:
        return "batfish"
    if metric in _TEXT_CONFIG_METRICS:
        return "parser"
    return "hybrid"


def infer_null_policy(answer_type: str) -> str:
    canonical = canonical_answer_type(answer_type)
    if canonical == "set":
        return "empty_list"
    if canonical == "map":
        return "empty_map"
    if canonical == "number":
        return "zero"
    if canonical == "boolean":
        return "false"
    return "empty_string"


def infer_scope_schema(metric: str, logic_ref: str = "") -> Dict[str, str]:
    if metric in _SCOPE_SCHEMA_OVERRIDES:
        return dict(_SCOPE_SCHEMA_OVERRIDES[metric])

    ref = str(logic_ref or "")
    schema: Dict[str, str] = {}
    if "[host]" in ref or ".devices[host]." in ref:
        schema["host"] = "hostname"
    if "{asn}" in ref or "[asn]" in ref:
        schema["asn"] = "int"
    if "host1" in ref:
        schema["host1"] = "hostname"
    if "host2" in ref:
        schema["host2"] = "hostname"
    return schema


def build_metric_contract(metric: str, metadata: Mapping[str, Any]) -> MetricContract:
    level = str(metadata.get("level", "")).upper()
    answer_type = str(metadata.get("answer_type", "text")).lower()
    logic_ref = str(metadata.get("logic_ref", "")).strip()
    return MetricContract(
        metric=metric,
        level=level,
        answer_type=answer_type,
        canonical_answer_type=canonical_answer_type(answer_type),
        oracle_source=infer_oracle_source(metric, level),
        null_policy=infer_null_policy(answer_type),
        scope_schema=infer_scope_schema(metric, logic_ref),
        logic_contract=logic_ref,
    )


def build_metric_contracts(metrics_metadata: Mapping[str, Mapping[str, Any]]) -> Dict[str, MetricContract]:
    return {
        metric: build_metric_contract(metric, metadata)
        for metric, metadata in metrics_metadata.items()
    }


def normalize_scope(scope: Mapping[str, Any] | None, scope_schema: Mapping[str, str] | None = None) -> Dict[str, Any]:
    scope = dict(scope or {})
    scope_schema = dict(scope_schema or {})
    normalized: Dict[str, Any] = {}

    for key, value in scope.items():
        if isinstance(value, str):
            value = value.strip()

        if scope_schema.get(key) == "hostname":
            normalized[key] = str(value).strip().lower() if value not in (None, "") else value
            continue

        if scope_schema.get(key) == "int":
            if isinstance(value, str) and value.isdigit():
                normalized[key] = int(value)
            else:
                normalized[key] = value
            continue

        if key in {"host", "host1", "host2", "src", "dst", "device"} and isinstance(value, str):
            normalized[key] = value.lower()
            continue

        if key == "asn" and isinstance(value, str) and value.isdigit():
            normalized[key] = int(value)
            continue

        normalized[key] = value

    return normalized


def normalize_scope_for_metric(
    metric: str,
    scope: Mapping[str, Any] | None,
    metrics_metadata: Mapping[str, Mapping[str, Any]] | None = None,
) -> Dict[str, Any]:
    if metrics_metadata and metric in metrics_metadata:
        contract = build_metric_contract(metric, metrics_metadata[metric])
        return normalize_scope(scope, contract.scope_schema)
    return normalize_scope(scope)


def serialize_contracts(contracts: Iterable[MetricContract]) -> Dict[str, Dict[str, Any]]:
    return {contract.metric: contract.to_dict() for contract in contracts}
