from __future__ import annotations
from typing import Dict, Any, Tuple, Sequence


class CommandAgent:
    """Rule-based CLI command generator.

    Converts high level intents into concrete network CLI commands
    using simple template substitution based on vendor type.
    """

    def __init__(self, network_facts: Dict[str, Any]):
        devices = network_facts.get("devices", [])
        self.vendor_map = {}
        for d in devices:
            host = (
                d.get("system", {}).get("hostname")
                or d.get("name")
                or d.get("file")
            )
            vendor = (d.get("vendor") or d.get("os") or "").lower()
            if host:
                self.vendor_map[host] = vendor or "ios-xr"

    def generate(
        self,
        intent: str,
        params: Dict[str, Any],
        allow_fallback: bool = False,
    ) -> str:
        """Return CLI command for given intent.

        Parameters
        ----------
        intent: str
            High level intent such as ``show_bgp_summary``.
        params: Dict[str, Any]
            Parameters required for the intent.
        allow_fallback: bool, optional
            When True, unsupported intents are replaced with a default
            lookup command or comment instead of raising ``ValueError``.
        """

        vendor = self.vendor_map.get(params.get("host"), "ios-xr")
        templates = self.command_templates().get(vendor, {})
        template_info = templates.get(intent)
        if not template_info:
            if allow_fallback:
                fallback = templates.get("_default")
                if fallback:
                    return fallback[0].format(**params)
                return f"# unsupported intent: {intent}"
            raise ValueError(f"Unsupported intent '{intent}' for vendor '{vendor}'")

        if isinstance(template_info, tuple):
            template, required = template_info
        else:  # backward compatibility
            template, required = template_info, []

        missing = [p for p in required if p not in params]
        if missing:
            raise ValueError(
                f"Missing parameters for intent '{intent}': {', '.join(missing)}"
            )
        return template.format(**params)

    @staticmethod
    def command_templates() -> Dict[str, Dict[str, Tuple[str, Sequence[str]]]]:
        """Return vendor specific command templates and required params."""
        templates: Dict[str, Dict[str, Tuple[str, Sequence[str]]]] = {
            "ios-xr": {
                "_default": ("show running-config", []),
                # Level 1
                "show_bgp_summary": ("show bgp summary", []),
                "show_ip_interface_brief": ("show ip interface brief", []),
                "show_ip_route_ospf": ("show ip route ospf", []),
                "show_processes_cpu": ("show processes cpu sorted", []),
                "show_l2vpn_vc": ("show l2vpn atom vc", []),
                "show_ip_ospf_neighbor": ("show ip ospf neighbor", []),
                "show_users": ("show users", []),
                "show_logging": ("show logging", []),
                "ssh_direct_access": ("ssh {user}@{host}", ["user", "host"]),
                # Level 2
                "set_static_route": (
                    "ip route {prefix} {mask} {next_hop}",
                    ["prefix", "mask", "next_hop"],
                ),
                "set_bgp_routemap": (
                    "router bgp {asn}\n neighbor {neighbor_ip} route-map {map_name} out",
                    ["asn", "neighbor_ip", "map_name"],
                ),
                "set_interface_description": (
                    "interface {interface}\n description {description}",
                    ["interface", "description"],
                ),
                "create_vrf_and_assign": (
                    "vrf definition {vrf_name}\n exit\n interface {interface}\n vrf forwarding {vrf_name}",
                    ["vrf_name", "interface"],
                ),
                "set_ospf_cost": (
                    "router ospf {process_id}\n interface {interface}\n ip ospf cost {cost}",
                    ["process_id", "interface", "cost"],
                ),
                "set_vty_acl": (
                    "line vty 0 4\n access-class {acl_name} in",
                    ["acl_name"],
                ),
                "set_hostname": ("hostname {new_hostname}", ["new_hostname"]),
                # Level 2.5 / 3
                "ssh_proxy_jump": (
                    "ssh -J {user}@{jump_host} {user}@{destination_host}",
                    ["user", "jump_host", "destination_host"],
                ),
                "ssh_multihop_jump": (
                    "ssh -J {user}@{jump_host1},{user}@{jump_host2} {user}@{destination_host}",
                    ["user", "jump_host1", "jump_host2", "destination_host"],
                ),
                # Additional intents for diagnostic plans
                "check_connectivity": ("ping {destination}", ["destination"]),
                "show_bgp_neighbor_detail": (
                    "show bgp neighbor {neighbor_ip} detail",
                    ["neighbor_ip"],
                ),
                "show_bgp_neighbors": ("show bgp neighbors", []),
                "show_log_include": (
                    "show logging | include {keyword}",
                    ["keyword"],
                ),
                "show_interface_status": (
                    "show interface {interface}",
                    ["interface"],
                ),
                "show_vrf": ("show vrf {vrf_name}", ["vrf_name"]),
                "show_route_table": ("show ip route", []),
                "show_ospf_database": ("show ip ospf database", []),
                "show_l2vpn_status": ("show l2vpn atom vc detail", []),
                "ssh_acl_applied_check": (
                    "show running-config | include ^line vty|access-class",
                    [],
                ),
            }
        }
        # IOS devices share the same basic syntax for these commands
        templates["ios"] = templates["ios-xr"]
        return templates
