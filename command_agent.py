from __future__ import annotations
from typing import Dict, Any


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

    def generate(self, intent: str, params: Dict[str, Any]) -> str:
        vendor = self.vendor_map.get(params.get("host"), "ios-xr")
        templates = self.command_templates().get(vendor, {})
        template = templates.get(intent)
        if not template:
            raise ValueError(f"Unsupported intent '{intent}' for vendor '{vendor}'")
        return template.format(**params)

    @staticmethod
    def command_templates() -> Dict[str, Dict[str, str]]:
        """Return vendor specific command templates."""
        templates = {
            "ios-xr": {
                # Level 1
                "show_bgp_summary": "show bgp summary",
                "show_ip_interface_brief": "show ip interface brief",
                "show_ip_route_ospf": "show ip route ospf",
                "show_processes_cpu": "show processes cpu sorted",
                "show_l2vpn_vc": "show l2vpn atom vc",
                "show_ip_ospf_neighbor": "show ip ospf neighbor",
                "show_users": "show users",
                "show_logging": "show logging",
                "ssh_direct_access": "ssh {user}@{host}",
                # Level 2
                "set_static_route": "ip route {prefix} {mask} {next_hop}",
                "set_bgp_routemap": (
                    "router bgp {asn}\n neighbor {neighbor_ip} route-map {map_name} out"
                ),
                "set_interface_description": (
                    "interface {interface}\n description {description}"
                ),
                "create_vrf_and_assign": (
                    "vrf definition {vrf_name}\n exit\n interface {interface}\n vrf forwarding {vrf_name}"
                ),
                "set_ospf_cost": (
                    "router ospf {process_id}\n interface {interface}\n ip ospf cost {cost}"
                ),
                "set_vty_acl": "line vty 0 4\n access-class {acl_name} in",
                "set_hostname": "hostname {new_hostname}",
                # Level 2.5 / 3
                "ssh_proxy_jump": "ssh -J {user}@{jump_host} {user}@{destination_host}",
                "ssh_multihop_jump": (
                    "ssh -J {user}@{jump_host1},{user}@{jump_host2} {user}@{destination_host}"
                ),
                # Additional intents for diagnostic plans
                "check_connectivity": "ping {destination}",
                "show_bgp_neighbor_detail": "show bgp neighbor {neighbor_ip} detail",
                "show_log_include": "show logging | include {keyword}",
            }
        }
        # IOS devices share the same basic syntax for these commands
        templates["ios"] = templates["ios-xr"]
        return templates
