#!/usr/bin/env python3
"""Batfish-free Cisco IOS config parser for Ground Truth verification.

This module parses raw .cfg files using ONLY Python + Regex (no pybatfish).
It produces a facts dict compatible with BuilderCore's expected input, then
computes L1-L3 metric answers independently.

Architecture:
  CfgParser     — parses a single .cfg → device facts dict
  TopologyFacts — aggregates all devices → computes any metric answer
"""

from __future__ import annotations

import re
from ipaddress import IPv4Network
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


# ════════════════════════════════════════════════════════════════════
#  CfgParser — Single Device Config Parser
# ════════════════════════════════════════════════════════════════════

class CfgParser:
    """Parse a single Cisco IOS .cfg file into a structured facts dict."""

    def __init__(self, cfg_text: str, filename: str):
        self.raw = cfg_text
        self.filename = filename
        self.lines = cfg_text.splitlines()
        self.hostname = self._stem(filename)

    @staticmethod
    def _stem(filename: str) -> str:
        return Path(filename).stem.lower() if filename else "unknown"

    # ── Public API ──────────────────────────────────────────────────

    def parse(self) -> Dict[str, Any]:
        """Run all parsers and return a complete device facts dict."""
        system = self._parse_system()
        self.hostname = system["hostname"]
        security = self._parse_security()
        logging_cfg = self._parse_logging()
        interfaces = self._parse_interfaces()
        routing = self._parse_routing()
        services = self._parse_services()
        configuration = self._parse_configuration()
        line_cfg = self._parse_line()

        # Merge VRF definitions into BGP vrfs (RD, RT)
        vrf_defs = {v["name"]: v for v in services.get("vrf", [])}
        for bgp_vrf in routing.get("bgp", {}).get("vrfs", []):
            vrf_name = bgp_vrf.get("name")
            if vrf_name and vrf_name in vrf_defs:
                vdef = vrf_defs[vrf_name]
                bgp_vrf["rd"] = vdef.get("rd")
                bgp_vrf["rt_import"] = vdef.get("rt_import", [])
                bgp_vrf["rt_export"] = vdef.get("rt_export", [])

        # Add VRF definitions that exist but aren't in BGP (e.g., only defined, no AF)
        bgp_vrf_names = {v["name"] for v in routing.get("bgp", {}).get("vrfs", []) if v.get("name")}
        for vname, vdef in vrf_defs.items():
            if vname not in bgp_vrf_names:
                routing["bgp"]["vrfs"].append({
                    "name": vname,
                    "rd": vdef.get("rd"),
                    "rt_import": vdef.get("rt_import", []),
                    "rt_export": vdef.get("rt_export", []),
                    "neighbors": [],
                })

        return {
            "vendor": "cisco",
            "system": system,
            "security": security,
            "logging": logging_cfg,
            "interfaces": interfaces,
            "routing": routing,
            "services": services,
            "configuration": configuration,
            "line": line_cfg,
            "file": Path(self.filename).name.lower(),
            "num_interfaces": len(interfaces),
        }

    # ── Tier 1: Simple Regex ────────────────────────────────────────

    def _parse_system(self) -> Dict[str, Any]:
        hostname = self._stem(self.filename)
        version = "15.0"
        timezone = None
        domain_name = ""
        users: List[str] = []

        for line in self.lines:
            stripped = line.strip()
            m = re.match(r'^hostname\s+(\S+)', stripped, re.IGNORECASE)
            if m:
                hostname = m.group(1).lower()
                continue
            m = re.match(r'^version\s+(\S+)', stripped)
            if m:
                version = m.group(1)
                continue
            m = re.match(r'^clock\s+timezone\s+(\S+)\s*(.*)', stripped, re.IGNORECASE)
            if m:
                tz_name = m.group(1)
                tz_offset = m.group(2).strip()
                timezone = f"{tz_name} +{tz_offset}" if tz_offset else tz_name
                continue
            m = re.match(r'^ip\s+domain[\s-]name\s+(\S+)', stripped, re.IGNORECASE)
            if m:
                domain_name = m.group(1)
                continue
            m = re.match(r'^username\s+(\S+)', stripped)
            if m:
                users.append(m.group(1))
                continue

        return {
            "hostname": hostname,
            "version": version,
            "users": sorted(set(users)),
            "domain_name": domain_name,
            "timezone": timezone,
        }

    def _parse_security(self) -> Dict[str, Any]:
        ssh_present = False
        ssh_version: Optional[str] = None
        aaa_present = False
        aaa_method = "local"

        for line in self.lines:
            stripped = line.strip()
            m = re.match(r'^ip\s+ssh\s+version\s+(\d+)', stripped, re.IGNORECASE)
            if m:
                ssh_present = True
                ssh_version = m.group(1)
                continue
            if re.match(r'^aaa\s+new-model', stripped, re.IGNORECASE):
                aaa_present = True
                continue
            if re.match(r'^no\s+aaa\s+new-model', stripped, re.IGNORECASE):
                aaa_present = False
                continue
            m = re.match(r'^aaa\s+authentication\s+login\s+\S+\s+(.*)', stripped, re.IGNORECASE)
            if m:
                aaa_method = m.group(1).strip().split()[0] if m.group(1).strip() else "local"

        # SSH present via transport input too
        if not ssh_present:
            for line in self.lines:
                if re.match(r'^\s+transport\s+input\s+ssh', line, re.IGNORECASE):
                    ssh_present = True
                    if ssh_version is None:
                        ssh_version = "2"  # default when transport input ssh but no explicit version
                    break

        return {
            "ssh": {"present": ssh_present, "version": ssh_version if ssh_version else ("2" if ssh_present else None)},
            "aaa": {"present": aaa_present, "authentication": aaa_method},
        }

    def _parse_logging(self) -> Dict[str, Any]:
        hosts: List[str] = []
        buffered_severity: Optional[str] = None
        severity_names = {"emergencies", "alerts", "critical", "errors", "warnings",
                          "notifications", "informational", "debugging"}

        for line in self.lines:
            stripped = line.strip()
            m = re.match(r'^logging\s+host\s+(\S+)', stripped, re.IGNORECASE)
            if m:
                hosts.append(m.group(1))
                continue
            # logging <IP> (without host keyword)
            m = re.match(r'^logging\s+(\d+\.\d+\.\d+\.\d+)', stripped, re.IGNORECASE)
            if m:
                hosts.append(m.group(1))
                continue
            m = re.match(r'^logging\s+buffered\s+(.*)', stripped, re.IGNORECASE)
            if m:
                parts = m.group(1).split()
                for p in parts:
                    if p.lower() in severity_names:
                        buffered_severity = p.lower()
                        break

        return {"hosts": sorted(set(hosts)), "buffered_severity": buffered_severity}

    def _parse_services(self) -> Dict[str, Any]:
        ntp_servers: List[str] = []
        snmp_communities: List[str] = []
        vrf_defs: List[Dict[str, Any]] = []
        mpls_ldp_interfaces: List[str] = []
        mpls_ldp: Dict[str, Any] = {}

        for line in self.lines:
            stripped = line.strip()
            m = re.match(r'^ntp\s+server\s+(\S+)', stripped, re.IGNORECASE)
            if m:
                ntp_servers.append(m.group(1))
                continue
            m = re.match(r'^snmp-server\s+community\s+(\S+)', stripped, re.IGNORECASE)
            if m:
                snmp_communities.append(m.group(1))
                continue
            m = re.match(r'^mpls\s+ldp\s+router-id\s+(\S+)', stripped, re.IGNORECASE)
            if m:
                mpls_ldp["router_id"] = m.group(1)
                continue

        # Parse VRF definitions (sections)
        vrf_defs = self._parse_vrf_definitions()

        # MPLS LDP interfaces (detected from interface sections)
        for iface in self._parse_interfaces():
            if iface.get("_mpls_ip"):
                mpls_ldp_interfaces.append(iface["name"])

        return {
            "ntp": {"servers": sorted(set(ntp_servers))},
            "snmp": {"communities": sorted(set(snmp_communities))},
            "vrf": vrf_defs,
            "mpls": {
                "ldp_interfaces": mpls_ldp_interfaces,
                "ldp": mpls_ldp,
            },
        }

    # ── Tier 2: Section-Based Parsing ───────────────────────────────

    def _extract_sections(self) -> List[Tuple[str, List[str]]]:
        """Extract indented blocks (interface X, router X, vrf definition X, etc.)."""
        sections: List[Tuple[str, List[str]]] = []
        current_header: Optional[str] = None
        current_body: List[str] = []

        section_re = re.compile(
            r'^(interface|router\s+\w+|vrf\s+definition|line\s+\w+|address-family)\s+',
            re.IGNORECASE,
        )

        for line in self.lines:
            # Skip comments and empty
            stripped = line.rstrip()
            if not stripped or stripped.startswith("!"):
                if current_header:
                    sections.append((current_header, current_body))
                    current_header = None
                    current_body = []
                continue

            if not line[0].isspace() and section_re.match(stripped):
                if current_header:
                    sections.append((current_header, current_body))
                current_header = stripped
                current_body = []
            elif current_header is not None:
                current_body.append(stripped)
            # else: global line, skip

        if current_header:
            sections.append((current_header, current_body))
        return sections

    def _parse_interfaces(self) -> List[Dict[str, Any]]:
        """Parse all interface blocks."""
        interfaces: List[Dict[str, Any]] = []
        sections = self._extract_sections()

        for header, body in sections:
            m = re.match(r'^interface\s+(.+)', header, re.IGNORECASE)
            if not m:
                continue
            iface_name = m.group(1).strip()
            ipv4 = None
            vrf = None
            shutdown = False
            description = ""
            mpls_ip = False
            acl_in = None
            acl_out = None

            for bline in body:
                bl = bline.strip()

                # IP address
                im = re.match(r'^ip\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)', bl, re.IGNORECASE)
                if im:
                    ip = im.group(1)
                    mask = im.group(2)
                    prefix_len = self._mask_to_prefix(mask)
                    ipv4 = f"{ip}/{prefix_len}"
                    continue

                # VRF forwarding
                vm = re.match(r'^(?:ip\s+)?vrf\s+forwarding\s+(\S+)', bl, re.IGNORECASE)
                if vm:
                    vrf = vm.group(1)
                    continue

                if re.match(r'^shutdown', bl, re.IGNORECASE):
                    shutdown = True
                    continue

                dm = re.match(r'^description\s+(.*)', bl, re.IGNORECASE)
                if dm:
                    description = dm.group(1).strip()
                    continue

                if re.match(r'^mpls\s+ip', bl, re.IGNORECASE):
                    mpls_ip = True
                    continue

                am = re.match(r'^ip\s+access-group\s+(\S+)\s+(in|out)', bl, re.IGNORECASE)
                if am:
                    if am.group(2).lower() == "in":
                        acl_in = am.group(1)
                    else:
                        acl_out = am.group(1)

            status = "down" if shutdown else "up"
            # Interfaces without IP and shutdown
            if not ipv4 and shutdown:
                ipv4 = None

            iface_dict: Dict[str, Any] = {
                "name": iface_name,
                "ipv4": ipv4,
                "vlan": None,
                "vrf": vrf,
                "status": status,
            }
            # Internal flags (not in final output)
            iface_dict["_mpls_ip"] = mpls_ip
            iface_dict["_description"] = description
            iface_dict["_acl_in"] = acl_in
            iface_dict["_acl_out"] = acl_out

            interfaces.append(iface_dict)

        return interfaces

    def _parse_routing(self) -> Dict[str, Any]:
        """Parse routing protocol configurations (BGP, OSPF)."""
        bgp = self._parse_bgp()
        ospf = self._parse_ospf()
        return {"bgp": bgp, "ospf": ospf}

    def _parse_bgp(self) -> Dict[str, Any]:
        """Parse router bgp section."""
        local_as: Optional[int] = None
        neighbors: List[Dict[str, Any]] = []
        vrfs: List[Dict[str, Any]] = []

        in_bgp = False
        in_af: Optional[str] = None  # current address-family context
        current_vrf_name: Optional[str] = None
        current_vrf_neighbors: List[Dict[str, Any]] = []

        for line in self.lines:
            stripped = line.strip()

            # Enter router bgp
            m = re.match(r'^router\s+bgp\s+(\d+)', stripped, re.IGNORECASE)
            if m:
                local_as = int(m.group(1))
                in_bgp = True
                continue

            if not in_bgp:
                continue

            # Exit router bgp (next top-level section)
            if stripped and not stripped.startswith("!") and not line[0].isspace():
                if not re.match(r'^router\s+bgp', stripped, re.IGNORECASE):
                    in_bgp = False
                    # Save last VRF
                    if current_vrf_name:
                        vrfs.append({"name": current_vrf_name, "neighbors": current_vrf_neighbors})
                        current_vrf_name = None
                        current_vrf_neighbors = []
                    continue

            # Address-family
            af_m = re.match(r'^address-family\s+ipv4\s+vrf\s+(\S+)', stripped, re.IGNORECASE)
            if af_m:
                # Save previous VRF if any
                if current_vrf_name:
                    vrfs.append({"name": current_vrf_name, "neighbors": current_vrf_neighbors})
                current_vrf_name = af_m.group(1)
                current_vrf_neighbors = []
                in_af = "vrf"
                continue

            af_m2 = re.match(r'^address-family\s+(.*)', stripped, re.IGNORECASE)
            if af_m2 and not af_m:
                in_af = af_m2.group(1).strip()
                continue

            if re.match(r'^exit-address-family', stripped, re.IGNORECASE):
                if current_vrf_name and in_af == "vrf":
                    vrfs.append({"name": current_vrf_name, "neighbors": current_vrf_neighbors})
                    current_vrf_name = None
                    current_vrf_neighbors = []
                in_af = None
                continue

            # Neighbor (global or within AF)
            nb_m = re.match(r'^neighbor\s+(\S+)\s+remote-as\s+(\d+)', stripped, re.IGNORECASE)
            if nb_m:
                nb_ip = nb_m.group(1)
                remote_as = int(nb_m.group(2))
                nb_entry = {"id": nb_ip, "ip": nb_ip, "remote_as": remote_as}
                if current_vrf_name and in_af == "vrf":
                    current_vrf_neighbors.append(nb_entry)
                else:
                    neighbors.append(nb_entry)

        # Handle trailing VRF
        if current_vrf_name:
            vrfs.append({"name": current_vrf_name, "neighbors": current_vrf_neighbors})

        return {
            "local_as": local_as,
            "neighbors": neighbors,
            "vrfs": vrfs,
        }

    def _parse_ospf(self) -> Dict[str, Any]:
        """Parse router ospf section."""
        process_ids: List[int] = []
        areas: Dict[str, List[str]] = {}

        in_ospf = False
        current_pid: Optional[int] = None

        for line in self.lines:
            stripped = line.strip()

            m = re.match(r'^router\s+ospf\s+(\d+)', stripped, re.IGNORECASE)
            if m:
                current_pid = int(m.group(1))
                process_ids.append(current_pid)
                in_ospf = True
                continue

            if not in_ospf:
                continue

            if stripped and not stripped.startswith("!") and not line[0].isspace():
                in_ospf = False
                continue

            # Network statement
            nm = re.match(r'^\s+network\s+(\S+)\s+(\S+)\s+area\s+(\S+)', stripped, re.IGNORECASE)
            if nm:
                area_id = nm.group(3)
                areas.setdefault(area_id, [])
                # We'll resolve which interfaces match later in TopologyFacts
                continue

        # Determine OSPF area → interface mapping from interface configs
        # by checking which interfaces' IPs fall within OSPF network statements
        ospf_networks = self._collect_ospf_networks()
        interfaces = self._parse_interfaces()
        area_interfaces: Dict[str, List[str]] = {}

        for net_ip, wildcard, area_id in ospf_networks:
            area_interfaces.setdefault(area_id, [])
            for iface in interfaces:
                if iface.get("ipv4"):
                    iface_ip = iface["ipv4"].split("/")[0]
                    if self._ip_matches_network(iface_ip, net_ip, wildcard):
                        if iface["name"] not in area_interfaces[area_id]:
                            area_interfaces[area_id].append(iface["name"])

        return {
            "process_ids": sorted(set(process_ids)),
            "areas": {k: sorted(v) for k, v in area_interfaces.items()},
        }

    def _collect_ospf_networks(self) -> List[Tuple[str, str, str]]:
        """Collect (network_ip, wildcard, area_id) from OSPF config."""
        networks: List[Tuple[str, str, str]] = []
        in_ospf = False
        for line in self.lines:
            stripped = line.strip()
            if re.match(r'^router\s+ospf', stripped, re.IGNORECASE):
                in_ospf = True
                continue
            if in_ospf and stripped and not stripped.startswith("!") and not line[0].isspace():
                in_ospf = False
                continue
            if in_ospf:
                m = re.match(r'^network\s+(\S+)\s+(\S+)\s+area\s+(\S+)', stripped, re.IGNORECASE)
                if m:
                    networks.append((m.group(1), m.group(2), m.group(3)))
        return networks

    def _parse_vrf_definitions(self) -> List[Dict[str, Any]]:
        """Parse vrf definition blocks."""
        vrfs: List[Dict[str, Any]] = []
        in_vrf = False
        current_name: Optional[str] = None
        current_rd: Optional[str] = None
        current_rt_export: List[str] = []
        current_rt_import: List[str] = []

        for line in self.lines:
            stripped = line.strip()

            m = re.match(r'^vrf\s+definition\s+(\S+)', stripped, re.IGNORECASE)
            if m:
                # Save previous
                if current_name:
                    vrfs.append({
                        "name": current_name,
                        "rd": current_rd,
                        "rt_export": current_rt_export[:],
                        "rt_import": current_rt_import[:],
                        "route_targets": sorted(set(current_rt_export + current_rt_import)),
                    })
                current_name = m.group(1)
                current_rd = None
                current_rt_export = []
                current_rt_import = []
                in_vrf = True
                continue

            if in_vrf:
                if stripped and not stripped.startswith("!") and not line[0].isspace():
                    if not re.match(r'^vrf\s+definition', stripped, re.IGNORECASE):
                        # End of VRF block
                        if current_name:
                            vrfs.append({
                                "name": current_name,
                                "rd": current_rd,
                                "rt_export": current_rt_export[:],
                                "rt_import": current_rt_import[:],
                                "route_targets": sorted(set(current_rt_export + current_rt_import)),
                            })
                        current_name = None
                        in_vrf = False
                        continue

                rdm = re.match(r'^rd\s+(\S+)', stripped, re.IGNORECASE)
                if rdm:
                    current_rd = rdm.group(1)
                    continue
                rtm = re.match(r'^route-target\s+(export|import)\s+(\S+)', stripped, re.IGNORECASE)
                if rtm:
                    direction = rtm.group(1).lower()
                    rt_val = rtm.group(2)
                    if direction == "export":
                        current_rt_export.append(rt_val)
                    else:
                        current_rt_import.append(rt_val)

        # Handle last VRF
        if current_name:
            vrfs.append({
                "name": current_name,
                "rd": current_rd,
                "rt_export": current_rt_export[:],
                "rt_import": current_rt_import[:],
                "route_targets": sorted(set(current_rt_export + current_rt_import)),
            })

        return vrfs

    def _parse_configuration(self) -> Dict[str, Any]:
        """Parse additional configuration details from raw text."""
        security = self._parse_config_security()
        operational = self._parse_config_operational()
        routing = self._parse_config_routing()
        advanced = self._parse_config_advanced()
        return {
            "security": security,
            "operational": operational,
            "routing": routing,
            "advanced": advanced,
        }

    def _parse_config_security(self) -> Dict[str, Any]:
        password_encryption = False
        enable_secret = "None"
        console_password = "None"
        exec_timeout = "None"
        banner_motd = "None"
        banner_login = "None"
        http_server = False
        cdp = True  # CDP is enabled by default on Cisco
        ip_source_route = True  # enabled by default

        for line in self.lines:
            stripped = line.strip()
            if re.match(r'^service\s+password-encryption', stripped, re.IGNORECASE):
                password_encryption = True
            if re.match(r'^no\s+service\s+password-encryption', stripped, re.IGNORECASE):
                password_encryption = False
            m = re.match(r'^enable\s+secret\s+(\d+)\s+(.*)', stripped, re.IGNORECASE)
            if m:
                enable_secret = f"type {m.group(1)}"
            if re.match(r'^ip\s+http\s+server', stripped, re.IGNORECASE):
                http_server = True
            if re.match(r'^no\s+ip\s+http\s+server', stripped, re.IGNORECASE):
                http_server = False
            if re.match(r'^no\s+cdp\s+run', stripped, re.IGNORECASE):
                cdp = False
            if re.match(r'^no\s+ip\s+source-route', stripped, re.IGNORECASE):
                ip_source_route = False
            # Banner detection
            if re.match(r'^banner\s+motd\s', stripped, re.IGNORECASE):
                banner_motd = "Configured"
            if re.match(r'^banner\s+login\s', stripped, re.IGNORECASE):
                banner_login = "Configured"

        # Console password: check line con 0 section
        in_con = False
        for line in self.lines:
            stripped = line.strip()
            if re.match(r'^line\s+con\s+0', stripped, re.IGNORECASE):
                in_con = True
                continue
            if in_con and stripped and not line[0].isspace():
                in_con = False
                continue
            if in_con:
                pm = re.match(r'^\s+password\s+(.+)', stripped, re.IGNORECASE)
                if pm:
                    console_password = pm.group(1).strip()
                tm = re.match(r'^\s+exec-timeout\s+(.+)', stripped, re.IGNORECASE)
                if tm:
                    exec_timeout = tm.group(1).strip()

        return {
            "password_encryption": password_encryption,
            "enable_secret": enable_secret,
            "console_password": console_password,
            "exec_timeout": exec_timeout,
            "banner_motd": banner_motd,
            "banner_login": banner_login,
            "http_server": http_server,
            "cdp": cdp,
            "ip_source_route": ip_source_route,
        }

    def _parse_config_operational(self) -> Dict[str, Any]:
        snmp_communities: List[str] = []
        loopback_interfaces: List[str] = []
        name_servers: List[str] = []

        for line in self.lines:
            stripped = line.strip()
            m = re.match(r'^snmp-server\s+community\s+(\S+)', stripped, re.IGNORECASE)
            if m:
                snmp_communities.append(m.group(1))
            m = re.match(r'^ip\s+name-server\s+(.+)', stripped, re.IGNORECASE)
            if m:
                for srv in m.group(1).split():
                    if re.match(r'\d+\.\d+\.\d+\.\d+', srv):
                        name_servers.append(srv)

        # Loopback interfaces
        for iface in self._parse_interfaces():
            if iface["name"].lower().startswith("loopback"):
                loopback_interfaces.append(iface["name"])

        return {
            "snmp_communities": sorted(set(snmp_communities)),
            "loopback_interfaces": sorted(set(loopback_interfaces)),
            "name_servers": sorted(set(name_servers)),
        }

    def _parse_config_routing(self) -> Dict[str, Any]:
        ospf_processes: List[str] = []
        bgp_as: List[str] = []
        mpls_ldp_enabled = False
        mpls_ldp_rid: Optional[str] = None
        default_route_next_hops: List[str] = []
        static_routes_count = 0

        for line in self.lines:
            stripped = line.strip()
            m = re.match(r'^router\s+ospf\s+(\d+)', stripped, re.IGNORECASE)
            if m:
                ospf_processes.append(m.group(1))
            m = re.match(r'^router\s+bgp\s+(\d+)', stripped, re.IGNORECASE)
            if m:
                bgp_as.append(m.group(1))
            if re.match(r'^mpls\s+label\s+protocol\s+ldp', stripped, re.IGNORECASE):
                mpls_ldp_enabled = True
            # "mpls ip" on interface or global also implies LDP enabled
            # (matches Batfish parser: re.search(r"^\s*mpls ip", content, re.MULTILINE))
            if re.match(r'^mpls\s+ip$', stripped, re.IGNORECASE):
                mpls_ldp_enabled = True
            m = re.match(r'^mpls\s+ldp\s+router-id\s+(\S+)', stripped, re.IGNORECASE)
            if m:
                mpls_ldp_rid = m.group(1)
                mpls_ldp_enabled = True  # mpls ldp router-id implies LDP is enabled
            # Static routes (global only, not VRF)
            m = re.match(r'^ip\s+route\s+(\S+)\s+(\S+)\s+(\S+)', stripped, re.IGNORECASE)
            if m and not re.match(r'^ip\s+route\s+vrf', stripped, re.IGNORECASE):
                static_routes_count += 1
                dest = m.group(1)
                if dest == "0.0.0.0":
                    next_hop = m.group(3)
                    if re.match(r'\d+\.\d+\.\d+\.\d+', next_hop):
                        default_route_next_hops.append(next_hop)
            # VRF static routes
            m = re.match(r'^ip\s+route\s+vrf\s+\S+\s+(\S+)\s+(\S+)\s+(\S+)', stripped, re.IGNORECASE)
            if m:
                static_routes_count += 1
                dest = m.group(1)
                if dest == "0.0.0.0":
                    default_route_next_hops.append(m.group(3))

        # Resolve MPLS LDP router-id to IP (e.g., "Loopback0" → "10.255.0.1")
        if mpls_ldp_rid and not re.match(r'\d+\.\d+\.\d+\.\d+', mpls_ldp_rid):
            # It's an interface reference like "Loopback0"
            resolved = False
            for iface in self._parse_interfaces():
                if iface["name"].lower() == mpls_ldp_rid.lower():
                    if iface.get("ipv4"):
                        mpls_ldp_rid = iface["ipv4"].split("/")[0]
                        resolved = True
                    break
            if not resolved:
                # Keep as interface name (will be resolved later if needed)
                pass

        return {
            "ospf_processes": sorted(set(ospf_processes)),
            "bgp_as": sorted(set(bgp_as)),
            "mpls_ldp_enabled": mpls_ldp_enabled,
            "mpls_ldp_rid": mpls_ldp_rid,
            "default_route_next_hops": sorted(set(default_route_next_hops)),
            "static_routes_count": static_routes_count,
        }

    def _parse_config_advanced(self) -> Dict[str, Any]:
        acls_count = 0
        acl_names: Set[str] = set()
        acl_interfaces: List[str] = []
        prefix_lists_count = 0
        route_maps_count = 0
        class_maps: List[str] = []
        netflow_monitors: List[str] = []
        eigrp_as: List[str] = []
        rip_enabled = False
        fhrp_groups: List[str] = []
        multicast_enabled = False

        for line in self.lines:
            stripped = line.strip()
            # ACLs
            m = re.match(r'^(?:ip\s+)?access-list\s+(?:extended|standard)?\s*(\S+)', stripped, re.IGNORECASE)
            if m:
                acl_names.add(m.group(1))
            m = re.match(r'^access-list\s+(\d+)', stripped, re.IGNORECASE)
            if m:
                acl_names.add(m.group(1))
            # Prefix lists
            if re.match(r'^ip\s+prefix-list\s+', stripped, re.IGNORECASE):
                prefix_lists_count += 1
            # Route maps
            if re.match(r'^route-map\s+', stripped, re.IGNORECASE):
                route_maps_count += 1
            # Class maps
            m = re.match(r'^class-map\s+\S+\s+(\S+)', stripped, re.IGNORECASE)
            if m:
                class_maps.append(m.group(1))
            # Netflow
            m = re.match(r'^flow\s+monitor\s+(\S+)', stripped, re.IGNORECASE)
            if m:
                netflow_monitors.append(m.group(1))
            # EIGRP
            m = re.match(r'^router\s+eigrp\s+(\d+)', stripped, re.IGNORECASE)
            if m:
                eigrp_as.append(m.group(1))
            # RIP
            if re.match(r'^router\s+rip', stripped, re.IGNORECASE):
                rip_enabled = True
            # FHRP
            m = re.match(r'^\s+standby\s+(\d+)', stripped, re.IGNORECASE)
            if m:
                fhrp_groups.append(m.group(1))
            # Multicast
            if re.match(r'^ip\s+multicast-routing', stripped, re.IGNORECASE):
                multicast_enabled = True

        acls_count = len(acl_names)

        # ACL applied on interfaces
        for iface in self._parse_interfaces():
            if iface.get("_acl_in") or iface.get("_acl_out"):
                acl_interfaces.append(iface["name"])

        # Missing descriptions
        missing_desc = sum(1 for iface in self._parse_interfaces() if not iface.get("_description"))

        return {
            "acls_count": acls_count,
            "acl_interfaces": sorted(set(acl_interfaces)),
            "prefix_lists_count": prefix_lists_count,
            "route_maps_count": route_maps_count,
            "class_maps": sorted(set(class_maps)),
            "netflow_monitors": sorted(set(netflow_monitors)),
            "missing_descriptions_count": missing_desc,
            "eigrp_as": sorted(set(eigrp_as)),
            "rip_enabled": rip_enabled,
            "fhrp_groups": sorted(set(fhrp_groups)),
            "multicast_enabled": multicast_enabled,
        }

    def _parse_line(self) -> Dict[str, Any]:
        """Parse line vty configuration."""
        transport_input = ""
        login_mode = ""

        in_vty = False
        for line in self.lines:
            stripped = line.strip()
            if re.match(r'^line\s+vty\s+', stripped, re.IGNORECASE):
                in_vty = True
                continue
            if in_vty and stripped and not stripped.startswith("!") and not line[0].isspace():
                in_vty = False
                continue
            if in_vty:
                m = re.match(r'^transport\s+input\s+(\S+)', stripped, re.IGNORECASE)
                if m:
                    transport_input = m.group(1)
                m = re.match(r'^login\s+(\S*)', stripped, re.IGNORECASE)
                if m:
                    login_mode = m.group(1) if m.group(1) else "line"

        return {"vty": {"transport_input": transport_input, "login_mode": login_mode}}

    # ── Utility ─────────────────────────────────────────────────────

    @staticmethod
    def _mask_to_prefix(mask: str) -> int:
        """Convert dotted-decimal mask to prefix length."""
        try:
            octets = [int(o) for o in mask.split(".")]
            bits = "".join(format(o, "08b") for o in octets)
            return bits.index("0") if "0" in bits else 32
        except Exception:
            return 24

    @staticmethod
    def _ip_matches_network(ip: str, network: str, wildcard: str) -> bool:
        """Check if ip falls within a network/wildcard pair (OSPF style)."""
        try:
            ip_int = CfgParser._ip_to_int(ip)
            net_int = CfgParser._ip_to_int(network)
            wild_int = CfgParser._ip_to_int(wildcard)
            # In OSPF, wildcard is inverse mask
            return (ip_int & ~wild_int) == (net_int & ~wild_int)
        except Exception:
            return False

    @staticmethod
    def _ip_to_int(ip: str) -> int:
        parts = [int(p) for p in ip.split(".")]
        return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]


# ════════════════════════════════════════════════════════════════════
#  TopologyFacts — Cross-Device Aggregation & Metric Computation
# ════════════════════════════════════════════════════════════════════

class TopologyFacts:
    """Aggregate multiple device facts and compute any L1-L3 metric."""

    def __init__(self, device_facts: Dict[str, Dict[str, Any]]):
        """
        Parameters
        ----------
        device_facts : dict mapping hostname → parsed facts dict
        """
        self.device_facts = device_facts
        self.devices = list(device_facts.values())
        self.host_index = {self._hostname(d): d for d in self.devices}
        self.loop_ip_index: Dict[str, str] = {}
        for d in self.devices:
            ip = self._loop_ip(d)
            if ip:
                self.loop_ip_index[ip] = self._hostname(d)

        # Precompute cross-device data
        self._pre = self._precompute()

    # ── Helpers (mirrors BuilderCore) ───────────────────────────────

    @staticmethod
    def _hostname(d: Dict) -> str:
        return d.get("system", {}).get("hostname") or d.get("file", "unknown")

    @staticmethod
    def _loop_ip(d: Dict) -> Optional[str]:
        for i in d.get("interfaces", []):
            if (i.get("name") or "").lower().startswith("loopback"):
                ip = (i.get("ipv4") or "").split("/", 1)[0]
                if ip:
                    return ip
        return None

    @staticmethod
    def _bgp(d: Dict) -> Dict:
        return d.get("routing", {}).get("bgp", {}) or {}

    @staticmethod
    def _bgp_neighbors(d: Dict) -> List[Dict]:
        return TopologyFacts._bgp(d).get("neighbors", []) or []

    @staticmethod
    def _bgp_vrfs(d: Dict) -> List[Dict]:
        return TopologyFacts._bgp(d).get("vrfs", []) or []

    @staticmethod
    def _bgp_local_as(d: Dict) -> Optional[int]:
        return TopologyFacts._bgp(d).get("local_as")

    @staticmethod
    def _ospf(d: Dict) -> Dict:
        return d.get("routing", {}).get("ospf", {}) or {}

    @staticmethod
    def _ssh_on(d: Dict) -> bool:
        return d.get("security", {}).get("ssh", {}).get("present", False)

    @staticmethod
    def _aaa_on(d: Dict) -> bool:
        return d.get("security", {}).get("aaa", {}).get("present", False)

    @staticmethod
    def _services_vrf(d: Dict) -> List[Dict]:
        return d.get("services", {}).get("vrf", []) or []

    @staticmethod
    def _l2vpns(d: Dict) -> List[Dict]:
        return d.get("services", {}).get("l2vpn", []) or []

    def _as_groups(self) -> Dict[int, List[Dict]]:
        groups: Dict[int, List[Dict]] = {}
        for d in self.devices:
            las = self._bgp_local_as(d)
            if las:
                groups.setdefault(las, []).append(d)
        return groups

    def _count_bgp_neighbors_total(self, d: Dict) -> int:
        peers: Set[str] = set()
        for n in self._bgp_neighbors(d):
            pid = n.get("id") or n.get("ip")
            if pid:
                peers.add(str(pid))
        for v in self._bgp_vrfs(d):
            for n in v.get("neighbors") or []:
                pid = n.get("id") or n.get("ip")
                if pid:
                    peers.add(str(pid))
        return len(peers)

    def _count_vrfs_total(self, d: Dict) -> int:
        names: Set[str] = set()
        for v in self._bgp_vrfs(d):
            if v.get("name"):
                names.add(v["name"])
        for v in self._services_vrf(d):
            if v.get("name"):
                names.add(v["name"])
        for iface in d.get("interfaces", []):
            vrf = iface.get("vrf") or iface.get("l3vrf")
            if vrf:
                names.add(vrf)
        return len(names)

    # ── Precompute ──────────────────────────────────────────────────

    def _precompute(self) -> Dict[str, Any]:
        pre: Dict[str, Any] = {}

        # iBGP full-mesh analysis
        missing_by_as: Dict[Any, Set[str]] = {}
        under_by_as: Dict[Any, Set[str]] = {}
        for asn, group in self._as_groups().items():
            if len(group) < 2:
                missing_by_as[asn] = set()
                under_by_as[asn] = set()
                continue
            loop_of = {self._hostname(d): self._loop_ip(d) for d in group}
            host_peers: Dict[str, Set[str]] = {}
            for d in group:
                host = self._hostname(d)
                peers = {(n.get("id") or n.get("ip")) for n in self._bgp_neighbors(d) if (n.get("id") or n.get("ip"))}
                host_peers[host] = peers
            miss: Set[str] = set()
            hosts = list(host_peers.keys())
            for i in range(len(hosts)):
                for j in range(i + 1, len(hosts)):
                    a, b = hosts[i], hosts[j]
                    a_loop, b_loop = loop_of.get(a), loop_of.get(b)
                    if not a_loop or not b_loop:
                        miss.add(f"{a}<->{b}")
                        continue
                    if not (b_loop in host_peers.get(a, set()) and a_loop in host_peers.get(b, set())):
                        miss.add(f"{a}<->{b}")
            missing_by_as[asn] = miss

            loop_set = {self._loop_ip(e) for e in group if self._loop_ip(e)}
            under: Set[str] = set()
            for d in group:
                host = self._hostname(d)
                self_ip = self._loop_ip(d)
                expected = max(0, len(loop_set - ({self_ip} if self_ip else set())))
                peers = {(n.get("id") or n.get("ip")) for n in self._bgp_neighbors(d) if (n.get("id") or n.get("ip"))}
                if len(peers) < expected:
                    under.add(host)
            under_by_as[asn] = under

        pre["bgp_missing_pairs_by_as"] = missing_by_as
        pre["bgp_under_by_as"] = under_by_as

        # VRF without RT
        without_rt: List[str] = []
        for d in self.devices:
            host = self._hostname(d)
            for sv in self._services_vrf(d):
                if not (sv.get("route_targets") or []):
                    without_rt.append(f"{host}/{sv.get('name')}")
        pre["vrf_without_rt_pairs"] = set(without_rt)

        # L2VPN
        pairs: Set[str] = set()
        unidir: Set[str] = set()
        mismatch: Set[str] = set()
        l2vpn_entries: List[Tuple[str, Optional[str], Any]] = []
        for d in self.devices:
            host = self._hostname(d)
            for xc in self._l2vpns(d):
                peer_host = self.loop_ip_index.get(xc.get("neighbor"))
                l2vpn_entries.append((host, peer_host, xc.get("pw_id")))
        seen_keys: Set[str] = set()
        for a, b, pw in l2vpn_entries:
            key = f"{a}<->{b or 'UNKNOWN'}"
            if key in seen_keys:
                continue
            seen_keys.add(key)
            pairs.add(key)
            if not b:
                unidir.add(key)
                continue
            peer = self.host_index.get(b)
            if not peer:
                unidir.add(key)
                continue
            a_loop = self._loop_ip(self.host_index.get(a, {}))
            back = None
            pw_back = None
            for xc in self._l2vpns(peer):
                if xc.get("neighbor") == a_loop:
                    back = xc
                    pw_back = xc.get("pw_id")
                    break
            if not back:
                unidir.add(key)
            elif pw is not None and pw_back is not None and str(pw) != str(pw_back):
                mismatch.add(key)
        pre["l2vpn_pairs"] = pairs
        pre["l2vpn_unidir"] = unidir
        pre["l2vpn_mismatch"] = mismatch

        # Security
        pre["ssh_enabled"] = {self._hostname(d) for d in self.devices if self._ssh_on(d)}
        pre["ssh_missing"] = {self._hostname(d) for d in self.devices if not self._ssh_on(d)}
        pre["aaa_enabled"] = {self._hostname(d) for d in self.devices if self._aaa_on(d)}
        pre["aaa_missing"] = {self._hostname(d) for d in self.devices if not self._aaa_on(d)}

        return pre

    # ── Metric Computation (mirrors BuilderCore._answer_for_metric) ─

    def compute_metric(self, metric: str, scope: Dict[str, Any]) -> Tuple[str, Any]:
        """Compute a metric answer. Returns (answer_type, value).

        This method mirrors BuilderCore._answer_for_metric for L1-L3 metrics.
        """
        pre = self._pre

        # ──── L1 Device-scoped metrics ────────────────────────
        host = scope.get("host")

        if metric == "system_hostname_text":
            d = self.host_index.get(host)
            return ("text", self._hostname(d)) if d else ("text", "")

        if metric == "system_version_text":
            d = self.host_index.get(host)
            return ("text", (d or {}).get("system", {}).get("version", "")) if d else ("text", "")

        if metric == "system_timezone_text":
            d = self.host_index.get(host)
            return ("text", (d or {}).get("system", {}).get("timezone") or "") if d else ("text", "")

        if metric == "system_user_list":
            d = self.host_index.get(host)
            if not d:
                return "set", []
            users = d.get("system", {}).get("users", [])
            names = [u if isinstance(u, str) else u.get("name", "") for u in users]
            return "set", sorted(set(n for n in names if n))

        if metric == "system_user_count":
            d = self.host_index.get(host)
            if not d:
                return "numeric", 0
            users = d.get("system", {}).get("users", [])
            names = [u if isinstance(u, str) else u.get("name", "") for u in users]
            return "numeric", len(set(n for n in names if n))

        if metric == "logging_buffered_severity_text":
            d = self.host_index.get(host)
            return ("text", (d or {}).get("logging", {}).get("buffered_severity") or "") if d else ("text", "")

        if metric == "ntp_server_list":
            d = self.host_index.get(host)
            if not d:
                return "set", []
            servers = (d.get("services", {}).get("ntp", {}).get("servers") or [])
            return "set", sorted(set(str(s) for s in servers if s))

        if metric == "snmp_community_list":
            d = self.host_index.get(host)
            if not d:
                return "set", []
            comms = (d.get("services", {}).get("snmp", {}).get("communities") or [])
            return "set", sorted(set(str(c) for c in comms if c))

        if metric == "syslog_server_list":
            d = self.host_index.get(host)
            if not d:
                return "set", []
            hosts_list = (d.get("logging", {}).get("hosts") or [])
            return "set", sorted(set(str(s) for s in hosts_list if s))

        if metric == "vty_login_mode_text":
            d = self.host_index.get(host)
            return ("text", (d or {}).get("line", {}).get("vty", {}).get("login_mode", "")) if d else ("text", "")

        if metric == "vty_transport_input_text":
            d = self.host_index.get(host)
            return ("text", (d or {}).get("line", {}).get("vty", {}).get("transport_input", "")) if d else ("text", "")

        if metric == "interface_count":
            d = self.host_index.get(host)
            return ("numeric", len((d or {}).get("interfaces", []))) if d else ("numeric", 0)

        if metric == "interface_ip_map":
            d = self.host_index.get(host)
            if not d:
                return "map", {}
            mp = {}
            for i in d.get("interfaces", []):
                name = i.get("name", "")
                ip = i.get("ipv4") or ""
                if name:
                    mp[name] = ip
            return "map", mp

        if metric == "subinterface_count":
            d = self.host_index.get(host)
            if not d:
                return "numeric", 0
            return "numeric", sum(1 for i in d.get("interfaces", []) if "." in (i.get("name") or ""))

        if metric == "vrf_bind_map":
            d = self.host_index.get(host)
            if not d:
                return "map", {}
            mp = {}
            for i in d.get("interfaces", []):
                name = i.get("name", "")
                vrf = i.get("vrf")
                if name:
                    mp[name] = vrf if vrf else "default"
            return "map", mp

        if metric == "interface_status_map":
            d = self.host_index.get(host)
            if not d:
                return "map", {}
            mp = {}
            for i in d.get("interfaces", []):
                name = i.get("name", "")
                status = i.get("status", "unknown")
                if name:
                    mp[name] = status
            return "map", mp

        if metric == "routing_table_entry_count":
            d = self.host_index.get(host)
            if not d:
                return "number", 0
            static = d.get("configuration", {}).get("routing", {}).get("static_routes_count", 0)
            connected = sum(1 for i in d.get("interfaces", []) if i.get("ipv4"))
            return "number", static + connected

        if metric == "bgp_local_as_numeric":
            d = self.host_index.get(host)
            if not d:
                return "numeric", 0
            las = self._bgp_local_as(d)
            return "numeric", int(las) if las else 0

        if metric == "bgp_neighbor_count":
            d = self.host_index.get(host)
            if not d:
                return "numeric", 0
            cnt = len(self._bgp_neighbors(d))
            for v in self._bgp_vrfs(d):
                cnt += len(v.get("neighbors") or [])
            return "numeric", cnt

        if metric in ("neighbor_list_ibgp", "neighbor_list_ebgp"):
            d = self.host_index.get(host)
            if not d:
                return "set", []
            want_ibgp = (metric == "neighbor_list_ibgp")
            las = self._bgp_local_as(d)
            peers: Set[str] = set()
            for n in self._bgp_neighbors(d):
                pid = n.get("id") or n.get("ip")
                ras = n.get("remote_as")
                if pid and ras is not None:
                    if (ras == las) == want_ibgp:
                        peers.add(pid)
            for v in self._bgp_vrfs(d):
                for n in v.get("neighbors") or []:
                    pid = n.get("id") or n.get("ip")
                    ras = n.get("remote_as")
                    if pid and ras is not None:
                        if (ras == las) == want_ibgp:
                            peers.add(pid)
            return "set", sorted(peers)

        if metric == "ospf_process_ids_set":
            d = self.host_index.get(host)
            if not d:
                return "set", []
            pids = self._ospf(d).get("process_ids", [])
            return "set", sorted(set(str(p) for p in pids))

        if metric == "ospf_area_set":
            d = self.host_index.get(host)
            if not d:
                return "set", []
            areas = self._ospf(d).get("areas", {})
            return "set", sorted(str(a) for a in areas.keys())

        if metric == "ospf_area0_if_list":
            d = self.host_index.get(host)
            if not d:
                return "set", []
            areas = self._ospf(d).get("areas", {})
            intfs = areas.get("0", areas.get(0, []))
            return "set", sorted(intfs) if isinstance(intfs, list) else []

        if metric == "ospf_area0_if_count":
            d = self.host_index.get(host)
            if not d:
                return "numeric", 0
            areas = self._ospf(d).get("areas", {})
            intfs = areas.get("0", areas.get(0, []))
            return "numeric", len(intfs) if isinstance(intfs, list) else 0

        if metric == "vrf_names_set":
            d = self.host_index.get(host)
            if not d:
                return "set", []
            names = set()
            for v in self._bgp_vrfs(d):
                if v.get("name"):
                    names.add(v["name"])
            return "set", sorted(names)

        if metric == "vrf_count":
            d = self.host_index.get(host)
            if not d:
                return "numeric", 0
            names = set()
            for v in self._bgp_vrfs(d):
                if v.get("name"):
                    names.add(v["name"])
            return "numeric", len(names)

        if metric == "vrf_rd_map":
            d = self.host_index.get(host)
            if not d:
                return "map", {}
            mp = {}
            for v in self._bgp_vrfs(d):
                nm = v.get("name")
                if nm:
                    mp[nm] = v.get("rd") or ""
            return "map", mp

        if metric == "rt_import_count":
            d = self.host_index.get(host)
            if not d:
                return "numeric", 0
            c = sum(len(v.get("rt_import", []) or []) for v in self._bgp_vrfs(d))
            return "numeric", c

        if metric == "rt_export_count":
            d = self.host_index.get(host)
            if not d:
                return "numeric", 0
            c = sum(len(v.get("rt_export", []) or []) for v in self._bgp_vrfs(d))
            return "numeric", c

        if metric == "l2vpn_pw_id_set":
            d = self.host_index.get(host)
            if not d:
                return "set", []
            s = set()
            for xc in self._l2vpns(d):
                if xc.get("pw_id") is not None:
                    s.add(str(xc["pw_id"]))
            return "set", sorted(s)

        if metric == "vrf_interface_bind_count":
            vrf = scope.get("vrf")
            if not vrf:
                return "numeric", 0
            cnt = 0
            for d in self.devices:
                if host and self._hostname(d) != host:
                    continue
                for iface in d.get("interfaces", []):
                    if (iface.get("vrf") or iface.get("l3vrf")) == vrf:
                        cnt += 1
            return "numeric", cnt

        if metric == "vrf_rt_list_per_device":
            d = self.host_index.get(host)
            if not d:
                return "set", []
            rts: List[str] = []
            for v in self._services_vrf(d):
                rts.extend(v.get("route_targets") or [])
            return "set", sorted(set(rts))

        # ──── Configuration L1 metrics ────────────────────────
        if metric == "ssh_version_text":
            d = self.host_index.get(host)
            if not d:
                return "text", "미설정"
            val = d.get("security", {}).get("ssh", {}).get("version")
            return "text", str(val) if val is not None else "미설정"

        if metric == "aaa_authentication_method":
            d = self.host_index.get(host)
            if not d:
                return "text", "미설정"
            aaa = d.get("security", {}).get("aaa", {})
            if not aaa.get("present"):
                return "text", "미설정"
            method = aaa.get("method") or aaa.get("authentication_method") or aaa.get("authentication")
            if not method:
                method = "local"
            return "text", method

        if metric == "mpls_ldp_router_id":
            d = self.host_index.get(host)
            if not d:
                return "text", "미설정"
            # Prioritize configuration.routing.mpls_ldp_rid (already resolved to IP)
            rid = d.get("configuration", {}).get("routing", {}).get("mpls_ldp_rid")
            if rid:
                return "text", str(rid)
            # Fallback: services.mpls.ldp.router_id (may need resolution)
            mpls = d.get("services", {}).get("mpls", {})
            ldp = mpls.get("ldp", {})
            rid2 = ldp.get("router_id")
            if rid2:
                # Resolve interface reference (e.g., Loopback0 → IP)
                if not re.match(r'\d+\.\d+\.\d+\.\d+', str(rid2)):
                    for iface in d.get("interfaces", []):
                        if iface.get("name", "").lower() == str(rid2).lower():
                            ip = (iface.get("ipv4") or "").split("/")[0]
                            if ip:
                                return "text", ip
                    return "text", "미설정"
                return "text", str(rid2)
            # No explicit mpls ldp router-id → 미설정 (NO Loopback0 fallback)
            return "text", "미설정"

        # Config-based L1 metrics (from configuration section)
        _cfg_text_metrics = {
            "password_encryption_config": ("security", "password_encryption", "bool_enabled"),
            "enable_secret_type": ("security", "enable_secret", "str_or_not_configured"),
            "console_password_val": ("security", "console_password", "str_or_not_configured"),
            "console_password_config": ("security", "console_password", "str_or_not_configured"),
            "exec_timeout_val": ("security", "exec_timeout", "str_or_not_configured"),
            "exec_timeout_config": ("security", "exec_timeout", "str_or_not_configured"),
            "banner_motd_content": ("security", "banner_motd", "str_or_empty"),
            "banner_login_content": ("security", "banner_login", "str_or_empty"),
            "banner_motd_config": ("security", "banner_motd", "configured_check"),
            "banner_login_config": ("security", "banner_login", "configured_check"),
            "http_server_config": ("security", "http_server", "bool_enabled"),
            "cdp_config": ("security", "cdp", "bool_enabled"),
            "source_route_config": ("security", "ip_source_route", "bool_enabled"),
            "ip_source_route_config": ("security", "ip_source_route", "bool_enabled"),
            "mpls_ldp_config": ("routing", "mpls_ldp_enabled", "bool_enabled"),
            "multicast_routing_config": ("advanced", "multicast_enabled", "bool_enabled"),
            "rip_processes": ("advanced", "rip_enabled", "bool_enabled"),
        }

        if metric in _cfg_text_metrics:
            d = self.host_index.get(host)
            if not d:
                return "text", "Disabled" if "bool" in _cfg_text_metrics[metric][2] else ""
            section, key, mode = _cfg_text_metrics[metric]
            val = d.get("configuration", {}).get(section, {}).get(key)
            if mode == "bool_enabled":
                return "text", "Enabled" if val else "Disabled"
            if mode == "configured_check":
                return "text", "Configured" if val and val != "None" else "Not Configured"
            if mode == "str_or_not_configured":
                return "text", str(val) if val and val != "None" else "Not Configured"
            if mode == "str_or_empty":
                return "text", str(val) if val and val != "None" else ""
            return "text", str(val) if val else ""

        # Config operational L1 metrics
        _cfg_set_metrics = {
            "snmp_server_communities": ("operational", "snmp_communities"),
            "loopback_interfaces_list": ("operational", "loopback_interfaces"),
            "name_servers_list": ("operational", "name_servers"),
            "dns_servers_list": ("operational", "name_servers"),
            "ntp_servers_list": ("operational", None),  # Special handling
            "syslog_servers_list": (None, None),  # Special handling
            "netflow_monitors_list": ("advanced", "netflow_monitors"),
            "qos_class_maps_list": ("advanced", "class_maps"),
            "hsrp_groups_list": ("advanced", "fhrp_groups"),
            "acl_applied_interfaces_list": ("advanced", "acl_interfaces"),
        }

        if metric in _cfg_set_metrics:
            d = self.host_index.get(host)
            if not d:
                return "set", []
            section, key = _cfg_set_metrics[metric]
            if metric == "ntp_servers_list":
                servers = d.get("services", {}).get("ntp", {}).get("servers", [])
                return "set", sorted(set(str(s) for s in servers))
            if metric == "syslog_servers_list":
                servers = d.get("logging", {}).get("hosts", [])
                return "set", sorted(set(str(s) for s in servers))
            if metric == "loopback_interfaces_list":
                val = d.get("configuration", {}).get(section, {}).get(key, [])
                result = []
                for s in val:
                    m = re.search(r"Loopback\d+", s)
                    if m:
                        result.append(m.group(0))
                return "set", sorted(set(result)) if result else []
            val = d.get("configuration", {}).get(section, {}).get(key, [])
            return "set", sorted(set(str(s) for s in val))

        # Config routing number metrics
        _cfg_num_metrics = {
            "static_route_count": ("routing", "static_routes_count"),
            "acl_configured_count": ("advanced", "acls_count"),
            "prefix_list_count": ("advanced", "prefix_lists_count"),
            "route_map_count": ("advanced", "route_maps_count"),
            "interfaces_missing_description_count": ("advanced", "missing_descriptions_count"),
        }

        if metric in _cfg_num_metrics:
            d = self.host_index.get(host)
            if not d:
                return "number", 0
            section, key = _cfg_num_metrics[metric]
            val = d.get("configuration", {}).get(section, {}).get(key)
            return "number", val if val is not None else 0

        if metric == "default_route_next_hops":
            d = self.host_index.get(host)
            if not d:
                return "set", []
            val = d.get("configuration", {}).get("routing", {}).get("default_route_next_hops", [])
            return "set", sorted(set(str(s) for s in val))

        if metric == "configured_bgp_as_numbers":
            d = self.host_index.get(host)
            if not d:
                return "set", []
            las = self._bgp_local_as(d)
            if las:
                return "text", str(las)
            val = d.get("configuration", {}).get("routing", {}).get("bgp_as", [])
            return "set", sorted([str(x) for x in val]) if val else []

        if metric == "active_ospf_processes":
            d = self.host_index.get(host)
            if not d:
                return "set", []
            val = d.get("configuration", {}).get("routing", {}).get("ospf_processes", [])
            return "set", sorted(set(str(s) for s in val))

        if metric == "eigrp_as_numbers":
            d = self.host_index.get(host)
            if not d:
                return "set", []
            val = d.get("configuration", {}).get("advanced", {}).get("eigrp_as", [])
            return "set", sorted([str(x) for x in val]) if val else []

        # ──── L2: Global / Cross-Device ───────────────────────
        if metric == "ssh_enabled_devices":
            return "set", sorted(pre["ssh_enabled"])

        if metric == "ssh_missing_devices":
            return "set", sorted(pre["ssh_missing"])

        if metric == "ssh_missing_count":
            return "numeric", len(pre["ssh_missing"])

        if metric == "aaa_enabled_devices":
            return "set", sorted(pre["aaa_enabled"])

        if metric == "aaa_missing_devices":
            return "set", sorted(pre["aaa_missing"])

        if metric == "devices_with_same_vrf":
            vrf_name = scope.get("vrf")
            if not vrf_name:
                return "set", []
            devs: Set[str] = set()
            for d in self.devices:
                h = self._hostname(d)
                for v in self._bgp_vrfs(d):
                    if v.get("name") == vrf_name:
                        devs.add(h)
                        break
                for sv in self._services_vrf(d):
                    if sv.get("name") == vrf_name:
                        devs.add(h)
                        break
                for iface in d.get("interfaces", []):
                    if (iface.get("vrf") or iface.get("l3vrf")) == vrf_name:
                        devs.add(h)
                        break
            return "set", sorted(devs)

        if metric == "ospf_area_membership":
            area_id = scope.get("area")
            if area_id is None:
                return "set", []
            area_str = str(area_id)
            devs_in_area: Set[str] = set()
            for d in self.devices:
                h = self._hostname(d)
                areas = self._ospf(d).get("areas", {})
                if isinstance(areas, dict):
                    if area_str in areas:
                        devs_in_area.add(h)
            return "set", sorted(devs_in_area)

        if metric == "devices_in_as":
            asn = scope.get("asn")
            if not asn:
                return "set", []
            devs_in_as: Set[str] = set()
            for d in self.devices:
                if self._bgp_local_as(d) == asn:
                    devs_in_as.add(self._hostname(d))
            return "set", sorted(devs_in_as)

        if metric == "interfaces_in_vrf":
            vrf_name = scope.get("vrf")
            if not vrf_name:
                return "number", 0
            count = 0
            for d in self.devices:
                for iface in d.get("interfaces", []):
                    if iface.get("vrf") == vrf_name or iface.get("l3vrf") == vrf_name:
                        count += 1
            return "number", count

        if metric == "ospf_neighbor_count_per_area":
            area_id = scope.get("area")
            if area_id is None:
                return "number", 0
            total = 0
            for d in self.devices:
                areas = self._ospf(d).get("areas", {})
                if isinstance(areas, dict):
                    area_data = areas.get(str(area_id))
                    if area_data and isinstance(area_data, dict):
                        total += len(area_data.get("neighbors", []))
            return "number", total

        # Interface type device lists (L2)
        _iface_type_metrics = {
            "port_channel_devices": lambda n: "Port-channel" in n or "Po" in n,
            "tunnel_interface_devices": lambda n: "Tunnel" in n or "Tu" in n,
            "serial_interface_devices": lambda n: "Serial" in n,
            "vlan_interface_devices": lambda n: "Vlan" in n,
            "gigabit_interface_devices": lambda n: "GigabitEthernet" in n,
            "ten_gigabit_interface_devices": lambda n: "TenGigabit" in n or "Te" in n,
        }

        if metric in _iface_type_metrics:
            check_fn = _iface_type_metrics[metric]
            devs_with: Set[str] = set()
            for d in self.devices:
                for i in d.get("interfaces", []):
                    if check_fn(i.get("name", "")):
                        devs_with.add(self._hostname(d))
                        break
            return "set", sorted(devs_with)

        # L2VPN metrics (L2/L3)
        if metric == "l2vpn_pairs":
            return "set", sorted(pre["l2vpn_pairs"])
        if metric == "l2vpn_unidirectional_pairs":
            return "set", sorted(pre["l2vpn_unidir"])
        if metric == "l2vpn_unidir_count":
            return "numeric", len(pre["l2vpn_unidir"])
        if metric == "l2vpn_pwid_mismatch_pairs":
            return "set", sorted(pre["l2vpn_mismatch"])
        if metric == "l2vpn_mismatch_count":
            return "numeric", len(pre["l2vpn_mismatch"])

        if metric == "vrf_without_rt_pairs":
            return "set", sorted(pre["vrf_without_rt_pairs"])
        if metric == "vrf_without_rt_count":
            return "numeric", len(pre["vrf_without_rt_pairs"])

        # ──── L3: iBGP Consistency ────────────────────────────
        asn = scope.get("asn")

        if metric == "ibgp_fullmesh_ok":
            miss = pre["bgp_missing_pairs_by_as"].get(asn, set())
            if not miss:
                return "text", "OK"
            miss_list = sorted(miss)[:5]
            miss_str = ", ".join(miss_list)
            if len(miss) > 5:
                miss_str += f" and {len(miss) - 5} more"
            return "text", f"Missing: {miss_str}"

        if metric == "ibgp_missing_pairs":
            return "set", sorted(pre["bgp_missing_pairs_by_as"].get(asn, set()))

        if metric == "ibgp_missing_pairs_count":
            return "numeric", len(pre["bgp_missing_pairs_by_as"].get(asn, set()))

        if metric == "ibgp_under_peered_devices":
            return "set", sorted(pre["bgp_under_by_as"].get(asn, set()))

        if metric == "ibgp_under_peered_count":
            return "numeric", len(pre["bgp_under_by_as"].get(asn, set()))

        # ──── L3: Comparison Metrics ──────────────────────────
        host1 = scope.get("host1")
        host2 = scope.get("host2")

        if metric == "compare_bgp_neighbor_count":
            d1, d2 = self.host_index.get(host1), self.host_index.get(host2)
            cnt1 = self._count_bgp_neighbors_total(d1) if d1 else 0
            cnt2 = self._count_bgp_neighbors_total(d2) if d2 else 0
            return "map_str_int", {"host1_count": cnt1, "host2_count": cnt2, "difference": abs(cnt1 - cnt2)}

        if metric == "compare_interface_count":
            d1, d2 = self.host_index.get(host1), self.host_index.get(host2)
            cnt1 = len((d1 or {}).get("interfaces", []))
            cnt2 = len((d2 or {}).get("interfaces", []))
            return "map_str_int", {"host1_count": cnt1, "host2_count": cnt2, "difference": abs(cnt1 - cnt2)}

        if metric == "compare_vrf_count":
            d1, d2 = self.host_index.get(host1), self.host_index.get(host2)
            cnt1 = self._count_vrfs_total(d1) if d1 else 0
            cnt2 = self._count_vrfs_total(d2) if d2 else 0
            return "map_str_int", {"host1_count": cnt1, "host2_count": cnt2, "difference": abs(cnt1 - cnt2)}

        if metric == "compare_bgp_as":
            d1, d2 = self.host_index.get(host1), self.host_index.get(host2)
            as1 = str(self._bgp_local_as(d1)) if d1 and self._bgp_local_as(d1) else "None"
            as2 = str(self._bgp_local_as(d2)) if d2 and self._bgp_local_as(d2) else "None"
            return "text", f"{host1}: AS {as1}, {host2}: AS {as2}"

        if metric == "compare_ospf_areas":
            d1, d2 = self.host_index.get(host1), self.host_index.get(host2)
            areas1 = set(self._ospf(d1 or {}).get("areas", {}).keys())
            areas2 = set(self._ospf(d2 or {}).get("areas", {}).keys())
            a1_str = ", ".join(sorted(str(a) for a in areas1)) if areas1 else "None"
            a2_str = ", ".join(sorted(str(a) for a in areas2)) if areas2 else "None"
            return "text", f"{host1}: Area {a1_str}, {host2}: Area {a2_str}"

        if metric == "max_interface_device":
            max_cnt, max_h = -1, None
            for d in self.devices:
                cnt = len(d.get("interfaces", []))
                if cnt > max_cnt:
                    max_cnt = cnt
                    max_h = self._hostname(d)
            return ("text", f"{max_h}: {max_cnt}") if max_h else ("text", "No Info")

        if metric == "min_interface_device":
            min_cnt, min_h = float("inf"), None
            for d in self.devices:
                cnt = len(d.get("interfaces", []))
                if 0 < cnt < min_cnt:
                    min_cnt = cnt
                    min_h = self._hostname(d)
            return ("text", f"{min_h}: {int(min_cnt)}") if min_h else ("text", "No Info")

        if metric == "max_bgp_peer_device":
            max_cnt, max_h = -1, None
            for d in self.devices:
                cnt = len(self._bgp_neighbors(d))
                if cnt > max_cnt:
                    max_cnt = cnt
                    max_h = self._hostname(d)
            return ("text", f"{max_h}: {max_cnt}") if max_h else ("text", "No Info")

        if metric == "all_devices_same_as":
            parts = []
            for d in self.devices:
                las = self._bgp_local_as(d)
                if las is not None:
                    parts.append(f"{self._hostname(d)}: AS {las}")
            return "text", ", ".join(parts) if parts else "No Info"

        if metric == "bgp_as_distribution":
            as_counts: Dict[int, int] = {}
            for d in self.devices:
                las = self._bgp_local_as(d)
                if las is not None:
                    as_counts[las] = as_counts.get(las, 0) + 1
            parts = [f"AS {asn}: {cnt} devices" for asn, cnt in sorted(as_counts.items())]
            return "text", ", ".join(parts) if parts else "No Info"

        if metric == "vrf_usage_statistics":
            stats: Dict[str, int] = {}
            for d in self.devices:
                h = self._hostname(d)
                unique_vrfs = set(v.get("name") for v in self._bgp_vrfs(d) if v.get("name"))
                stats[h] = len(unique_vrfs)
            parts = [f"{h}: {cnt}개" for h, cnt in sorted(stats.items())]
            return "text", ", ".join(parts) if parts else "No Info"

        # Metric not found
        return "text", None
