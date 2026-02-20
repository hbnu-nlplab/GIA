#!/usr/bin/env python3
"""IP conflict checker for topology YAML files."""

import yaml
import ipaddress
from collections import defaultdict
import json
import os
import datetime

FILES = {
    "LabB_20nodes": "/home/yujin/Desktop/Projects/GIA/Make_Dataset/config_generator/topologies/lab_b_20nodes.yaml",
    "LabC_30nodes": "/home/yujin/Desktop/Projects/GIA/Make_Dataset/config_generator/topologies/lab_c_30nodes.yaml",
    "LabD_40nodes": "/home/yujin/Desktop/Projects/GIA/Make_Dataset/config_generator/topologies/lab_d_40nodes.yaml",
}

# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def strip_prefix(ip_cidr):
    """Return just the host IP, no prefix length."""
    return ip_cidr.split("/")[0] if ip_cidr else None

def get_network(ip_cidr):
    """Return network address string for the subnet (e.g. 10.0.1.0/31)."""
    try:
        return str(ipaddress.ip_interface(ip_cidr).network)
    except Exception:
        return None

def parse_lab(data):
    """
    Extract per-node:
      - management_ip (host only)
      - loopback (host only)
      - interface IPs: {node -> [(intf_name, ip_cidr)]}
    Returns dict of structured info.
    """
    nodes = data.get("nodes", [])
    result = {}
    for node in nodes:
        name = node["name"]
        mgmt = node.get("management_ip")
        loopback = node.get("loopback")
        intfs = []
        for intf in node.get("interfaces", []):
            ip = intf.get("ip")
            if ip:
                intfs.append((intf["name"], ip))
        result[name] = {
            "management_ip": strip_prefix(mgmt) if mgmt else None,
            "management_ip_raw": mgmt,
            "loopback": strip_prefix(loopback) if loopback else None,
            "loopback_raw": loopback,
            "interfaces": intfs,
        }
    return result

# ─────────────────────────────────────────────
# Check 1: Management IP uniqueness
# ─────────────────────────────────────────────

def check_mgmt_uniqueness(parsed):
    """Returns list of conflict dicts: {ip, nodes}."""
    seen = defaultdict(list)
    for node, info in parsed.items():
        ip = info["management_ip"]
        if ip:
            seen[ip].append(node)
    conflicts = {ip: nodes for ip, nodes in seen.items() if len(nodes) > 1}
    return conflicts, dict(sorted(seen.items(), key=lambda x: ipaddress.ip_address(x[0])))

# ─────────────────────────────────────────────
# Check 2: Loopback IP uniqueness
# ─────────────────────────────────────────────

def check_loopback_uniqueness(parsed):
    seen = defaultdict(list)
    for node, info in parsed.items():
        lb = info["loopback"]
        if lb:
            seen[lb].append(node)
    conflicts = {ip: nodes for ip, nodes in seen.items() if len(nodes) > 1}
    return conflicts, dict(sorted(seen.items(), key=lambda x: ipaddress.ip_address(x[0])))

# ─────────────────────────────────────────────
# Check 3: Data link subnet overlap
# For /31 point-to-point links: two nodes share the same /31.
# A conflict is when the SAME /31 network appears more than once
# (excluding the expected paired endpoints which share it legitimately).
# Real conflict: same network assigned to interfaces that are NOT peered.
# We collect (network -> [(node, intf, ip)]) and flag networks with >2 entries
# OR where the same host IP appears more than once.
# ─────────────────────────────────────────────

def check_subnet_overlap(parsed):
    net_to_ips = defaultdict(list)   # network_str -> [(node, intf, ip_cidr)]
    host_to_entries = defaultdict(list)  # host_ip -> [(node, intf)]

    for node, info in parsed.items():
        for intf_name, ip_cidr in info["interfaces"]:
            net = get_network(ip_cidr)
            host = strip_prefix(ip_cidr)
            if net:
                net_to_ips[net].append((node, intf_name, ip_cidr))
            if host:
                host_to_entries[host].append((node, intf_name))

    # Subnet used by >2 endpoints (could indicate mis-assignment)
    subnet_conflicts = {
        net: entries for net, entries in net_to_ips.items() if len(entries) > 2
    }
    # Duplicate host IPs on data interfaces
    host_conflicts = {
        ip: entries for ip, entries in host_to_entries.items() if len(entries) > 1
    }
    return subnet_conflicts, host_conflicts, net_to_ips

# ─────────────────────────────────────────────
# Check 4: Interface slot conflicts (same node, same slot, two links)
# ─────────────────────────────────────────────

def check_slot_conflicts(parsed):
    conflicts = {}
    for node, info in parsed.items():
        slot_seen = defaultdict(list)
        for intf_name, ip_cidr in info["interfaces"]:
            slot_seen[intf_name].append(ip_cidr)
        dupes = {slot: ips for slot, ips in slot_seen.items() if len(ips) > 1}
        if dupes:
            conflicts[node] = dupes
    return conflicts

# ─────────────────────────────────────────────
# Main analysis
# ─────────────────────────────────────────────

def analyze_lab(lab_name, data):
    parsed = parse_lab(data)
    node_count = len(parsed)

    print("=" * 70)
    print(f"LAB: {lab_name}  ({node_count} nodes)")
    print("=" * 70)

    all_clean = True

    # --- Check 1: Management IP ---
    mgmt_conflicts, mgmt_table = check_mgmt_uniqueness(parsed)
    print(f"\n[CHECK 1] Management IP uniqueness")
    if mgmt_conflicts:
        all_clean = False
        print(f"  CONFLICT FOUND: {len(mgmt_conflicts)} duplicate(s)")
        for ip, nodes in mgmt_conflicts.items():
            print(f"    IP {ip} -> {nodes}")
    else:
        print(f"  OK — all {len(mgmt_table)} management IPs are unique")

    # Management IP summary table
    print(f"\n  Management IP summary (sorted):")
    print(f"  {'Node':<12} {'Management IP':<18}")
    print(f"  {'-'*12} {'-'*18}")
    node_mgmt = [(n, i["management_ip_raw"]) for n, i in parsed.items() if i["management_ip"]]
    node_mgmt_sorted = sorted(node_mgmt, key=lambda x: ipaddress.ip_address(x[1].split("/")[0]))
    for node, ip in node_mgmt_sorted:
        print(f"  {node:<12} {ip:<18}")

    # --- Check 2: Loopback IP ---
    lb_conflicts, lb_table = check_loopback_uniqueness(parsed)
    print(f"\n[CHECK 2] Loopback IP uniqueness")
    if lb_conflicts:
        all_clean = False
        print(f"  CONFLICT FOUND: {len(lb_conflicts)} duplicate(s)")
        for ip, nodes in lb_conflicts.items():
            print(f"    IP {ip} -> {nodes}")
    else:
        lb_count = len(lb_table)
        print(f"  OK — all {lb_count} loopback IPs are unique")
        print(f"  Loopbacks: {', '.join(sorted(lb_table.keys(), key=lambda x: ipaddress.ip_address(x)))}")

    # --- Check 3: Subnet / host IP overlap ---
    subnet_conflicts, host_conflicts, net_map = check_subnet_overlap(parsed)
    print(f"\n[CHECK 3] Data link subnet & host IP overlap")
    print(f"  Total unique subnets assigned: {len(net_map)}")

    if subnet_conflicts:
        all_clean = False
        print(f"  SUBNET OVERLOAD (>2 endpoints on same subnet):")
        for net, entries in sorted(subnet_conflicts.items()):
            print(f"    Subnet {net}:")
            for node, intf, ip in entries:
                print(f"      {node} {intf} -> {ip}")
    else:
        print(f"  OK — no subnet has more than 2 endpoints")

    if host_conflicts:
        all_clean = False
        print(f"  DUPLICATE HOST IPs on data interfaces:")
        for ip, entries in sorted(host_conflicts.items(), key=lambda x: ipaddress.ip_address(x[0])):
            print(f"    IP {ip}:")
            for node, intf in entries:
                print(f"      {node} {intf}")
    else:
        print(f"  OK — no duplicate host IPs on data interfaces")

    # --- Check 4: Slot conflicts ---
    slot_conflicts = check_slot_conflicts(parsed)
    print(f"\n[CHECK 4] Interface slot conflicts (same node reusing same slot)")
    if slot_conflicts:
        all_clean = False
        print(f"  CONFLICT FOUND on {len(slot_conflicts)} node(s):")
        for node, dupes in slot_conflicts.items():
            for slot, ips in dupes.items():
                print(f"    {node} slot {slot} used {len(ips)} times: {ips}")
    else:
        print(f"  OK — no slot reuse detected")

    print()
    if all_clean:
        print(f"  RESULT: No conflicts found in {lab_name}")
    else:
        print(f"  RESULT: Conflicts detected — see above")
    print()
    return all_clean


results = {}
for lab_name, path in FILES.items():
    with open(path) as f:
        data = yaml.safe_load(f)
    results[lab_name] = analyze_lab(lab_name, data)

print("=" * 70)
print("SUMMARY")
print("=" * 70)
for lab, clean in results.items():
    status = "CLEAN" if clean else "HAS CONFLICTS"
    print(f"  {lab:<20} {status}")
