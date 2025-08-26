from __future__ import annotations
from pathlib import Path
import xml.etree.ElementTree as ET
import json
import re
from typing import Dict, Any, List, Optional

NS = {
    "cfg": "http://tail-f.com/ns/config/1.0",
    "ncs": "http://tail-f.com/ns/ncs",
    "xr":  "http://tail-f.com/ned/cisco-ios-xr",
    "ios": "urn:ios"  # ← 추가
}

def ln(tag: str) -> str:
    return tag.split('}', 1)[1] if '}' in tag else tag

def find(root: ET.Element, path: str):
    return root.find(path, NS)

def findall(root: ET.Element, path: str):
    return root.findall(path, NS)

def text(el) -> Optional[str]:
    return el.text.strip() if (el is not None and el.text) else None


# Moved from GIA/parser/vendor/xr_facts_v2_4.py → unified as xr_facts_parser.py

def parse_xr_device(tree: ET.ElementTree) -> Dict[str, Any]:
    root = tree.getroot()
    dev = find(root, ".//ncs:devices/ncs:device")

    facts: Dict[str, Any] = {
        "vendor": "ios-xr",
        "system": {},
        "security": {},
        "interfaces": [],
        "num_interfaces": 0,
        "routing": {},
        "services": {},
        "file": None,
    }

    # -------- System --------
    hostname = text(find(dev, "ncs:name"))
    mgmt_ip  = text(find(dev, "ncs:address"))
    mgmt_port = text(find(dev, "ncs:port"))  # mgmt 포트 확인
    facts["system"] = {"hostname": hostname, "mgmt_address": mgmt_ip}

    # -------- Security --------
    admin = find(dev, "ncs:config/xr:admin")

    # (1) XR 장비 구성 기반 SSH
    xr_ssh_present = find(dev, "ncs:config/xr:ssh") is not None

    # (2) NSO 인벤토리 기반 SSH(mgmt)
    #    - <ncs:device><ncs:ssh> 가 있거나
    #    - mgmt 포트가 22면 SSH 접속 관리로 간주
    nso_mgmt_ssh_present = (find(dev, "ncs:ssh") is not None) or (mgmt_port == "22")

    # (3) XR admin 영역의 AAA
    aaa_present = (find(admin, "xr:aaa") is not None) if admin is not None else False

    # 최종 반영: xr_ssh OR nso_mgmt_ssh 둘 중 하나라도 True면 present=True
    facts["security"] = {
        "ssh": {"present": bool(xr_ssh_present or nso_mgmt_ssh_present)},
        "aaa": {"present": aaa_present},
    }

    # XR admin: 디스크/메모리 상태 임계값
    try:
        if admin is not None:
            dsk = find(admin, "xr:disk_status_config")
            if dsk is not None:
                facts["system"].setdefault("disk_status_config", {})
                for key in ("minor","severe","critical"):
                    v = text(find(dsk, f"xr:{key}"))
                    if v is not None:
                        try:
                            facts["system"]["disk_status_config"][key] = int(v)
                        except Exception:
                            pass
            mem = find(admin, "xr:memory_status_config")
            if mem is not None:
                facts["system"].setdefault("memory_status_config", {})
                for key in ("minor","severe","critical"):
                    v = text(find(mem, f"xr:{key}"))
                    if v is not None:
                        try:
                            facts["system"]["memory_status_config"][key] = int(v)
                        except Exception:
                            pass
                rec = text(find(mem, "xr:recovery_enabled"))
                if rec is not None:
                    facts["system"].setdefault("memory_status_config", {})
                    facts["system"]["memory_status_config"]["recovery_enabled"] = (rec.lower() == "true")
    except Exception:
        pass

    # XR admin: AAA 사용자 상세를 system.users로 누적
    try:
        sys_users: List[Dict[str, Any]] = []
        users_root = find(admin, "xr:aaa/xr:authentication/xr:users") if admin is not None else None
        for u in (findall(users_root, "xr:user") if users_root is not None else []):
            sys_users.append({
                "name": text(find(u, "xr:name")),
                "uid": text(find(u, "xr:uid")),
                "gid": text(find(u, "xr:gid")),
                "password": text(find(u, "xr:password")),
                "ssh_keydir": text(find(u, "xr:ssh_keydir")),
                "homedir": text(find(u, "xr:homedir")),
            })
        if sys_users:
            facts["system"]["users"] = sys_users
    except Exception:
        pass

    # -------- IOS specific extraction (optional) --------
    try:
        # System basics
        ios_ver = text(find(dev, "ncs:config/ios:version"))
        if ios_ver:
            facts["system"]["version"] = ios_ver
        ios_tz = text(find(dev, "ncs:config/ios:clock/ios:timezone/ios:zone"))
        if ios_tz:
            facts["system"]["timezone"] = ios_tz
        cfg_reg = text(find(dev, "ncs:config/ios:config-register"))
        if cfg_reg:
            facts["system"]["config_register"] = cfg_reg

        # Security/IP services
        ssh_ver = text(find(dev, "ncs:config/ios:ip/ios:ssh/ios:version"))
        if ssh_ver:
            facts.setdefault("security", {}).setdefault("ssh", {})
            facts["security"]["ssh"]["version"] = ssh_ver
        http_srv = text(find(dev, "ncs:config/ios:ip/ios:http/ios:server"))
        if http_srv is not None:
            facts.setdefault("security", {}).setdefault("http", {})
            facts["security"]["http"]["server_enabled"] = (http_srv.lower() == "true")
        # ip forward-protocol nd
        fwd_nd_present = find(dev, "ncs:config/ios:ip/ios:forward-protocol/ios:nd") is not None
        if fwd_nd_present:
            facts.setdefault("services", {}).setdefault("ip", {})
            facts["services"]["ip"]["forward_protocol_nd"] = True
        # ip cef
        cef_present = find(dev, "ncs:config/ios:ip/ios:cef-conf/ios:cef") is not None
        if cef_present:
            facts.setdefault("services", {}).setdefault("ip", {})
            facts["services"]["ip"]["cef_enabled"] = True

        # Logging
        log_buf = text(find(dev, "ncs:config/ios:logging/ios:buffered/ios:severity-level"))
        if log_buf:
            facts.setdefault("logging", {})["buffered_severity"] = log_buf

        # Line VTY
        vty = find(dev, "ncs:config/ios:line/ios:vty")
        if vty is not None:
            facts.setdefault("line", {}).setdefault("vty", {})
            first = text(find(vty, "ios:first"))
            last  = text(find(vty, "ios:last"))
            facts["line"]["vty"]["first"] = int(first) if (first and first.isdigit()) else None
            facts["line"]["vty"]["last"]  = int(last) if (last and last.isdigit()) else None
            if find(vty, "ios:login/ios:local") is not None:
                facts["line"]["vty"]["login_mode"] = "local"
            pw = text(find(vty, "ios:password/ios:secret"))
            if pw is not None:
                facts["line"]["vty"]["password_secret"] = pw
            trans = text(find(vty, "ios:transport/ios:input"))
            if trans is not None:
                facts["line"]["vty"]["transport_input"] = trans

        # IOS usernames
        sys_users_ios: List[Dict[str, Any]] = []
        for u in findall(dev, "ncs:config/ios:username"):
            sys_users_ios.append({
                "name": text(find(u, "ios:name")),
                "privilege": text(find(u, "ios:privilege")),
                "secret_type": text(find(u, "ios:secret/ios:type")),
                "secret": text(find(u, "ios:secret/ios:secret")),
            })
        if sys_users_ios:
            facts["system"].setdefault("users", [])
            facts["system"]["users"].extend(sys_users_ios)

        # IOS interfaces
        iface_root_ios = find(dev, "ncs:config/ios:interface")
        if iface_root_ios is not None:
            for eth in findall(iface_root_ios, "ios:Ethernet"):
                nm = text(find(eth, "ios:name"))
                if_name = f"Ethernet{nm}" if nm else "Ethernet"
                ip = text(find(eth, "ios:ip/ios:address/ios:primary/ios:address"))
                mask = text(find(eth, "ios:ip/ios:address/ios:primary/ios:mask"))
                ipv4 = f"{ip}/{mask}" if (ip and mask) else (ip or None)
                vlan = text(find(eth, "ios:encapsulation/ios:dot1Q/ios:vlan-id"))
                mop_x = text(find(eth, "ios:mop/ios:xenabled"))
                mop_enabled = (mop_x is not None and mop_x.lower() == "true")
                facts["interfaces"].append({
                    "name": if_name,
                    "ipv4": ipv4,
                    "vlan": vlan,
                    "mop_xenabled": mop_enabled,
                })
    except Exception:
        pass

    # -------- Interfaces --------
    iface_root = find(dev, "ncs:config/xr:interface")
    if iface_root is not None:
        for ch in list(iface_root):
            tag = ln(ch.tag)
            if tag in ("Loopback", "MgmtEth", "GigabitEthernet"):
                if_id = text(find(ch, "xr:id"))
                name = f"{tag}{if_id}" if if_id else tag
                ip   = text(find(ch, "xr:ipv4/xr:address/xr:ip"))
                mask = text(find(ch, "xr:ipv4/xr:address/xr:mask"))
                ipv4 = f"{ip}/{mask}" if (ip and mask) else (ip or None)
                facts["interfaces"].append({"name": name, "ipv4": ipv4, "vlan": None})
        sub = find(iface_root, "xr:GigabitEthernet-subinterface")
        if sub is not None:
            for gig in findall(sub, "xr:GigabitEthernet"):
                gid  = text(find(gig, "xr:id"))
                name = f"GigabitEthernet{gid}" if gid else "GigabitEthernet"
                ip   = text(find(gig, "xr:ipv4/xr:address/xr:ip"))
                mask = text(find(gig, "xr:ipv4/xr:address/xr:mask"))
                vlan = text(find(gig, "xr:encapsulation/xr:dot1q/xr:vlan-id"))
                ipv4 = f"{ip}/{mask}" if (ip and mask) else (ip or None)
                facts["interfaces"].append({"name": name, "ipv4": ipv4, "vlan": vlan})
    facts["num_interfaces"] = len(facts["interfaces"])

    # -------- Services (VRF/L2VPN/MPLS/SNMP) --------
    vrfs = []
    for v in findall(dev, "ncs:config/xr:vrf/xr:vrf-list"):
        vname = text(find(v, "xr:name"))
        rts = []
        for addr in findall(v, ".//xr:route-target//xr:address-list/xr:name"):
            if text(addr):
                rts.append(text(addr))
        vrfs.append({"name": vname, "rd": None, "route_targets": sorted(set(rts))})
    l2vpns = []
    for p2p in findall(dev, "ncs:config/xr:l2vpn/xr:xconnect/xr:group/xr:p2p"):
        ifn   = text(find(p2p, "xr:interface/xr:name"))
        neigh = text(find(p2p, "xr:neighbor/xr:address"))
        pwid  = text(find(p2p, "xr:neighbor/xr:pw-id"))
        l2vpns.append({"interface": ifn, "neighbor": neigh, "pw_id": pwid})
    ldp_ifs = [text(e) for e in findall(dev, "ncs:config/xr:mpls/xr:ldp/xr:interface/xr:name")]
    snmp_present = admin is not None and (
        find(admin, "xr:SNMP-COMMUNITY-MIB") is not None or find(admin, "xr:SNMPv2-MIB") is not None
    )
    facts["services"] = {
        "vrf": vrfs,
        "l2vpn": l2vpns,
        "mpls": {"ldp_interfaces": ldp_ifs},
        "snmp": {"present": snmp_present},
    }

    # -------- Routing: BGP / OSPF --------
    bgp = {"local_as": None, "neighbors": [], "vrfs": []}
    bgp_ni = find(dev, "ncs:config/xr:router/xr:bgp/xr:bgp-no-instance")
    if bgp_ni is not None:
        bgp["local_as"] = text(find(bgp_ni, "xr:id"))
        for n in findall(bgp_ni, "xr:neighbor"):
            bgp["neighbors"].append(
                {"id": text(find(n, "xr:id")), "remote_as": text(find(n, "xr:remote-as"))}
            )
        for v in findall(bgp_ni, "xr:vrf"):
            vname = text(find(v, "xr:name"))
            rd    = text(find(v, "xr:rd"))
            vneis = []
            for n in findall(v, "xr:neighbor"):
                vneis.append({"id": text(find(n, "xr:id")), "remote_as": text(find(n, "xr:remote-as"))})
            bgp["vrfs"].append({"name": vname, "rd": rd, "neighbors": vneis})
    # IOS BGP (optional)
    bgp_ios = find(dev, "ncs:config/ios:router/ios:bgp")
    if bgp_ios is not None:
        las = text(find(bgp_ios, "ios:as-no"))
        if las:
            bgp["local_as"] = bgp.get("local_as") or las
        for n in findall(bgp_ios, "ios:neighbor"):
            bgp["neighbors"].append({
                "id": text(find(n, "ios:id")),
                "remote_as": text(find(n, "ios:remote-as"))
            })
    facts["routing"].setdefault("bgp", bgp)

    ospf = {"process_ids": [], "areas": {}}
    ospf_root = find(dev, "ncs:config/xr:router/xr:ospf")
    if ospf_root is not None:
        pid = text(find(ospf_root, "xr:name"))
        if pid:
            ospf["process_ids"].append(pid)
        for area in findall(ospf_root, "xr:area"):
            aid = text(find(area, "xr:id"))
            if not aid:
                continue
            if_list = [text(e) for e in findall(area, "xr:interface/xr:name")]
            ospf["areas"][aid] = [x for x in if_list if x]
    facts["routing"]["ospf"] = ospf

    return facts


def parse_files(xml_files: List[Path]) -> Dict[str, Any]:
    devices = []
    for p in xml_files:
        try:
            t = ET.parse(p)
            f = parse_xr_device(t)
            f["file"] = p.name

            # --- IOS 텍스트 폴백: 이미 True면 덮어쓰지 않음 ---
            raw = p.read_text(encoding="utf-8", errors="ignore")
            try:
                ios_ssh = bool(re.search(r"\bip\s+ssh\b", raw, re.IGNORECASE)) or \
                          bool(re.search(r"line\s+vty[\s\S]*transport\s+input\s+ssh", raw, re.IGNORECASE))
                if ios_ssh:
                    f.setdefault("security", {}).setdefault("ssh", {})
                    if not f["security"]["ssh"].get("present", False):
                        f["security"]["ssh"]["present"] = True
            except Exception:
                pass

            devices.append(f)
        except Exception as e:
            devices.append({"file": p.name, "error": str(e)})
    return {"devices": devices}


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--in-dir", required=True, help="XML 디렉토리")
    ap.add_argument("--out", required=True, help="JSON 출력 경로")
    args = ap.parse_args()

    in_dir = Path(args.in_dir)
    xmls = sorted([p for p in in_dir.iterdir() if p.suffix.lower() == ".xml"], key=lambda x: x.name)
    result = parse_files(xmls)
    Path(args.out).write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote {args.out} (devices={len(result.get('devices', []))})")


if __name__ == "__main__":
    main() 