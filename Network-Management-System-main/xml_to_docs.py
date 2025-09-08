# %% [markdown]
# # XML → Sectioned Docs (Deterministic XPath/Flatten)
# Run this cell to regenerate docs from `/mnt/data/ce1.xml`. Secrets are masked.

# %%
!pip install lxml

# %%
# Repro: XML -> Sectioned Docs (Deterministic XPath/Flatten, exact sections)
# pip install lxml
import os
from lxml import etree as ET

SRC_XML = "/workspace/jke/xml_parssing/ce1.xml"
OUT_DIR = "./CE1_docs"
COMBINED_PATH = os.path.join(OUT_DIR, "CE1__ALL_SECTIONS.txt")
os.makedirs(OUT_DIR, exist_ok=True)

# --------------------------
# Helpers
# --------------------------
def strip_ns(tag: str) -> str:
    return tag.split('}')[-1] if '}' in tag else tag

def xtext(elem, xpath_expr: str) -> str | None:
    """Return first text() of xpath; robust to namespaces via local-name()."""
    if elem is None:
        return None
    vals = elem.xpath(xpath_expr)
    if not vals:
        return None
    v = vals[0]
    return v.strip() if isinstance(v, str) else (str(v).strip() if v is not None else None)

def text_of(elem) -> str | None:
    if elem is None:
        return None
    t = (elem.text or "").strip()
    return t if t else None

MASK_SECRETS = False
def mask_if_secret(key_path: str, value: str) -> str:
    if not MASK_SECRETS:
        return value
    lower = key_path.lower()
    if any(k in lower for k in ["secret", "password", "key-data", "private-key"]):
        return f"[MASKED:{len(value)}]"
    return value

def flatten(elem, prefix=""):
    """
    Deterministic flatten: emits (key, value) pairs like 'ip.http.server: false'
    - Groups repeated tags; uses inner <name> text as discriminator when present.
    - Stable key form: <prefix><tag>[<name or idx>].<sub>...
    """
    out = []
    def _rec(e, pfx):
        children = list(e)
        if not children:
            val = (e.text or "").strip()
            if val:
                out.append((pfx.rstrip('.'), val))
            return

        by_tag = {}
        for c in children:
            name = strip_ns(c.tag)
            by_tag.setdefault(name, []).append(c)

        for name, group in by_tag.items():
            if len(group) == 1:
                _rec(group[0], pfx + name + ".")
            else:
                for idx, c in enumerate(group):
                    # Prefer <name> child as stable discriminator
                    name_texts = c.xpath("./*[local-name()='name']/text()")
                    name_field = name_texts[0].strip() if name_texts else None
                    suffix = name_field.replace("/", "_") if name_field else str(idx)
                    _rec(c, pfx + f"{name}[{suffix}].")
    _rec(elem, prefix)
    return out

def write_section(section_name: str, kv_pairs: list[tuple[str,str]], device_name="device"):
    header = [
        "[METADATA]",
        f"section: {section_name}",
        f"device_name: {device_name}",
        f"source: {SRC_XML}",
        "",
        "[CONTENT]",
        f"[SECTION] {section_name}",
    ]
    lines = [f"{k}: {mask_if_secret(k, v)}" for (k, v) in kv_pairs]
    txt = "\n".join(header + lines) + "\n"
    fname = f"{device_name}__{section_name}.txt".replace("/", "_")
    fpath = os.path.join(OUT_DIR, fname)
    with open(fpath, "w", encoding="utf-8") as f:
        f.write(txt)
    return fpath, txt

# --------------------------
# Parse & locate device/config
# --------------------------
tree = ET.parse(SRC_XML)
root = tree.getroot()

device = None
for e in root.iter():
    if strip_ns(e.tag) == "device":
        device = e
        break

if device is None:
    raise RuntimeError("device element not found")

# Device meta (exactly as you wanted)
device_name   = xtext(device, "./*[local-name()='name']/text()") or "device"
device_addr   = xtext(device, "./*[local-name()='address']/text()") or ""
device_port   = xtext(device, "./*[local-name()='port']/text()") or ""
auth_group    = xtext(device, "./*[local-name()='authgroup']/text()") or ""
admin_state   = xtext(device, "./*[local-name()='state']/*[local-name()='admin-state']/text()") or ""
ned_id        = xtext(device, "./*[local-name()='device-type']/*[local-name()='cli']/*[local-name()='ned-id']/text()") or ""
cli_protocol  = xtext(device, "./*[local-name()='device-type']/*[local-name()='cli']/*[local-name()='protocol']/text()") or ""

config_elem = None
for c in list(device):
    if strip_ns(c.tag) == "config":
        config_elem = c
        break
if config_elem is None:
    raise RuntimeError("config element not found under device")

# --------------------------
# Emit sections in desired style/order
# --------------------------
files_made, combined_parts = [], []

# 0) device_meta
fp, t = write_section("device_meta", [
    ("device.name", device_name),
    ("device.address", device_addr),
    ("device.port", device_port),
    ("device.authgroup", auth_group),
    ("device.admin_state", admin_state),
    ("device.cli.ned_id", ned_id),
    ("device.cli.protocol", cli_protocol),
], device_name)
files_made.append(fp); combined_parts.append(t)

# Preferred top-level section order (others will follow)
preferred_order = [
    "hostname", "tailfned", "version", "service", "enable", "clock", "ip",
    "multilink", "username", "redundancy", "interface", "control-plane",
    "config-register", "line", "logging", "router"
]

# Map name -> element list
top_children = list(config_elem)
name_to_elems = {}
for child in top_children:
    lname = strip_ns(child.tag)
    name_to_elems.setdefault(lname, []).append(child)

def emit_simple_section(lname: str):
    elems = name_to_elems.get(lname, [])
    for elem in elems:
        kv = flatten(elem, prefix=f"{lname}.") if lname not in ("hostname",) else []
        # hostname is a single leaf: we want "hostname: <text>" exactly
        if lname == "hostname":
            hv = text_of(elem)
            kv = [("hostname", hv)] if hv else []
        sec = lname
        fp, txt = write_section(sec, kv, device_name)
        files_made.append(fp); combined_parts.append(txt)

# 1) Simple singletons (and blanks allowed)
for lname in ["hostname", "tailfned", "version", "service", "enable", "clock", "ip",
              "multilink", "username", "redundancy", "control-plane", "config-register",
              "logging", "router"]:
    if lname in name_to_elems:
        emit_simple_section(lname)

# 2) Interfaces (split by instance name exactly like your example)
if "interface" in name_to_elems:
    for interface_root in name_to_elems["interface"]:
        # Under <interface>, multiple types (Ethernet, Loopback, etc.)
        for itf in list(interface_root):
            itf_type = strip_ns(itf.tag)  # e.g., Ethernet
            # instance name text
            itf_name = xtext(itf, "./*[local-name()='name']/text()") or ""
            sec_name = f"interface_{itf_type}_{itf_name.replace('/', '_')}"
            kv = flatten(itf, prefix=f"interface.{itf_type}.")
            fp, txt = write_section(sec_name, kv, device_name)
            files_made.append(fp); combined_parts.append(txt)

# 3) line (console/aux/vty -> separate sections)
if "line" in name_to_elems:
    for line_root in name_to_elems["line"]:
        for sub in list(line_root):
            subname = strip_ns(sub.tag)  # console/aux/vty
            kv = flatten(sub, prefix=f"line.{subname}.")
            fp, txt = write_section(f"line_{subname}", kv, device_name)
            files_made.append(fp); combined_parts.append(txt)

# 4) Any remaining top-level blocks not covered above
covered = set(["device_meta"] + preferred_order)
for child in top_children:
    lname = strip_ns(child.tag)
    if lname in covered:
        continue
    kv = flatten(child, prefix=f"{lname}.")
    fp, txt = write_section(lname, kv, device_name)
    files_made.append(fp); combined_parts.append(txt)

# Combined file (with separators like your sample)
with open(COMBINED_PATH, "w", encoding="utf-8") as f:
    f.write(("\n" + ("-"*80) + "\n").join(s.strip("\n") for s in combined_parts))

print(f"Done. Files: {len(files_made)}, combined: {COMBINED_PATH}")


# %%



