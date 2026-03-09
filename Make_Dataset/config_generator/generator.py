import yaml
import os
import csv
import shutil
import argparse
import ipaddress
from jinja2 import Environment, FileSystemLoader

def load_topology(yaml_file):
    with open(yaml_file, 'r') as f:
        return yaml.safe_load(f)

def ip_address_filter(value):
    """Extracts IP address from CIDR notation (e.g., 10.0.0.1/24 -> 10.0.0.1)"""
    if not value: return ""
    interface = ipaddress.ip_interface(value)
    return str(interface.ip)

def netmask_filter(value):
    """Extracts netmask from CIDR notation (e.g., 10.0.0.1/24 -> 255.255.255.0)"""
    if not value: return ""
    interface = ipaddress.ip_interface(value)
    return str(interface.netmask)

def network_address_filter(value):
    """Extracts network address from CIDR notation (e.g., 10.0.0.1/24 -> 10.0.0.0)"""
    if not value: return ""
    interface = ipaddress.ip_interface(value)
    return str(interface.network.network_address)

def wildcard_mask_filter(value):
    """Calculates wildcard mask from CIDR notation (e.g., 10.0.0.1/24 -> 0.0.0.255)"""
    if not value: return ""
    interface = ipaddress.ip_interface(value)
    return str(interface.hostmask)

def generate_configs(topology_file, template_dir, output_dir):
    # Load Topology
    topology = load_topology(topology_file)
    lab_name = topology.get('name', 'Unknown_Lab')
    
    # Setup Jinja2 Environment
    env = Environment(loader=FileSystemLoader(template_dir))
    env.filters['ip_address'] = ip_address_filter
    env.filters['netmask'] = netmask_filter
    env.filters['network_address'] = network_address_filter
    env.filters['wildcard_mask'] = wildcard_mask_filter

    # Prepare Output Directories
    lab_output_dir = os.path.join(output_dir, lab_name)
    config_output_dir = os.path.join(lab_output_dir, 'configs')
    txt_output_dir = os.path.join(lab_output_dir, 'txt')
    os.makedirs(config_output_dir, exist_ok=True)
    os.makedirs(txt_output_dir, exist_ok=True)
    print(f"Generating configs for {lab_name}...")
    print(f"  configs/ : {config_output_dir}")
    print(f"  txt/     : {txt_output_dir}")

    # Generate Configs for each Node
    nodes = topology.get('nodes', [])
    node_id_map = []  # (node_id, hostname, role) mapping for PNETLab import
    node_id = 0
    for node in nodes:
        role = node.get('role')
        template_name = ""

        if role == 'pe':
            template_name = 'pe_router.j2'
        elif role == 'p':
            template_name = 'p_router.j2'
        elif role == 'leaf':
            template_name = 'leaf_switch.j2'
        elif role == 'asbr':
            template_name = 'asbr_router.j2'
        else:
            print(f"Skipping {node['name']}: Unknown role {role}")
            continue

        try:
            node_id += 1
            template = env.get_template(template_name)

            # Enrich node data with topology context (e.g. for global routing params)
            render_context = {
                'node': node,
                'topology': topology
            }

            output = template.render(render_context)

            # Write .cfg file (named by hostname)
            cfg_file = os.path.join(config_output_dir, f"{node['name']}.cfg")
            with open(cfg_file, 'w') as f:
                f.write(output)

            # Write .txt file (named by node_id for PNETLab Import)
            txt_file = os.path.join(txt_output_dir, f"{node_id}.txt")
            with open(txt_file, 'w') as f:
                f.write(output)

            node_id_map.append((node_id, node['name'], role))
            print(f"  [OK] {node['name']}.cfg + {node_id}.txt ({template_name})")

        except Exception as e:
            print(f"  [ERROR] Failed to generate {node['name']}: {e}")

    # Write node_id mapping file for PNETLab reference
    mapping_file = os.path.join(txt_output_dir, 'NODE_ID_MAP.md')
    with open(mapping_file, 'w') as f:
        f.write(f"# PNETLab Node ID Mapping — {lab_name}\n\n")
        f.write("PNETLab Import 시 노드 생성 순서와 아래 ID가 일치해야 합니다.\n")
        f.write("노드를 YAML 순서대로 생성하면 자동으로 매칭됩니다.\n\n")
        f.write("| Node ID | Hostname | Role |\n")
        f.write("|:---:|---|---|\n")
        for nid, name, role in node_id_map:
            f.write(f"| {nid} | {name} | {role} |\n")
    print(f"\n  Node ID mapping: {mapping_file}")
    print(f"  Total: {len(node_id_map)} configs + {len(node_id_map)} txt files")

def remap_txt_files(output_dir, lab_name, remap_file):
    """PNETLab 실제 node_id에 맞춰 txt 파일을 재매핑한다.

    remap CSV 형식 (헤더 행 자동 스킵):
      pnetlab_node_id,hostname
      1,P3
      2,P2
      3,P1
    """
    lab_output_dir = os.path.join(output_dir, lab_name)
    config_dir = os.path.join(lab_output_dir, 'configs')
    txt_dir = os.path.join(lab_output_dir, 'txt')

    if not os.path.isdir(config_dir):
        print(f"[ERROR] configs 디렉토리를 찾을 수 없습니다: {config_dir}")
        print(f"  먼저 --topology로 config를 생성하세요.")
        return

    # Read remap CSV
    remap_entries = []
    with open(remap_file, 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or row[0].strip().startswith('#'):
                continue
            # Skip header row (non-numeric first column)
            try:
                node_id = int(row[0].strip())
            except ValueError:
                continue
            hostname = row[1].strip()
            remap_entries.append((node_id, hostname))

    # Validate: check all hostnames have matching .cfg files
    available_cfgs = {os.path.splitext(f)[0] for f in os.listdir(config_dir) if f.endswith('.cfg')}
    missing = [h for _, h in remap_entries if h not in available_cfgs]
    if missing:
        print(f"[ERROR] configs/에 없는 hostname: {missing}")
        print(f"  사용 가능: {sorted(available_cfgs)}")
        return

    # Clear existing txt files
    if os.path.isdir(txt_dir):
        shutil.rmtree(txt_dir)
    os.makedirs(txt_dir)

    print(f"Remapping txt files for {lab_name}...")
    print(f"  remap CSV : {remap_file} ({len(remap_entries)} entries)")
    print(f"  configs/  : {config_dir}")
    print(f"  txt/      : {txt_dir}")
    print()

    # Copy configs with remapped node_id
    for node_id, hostname in sorted(remap_entries, key=lambda x: x[0]):
        cfg_file = os.path.join(config_dir, f"{hostname}.cfg")
        txt_file = os.path.join(txt_dir, f"{node_id}.txt")
        with open(cfg_file, 'r') as src:
            content = src.read()
        with open(txt_file, 'w') as dst:
            dst.write(content)
        print(f"  [OK] {node_id}.txt ← {hostname}.cfg")

    # Write updated NODE_ID_MAP.md
    mapping_file = os.path.join(txt_dir, 'NODE_ID_MAP.md')
    with open(mapping_file, 'w') as f:
        f.write(f"# PNETLab Node ID Mapping — {lab_name}\n\n")
        f.write("**Remapped**: PNETLab 실제 node_id 기준으로 재매핑되었습니다.\n")
        f.write(f"소스: `{os.path.basename(remap_file)}`\n\n")
        f.write("| Node ID | Hostname |\n")
        f.write("|:---:|---|\n")
        for node_id, hostname in sorted(remap_entries, key=lambda x: x[0]):
            f.write(f"| {node_id} | {hostname} |\n")

    print(f"\n  Node ID mapping: {mapping_file}")
    print(f"  Total: {len(remap_entries)} txt files remapped")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate Network Configs from YAML Topology")
    parser.add_argument('--topology', help="Path to topology YAML file")
    parser.add_argument('--templates', default='Make_Dataset/config_generator/templates', help="Path to Jinja2 templates directory")
    parser.add_argument('--output', default='Make_Dataset/config_generator/output', help="Path to output directory")
    parser.add_argument('--remap', help="Path to remap CSV file (pnetlab_node_id,hostname)")
    parser.add_argument('--lab', help="Lab output folder name (required with --remap)")

    args = parser.parse_args()

    if args.remap:
        if not args.lab:
            parser.error("--lab is required when using --remap")
        remap_txt_files(args.output, args.lab, args.remap)
    else:
        if not args.topology:
            parser.error("--topology is required for config generation")
        generate_configs(args.topology, args.templates, args.output)
