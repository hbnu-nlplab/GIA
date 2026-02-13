import yaml
import os
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

    # Prepare Output Directory
    config_output_dir = os.path.join(output_dir, lab_name, 'configs')
    os.makedirs(config_output_dir, exist_ok=True)
    print(f"Generating configs for {lab_name}...")
    print(f"Output directory: {config_output_dir}")

    # Generate Configs for each Node
    nodes = topology.get('nodes', [])
    for node in nodes:
        role = node.get('role')
        template_name = ""
        
        if role == 'pe':
            template_name = 'pe_router.j2'
        elif role == 'p':
            template_name = 'p_router.j2'
        elif role == 'leaf':
            template_name = 'leaf_switch.j2'
        else:
            print(f"Skipping {node['name']}: Unknown role {role}")
            continue
            
        try:
            template = env.get_template(template_name)
            
            # Enrich node data with topology context (e.g. for global routing params)
            render_context = {
                'node': node,
                'topology': topology
            }
            
            output = template.render(render_context)
            
            output_file = os.path.join(config_output_dir, f"{node['name']}.cfg")
            with open(output_file, 'w') as f:
                f.write(output)
            
            print(f"  [OK] Generated {node['name']}.cfg using {template_name}")
            
        except Exception as e:
            print(f"  [ERROR] Failed to generate {node['name']}: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate Network Configs from YAML Topology")
    parser.add_argument('--topology', required=True, help="Path to topology YAML file")
    parser.add_argument('--templates', default='Make_Dataset/config_generator/templates', help="Path to Jinja2 templates directory")
    parser.add_argument('--output', default='Make_Dataset/config_generator/output', help="Path to output directory")
    
    args = parser.parse_args()
    
    generate_configs(args.topology, args.templates, args.output)
