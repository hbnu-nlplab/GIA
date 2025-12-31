import json

# Check policies.json
policies = json.load(open(r'c:\Users\Yujin\CodeSpace\GIA\Make_Dataset\policies.json', encoding='utf-8'))

print(f'Total metrics in policies.json: {len(policies)}')

l1_metrics = [k for k,v in policies.items() if v.get('level') == 'L1']
print(f'\nL1 metrics: {len(l1_metrics)}')

# Check specific metrics mentioned by user
test_metrics = [
    'banner_motd_content', 'banner_login_content', 'enable_secret_type',
    'password_encryption_config', 'snmp_server_communities', 'loopback_interfaces_list',
    'static_route_count', 'port_channel_devices'
]

print('\n28 New L1 Metrics Status:')
found_count = 0
for m in test_metrics:
    status = "✓ FOUND" if m in policies else "✗ MISSING"
    if m in policies:
        found_count += 1
    print(f'  {m}: {status}')

print(f'\nSample check: {found_count}/{len(test_metrics)} found')

# Check if they have correct scope
if found_count > 0:
    print('\nChecking scope types:')
    for m in test_metrics[:3]:
        if m in policies:
            scope_type = policies[m].get('scope', {}).get('type', 'UNKNOWN')
            print(f'  {m}: scope_type = {scope_type}')
