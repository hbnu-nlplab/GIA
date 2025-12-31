"""
28개 L1 메트릭이 데이터셋에 포함되지 않는 이유 분석 (출력을 파일로 저장)
"""
import json
import sys
from pathlib import Path

output_file = Path(r'c:\Users\Yujin\CodeSpace\GIA\l1_metrics_analysis_report.txt')
output_lines = []

def log(msg):
    print(msg)
    output_lines.append(msg)

# 1. policies.json 로드
policies_path = Path(r'c:\Users\Yujin\CodeSpace\GIA\Make_Dataset\policies.json')
with open(policies_path, 'r', encoding='utf-8') as f:
    policies_data = json.load(f)

# 2. metrics_metadata 추출
metrics_meta = policies_data.get('metrics_metadata', {})
log(f"Total metrics in metrics_metadata: {len(metrics_meta)}\n")

# 3. L1 메트릭 필터링
l1_metrics = {k: v for k, v in metrics_meta.items() if v.get('level') == 'L1'}
log(f"Total L1 metrics: {len(l1_metrics)}\n")

# 4. 사용자가 언급한 28개 메트릭 확인
target_metrics = [
    'banner_motd_content', 'banner_login_content', 'enable_secret_type',
    'console_password_val', 'exec_timeout_val', 'password_encryption_config',
    'http_server_config', 'cdp_config', 'ip_source_route_config',
    'mpls_ldp_config', 'multicast_routing_config', 'snmp_server_communities',
    'loopback_interfaces_list', 'dns_servers_list', 'netflow_monitors_list',
    'qos_class_maps_list', 'static_route_count', 'acl_configured_count',
    'prefix_list_count', 'route_map_count', 'interfaces_missing_description_count',
    'port_channel_devices', 'tunnel_interface_devices', 'serial_interface_devices',
    'vlan_interface_devices'
]

log("=== 28개 메트릭 중 policies.json에 정의된 것 ===")
found_in_policies = []
missing_in_policies = []

for m in target_metrics:
    if m in metrics_meta:
        found_in_policies.append(m)
        category = metrics_meta[m].get('category', 'Unknown')
        log(f"  ✓ {m} (category: {category})")
    else:
        missing_in_policies.append(m)
        log(f"  ✗ {m} - NOT IN POLICIES.JSON")

log(f"\nFound: {len(found_in_policies)}/{len(target_metrics)}")
log(f"Missing: {len(missing_in_policies)}/{len(target_metrics)}")

if missing_in_policies:
    log(f"\nMissing metrics:")
    for m in missing_in_policies:
        log(f"  - {m}")

# 5. 카테고리별 분포 확인
log("\n=== 28개 메트릭의 카테고리 분포 ===")
categories = {}
for m in found_in_policies:
    cat = metrics_meta[m].get('category', 'Unknown')
    categories[cat] = categories.get(cat, 0) + 1

for cat, count in sorted(categories.items()):
    log(f"  {cat}: {count}")

# 6. RuleBasedGenerator에서 사용하는 카테고리 확인
expected_categories = [
    "System_Inventory", "Security_Inventory", "Interface_Inventory", 
    "Routing_Inventory", "Services_Inventory", "Security_Policy",
    "OSPF_Consistency", "BGP_Consistency", "VRF_Consistency", 
    "L2VPN_Consistency", "Comparison_Analysis", "Reachability_Analysis", "What_If_Analysis"
]

log("\n=== 카테고리 매칭 분석 ===")
log("main_batfish.py에서 사용하는 카테고리:")
for cat in expected_categories:
    log(f"  - {cat}")

log("\n28개 메트릭의 카테고리가 위 리스트에 포함되는지 확인:")
unmatched_categories = set()
matched_count = 0
for m in found_in_policies:
    cat = metrics_meta[m].get('category', 'Unknown')
    if cat not in expected_categories:
        unmatched_categories.add(cat)
        log(f"  ⚠ {m}: category '{cat}' NOT in expected list!")
    else:
        matched_count += 1

if not unmatched_categories:
    log("  ✓ All categories match!")
else:
    log(f"\n⚠ Matched: {matched_count}, Unmatched: {len(found_in_policies) - matched_count}")
    log(f"⚠ Unmatched categories: {sorted(unmatched_categories)}")

# 7. 출력 저장
with open(output_file, 'w', encoding='utf-8') as f:
    f.write('\n'.join(output_lines))

log(f"\n=== 분석 완료 ===")
log(f"리포트 저장됨: {output_file}")

# 8. 결론
log("\n" + "="*60)
log("결론:")
log("="*60)
if unmatched_categories:
    log("🔴 문제: 카테고리 미스매치!")
    log(f"  - {len(found_in_policies)}개 메트릭이 policies.json에 정의됨")
    log(f"  - 하지만 {len(unmatched_categories)}개 카테고리가 main_batfish.py에 없음")
    log(f"\n🔧 해결방법:")
    log(f"  main_batfish.py 라인 255-260의 categories 리스트에 추가:")
    for cat in sorted(unmatched_categories):
        log(f'    "{cat}",')
else:
    log("✅ 모든 카테고리가 매칭됨!")
    log("   다른 원인 조사 필요")
