#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from utils.builder_core import BuilderCore

def main():
    print('Testing Command Generation metrics...')

    # 테스트 장비 데이터
    test_devices = [
        {
            'system': {'hostname': 'PE1'},
            'vendor': 'ios-xr',
            'file': 'pe1.xml'
        }
    ]

    builder = BuilderCore(test_devices)

    # 테스트할 메트릭들
    test_metrics = [
        'cmd_show_bgp_summary',
        'cmd_set_static_route', 
        'cmd_ssh_direct_access'
    ]

    for metric in test_metrics:
        try:
            result, files = builder.calculate_metric(metric, {'host': 'PE1', 'user': 'admin'})
            print(f'✅ {metric}: {result}')
        except Exception as e:
            print(f'❌ {metric}: {e}')

if __name__ == "__main__":
    main()
