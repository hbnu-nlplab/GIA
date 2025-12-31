# NetConfigQA Dataset Verification Report

> Generated: 2025-12-30 17:21:14
> Dataset: `Research_Institute_Internal_DC_dataset_batfish_20251230_125613.csv`

## 1. Summary

| Metric | Count | Percentage |
|--------|------:|------------|
| Total | 762 | 100% |
| ✅ PASS | 220 | 28.9% |
| ❌ FAIL | 48 | 6.3% |
| ⏭️ SKIP | 494 | 64.8% |

## 2. Results by Level

| Level | PASS | FAIL | SKIP | Total |
|-------|-----:|-----:|-----:|------:|
| L1 | 170 | 2 | 192 | 364 |
| L2 | 0 | 0 | 21 | 21 |
| L3 | 0 | 0 | 127 | 127 |
| L4 | 50 | 45 | 54 | 149 |
| L5 | 0 | 1 | 100 | 101 |

## 3. Top Failed Metrics

| Metric | Fail Count |
|--------|----------:|
| bounded_path_length | 33 |
| traceroute_path | 7 |
| waypoint_traversal_path | 5 |
| vrf_count | 2 |
| ospf_area0_routers | 1 |

## 4. Sample Failures (Top 20)

### Row 272: VRF_COUNT
- **Level**: L1, **Category**: Services_Inventory
- **Metric**: vrf_count
- **Reason**: mismatch
- **Expected**: `6`
- **Actual**: `3`
- **Question**: pe2 장비에 설정된 VRF는 총 몇 개입니까? [답변 형식: 숫자]...

### Row 280: VRF_COUNT
- **Level**: L1, **Category**: Services_Inventory
- **Metric**: vrf_count
- **Reason**: mismatch
- **Expected**: `6`
- **Actual**: `3`
- **Question**: pe1 장비에 설정된 VRF는 총 몇 개입니까? [답변 형식: 숫자]...

### Row 515: TRACEROUTE_pe2_pe1
- **Level**: L4, **Category**: Reachability_Analysis
- **Metric**: traceroute_path
- **Reason**: verified
- **Expected**: `pe2 → p3 → p2 → pe1`
- **Actual**: `경로 없음`
- **Question**: pe2에서 10.0.1.1까지의 네트워크 경로(장비 순서)를 나열해주세요. [답변 형식: 화살표(→)로 구분된 장비이름 목록(IP 주소 아님)]...

### Row 519: TRACEROUTE_pe2_leaf3
- **Level**: L4, **Category**: Reachability_Analysis
- **Metric**: traceroute_path
- **Reason**: verified
- **Expected**: `pe2`
- **Actual**: `경로 없음`
- **Question**: pe2에서 172.16.3.2까지의 네트워크 경로(장비 순서)를 나열해주세요. [답변 형식: 화살표(→)로 구분된 장비이름 목록(IP 주소 아님)]...

### Row 521: TRACEROUTE_pe1_p2
- **Level**: L4, **Category**: Reachability_Analysis
- **Metric**: traceroute_path
- **Reason**: verified
- **Expected**: `pe1 → p2`
- **Actual**: `경로 없음`
- **Question**: pe1에서 10.0.0.1까지의 네트워크 경로(장비 순서)를 나열해주세요. [답변 형식: 화살표(→)로 구분된 장비이름 목록(IP 주소 아님)]...

### Row 532: TRACEROUTE_pe2_p3
- **Level**: L4, **Category**: Reachability_Analysis
- **Metric**: traceroute_path
- **Reason**: verified
- **Expected**: `pe2 → p3`
- **Actual**: `경로 없음`
- **Question**: pe2에서 10.0.0.3까지의 네트워크 경로(장비 순서)를 나열해주세요. [답변 형식: 화살표(→)로 구분된 장비이름 목록(IP 주소 아님)]...

### Row 533: TRACEROUTE_pe2_p2
- **Level**: L4, **Category**: Reachability_Analysis
- **Metric**: traceroute_path
- **Reason**: verified
- **Expected**: `pe2 → p3 → p2`
- **Actual**: `경로 없음`
- **Question**: pe2에서 10.0.0.1까지의 네트워크 경로(장비 순서)를 나열해주세요. [답변 형식: 화살표(→)로 구분된 장비이름 목록(IP 주소 아님)]...

### Row 543: TRACEROUTE_pe1_p3
- **Level**: L4, **Category**: Reachability_Analysis
- **Metric**: traceroute_path
- **Reason**: verified
- **Expected**: `pe1 → p2 → p3`
- **Actual**: `경로 없음`
- **Question**: pe1에서 10.0.0.3까지의 네트워크 경로(장비 순서)를 나열해주세요. [답변 형식: 화살표(→)로 구분된 장비이름 목록(IP 주소 아님)]...

### Row 558: TRACEROUTE_pe1_leaf3
- **Level**: L4, **Category**: Reachability_Analysis
- **Metric**: traceroute_path
- **Reason**: verified
- **Expected**: `pe1`
- **Actual**: `경로 없음`
- **Question**: pe1에서 172.16.3.2까지의 네트워크 경로(장비 순서)를 나열해주세요. [답변 형식: 화살표(→)로 구분된 장비이름 목록(IP 주소 아님)]...

### Row 591: BOUNDED_PATH_leaf1_leaf2
- **Level**: L4, **Category**: Reachability_Analysis
- **Metric**: bounded_path_length
- **Reason**: no_route
- **Expected**: `2`
- **Actual**: `0`
- **Question**: leaf1에서 172.16.2.2로 가는 경로의 홉 수는 몇 개입니까? [답변 형식: 숫자]...

### Row 593: BOUNDED_PATH_leaf4_leaf3
- **Level**: L4, **Category**: Reachability_Analysis
- **Metric**: bounded_path_length
- **Reason**: no_route
- **Expected**: `2`
- **Actual**: `0`
- **Question**: leaf4에서 172.16.3.2로 가는 경로의 홉 수는 몇 개입니까? [답변 형식: 숫자]...

### Row 594: BOUNDED_PATH_pe2_leaf3
- **Level**: L4, **Category**: Reachability_Analysis
- **Metric**: bounded_path_length
- **Reason**: no_route
- **Expected**: `1`
- **Actual**: `0`
- **Question**: pe2에서 172.16.3.2로 가는 경로의 홉 수는 몇 개입니까? [답변 형식: 숫자]...

### Row 595: BOUNDED_PATH_pe2_p3
- **Level**: L4, **Category**: Reachability_Analysis
- **Metric**: bounded_path_length
- **Reason**: no_route
- **Expected**: `2`
- **Actual**: `0`
- **Question**: pe2에서 10.0.0.3로 가는 경로의 홉 수는 몇 개입니까? [답변 형식: 숫자]...

### Row 596: BOUNDED_PATH_leaf2_p4
- **Level**: L4, **Category**: Reachability_Analysis
- **Metric**: bounded_path_length
- **Reason**: no_route
- **Expected**: `2`
- **Actual**: `0`
- **Question**: leaf2에서 10.0.0.5로 가는 경로의 홉 수는 몇 개입니까? [답변 형식: 숫자]...

### Row 597: BOUNDED_PATH_leaf4_p1
- **Level**: L4, **Category**: Reachability_Analysis
- **Metric**: bounded_path_length
- **Reason**: no_route
- **Expected**: `2`
- **Actual**: `0`
- **Question**: leaf4에서 10.0.0.0로 가는 경로의 홉 수는 몇 개입니까? [답변 형식: 숫자]...

### Row 600: BOUNDED_PATH_leaf2_p3
- **Level**: L4, **Category**: Reachability_Analysis
- **Metric**: bounded_path_length
- **Reason**: no_route
- **Expected**: `2`
- **Actual**: `0`
- **Question**: leaf2에서 10.0.0.3로 가는 경로의 홉 수는 몇 개입니까? [답변 형식: 숫자]...

### Row 602: BOUNDED_PATH_leaf2_p1
- **Level**: L4, **Category**: Reachability_Analysis
- **Metric**: bounded_path_length
- **Reason**: no_route
- **Expected**: `2`
- **Actual**: `0`
- **Question**: leaf2에서 10.0.0.0로 가는 경로의 홉 수는 몇 개입니까? [답변 형식: 숫자]...

### Row 603: BOUNDED_PATH_pe1_leaf3
- **Level**: L4, **Category**: Reachability_Analysis
- **Metric**: bounded_path_length
- **Reason**: no_route
- **Expected**: `1`
- **Actual**: `0`
- **Question**: pe1에서 172.16.3.2로 가는 경로의 홉 수는 몇 개입니까? [답변 형식: 숫자]...

### Row 604: BOUNDED_PATH_leaf1_p2
- **Level**: L4, **Category**: Reachability_Analysis
- **Metric**: bounded_path_length
- **Reason**: no_route
- **Expected**: `2`
- **Actual**: `0`
- **Question**: leaf1에서 10.0.0.1로 가는 경로의 홉 수는 몇 개입니까? [답변 형식: 숫자]...

### Row 605: BOUNDED_PATH_leaf2_pe2
- **Level**: L4, **Category**: Reachability_Analysis
- **Metric**: bounded_path_length
- **Reason**: no_route
- **Expected**: `2`
- **Actual**: `0`
- **Question**: leaf2에서 10.0.1.3로 가는 경로의 홉 수는 몇 개입니까? [답변 형식: 숫자]...
