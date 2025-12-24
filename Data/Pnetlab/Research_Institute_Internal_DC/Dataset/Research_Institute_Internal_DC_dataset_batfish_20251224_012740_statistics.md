# NetConfigQA Dataset Statistics

> Generated: 2025-12-24 10:35:18

> Dataset: `Research_Institute_Internal_DC_dataset_batfish_20251224_012740.csv`


## 1. Overview

| Metric | Value |
|--------|-------|
| Total Questions | **720** |
| Difficulty Levels | 5 |
| Categories | 13 |
| Answer Types | 6 |
| Positive Testing (OK) | 680 (94.4%) |
| Negative Testing (NOT_CONFIGURED) | 40 (5.6%) |

## 2. Distribution by Difficulty Level

| Level | Description | Count | Percentage |
|-------|-------------|------:|------------|
| L1 | Single Device Extraction | 340 | 47.2% |
| L2 | Multi-Device Aggregation | 21 | 2.9% |
| L3 | Cross-Device Comparison | 127 | 17.6% |
| L4 | Reachability Analysis | 128 | 17.8% |
| L5 | What-If Analysis | 104 | 14.4% |
| **Total** | | **720** | **100%** |

## 3. Distribution by Category (Metric)

| Category | Count | Percentage |
|----------|------:|------------|
| BGP_Consistency | 5 | 0.7% |
| Comparison_Analysis | 106 | 14.7% |
| Interface_Inventory | 40 | 5.6% |
| L2VPN_Consistency | 5 | 0.7% |
| OSPF_Consistency | 12 | 1.7% |
| Reachability_Analysis | 122 | 16.9% |
| Routing_Inventory | 70 | 9.7% |
| Security_Inventory | 50 | 6.9% |
| Security_Policy | 14 | 1.9% |
| Services_Inventory | 70 | 9.7% |
| System_Inventory | 110 | 15.3% |
| VRF_Consistency | 12 | 1.7% |
| What_If_Analysis | 104 | 14.4% |
| **Total** | **720** | **100%** |

## 4. Distribution by Answer Type

| Answer Type | Count | Percentage |
|-------------|------:|------------|
| boolean | 81 | 11.2% |
| map | 40 | 5.6% |
| number | 67 | 9.3% |
| numeric | 96 | 13.3% |
| set | 135 | 18.8% |
| text | 301 | 41.8% |
| **Total** | **720** | **100%** |

## 5. Level × Category Distribution

| Level | BGP Consistency | Comparison Analysis | Interface Inventory | L2VPN Consistency | OSPF Consistency | Reachability Analysis | Routing Inventory | Security Inventory | Security Policy | Services Inventory | System Inventory | VRF Consistency | What If Analysis | Total |
|-------|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| L1 | - | - | 40 | - | - | - | 70 | 50 | - | 70 | 110 | - | - | 340 |
| L2 | - | - | - | 1 | 12 | - | - | - | 8 | - | - | - | - | 21 |
| L3 | 5 | 106 | - | 4 | - | - | - | - | - | - | - | 12 | - | 127 |
| L4 | - | - | - | - | - | 122 | - | - | 6 | - | - | - | - | 128 |
| L5 | - | - | - | - | - | - | - | - | - | - | - | - | 104 | 104 |

## 6. Level × Answer Type Distribution

| Level | boolean | map | number | numeric | set | text | Total |
|-------|---:|---:|---:|---:|---:|---:|---:|
| L1 | 30 | 40 | 10 | 80 | 110 | 70 | 340 |
| L2 | - | - | 1 | 11 | 9 | - | 21 |
| L3 | - | - | - | 5 | 15 | 107 | 127 |
| L4 | 1 | - | 45 | - | - | 82 | 128 |
| L5 | 50 | - | 11 | - | 1 | 42 | 104 |

## 7. Summary for Paper

```
Total Questions: 720
Difficulty Levels: 5 (L1-L5)
Categories: 13
Answer Types: 6
Positive Testing: 680 (94.4%)
Negative Testing: 40 (5.6%)
```

### Level Distribution

```
L1: 340 (47.2%)
L2: 21 (2.9%)
L3: 127 (17.6%)
L4: 128 (17.8%)
L5: 104 (14.4%)
```

### Answer Type Distribution

```
boolean: 81 (11.2%)
map: 40 (5.6%)
number: 67 (9.3%)
numeric: 96 (13.3%)
set: 135 (18.8%)
text: 301 (41.8%)
```