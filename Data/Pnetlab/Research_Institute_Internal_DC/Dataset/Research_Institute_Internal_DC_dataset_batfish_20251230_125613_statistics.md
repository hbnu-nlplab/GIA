# NetConfigQA Dataset Statistics

> Generated: 2025-12-30 14:32:26

> Dataset: `Research_Institute_Internal_DC_dataset_batfish_20251230_125613.csv`


## 1. Overview

| Metric | Value |
|--------|-------|
| Total Questions | **762** |
| Difficulty Levels | 5 |
| Categories | 17 |
| Answer Types | 5 |
| Positive Testing (OK) | 577 (75.7%) |
| Negative Testing (NOT_CONFIGURED) | 185 (24.3%) |

## 2. Distribution by Difficulty Level

| Level | Description | Count | Percentage |
|-------|-------------|------:|------------|
| L1 | Single Device Extraction | 364 | 47.8% |
| L2 | Multi-Device Aggregation | 21 | 2.8% |
| L3 | Cross-Device Comparison | 127 | 16.7% |
| L4 | Reachability Analysis | 149 | 19.6% |
| L5 | What-If Analysis | 101 | 13.3% |
| **Total** | | **762** | **100%** |

## 3. Distribution by Category (Metric)

| Category | Count | Percentage |
|----------|------:|------------|
| BGP_Consistency | 5 | 0.7% |
| Comparison_Analysis | 106 | 13.9% |
| Configuration_Check | 30 | 3.9% |
| Hardware_Inventory | 4 | 0.5% |
| Interface_Inventory | 40 | 5.2% |
| L2VPN_Consistency | 5 | 0.7% |
| OSPF_Consistency | 12 | 1.6% |
| Reachability_Analysis | 127 | 16.7% |
| Routing_Analysis | 10 | 1.3% |
| Routing_Inventory | 70 | 9.2% |
| Security_Analysis | 6 | 0.8% |
| Security_Inventory | 40 | 5.2% |
| Security_Policy | 14 | 1.8% |
| Services_Inventory | 70 | 9.2% |
| System_Inventory | 110 | 14.4% |
| VRF_Consistency | 12 | 1.6% |
| What_If_Analysis | 101 | 13.3% |
| **Total** | **762** | **100%** |

## 4. Distribution by Answer Type

| Answer Type | Count | Percentage |
|-------------|------:|------------|
| map | 40 | 5.2% |
| number | 67 | 8.8% |
| numeric | 101 | 13.3% |
| set | 162 | 21.3% |
| text | 392 | 51.4% |
| **Total** | **762** | **100%** |

## 5. Level × Category Distribution

| Level | BGP Consistency | Comparison Analysis | Configuration Check | Hardware Inventory | Interface Inventory | L2VPN Consistency | OSPF Consistency | Reachability Analysis | Routing Analysis | Routing Inventory | Security Analysis | Security Inventory | Security Policy | Services Inventory | System Inventory | VRF Consistency | What If Analysis | Total |
|-------|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| L1 | - | - | 30 | 4 | 40 | - | - | - | - | 70 | - | 40 | - | 70 | 110 | - | - | 364 |
| L2 | - | - | - | - | - | 1 | 12 | - | - | - | - | - | 8 | - | - | - | - | 21 |
| L3 | 5 | 106 | - | - | - | 4 | - | - | - | - | - | - | - | - | - | 12 | - | 127 |
| L4 | - | - | - | - | - | - | - | 127 | 10 | - | 6 | - | 6 | - | - | - | - | 149 |
| L5 | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | 101 | 101 |

## 6. Level × Answer Type Distribution

| Level | map | number | numeric | set | text | Total |
|-------|---:|---:|---:|---:|---:|---:|
| L1 | 40 | 10 | 85 | 128 | 101 | 364 |
| L2 | - | 1 | 11 | 9 | - | 21 |
| L3 | - | - | 5 | 15 | 107 | 127 |
| L4 | - | 45 | - | 7 | 97 | 149 |
| L5 | - | 11 | - | 3 | 87 | 101 |

## 7. Summary for Paper

```
Total Questions: 762
Difficulty Levels: 5 (L1-L5)
Categories: 17
Answer Types: 5
Positive Testing: 577 (75.7%)
Negative Testing: 185 (24.3%)
```

### Level Distribution

```
L1: 364 (47.8%)
L2: 21 (2.8%)
L3: 127 (16.7%)
L4: 149 (19.6%)
L5: 101 (13.3%)
```

### Answer Type Distribution

```
map: 40 (5.2%)
number: 67 (8.8%)
numeric: 101 (13.3%)
set: 162 (21.3%)
text: 392 (51.4%)
```