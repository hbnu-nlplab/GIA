# NetConfigQA Dataset Statistics

> Generated: 2026-01-29 17:11:36

> Dataset: `configs_dataset_batfish_20260129_170416.csv`


## 1. Overview

| Metric | Value |
|--------|-------|
| Total Questions | **1128** |
| Difficulty Levels | 5 |
| Categories | 17 |
| Answer Types | 5 |
| Positive Testing (OK) | 644 (57.1%) |
| Negative Testing (NOT_CONFIGURED) | 484 (42.9%) |

## 2. Distribution by Difficulty Level

| Level | Description | Count | Percentage |
|-------|-------------|------:|------------|
| L1 | Single Device Extraction | 634 | 56.2% |
| L2 | Multi-Device Aggregation | 21 | 1.9% |
| L3 | Cross-Device Comparison | 127 | 11.3% |
| L4 | Reachability Analysis | 159 | 14.1% |
| L5 | What-If Analysis | 187 | 16.6% |
| **Total** | | **1128** | **100%** |

## 3. Distribution by Category (Metric)

| Category | Count | Percentage |
|----------|------:|------------|
| BGP_Consistency | 5 | 0.4% |
| Comparison_Analysis | 106 | 9.4% |
| Configuration_Check | 300 | 26.6% |
| Hardware_Inventory | 4 | 0.4% |
| Interface_Inventory | 40 | 3.5% |
| L2VPN_Consistency | 5 | 0.4% |
| OSPF_Consistency | 12 | 1.1% |
| Reachability_Analysis | 127 | 11.3% |
| Routing_Analysis | 10 | 0.9% |
| Routing_Inventory | 70 | 6.2% |
| Security_Analysis | 16 | 1.4% |
| Security_Inventory | 40 | 3.5% |
| Security_Policy | 14 | 1.2% |
| Services_Inventory | 70 | 6.2% |
| System_Inventory | 110 | 9.8% |
| VRF_Consistency | 12 | 1.1% |
| What_If_Analysis | 187 | 16.6% |
| **Total** | **1128** | **100%** |

## 4. Distribution by Answer Type

| Answer Type | Count | Percentage |
|-------------|------:|------------|
| map | 40 | 3.5% |
| number | 67 | 5.9% |
| numeric | 146 | 12.9% |
| set | 288 | 25.5% |
| text | 587 | 52.0% |
| **Total** | **1128** | **100%** |

## 5. Level × Category Distribution

| Level | BGP Consistency | Comparison Analysis | Configuration Check | Hardware Inventory | Interface Inventory | L2VPN Consistency | OSPF Consistency | Reachability Analysis | Routing Analysis | Routing Inventory | Security Analysis | Security Inventory | Security Policy | Services Inventory | System Inventory | VRF Consistency | What If Analysis | Total |
|-------|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| L1 | - | - | 300 | 4 | 40 | - | - | - | - | 70 | - | 40 | - | 70 | 110 | - | - | 634 |
| L2 | - | - | - | - | - | 1 | 12 | - | - | - | - | - | 8 | - | - | - | - | 21 |
| L3 | 5 | 106 | - | - | - | 4 | - | - | - | - | - | - | - | - | - | 12 | - | 127 |
| L4 | - | - | - | - | - | - | - | 127 | 10 | - | 16 | - | 6 | - | - | - | - | 159 |
| L5 | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | 187 | 187 |

## 6. Level × Answer Type Distribution

| Level | map | number | numeric | set | text | Total |
|-------|---:|---:|---:|---:|---:|---:|
| L1 | 40 | 10 | 130 | 254 | 200 | 634 |
| L2 | - | 1 | 11 | 9 | - | 21 |
| L3 | - | - | 5 | 15 | 107 | 127 |
| L4 | - | 45 | - | 7 | 107 | 159 |
| L5 | - | 11 | - | 3 | 173 | 187 |

## 7. Summary for Paper

```
Total Questions: 1128
Difficulty Levels: 5 (L1-L5)
Categories: 17
Answer Types: 5
Positive Testing: 644 (57.1%)
Negative Testing: 484 (42.9%)
```

### Level Distribution

```
L1: 634 (56.2%)
L2: 21 (1.9%)
L3: 127 (11.3%)
L4: 159 (14.1%)
L5: 187 (16.6%)
```

### Answer Type Distribution

```
map: 40 (3.5%)
number: 67 (5.9%)
numeric: 146 (12.9%)
set: 288 (25.5%)
text: 587 (52.0%)
```