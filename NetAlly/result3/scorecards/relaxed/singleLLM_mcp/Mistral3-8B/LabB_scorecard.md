# NetConfigQA Result3 Scorecard

- Mode: `relaxed`
- Method: `singleLLM_mcp`
- Model: `Mistral3-8B`
- Lab: `LabB`
- Raw: `/home/sdlab08/projects/GIA/NetAlly/result2/singleLLM_mcp/mistral3-8b/LabB/current/netally_eval_direct_singleLLM_mcp_LabB_20260428_194024.json`
- Dataset status overlay: 0 rows
- Generated: 2026-04-28T20:38:46

## Overall

| Metric | Value |
|---|---:|
| Type-Aware Accuracy | 76.68% |
| Strict TA-Acc | 56.93% |
| Total Samples | 2157 |

## Level Breakdown

| Level | TA-Acc |
|---|---:|
| L1 | 79.68% |
| L2 | 93.57% |
| L3 | 76.73% |
| L4 | 70.88% |
| L5 | 59.38% |

## Type Breakdown

| Type | TA-Acc |
|---|---:|
| map | 61.72% |
| number | 79.33% |
| set | 91.64% |
| text | 67.74% |

## Positive vs Negative

| Slice | Accuracy |
|---|---:|
| OK | 72.20% |
| Explicit NOT_CONFIGURED | 14.54% |
| Semantic Negative | 89.14% |
| Contract Compliance | 16.31% |

## Sample Errors

| ID | Level | Status | Type | Gold | Pred | Score |
|---|---|---|---|---|---|---:|
| SYSTEM_VERSION_TEXT_p1 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_pe1 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_leaf6 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_pe3 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_leaf1 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_leaf3 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_leaf5 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_p2 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_leaf8 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_p6 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_leaf7 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_pe4 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_pe2 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_USER_LIST_leaf5 | L1 | OK | set | `["admin"]` | `[]` | 0.00 |
| INTERFACE_STATUS_MAP_leaf2 | L1 | OK | map | `{"GigabitEthernet0/0": "up", "GigabitEthernet0/7": "up"}` | `{ "GigabitEthernet0/0": "up", "GigabitEthernet0/1": "down", "GigabitEthernet0/2"` | 0.40 |
