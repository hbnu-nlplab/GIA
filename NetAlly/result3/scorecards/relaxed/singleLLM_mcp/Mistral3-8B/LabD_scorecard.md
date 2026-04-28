# NetConfigQA Result3 Scorecard

- Mode: `relaxed`
- Method: `singleLLM_mcp`
- Model: `Mistral3-8B`
- Lab: `LabD`
- Raw: `/home/sdlab08/projects/GIA/NetAlly/result2/singleLLM_mcp/mistral3-8b/LabD/netally_eval_direct_singleLLM_mcp_LabD_20260428_142414.json`
- Dataset status overlay: 0 rows
- Generated: 2026-04-28T20:48:32

## Overall

| Metric | Value |
|---|---:|
| Type-Aware Accuracy | 68.80% |
| Strict TA-Acc | 56.37% |
| Total Samples | 3370 |

## Level Breakdown

| Level | TA-Acc |
|---|---:|
| L1 | 80.23% |
| L2 | 84.29% |
| L3 | 64.58% |
| L4 | 64.39% |
| L5 | 27.95% |

## Type Breakdown

| Type | TA-Acc |
|---|---:|
| map | 59.15% |
| number | 67.95% |
| set | 91.43% |
| text | 62.36% |

## Positive vs Negative

| Slice | Accuracy |
|---|---:|
| OK | 64.49% |
| Explicit NOT_CONFIGURED | 15.29% |
| Semantic Negative | 90.65% |
| Contract Compliance | 16.87% |

## Sample Errors

| ID | Level | Status | Type | Gold | Pred | Score |
|---|---|---|---|---|---|---:|
| SYSTEM_VERSION_TEXT_leaf3 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_pe1 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_leaf13 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_p3 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_pe6 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_leaf1 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_p6 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_p10 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_pe4 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_pe2 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_USER_LIST_leaf5 | L1 | OK | set | `["admin"]` | `[]` | 0.00 |
| SYSTEM_USER_LIST_fw1 | L1 | OK | set | `["admin"]` | `[]` | 0.00 |
| INTERFACE_STATUS_MAP_leaf2 | L1 | OK | map | `{"GigabitEthernet0/0": "up", "GigabitEthernet0/7": "up"}` | `{ "GigabitEthernet0/0": "up", "GigabitEthernet0/1": "down", "GigabitEthernet0/2"` | 0.40 |
| INTERFACE_STATUS_MAP_fw2 | L1 | OK | map | `{"GigabitEthernet0/0": "up", "GigabitEthernet0/1": "up", "GigabitEthernet0/2": "` | `{ "GigabitEthernet0/0": "up", "GigabitEthernet0/1": "up", "GigabitEthernet0/2": ` | 0.71 |
| INTERFACE_STATUS_MAP_p8 | L1 | OK | map | `{"GigabitEthernet0/0": "up", "GigabitEthernet0/1": "up", "GigabitEthernet0/2": "` | `{ "GigabitEthernet0/0": "up", "GigabitEthernet0/1": "up", "GigabitEthernet0/2": ` | 0.71 |
