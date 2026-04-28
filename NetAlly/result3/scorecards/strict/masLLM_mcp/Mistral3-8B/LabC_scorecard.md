# NetConfigQA Result3 Scorecard

- Mode: `strict`
- Method: `masLLM_mcp`
- Model: `Mistral3-8B`
- Lab: `LabC`
- Raw: `/home/sdlab08/projects/GIA/NetAlly/result2/masLLM_mcp_paper/masLLM_mistral3-8b_mcp/LabC/netally_eval_direct_LabC_NCN_Security_L2VPN_30nodes_20260424_130543.json`
- Dataset status overlay: 0 rows
- Generated: 2026-04-28T20:46:43

## Overall

| Metric | Value |
|---|---:|
| Type-Aware Accuracy | 60.01% |
| Strict TA-Acc | 60.01% |
| Total Samples | 2674 |

## Level Breakdown

| Level | TA-Acc |
|---|---:|
| L1 | 46.89% |
| L2 | 82.67% |
| L3 | 75.82% |
| L4 | 77.25% |
| L5 | 29.68% |

## Type Breakdown

| Type | TA-Acc |
|---|---:|
| map | 50.23% |
| number | 72.99% |
| set | 44.46% |
| text | 58.81% |

## Positive vs Negative

| Slice | Accuracy |
|---|---:|
| OK | 71.94% |
| Explicit NOT_CONFIGURED | 14.13% |
| Semantic Negative | 88.77% |
| Contract Compliance | 15.92% |

## Sample Errors

| ID | Level | Status | Type | Gold | Pred | Score |
|---|---|---|---|---|---|---:|
| SYSTEM_VERSION_TEXT_p1 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_p10 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_leaf7 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_p2 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_leaf3 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_pe3 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_leaf8 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_leaf5 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_pe4 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_pe6 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_leaf1 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_p7 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_leaf2 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_USER_LIST_leaf11 | L1 | OK | set | `["admin"]` | `[]` | 0.00 |
| SNMP_COMMUNITY_LIST_leaf3 | L1 | NOT_CONFIGURED | set | `[]` | `[]` | 0.00 |
