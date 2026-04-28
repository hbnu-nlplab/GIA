# NetConfigQA Result3 Scorecard

- Mode: `strict`
- Method: `singleLLM_mcp`
- Model: `Mistral3-8B`
- Lab: `LabC`
- Raw: `/home/sdlab08/projects/GIA/NetAlly/result2/singleLLM_mcp/mistral3-8b/LabC/netally_eval_direct_singleLLM_mcp_LabC_20260424_182525.json`
- Dataset status overlay: 0 rows
- Generated: 2026-04-28T20:44:01

## Overall

| Metric | Value |
|---|---:|
| Type-Aware Accuracy | 54.80% |
| Strict TA-Acc | 54.80% |
| Total Samples | 2674 |

## Level Breakdown

| Level | TA-Acc |
|---|---:|
| L1 | 46.89% |
| L2 | 82.73% |
| L3 | 72.93% |
| L4 | 63.52% |
| L5 | 29.03% |

## Type Breakdown

| Type | TA-Acc |
|---|---:|
| map | 49.72% |
| number | 64.81% |
| set | 42.43% |
| text | 53.74% |

## Positive vs Negative

| Slice | Accuracy |
|---|---:|
| OK | 65.37% |
| Explicit NOT_CONFIGURED | 14.13% |
| Semantic Negative | 88.59% |
| Contract Compliance | 15.95% |

## Sample Errors

| ID | Level | Status | Type | Gold | Pred | Score |
|---|---|---|---|---|---|---:|
| SYSTEM_VERSION_TEXT_p1 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_p9 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_p2 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_pe3 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_leaf3 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_p5 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_leaf5 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_p3 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_pe4 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_leaf8 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_asbr2 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_leaf1 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_pe6 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_leaf2 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SNMP_COMMUNITY_LIST_leaf1 | L1 | NOT_CONFIGURED | set | `[]` | `[]` | 0.00 |
