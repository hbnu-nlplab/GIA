# NetConfigQA Result3 Scorecard

- Mode: `strict`
- Method: `masLLM_mcp`
- Model: `Mistral3-8B`
- Lab: `LabD`
- Raw: `/home/sdlab08/projects/GIA/NetAlly/result2/masLLM_mcp_paper/masLLM_mistral3-8b_mcp/LabD/netally_eval_direct_masLLM_mcp_LabD_20260427_113334.json`
- Dataset status overlay: 0 rows
- Generated: 2026-04-28T20:48:14

## Overall

| Metric | Value |
|---|---:|
| Type-Aware Accuracy | 62.96% |
| Strict TA-Acc | 62.96% |
| Total Samples | 3370 |

## Level Breakdown

| Level | TA-Acc |
|---|---:|
| L1 | 47.15% |
| L2 | 84.29% |
| L3 | 66.37% |
| L4 | 77.19% |
| L5 | 32.30% |

## Type Breakdown

| Type | TA-Acc |
|---|---:|
| map | 48.40% |
| number | 69.32% |
| set | 44.42% |
| text | 65.97% |

## Positive vs Negative

| Slice | Accuracy |
|---|---:|
| OK | 72.20% |
| Explicit NOT_CONFIGURED | 16.19% |
| Semantic Negative | 91.37% |
| Contract Compliance | 17.72% |

## Sample Errors

| ID | Level | Status | Type | Gold | Pred | Score |
|---|---|---|---|---|---|---:|
| SYSTEM_VERSION_TEXT_leaf4 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_leaf5 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_leaf3 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_pe1 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_asbr1 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_p5 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_leaf2 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_leaf13 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_p3 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_leaf15 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_p8 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_pe6 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_leaf1 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_fw2 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_p6 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
