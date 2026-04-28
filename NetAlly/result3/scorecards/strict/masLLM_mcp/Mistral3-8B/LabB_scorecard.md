# NetConfigQA Result3 Scorecard

- Mode: `strict`
- Method: `masLLM_mcp`
- Model: `Mistral3-8B`
- Lab: `LabB`
- Raw: `/home/sdlab08/projects/GIA/NetAlly/result2/masLLM_mcp_paper/masLLM_mistral3-8b_mcp/LabB/results_raw_netally_20260423_143122.json`
- Dataset status overlay: 571 rows
- Generated: 2026-04-28T20:48:13

## Overall

| Metric | Value |
|---|---:|
| Type-Aware Accuracy | 59.75% |
| Strict TA-Acc | 59.75% |
| Total Samples | 2157 |

## Level Breakdown

| Level | TA-Acc |
|---|---:|
| L1 | 46.03% |
| L2 | 94.74% |
| L3 | 81.31% |
| L4 | 80.36% |
| L5 | 66.41% |

## Type Breakdown

| Type | TA-Acc |
|---|---:|
| map | 49.34% |
| number | 69.58% |
| set | 46.33% |
| text | 63.25% |

## Positive vs Negative

| Slice | Accuracy |
|---|---:|
| OK | 75.83% |
| Explicit NOT_CONFIGURED | 15.06% |
| Semantic Negative | 89.67% |
| Contract Compliance | 16.80% |

## Sample Errors

| ID | Level | Status | Type | Gold | Pred | Score |
|---|---|---|---|---|---|---:|
| SYSTEM_VERSION_TEXT_p1 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_leaf4 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_p4 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_pe1 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_leaf2 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_p5 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_leaf6 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_leaf3 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_pe3 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_leaf1 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_leaf5 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_p2 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_pe4 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_leaf7 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_pe2 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
