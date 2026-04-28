# NetConfigQA Result3 Scorecard

- Mode: `relaxed`
- Method: `singleLLM_cfg`
- Model: `Mistral3-8B`
- Lab: `LabA`
- Raw: `/home/sdlab08/projects/GIA/Experiment/code/NetConfigQA2_2/result_final/Mistral3-8B/LabA/results_raw_vllm_en_20260325_202043.json`
- Dataset status overlay: 0 rows
- Generated: 2026-04-28T20:43:55

## Overall

| Metric | Value |
|---|---:|
| Type-Aware Accuracy | 56.59% |
| Strict TA-Acc | 35.68% |
| Total Samples | 1272 |

## Level Breakdown

| Level | TA-Acc |
|---|---:|
| L1 | 79.44% |
| L2 | 77.86% |
| L3 | 26.59% |
| L4 | 21.57% |
| L5 | 13.59% |

## Type Breakdown

| Type | TA-Acc |
|---|---:|
| map | 29.28% |
| number | 46.38% |
| set | 86.29% |
| text | 45.40% |

## Positive vs Negative

| Slice | Accuracy |
|---|---:|
| OK | 42.23% |
| Explicit NOT_CONFIGURED | 20.00% |
| Semantic Negative | 90.93% |
| Contract Compliance | 21.99% |

## Sample Errors

| ID | Level | Status | Type | Gold | Pred | Score |
|---|---|---|---|---|---|---:|
| 16 | L1 | OK | text | `"15.7"` | `version 15.7` | 0.00 |
| 21 | L1 | NOT_CONFIGURED | text | `null` | `UTC` | 0.00 |
| 22 | L1 | NOT_CONFIGURED | text | `null` | `UTC` | 0.00 |
| 23 | L1 | NOT_CONFIGURED | text | `null` | `UTC` | 0.00 |
| 24 | L1 | NOT_CONFIGURED | text | `null` | `UTC` | 0.00 |
| 25 | L1 | NOT_CONFIGURED | text | `null` | `UTC` | 0.00 |
| 26 | L1 | NOT_CONFIGURED | text | `null` | `UTC` | 0.00 |
| 27 | L1 | NOT_CONFIGURED | text | `null` | `UTC` | 0.00 |
| 28 | L1 | NOT_CONFIGURED | text | `null` | `UTC` | 0.00 |
| 30 | L1 | NOT_CONFIGURED | text | `null` | `UTC` | 0.00 |
| 91 | L1 | OK | map | `{"GigabitEthernet0/0": "up", "GigabitEthernet0/1": "up", "GigabitEthernet0/2": "` | `{"GigabitEthernet0/0":"up","GigabitEthernet0/1":"up","GigabitEthernet0/2":"up","` | 0.89 |
| 92 | L1 | OK | map | `{"GigabitEthernet0/0": "up", "GigabitEthernet0/1": "up", "GigabitEthernet0/2": "` | `{"GigabitEthernet0/0":"up","GigabitEthernet0/1":"up","GigabitEthernet0/2":"up","` | 0.89 |
| 94 | L1 | OK | map | `{"GigabitEthernet0/0": "up", "GigabitEthernet0/1": "up", "GigabitEthernet0/2": "` | `{"GigabitEthernet0/0":"up","GigabitEthernet0/1":"down","GigabitEthernet0/2":"up"` | 0.67 |
| 96 | L1 | OK | map | `{"GigabitEthernet0/0": "up", "GigabitEthernet0/1": "up", "GigabitEthernet0/2": "` | `{"GigabitEthernet0/0": "up","GigabitEthernet0/1": "up","GigabitEthernet0/2": "up` | 0.89 |
| 97 | L1 | OK | map | `{"GigabitEthernet0/0": "up", "GigabitEthernet0/1": "up", "GigabitEthernet0/2": "` | `{"Loopback0": "up","GigabitEthernet0/0": "up","GigabitEthernet0/1": "up","Gigabi` | 0.80 |
