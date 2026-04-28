# Result3 Combined Summary

Generated: 2026-04-28T20:48:32

## Method Averages

| Mode | Method | Model | Labs | Total | Weighted TA | Macro TA |
| --- | --- | --- | --- | --- | --- | --- |
| relaxed | masLLM_cfg | Mistral3-8B | 4 | 9473 | 44.88% | 47.64% |
| relaxed | singleLLM_cfg | GPT-4o-mini | 4 | 9473 | 37.11% | 40.71% |
| relaxed | singleLLM_cfg | GPT-OSS-20B | 4 | 9473 | 30.54% | 35.60% |
| relaxed | singleLLM_cfg | Llama-3.1-8B | 4 | 9473 | 28.24% | 30.78% |
| relaxed | singleLLM_cfg | Mistral3-8B | 4 | 9473 | 42.51% | 45.71% |
| relaxed | singleLLM_cfg | Qwen3-8B | 4 | 9473 | 14.89% | 20.82% |
| relaxed | masLLM_mcp | Mistral3-8B | 4 | 9473 | 76.73% | 77.17% |
| relaxed | singleLLM_mcp | Mistral3-8B | 4 | 9473 | 71.01% | 71.17% |
| strict | masLLM_cfg | Mistral3-8B | 4 | 9473 | 29.72% | 31.38% |
| strict | singleLLM_cfg | GPT-4o-mini | 4 | 9473 | 25.20% | 27.30% |
| strict | singleLLM_cfg | GPT-OSS-20B | 4 | 9473 | 19.00% | 22.49% |
| strict | singleLLM_cfg | Llama-3.1-8B | 4 | 9473 | 20.00% | 21.08% |
| strict | singleLLM_cfg | Mistral3-8B | 4 | 9473 | 28.57% | 30.36% |
| strict | singleLLM_cfg | Qwen3-8B | 4 | 9473 | 11.87% | 15.47% |
| strict | masLLM_mcp | Mistral3-8B | 4 | 9473 | 60.76% | 60.24% |
| strict | singleLLM_mcp | Mistral3-8B | 4 | 9473 | 55.07% | 54.29% |

## Strict Lab Results

| Method | Model | Lab | Total | TA | L1 | L2 | L3 | L4 | L5 | OK | Strict NOT_CONFIGURED | Semantic NOT_CONFIGURED |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| masLLM_cfg | Mistral3-8B | LabA | 1272 | 37.09 | 41.39 | 43.58 | 46.43 | 18.95 | 7.77 | 49.25 | 8.00 | 78.13 |
| masLLM_cfg | Mistral3-8B | LabB | 2157 | 35.85 | 46.25 | 57.51 | 36.96 | 10.61 | 7.81 | 45.86 | 8.06 | 77.23 |
| masLLM_cfg | Mistral3-8B | LabC | 2674 | 28.99 | 47.33 | 38.93 | 25.66 | 7.86 | 11.61 | 34.36 | 8.33 | 78.08 |
| masLLM_cfg | Mistral3-8B | LabD | 3370 | 23.60 | 48.30 | 56.91 | 22.33 | 5.67 | 9.32 | 26.56 | 8.63 | 79.32 |
| masLLM_mcp | Mistral3-8B | LabA | 1272 | 58.26 | 41.61 | 88.57 | 79.10 | 70.59 | 80.58 | 76.04 | 15.73 | 84.00 |
| masLLM_mcp | Mistral3-8B | LabB | 2157 | 59.75 | 46.03 | 94.74 | 81.31 | 80.36 | 66.41 | 75.83 | 15.06 | 89.67 |
| masLLM_mcp | Mistral3-8B | LabC | 2674 | 60.01 | 46.89 | 82.67 | 75.82 | 77.25 | 29.68 | 71.94 | 14.13 | 88.77 |
| masLLM_mcp | Mistral3-8B | LabD | 3370 | 62.96 | 47.15 | 84.29 | 66.37 | 77.19 | 32.30 | 72.20 | 16.19 | 91.37 |
| singleLLM_cfg | GPT-4o-mini | LabA | 1272 | 34.25 | 40.55 | 74.54 | 28.17 | 12.42 | 11.65 | 40.31 | 19.73 | 85.60 |
| singleLLM_cfg | GPT-4o-mini | LabB | 2157 | 33.84 | 40.45 | 74.74 | 50.59 | 6.55 | 10.94 | 41.93 | 11.38 | 74.08 |
| singleLLM_cfg | GPT-4o-mini | LabC | 2674 | 23.48 | 42.09 | 65.04 | 10.77 | 4.09 | 0.65 | 25.86 | 14.31 | 63.95 |
| singleLLM_cfg | GPT-4o-mini | LabD | 3370 | 17.62 | 38.68 | 42.17 | 10.30 | 3.44 | 4.41 | 18.54 | 12.95 | 57.73 |
| singleLLM_cfg | GPT-OSS-20B | LabA | 1272 | 40.50 | 41.37 | 98.57 | 42.46 | 24.84 | 13.59 | 55.87 | 3.73 | 73.07 |
| singleLLM_cfg | GPT-OSS-20B | LabB | 2157 | 22.21 | 27.12 | 73.92 | 29.93 | 3.16 | 0.86 | 26.42 | 10.51 | 64.27 |
| singleLLM_cfg | GPT-OSS-20B | LabC | 2674 | 16.21 | 26.79 | 57.60 | 23.34 | 0.84 | 1.94 | 18.21 | 8.51 | 58.33 |
| singleLLM_cfg | GPT-OSS-20B | LabD | 3370 | 11.03 | 23.47 | 60.00 | 18.42 | 0.60 | 0.03 | 12.18 | 5.22 | 50.54 |
| singleLLM_cfg | Llama-3.1-8B | LabA | 1272 | 22.40 | 29.32 | 49.28 | 11.90 | 5.23 | 8.74 | 29.54 | 5.33 | 57.33 |
| singleLLM_cfg | Llama-3.1-8B | LabB | 2157 | 29.04 | 36.73 | 49.94 | 43.14 | 2.26 | 7.89 | 38.30 | 3.33 | 55.34 |
| singleLLM_cfg | Llama-3.1-8B | LabC | 2674 | 17.89 | 32.36 | 50.19 | 9.18 | 1.99 | 3.23 | 22.54 | 0.00 | 26.63 |
| singleLLM_cfg | Llama-3.1-8B | LabD | 3370 | 14.97 | 33.59 | 52.69 | 7.75 | 1.99 | 6.32 | 17.71 | 1.08 | 26.62 |
| singleLLM_cfg | Mistral3-8B | LabA | 1272 | 35.68 | 41.11 | 77.86 | 26.59 | 21.57 | 13.59 | 42.23 | 20.00 | 90.93 |
| singleLLM_cfg | Mistral3-8B | LabB | 2157 | 36.80 | 42.93 | 89.10 | 51.37 | 9.26 | 18.87 | 44.69 | 14.89 | 84.59 |
| singleLLM_cfg | Mistral3-8B | LabC | 2674 | 27.50 | 41.62 | 69.78 | 20.00 | 5.77 | 47.10 | 32.01 | 10.14 | 70.47 |
| singleLLM_cfg | Mistral3-8B | LabD | 3370 | 21.48 | 41.82 | 55.78 | 21.98 | 5.49 | 18.63 | 23.87 | 9.35 | 67.45 |
| singleLLM_cfg | Qwen3-8B | LabA | 1272 | 36.35 | 37.02 | 72.14 | 36.90 | 24.84 | 23.30 | 51.33 | 0.53 | 68.00 |
| singleLLM_cfg | Qwen3-8B | LabB | 2157 | 11.64 | 13.41 | 51.32 | 19.61 | 0.23 | 0.00 | 15.83 | 0.00 | 5.25 |
| singleLLM_cfg | Qwen3-8B | LabC | 2674 | 8.22 | 13.72 | 48.51 | 8.00 | 0.63 | 0.00 | 10.36 | 0.00 | 0.54 |
| singleLLM_cfg | Qwen3-8B | LabD | 3370 | 5.68 | 12.91 | 45.07 | 5.83 | 0.00 | 0.00 | 6.81 | 0.00 | 0.00 |
| singleLLM_mcp | Mistral3-8B | LabA | 1272 | 49.07 | 31.59 | 43.67 | 80.29 | 67.32 | 66.99 | 63.00 | 15.73 | 83.47 |
| singleLLM_mcp | Mistral3-8B | LabB | 2157 | 56.93 | 46.24 | 93.57 | 76.73 | 70.88 | 59.38 | 72.20 | 14.54 | 89.14 |
| singleLLM_mcp | Mistral3-8B | LabC | 2674 | 54.80 | 46.89 | 82.73 | 72.93 | 63.52 | 29.03 | 65.37 | 14.13 | 88.59 |
| singleLLM_mcp | Mistral3-8B | LabD | 3370 | 56.37 | 47.26 | 84.29 | 64.58 | 64.39 | 27.95 | 64.49 | 15.29 | 90.65 |

## Strict Type Breakdown

| Method | Model | Lab | TA | Map | Number | Set | Text | Boolean | Path |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| masLLM_cfg | Mistral3-8B | LabA | 37.09 | 25.79 | 50.99 | 43.91 | 25.31 |  |  |
| masLLM_cfg | Mistral3-8B | LabB | 35.85 | 24.16 | 45.21 | 41.06 | 28.00 |  |  |
| masLLM_cfg | Mistral3-8B | LabC | 28.99 | 22.88 | 31.16 | 41.39 | 22.53 |  |  |
| masLLM_cfg | Mistral3-8B | LabD | 23.60 | 24.90 | 23.99 | 40.06 | 17.38 |  |  |
| masLLM_mcp | Mistral3-8B | LabA | 58.26 | 54.45 | 68.42 | 46.18 | 62.34 |  |  |
| masLLM_mcp | Mistral3-8B | LabB | 59.75 | 49.34 | 69.58 | 46.33 | 63.25 |  |  |
| masLLM_mcp | Mistral3-8B | LabC | 60.01 | 50.23 | 72.99 | 44.46 | 58.81 |  |  |
| masLLM_mcp | Mistral3-8B | LabD | 62.96 | 48.40 | 69.32 | 44.42 | 65.97 |  |  |
| singleLLM_cfg | GPT-4o-mini | LabA | 34.25 | 19.38 | 36.84 | 34.95 | 35.36 |  |  |
| singleLLM_cfg | GPT-4o-mini | LabB | 33.84 | 26.64 | 36.97 | 41.45 | 28.00 |  |  |
| singleLLM_cfg | GPT-4o-mini | LabC | 23.48 | 28.09 | 20.85 | 31.40 | 21.24 |  |  |
| singleLLM_cfg | GPT-4o-mini | LabD | 17.62 | 27.42 | 14.40 | 27.00 | 15.87 |  |  |
| singleLLM_cfg | GPT-OSS-20B | LabA | 40.50 | 23.47 | 61.18 | 46.74 | 26.15 |  |  |
| singleLLM_cfg | GPT-OSS-20B | LabB | 22.21 | 24.88 | 0.00 | 46.79 | 21.31 |  |  |
| singleLLM_cfg | GPT-OSS-20B | LabC | 16.21 | 27.28 | 0.00 | 44.46 | 13.84 |  |  |
| singleLLM_cfg | GPT-OSS-20B | LabD | 11.03 | 24.85 | 0.00 | 39.58 | 8.13 |  |  |
| singleLLM_cfg | Llama-3.1-8B | LabA | 22.40 | 14.34 | 23.36 | 28.88 | 18.41 |  |  |
| singleLLM_cfg | Llama-3.1-8B | LabB | 29.04 | 28.88 | 26.89 | 39.54 | 23.85 |  |  |
| singleLLM_cfg | Llama-3.1-8B | LabC | 17.89 | 24.29 | 13.27 | 35.55 | 12.47 |  |  |
| singleLLM_cfg | Llama-3.1-8B | LabD | 14.97 | 24.04 | 10.80 | 31.93 | 11.34 |  |  |
| singleLLM_cfg | Mistral3-8B | LabA | 35.68 | 21.81 | 33.88 | 40.34 | 36.19 |  |  |
| singleLLM_cfg | Mistral3-8B | LabB | 36.80 | 29.22 | 37.98 | 43.49 | 32.95 |  |  |
| singleLLM_cfg | Mistral3-8B | LabC | 27.50 | 28.98 | 20.62 | 40.92 | 26.23 |  |  |
| singleLLM_cfg | Mistral3-8B | LabD | 21.48 | 25.91 | 17.65 | 37.07 | 18.49 |  |  |
| singleLLM_cfg | Qwen3-8B | LabA | 36.35 | 20.78 | 48.68 | 45.21 | 24.90 |  |  |
| singleLLM_cfg | Qwen3-8B | LabB | 11.64 | 29.56 | 0.00 | 37.85 | 0.00 |  |  |
| singleLLM_cfg | Qwen3-8B | LabC | 8.22 | 28.07 | 0.00 | 34.24 | 0.00 |  |  |
| singleLLM_cfg | Qwen3-8B | LabD | 5.68 | 27.35 | 0.00 | 28.48 | 0.00 |  |  |
| singleLLM_mcp | Mistral3-8B | LabA | 49.07 | 39.80 | 67.43 | 33.57 | 51.88 |  |  |
| singleLLM_mcp | Mistral3-8B | LabB | 56.93 | 50.29 | 66.55 | 45.07 | 58.99 |  |  |
| singleLLM_mcp | Mistral3-8B | LabC | 54.80 | 49.72 | 64.81 | 42.43 | 53.74 |  |  |
| singleLLM_mcp | Mistral3-8B | LabD | 56.37 | 47.01 | 61.78 | 44.03 | 57.44 |  |  |

## Strict NOT_CONFIGURED Breakdown

| Method | Model | Lab | Negative Total | Strict NOT_CONFIGURED | Strict Correct | Semantic NOT_CONFIGURED | Semantic Correct | Compliance | Blank |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| masLLM_cfg | Mistral3-8B | LabA | 375 | 8.00 | 30 | 78.13 | 293 | 10.24 | 4 |
| masLLM_cfg | Mistral3-8B | LabB | 571 | 8.06 | 46 | 77.23 | 441 | 10.43 | 0 |
| masLLM_cfg | Mistral3-8B | LabC | 552 | 8.33 | 46 | 78.08 | 431 | 10.67 | 4 |
| masLLM_cfg | Mistral3-8B | LabD | 556 | 8.63 | 48 | 79.32 | 441 | 10.88 | 2 |
| masLLM_mcp | Mistral3-8B | LabA | 375 | 15.73 | 59 | 84.00 | 315 | 18.73 | 12 |
| masLLM_mcp | Mistral3-8B | LabB | 571 | 15.06 | 86 | 89.67 | 512 | 16.80 | 18 |
| masLLM_mcp | Mistral3-8B | LabC | 552 | 14.13 | 78 | 88.77 | 490 | 15.92 | 24 |
| masLLM_mcp | Mistral3-8B | LabD | 556 | 16.19 | 90 | 91.37 | 508 | 17.72 | 15 |
| singleLLM_cfg | GPT-4o-mini | LabA | 375 | 19.73 | 74 | 85.60 | 321 | 23.05 | 0 |
| singleLLM_cfg | GPT-4o-mini | LabB | 571 | 11.38 | 65 | 74.08 | 423 | 15.37 | 0 |
| singleLLM_cfg | GPT-4o-mini | LabC | 552 | 14.31 | 79 | 63.95 | 353 | 22.38 | 3 |
| singleLLM_cfg | GPT-4o-mini | LabD | 556 | 12.95 | 72 | 57.73 | 321 | 22.43 | 0 |
| singleLLM_cfg | GPT-OSS-20B | LabA | 375 | 3.73 | 14 | 73.07 | 274 | 5.11 | 1 |
| singleLLM_cfg | GPT-OSS-20B | LabB | 571 | 10.51 | 60 | 64.27 | 367 | 16.35 | 143 |
| singleLLM_cfg | GPT-OSS-20B | LabC | 552 | 8.51 | 47 | 58.33 | 322 | 14.60 | 151 |
| singleLLM_cfg | GPT-OSS-20B | LabD | 556 | 5.22 | 29 | 50.54 | 281 | 10.32 | 174 |
| singleLLM_cfg | Llama-3.1-8B | LabA | 375 | 5.33 | 20 | 57.33 | 215 | 9.30 | 0 |
| singleLLM_cfg | Llama-3.1-8B | LabB | 571 | 3.33 | 19 | 55.34 | 316 | 6.01 | 0 |
| singleLLM_cfg | Llama-3.1-8B | LabC | 552 | 0.00 | 0 | 26.63 | 147 | 0.00 | 0 |
| singleLLM_cfg | Llama-3.1-8B | LabD | 556 | 1.08 | 6 | 26.62 | 148 | 4.05 | 20 |
| singleLLM_cfg | Mistral3-8B | LabA | 375 | 20.00 | 75 | 90.93 | 341 | 21.99 | 0 |
| singleLLM_cfg | Mistral3-8B | LabB | 571 | 14.89 | 85 | 84.59 | 483 | 17.60 | 0 |
| singleLLM_cfg | Mistral3-8B | LabC | 552 | 10.14 | 56 | 70.47 | 389 | 14.40 | 0 |
| singleLLM_cfg | Mistral3-8B | LabD | 556 | 9.35 | 52 | 67.45 | 375 | 13.87 | 0 |
| singleLLM_cfg | Qwen3-8B | LabA | 375 | 0.53 | 2 | 68.00 | 255 | 0.78 | 13 |
| singleLLM_cfg | Qwen3-8B | LabB | 571 | 0.00 | 0 | 5.25 | 30 | 0.00 | 293 |
| singleLLM_cfg | Qwen3-8B | LabC | 552 | 0.00 | 0 | 0.54 | 3 | 0.00 | 282 |
| singleLLM_cfg | Qwen3-8B | LabD | 556 | 0.00 | 0 | 0.00 | 0 |  | 282 |
| singleLLM_mcp | Mistral3-8B | LabA | 375 | 15.73 | 59 | 83.47 | 313 | 18.85 | 17 |
| singleLLM_mcp | Mistral3-8B | LabB | 571 | 14.54 | 83 | 89.14 | 509 | 16.31 | 21 |
| singleLLM_mcp | Mistral3-8B | LabC | 552 | 14.13 | 78 | 88.59 | 489 | 15.95 | 24 |
| singleLLM_mcp | Mistral3-8B | LabD | 556 | 15.29 | 85 | 90.65 | 504 | 16.87 | 20 |

## Relaxed Lab Results

| Method | Model | Lab | Total | TA | L1 | L2 | L3 | L4 | L5 | OK | Strict NOT_CONFIGURED | Semantic NOT_CONFIGURED |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| masLLM_cfg | Mistral3-8B | LabA | 1272 | 57.76 | 79.29 | 43.58 | 46.43 | 18.95 | 7.77 | 49.25 | 8.00 | 78.13 |
| masLLM_cfg | Mistral3-8B | LabB | 2157 | 54.16 | 77.26 | 57.51 | 36.96 | 10.61 | 7.81 | 45.86 | 8.06 | 77.23 |
| masLLM_cfg | Mistral3-8B | LabC | 2674 | 43.39 | 77.62 | 38.93 | 25.66 | 7.86 | 11.61 | 34.36 | 8.33 | 78.08 |
| masLLM_cfg | Mistral3-8B | LabD | 3370 | 35.26 | 79.22 | 56.91 | 22.33 | 5.67 | 9.32 | 26.56 | 8.63 | 79.32 |
| masLLM_mcp | Mistral3-8B | LabA | 1272 | 78.39 | 78.50 | 88.57 | 79.10 | 70.59 | 80.58 | 76.04 | 15.73 | 84.00 |
| masLLM_mcp | Mistral3-8B | LabB | 2157 | 79.50 | 79.47 | 94.74 | 81.31 | 80.36 | 66.41 | 75.83 | 15.06 | 89.67 |
| masLLM_mcp | Mistral3-8B | LabC | 2674 | 75.41 | 79.31 | 82.67 | 75.82 | 77.25 | 29.68 | 71.94 | 14.13 | 88.77 |
| masLLM_mcp | Mistral3-8B | LabD | 3370 | 75.36 | 80.03 | 84.29 | 66.37 | 77.19 | 32.30 | 72.20 | 16.19 | 91.37 |
| singleLLM_cfg | GPT-4o-mini | LabA | 1272 | 53.66 | 76.14 | 74.54 | 28.17 | 12.42 | 11.65 | 40.31 | 19.73 | 85.60 |
| singleLLM_cfg | GPT-4o-mini | LabB | 2157 | 50.44 | 68.55 | 74.74 | 50.59 | 6.55 | 10.94 | 41.93 | 11.38 | 74.08 |
| singleLLM_cfg | GPT-4o-mini | LabC | 2674 | 33.73 | 63.65 | 65.04 | 10.77 | 4.09 | 0.65 | 25.86 | 14.31 | 63.95 |
| singleLLM_cfg | GPT-4o-mini | LabD | 3370 | 25.00 | 58.27 | 42.17 | 10.30 | 3.44 | 4.41 | 18.54 | 12.95 | 57.73 |
| singleLLM_cfg | GPT-OSS-20B | LabA | 1272 | 60.94 | 78.84 | 98.57 | 42.46 | 24.84 | 13.59 | 55.87 | 3.73 | 73.07 |
| singleLLM_cfg | GPT-OSS-20B | LabB | 2157 | 36.44 | 51.22 | 73.92 | 29.93 | 3.16 | 0.86 | 26.42 | 10.51 | 64.27 |
| singleLLM_cfg | GPT-OSS-20B | LabC | 2674 | 26.50 | 48.43 | 57.60 | 23.34 | 0.84 | 1.94 | 18.21 | 8.51 | 58.33 |
| singleLLM_cfg | GPT-OSS-20B | LabD | 3370 | 18.51 | 43.30 | 60.00 | 18.42 | 0.60 | 0.03 | 12.18 | 5.22 | 50.54 |
| singleLLM_cfg | Llama-3.1-8B | LabA | 1272 | 37.73 | 57.41 | 49.28 | 11.90 | 5.23 | 8.74 | 29.54 | 5.33 | 57.33 |
| singleLLM_cfg | Llama-3.1-8B | LabB | 2157 | 42.81 | 60.04 | 49.94 | 43.14 | 2.26 | 7.89 | 38.30 | 3.33 | 55.34 |
| singleLLM_cfg | Llama-3.1-8B | LabC | 2674 | 23.39 | 43.93 | 50.19 | 9.18 | 1.99 | 3.23 | 22.54 | 0.00 | 26.63 |
| singleLLM_cfg | Llama-3.1-8B | LabD | 3370 | 19.18 | 44.76 | 52.69 | 7.75 | 1.99 | 6.32 | 17.71 | 1.08 | 26.62 |
| singleLLM_cfg | Mistral3-8B | LabA | 1272 | 56.59 | 79.44 | 77.86 | 26.59 | 21.57 | 13.59 | 42.23 | 20.00 | 90.93 |
| singleLLM_cfg | Mistral3-8B | LabB | 2157 | 55.25 | 74.17 | 89.10 | 51.37 | 9.26 | 18.87 | 44.69 | 14.89 | 84.59 |
| singleLLM_cfg | Mistral3-8B | LabC | 2674 | 39.95 | 67.82 | 69.78 | 20.00 | 5.77 | 47.10 | 32.01 | 10.14 | 70.47 |
| singleLLM_cfg | Mistral3-8B | LabD | 3370 | 31.06 | 67.23 | 55.78 | 21.98 | 5.49 | 18.63 | 23.87 | 9.35 | 67.45 |
| singleLLM_cfg | Qwen3-8B | LabA | 1272 | 56.24 | 73.47 | 72.14 | 36.90 | 24.84 | 23.30 | 51.33 | 0.53 | 68.00 |
| singleLLM_cfg | Qwen3-8B | LabB | 2157 | 13.03 | 15.76 | 51.32 | 19.61 | 0.23 | 0.00 | 15.83 | 0.00 | 5.25 |
| singleLLM_cfg | Qwen3-8B | LabC | 2674 | 8.33 | 13.96 | 48.51 | 8.00 | 0.63 | 0.00 | 10.36 | 0.00 | 0.54 |
| singleLLM_cfg | Qwen3-8B | LabD | 3370 | 5.68 | 12.91 | 45.07 | 5.83 | 0.00 | 0.00 | 6.81 | 0.00 | 0.00 |
| singleLLM_mcp | Mistral3-8B | LabA | 1272 | 69.04 | 68.19 | 43.67 | 80.29 | 67.32 | 66.99 | 63.00 | 15.73 | 83.47 |
| singleLLM_mcp | Mistral3-8B | LabB | 2157 | 76.68 | 79.68 | 93.57 | 76.73 | 70.88 | 59.38 | 72.20 | 14.54 | 89.14 |
| singleLLM_mcp | Mistral3-8B | LabC | 2674 | 70.17 | 79.23 | 82.73 | 72.93 | 63.52 | 29.03 | 65.37 | 14.13 | 88.59 |
| singleLLM_mcp | Mistral3-8B | LabD | 3370 | 68.80 | 80.23 | 84.29 | 64.58 | 64.39 | 27.95 | 64.49 | 15.29 | 90.65 |

## Relaxed Type Breakdown

| Method | Model | Lab | TA | Map | Number | Set | Text | Boolean | Path |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| masLLM_cfg | Mistral3-8B | LabA | 57.76 | 31.40 | 63.49 | 89.34 | 34.73 |  |  |
| masLLM_cfg | Mistral3-8B | LabB | 54.16 | 32.73 | 57.65 | 83.30 | 36.64 |  |  |
| masLLM_cfg | Mistral3-8B | LabC | 43.39 | 33.59 | 39.45 | 84.27 | 28.89 |  |  |
| masLLM_cfg | Mistral3-8B | LabD | 35.26 | 34.18 | 29.99 | 83.37 | 22.43 |  |  |
| masLLM_mcp | Mistral3-8B | LabA | 78.39 | 61.93 | 80.92 | 89.52 | 71.55 |  |  |
| masLLM_mcp | Mistral3-8B | LabB | 79.50 | 60.77 | 82.35 | 92.90 | 72.00 |  |  |
| masLLM_mcp | Mistral3-8B | LabC | 75.41 | 61.65 | 81.52 | 92.08 | 65.09 |  |  |
| masLLM_mcp | Mistral3-8B | LabD | 75.36 | 60.54 | 75.49 | 91.63 | 70.89 |  |  |
| singleLLM_cfg | GPT-4o-mini | LabA | 53.66 | 21.25 | 48.68 | 78.03 | 44.56 |  |  |
| singleLLM_cfg | GPT-4o-mini | LabB | 50.44 | 26.64 | 48.40 | 80.08 | 36.75 |  |  |
| singleLLM_cfg | GPT-4o-mini | LabC | 33.73 | 28.09 | 28.20 | 57.78 | 27.52 |  |  |
| singleLLM_cfg | GPT-4o-mini | LabD | 25.00 | 27.42 | 19.97 | 47.81 | 20.59 |  |  |
| singleLLM_cfg | GPT-OSS-20B | LabA | 60.94 | 29.08 | 72.70 | 92.43 | 35.36 |  |  |
| singleLLM_cfg | GPT-OSS-20B | LabB | 36.44 | 32.73 | 0.00 | 91.20 | 27.07 |  |  |
| singleLLM_cfg | GPT-OSS-20B | LabC | 26.50 | 37.28 | 0.00 | 87.35 | 16.85 |  |  |
| singleLLM_cfg | GPT-OSS-20B | LabD | 18.51 | 34.13 | 0.00 | 78.80 | 9.97 |  |  |
| singleLLM_cfg | Llama-3.1-8B | LabA | 37.73 | 15.28 | 35.53 | 59.16 | 26.99 |  |  |
| singleLLM_cfg | Llama-3.1-8B | LabB | 42.81 | 28.88 | 38.32 | 67.34 | 32.49 |  |  |
| singleLLM_cfg | Llama-3.1-8B | LabC | 23.39 | 24.29 | 14.69 | 49.40 | 17.80 |  |  |
| singleLLM_cfg | Llama-3.1-8B | LabD | 19.18 | 24.04 | 13.37 | 40.85 | 15.54 |  |  |
| singleLLM_cfg | Mistral3-8B | LabA | 56.59 | 29.28 | 46.38 | 86.29 | 45.40 |  |  |
| singleLLM_cfg | Mistral3-8B | LabB | 55.25 | 37.79 | 50.42 | 86.09 | 41.71 |  |  |
| singleLLM_cfg | Mistral3-8B | LabC | 39.95 | 40.40 | 28.91 | 74.89 | 32.07 |  |  |
| singleLLM_cfg | Mistral3-8B | LabD | 31.06 | 36.63 | 23.39 | 68.86 | 23.08 |  |  |
| singleLLM_cfg | Qwen3-8B | LabA | 56.24 | 26.39 | 60.53 | 89.07 | 33.89 |  |  |
| singleLLM_cfg | Qwen3-8B | LabB | 13.03 | 29.56 | 0.00 | 43.27 | 0.00 |  |  |
| singleLLM_cfg | Qwen3-8B | LabC | 8.33 | 28.07 | 0.00 | 34.81 | 0.00 |  |  |
| singleLLM_cfg | Qwen3-8B | LabD | 5.68 | 27.35 | 0.00 | 28.48 | 0.00 |  |  |
| singleLLM_mcp | Mistral3-8B | LabA | 69.04 | 47.27 | 79.93 | 76.39 | 61.09 |  |  |
| singleLLM_mcp | Mistral3-8B | LabB | 76.68 | 61.72 | 79.33 | 91.64 | 67.74 |  |  |
| singleLLM_mcp | Mistral3-8B | LabC | 70.17 | 61.15 | 73.34 | 89.87 | 60.02 |  |  |
| singleLLM_mcp | Mistral3-8B | LabD | 68.80 | 59.15 | 67.95 | 91.43 | 62.36 |  |  |

## Relaxed NOT_CONFIGURED Breakdown

| Method | Model | Lab | Negative Total | Strict NOT_CONFIGURED | Strict Correct | Semantic NOT_CONFIGURED | Semantic Correct | Compliance | Blank |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| masLLM_cfg | Mistral3-8B | LabA | 375 | 8.00 | 30 | 78.13 | 293 | 10.24 | 4 |
| masLLM_cfg | Mistral3-8B | LabB | 571 | 8.06 | 46 | 77.23 | 441 | 10.43 | 0 |
| masLLM_cfg | Mistral3-8B | LabC | 552 | 8.33 | 46 | 78.08 | 431 | 10.67 | 4 |
| masLLM_cfg | Mistral3-8B | LabD | 556 | 8.63 | 48 | 79.32 | 441 | 10.88 | 2 |
| masLLM_mcp | Mistral3-8B | LabA | 375 | 15.73 | 59 | 84.00 | 315 | 18.73 | 12 |
| masLLM_mcp | Mistral3-8B | LabB | 571 | 15.06 | 86 | 89.67 | 512 | 16.80 | 18 |
| masLLM_mcp | Mistral3-8B | LabC | 552 | 14.13 | 78 | 88.77 | 490 | 15.92 | 24 |
| masLLM_mcp | Mistral3-8B | LabD | 556 | 16.19 | 90 | 91.37 | 508 | 17.72 | 15 |
| singleLLM_cfg | GPT-4o-mini | LabA | 375 | 19.73 | 74 | 85.60 | 321 | 23.05 | 0 |
| singleLLM_cfg | GPT-4o-mini | LabB | 571 | 11.38 | 65 | 74.08 | 423 | 15.37 | 0 |
| singleLLM_cfg | GPT-4o-mini | LabC | 552 | 14.31 | 79 | 63.95 | 353 | 22.38 | 3 |
| singleLLM_cfg | GPT-4o-mini | LabD | 556 | 12.95 | 72 | 57.73 | 321 | 22.43 | 0 |
| singleLLM_cfg | GPT-OSS-20B | LabA | 375 | 3.73 | 14 | 73.07 | 274 | 5.11 | 1 |
| singleLLM_cfg | GPT-OSS-20B | LabB | 571 | 10.51 | 60 | 64.27 | 367 | 16.35 | 143 |
| singleLLM_cfg | GPT-OSS-20B | LabC | 552 | 8.51 | 47 | 58.33 | 322 | 14.60 | 151 |
| singleLLM_cfg | GPT-OSS-20B | LabD | 556 | 5.22 | 29 | 50.54 | 281 | 10.32 | 174 |
| singleLLM_cfg | Llama-3.1-8B | LabA | 375 | 5.33 | 20 | 57.33 | 215 | 9.30 | 0 |
| singleLLM_cfg | Llama-3.1-8B | LabB | 571 | 3.33 | 19 | 55.34 | 316 | 6.01 | 0 |
| singleLLM_cfg | Llama-3.1-8B | LabC | 552 | 0.00 | 0 | 26.63 | 147 | 0.00 | 0 |
| singleLLM_cfg | Llama-3.1-8B | LabD | 556 | 1.08 | 6 | 26.62 | 148 | 4.05 | 20 |
| singleLLM_cfg | Mistral3-8B | LabA | 375 | 20.00 | 75 | 90.93 | 341 | 21.99 | 0 |
| singleLLM_cfg | Mistral3-8B | LabB | 571 | 14.89 | 85 | 84.59 | 483 | 17.60 | 0 |
| singleLLM_cfg | Mistral3-8B | LabC | 552 | 10.14 | 56 | 70.47 | 389 | 14.40 | 0 |
| singleLLM_cfg | Mistral3-8B | LabD | 556 | 9.35 | 52 | 67.45 | 375 | 13.87 | 0 |
| singleLLM_cfg | Qwen3-8B | LabA | 375 | 0.53 | 2 | 68.00 | 255 | 0.78 | 13 |
| singleLLM_cfg | Qwen3-8B | LabB | 571 | 0.00 | 0 | 5.25 | 30 | 0.00 | 293 |
| singleLLM_cfg | Qwen3-8B | LabC | 552 | 0.00 | 0 | 0.54 | 3 | 0.00 | 282 |
| singleLLM_cfg | Qwen3-8B | LabD | 556 | 0.00 | 0 | 0.00 | 0 |  | 282 |
| singleLLM_mcp | Mistral3-8B | LabA | 375 | 15.73 | 59 | 83.47 | 313 | 18.85 | 17 |
| singleLLM_mcp | Mistral3-8B | LabB | 571 | 14.54 | 83 | 89.14 | 509 | 16.31 | 21 |
| singleLLM_mcp | Mistral3-8B | LabC | 552 | 14.13 | 78 | 88.59 | 489 | 15.95 | 24 |
| singleLLM_mcp | Mistral3-8B | LabD | 556 | 15.29 | 85 | 90.65 | 504 | 16.87 | 20 |

## Strict vs Relaxed Gap

| Method | Model | Lab | Strict TA | Relaxed TA | Gap pp |
| --- | --- | --- | --- | --- | --- |
| masLLM_cfg | Mistral3-8B | LabA | 37.09% | 57.76% | 20.68 |
| masLLM_cfg | Mistral3-8B | LabB | 35.85% | 54.16% | 18.31 |
| masLLM_cfg | Mistral3-8B | LabC | 28.99% | 43.39% | 14.40 |
| masLLM_cfg | Mistral3-8B | LabD | 23.60% | 35.26% | 11.66 |
| masLLM_mcp | Mistral3-8B | LabA | 58.26% | 78.39% | 20.13 |
| masLLM_mcp | Mistral3-8B | LabB | 59.75% | 79.50% | 19.75 |
| masLLM_mcp | Mistral3-8B | LabC | 60.01% | 75.41% | 15.41 |
| masLLM_mcp | Mistral3-8B | LabD | 62.96% | 75.36% | 12.40 |
| singleLLM_cfg | GPT-4o-mini | LabA | 34.25% | 53.66% | 19.42 |
| singleLLM_cfg | GPT-4o-mini | LabB | 33.84% | 50.44% | 16.60 |
| singleLLM_cfg | GPT-4o-mini | LabC | 23.48% | 33.73% | 10.25 |
| singleLLM_cfg | GPT-4o-mini | LabD | 17.62% | 25.00% | 7.39 |
| singleLLM_cfg | GPT-OSS-20B | LabA | 40.50% | 60.94% | 20.44 |
| singleLLM_cfg | GPT-OSS-20B | LabB | 22.21% | 36.44% | 14.23 |
| singleLLM_cfg | GPT-OSS-20B | LabC | 16.21% | 26.50% | 10.28 |
| singleLLM_cfg | GPT-OSS-20B | LabD | 11.03% | 18.51% | 7.48 |
| singleLLM_cfg | Llama-3.1-8B | LabA | 22.40% | 37.73% | 15.33 |
| singleLLM_cfg | Llama-3.1-8B | LabB | 29.04% | 42.81% | 13.77 |
| singleLLM_cfg | Llama-3.1-8B | LabC | 17.89% | 23.39% | 5.50 |
| singleLLM_cfg | Llama-3.1-8B | LabD | 14.97% | 19.18% | 4.21 |
| singleLLM_cfg | Mistral3-8B | LabA | 35.68% | 56.59% | 20.91 |
| singleLLM_cfg | Mistral3-8B | LabB | 36.80% | 55.25% | 18.45 |
| singleLLM_cfg | Mistral3-8B | LabC | 27.50% | 39.95% | 12.45 |
| singleLLM_cfg | Mistral3-8B | LabD | 21.48% | 31.06% | 9.58 |
| singleLLM_cfg | Qwen3-8B | LabA | 36.35% | 56.24% | 19.89 |
| singleLLM_cfg | Qwen3-8B | LabB | 11.64% | 13.03% | 1.39 |
| singleLLM_cfg | Qwen3-8B | LabC | 8.22% | 8.33% | 0.11 |
| singleLLM_cfg | Qwen3-8B | LabD | 5.68% | 5.68% | 0.00 |
| singleLLM_mcp | Mistral3-8B | LabA | 49.07% | 69.04% | 19.97 |
| singleLLM_mcp | Mistral3-8B | LabB | 56.93% | 76.68% | 19.75 |
| singleLLM_mcp | Mistral3-8B | LabC | 54.80% | 70.17% | 15.37 |
| singleLLM_mcp | Mistral3-8B | LabD | 56.37% | 68.80% | 12.43 |
