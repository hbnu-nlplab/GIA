# Result3 Combined Summary

Generated: 2026-04-28T20:38:48

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

| Method | Model | Lab | Total | TA | L1 | L2 | L3 | L4 | L5 | OK | Strict NC | Semantic NC |
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

## Relaxed Lab Results

| Method | Model | Lab | Total | TA | L1 | L2 | L3 | L4 | L5 | OK | Strict NC | Semantic NC |
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
