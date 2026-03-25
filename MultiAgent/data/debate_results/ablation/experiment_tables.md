# Experiment Tables

## Table 1. External Benchmark and NetConfig Results

| Model | TeleQuAD (EM) | NetBench (BertScore) | TeleQnA (Accuracy) | NetConfig2.0 (EM) | NetConfig2.0 (TA-Acc) |
|---|---|---|---|---|---|
| GPT-4o mini | 0.1030 | 0.7199 | 74.26 | 0.3976 | 51.51 |
| Llama-3.1-8B | 0.3081 | 0.798 | 66.42 | 0.1759 | 29.08 |
| Mistral3-8B | 0.3958 | 0.79 | 70.57 | 0.2008 | 41.57 |
| Qwen3-8B | 0.3409 | 0.799 | 73.33 | 0.3386 | 46.47 |
| GPT-OSS-20B | 0.4163 | 0.808 | 75.71 | 0.437 | **61.18** |
| NetAgent [a] | 0.4223 | **0.8620** | 74.35 | 0.2456 | 31.00 |
| NetAgent [b] | **0.5002** | 0.8564 | **79.48** | **0.5472** | 57.80 |

> [a] A: gemini2.5-flash-lite, B: GPT-4o mini
> [b] A: gemini3.1-flash-lite, B: GPT-4o mini

### Paper Writing — Experimental Results (Table 1)

Table~\ref{tab:benchmark_com} reports the performance of single-LLM baselines and our proposed NetAgent across four benchmarks: TeleQuAD, NetBench, TeleQnA, and NetConfigQA2.0.

**Single-LLM baselines.**
Among the standalone LLMs, GPT-OSS-20B achieves the strongest overall performance, attaining the highest TA-Acc of 61.18 on NetConfigQA2.0 and leading on NetBench BertScore (0.808) and TeleQnA accuracy (75.71).
GPT-4o mini, despite being a smaller model, scores competitively on TeleQnA (74.26) and NetConfigQA2.0 EM (0.3976), while the open-source 8B models (Llama-3.1-8B, Mistral3-8B, Qwen3-8B) trail behind on network-specific tasks, reflecting the domain knowledge demands of the benchmarks.

**NetAgent.**
NetAgent [b] (A: gemini3.1-flash-lite, B: GPT-4o mini) outperforms all baselines on TeleQuAD (EM 0.5002), TeleQnA (79.48%), and NetConfigQA2.0 EM (0.5472), demonstrating that the multi-agent debate framework consistently improves performance across heterogeneous network QA tasks.
Notably, NetAgent [b] improves NetConfigQA2.0 EM by **+15.0 points** over the single GPT-4o mini baseline (0.5472 vs. 0.3976), confirming that collaborative debate enables more accurate extraction and verification of network configuration facts.

However, NetAgent [a] (A: gemini2.5-flash-lite, B: GPT-4o mini) yields a substantially lower TA-Acc of 31.00 on NetConfigQA2.0, even below the single-LLM baseline, while achieving the best NetBench BertScore (0.8620).
This performance gap between [a] and [b] suggests that the choice of the synthesizer model (role A) is critical: a stronger synthesizer not only improves answer quality but also enables the debate pipeline to converge on correct answers rather than amplifying errors introduced by a weaker agent.

**Key takeaway.**
The results indicate that multi-agent debate is most effective when the participating models possess sufficient domain capability. When model capacity is adequate, the debate mechanism provides consistent gains across all benchmarks; when it is insufficient, the iterative debate loop risks reinforcing incorrect intermediate answers.

---

## Table 2. NetConfigQA2.0 난이도별(L1–L5) 성능 비교 (TA-Acc)

| Model | L1 | L2 | L3 | L4 | L5 |
|---|---|---|---|---|---|
| GPT-4o-mini | 0.765 | 0.541 | 0.369 | **0.267** | 0.159 |
| Llama-3.1-8B | 0.368 | 0.371 | 0.305 | 0.184 | 0.138 |
| Mistral3-8B | 0.572 | 0.143 | 0.500 | 0.158 | 0.183 |
| Qwen3-8B | 0.639 | 0.294 | 0.431 | 0.256 | **0.225** |
| GPT-OSS-20B | 0.873 | 0.873 | 0.605 | 0.266 | 0.134 |
| NetAgent * | **0.881** | **0.899** | **0.727** | 0.167 | 0.205 |

> \* A: gemini3.1-flash-lite, B: GPT-4o mini

---

## Table 3. 타입별 점수 (TA-Acc)

| Model | Map | Numeric | Text | Number | Set |
|---|---|---|---|---|---|
| GPT-4o-mini | 61.8 | 68.3 | 42.6 | 19.4 | 73.3 |
| Llama-3.1-8B | 67.9 | 15.8 | 30.2 | 11.9 | 32.2 |
| Mistral3-8B | 4.2 | 48.5 | 37.5 | 1.5 | 72.8 |
| Qwen3-8B | 72.9 | 43.6 | 41.1 | 28.4 | 62.3 |
| GPT-OSS-20B | **89.7** | 77.2 | 48.0 | **26.9** | 90.3 |
| NetAgent * | 70.0 | **94.1** | **51.3** | 4.5 | **92.8** |

> \* A: gemini3.1-flash-lite, B: GPT-4o mini

---

## Table 4. Ablation Study on NetConfigQA2.0

### 4-1. Overall Metrics

| Configuration | Rouge-1 | Rouge-2 | Rouge-L | EM | BLEU | BertScore | F1 (Token) | TA-Acc |
|---|---|---|---|---|---|---|---|---|
| Single LLM (GPT-4o mini) | 0.4206 | 0.4177 | 0.1548 | 0.3976 | — | 0.9417 | 0.5387 | 51.51 |
| NetAgent, homo (GPT-4o mini) | 0.5192 | 0.2451 | 0.5133 | 0.4869 | 0.2126 | 0.9596 | 0.5867 | 56.06 |
| NetAgent, hetero, Debate-1 Only | 0.5068 | 0.2484 | 0.5009 | 0.4921 | 0.2012 | 0.9521 | 0.5891 | 59.75 |
| NetAgent, hetero, Debate-2 Only | **0.5845** | **0.2860** | **0.5786** | 0.5866 | 0.2413 | **0.9640** | 0.6558 | **67.33** |
| NetAgent, hetero v2 [a] | 0.5480 | 0.2347 | 0.5455 | 0.6260 | 0.2428 | 0.9620 | **0.6909** | 65.79 |
| NetAgent, hetero v3 [b] | 0.5445 | 0.2545 | 0.5425 | **0.6312** | **0.2669** | 0.9625 | 0.6856 | 65.81 |

> [a] A: gemini3.1-flash-lite, B: GPT-4o mini (v2)
> [b] A: gemini3.1-flash-lite, B: GPT-4o mini + Fix1(Verifier L3 bypass) + Fix2(Proponent CONCEDE) + Fix3(feedback_to_collector)

### 4-2. 타입별 TA-Acc

| Configuration | Map | Numeric | Text | Number | Set |
|---|---|---|---|---|---|
| Single LLM (GPT-4o mini) | 61.8 | 68.3 | 42.6 | 19.4 | 73.3 |
| NetAgent, homo (GPT-4o mini) | 15.0 | 78.2 | 48.4 | 19.4 | 86.1 |
| NetAgent, hetero, Debate-1 Only | 12.5 | **95.0** | 51.6 | 3.0 | 92.7 |
| NetAgent, hetero, Debate-2 Only | 17.5 | 94.1 | **60.5** | 29.9 | **95.1** |
| NetAgent, hetero v2 [a] | 85.0 | 94.1 | 49.7 | **37.3** | 94.1 |
| NetAgent, hetero v3 [b] | **87.5** | 94.1 | 52.1 | 26.9 | 92.2 |

> [a] A: gemini3.1-flash-lite, B: GPT-4o mini (v2)
> [b] A: gemini3.1-flash-lite, B: GPT-4o mini (v3)

### 4-3. 난이도별 TA-Acc

| Configuration | L1 | L2 | L3 | L4 | L5 |
|---|---|---|---|---|---|
| Single LLM (GPT-4o mini) | 76.5 | 54.1 | 36.9 | 26.7 | 15.9 |
| NetAgent, homo (GPT-4o mini) | 72.0 | 54.7 | 70.6 | 10.1 | **48.5** |
| NetAgent, hetero, Debate-1 Only | 80.7 | 87.9 | 73.5 | 18.8 | 21.5 |
| NetAgent, hetero, Debate-2 Only | 84.3 | 87.3 | **81.9** | **34.5** | 32.2 |
| NetAgent, hetero v2 [a] | **89.2** | **89.9** | 74.3 | 30.3 | 18.1 |
| NetAgent, hetero v3 [b] | 87.9 | 83.7 | 80.1 | 30.3 | 17.1 |

> [a] A: gemini3.1-flash-lite, B: GPT-4o mini (v2)
> [b] A: gemini3.1-flash-lite, B: GPT-4o mini (v3)
