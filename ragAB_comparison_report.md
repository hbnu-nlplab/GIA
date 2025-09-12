# Experiment Comparison Report (Enhanced)

## 🔎 Highlights
- Best Overall EM (Strict): 0.6884 (*RAG B_k=10*)
- Best Overall F1 (Strict): 0.7240 (*RAG B_k=10*)
- Best Overall EM (Relaxed): 0.6958 (*RAG B_k=10*)
- Best Overall F1 (Relaxed): 0.7095 (*RAG B_k=10*)

## 📊 Results Table (Strict Evaluation)
| Method | Setting | Overall EM | Overall F1 | Rule-based EM | Enhanced LLM GT EM |
|--------|---------|-----------:|-----------:|--------------:|--------------------:|
| RAG | A_k=10 | 0.6667 | 0.6965 | 0.6881 | 0.3400 |
| RAG | B_k=10 | **0.6884** | **0.7240** | 0.7156 | 0.2653 |
| RAG | Bexp_k=10 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |

## 📊 Results Table (Relaxed Evaluation - Order-insensitive)
| Method | Setting | Overall EM | Overall F1 | Rule-based EM | Enhanced LLM GT EM |
|--------|---------|-----------:|-----------:|--------------:|--------------------:|
| RAG | A_k=10 | 0.6691 | 0.6935 | 0.6881 | 0.3400 |
| RAG | B_k=10 | **0.6958** | **0.7095** | 0.7156 | 0.2653 |
| RAG | Bexp_k=10 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |

## 🧪 LaTeX Table (copy-paste ready)
```
\begin{table}[t]
\centering
\caption{Non-RAG vs. RAG Performance (Overall EM/F1).}
\label{tab:rag_nonrag_results}
\begin{tabular}{llcccc}
\hline
Method & Setting & Overall EM & Overall F1 & Rule-based EM & Enhanced LLM GT EM \\ 
\hline
RAG & A_k=10 & 0.6667 & 0.6965 & 0.6881 & 0.3400 \\
RAG & B_k=10 & \textbf{0.6884} & \textbf{0.7240} & 0.7156 & 0.2653 \\
RAG & Bexp_k=10 & 0.0000 & 0.0000 & 0.0000 & 0.0000 \\
\hline
\end{tabular}
\end{table}
```


## 표 1: RAG vs Non-RAG 기본 비교
| Method | Setting | Overall EM | Overall F1 | Processing Time |
|--------|---------|-----------:|-----------:|----------------:|
| RAG | A_k=10 | 0.6667 | 0.6965 | 0.0000 |
| RAG | B_k=10 | 0.6884 | 0.7240 | 0.0000 |
| RAG | Bexp_k=10 | 0.0000 | 0.0000 | 0.0000 |

## 표 2: RAG k값별 상세 분석
| Setting | Overall EM | Overall F1 | BERTScore F1 | ROUGE-L F1 |
|---------|-----------:|-----------:|-------------:|-----------:|
| A_k=10 | 0.6667 | 0.6965 | 0.5744 | 0.0064 |
| B_k=10 | 0.6884 | 0.7240 | 0.5626 | 0.0065 |
| Bexp_k=10 | 0.0000 | 0.0000 | 0.5637 | 0.0065 |

## 표 3: RAG vs Non-RAG 상세 분석 비교 (RAG 최고성능 K 기준)
Setting | BERTScore F1 | Exact Match | ROUGE-1 F1 | ROUGE-2 F1 | ROUGE-L F1 |
---|---:|---:|---:|---:|---:|
RAG B_k=10 | 0.5626 | 0.6884 | 0.0068 | 0.0012 | 0.0065 |

## 표 1 (그룹): Main Results @ Top-K=10
| Group | Overall EM | Overall F1 | BERTScore F1 | ROUGE-L F1 |
|-------|-----------:|-----------:|-------------:|-----------:|
| A | 0.6667 | 0.6965 | 0.5744 | 0.0064 |
| B | 0.6884 | 0.7240 | 0.5626 | 0.0065 |

## 표 2 (그룹): Sensitivity to Top-K

### Group A
## 표 2: RAG k값별 상세 분석
| Setting | Overall EM | Overall F1 | BERTScore F1 | ROUGE-L F1 |
|---------|-----------:|-----------:|-------------:|-----------:|
| k=10 | 0.6667 | 0.6965 | 0.5744 | 0.0064 |

### Group B
## 표 2: RAG k값별 상세 분석
| Setting | Overall EM | Overall F1 | BERTScore F1 | ROUGE-L F1 |
|---------|-----------:|-----------:|-------------:|-----------:|
| k=10 | 0.6884 | 0.7240 | 0.5626 | 0.0065 |
| Bexp_k=10 | 0.0000 | 0.0000 | 0.5637 | 0.0065 |

## 표 3 (그룹): Explanation Quality @ Top-K=10
| Group | BERTScore F1 | ROUGE-1 F1 | ROUGE-2 F1 | ROUGE-L F1 |
|-------|-------------:|----------:|----------:|-----------:|
| A | 0.5744 | 0.0065 | 0.0008 | 0.0064 |
| B (Pass-1 explanation only) | 0.5637 | 0.0067 | 0.0009 | 0.0065 |

## 표 4 (그룹): 정성 분석 — 샘플 점수 불일치로 생략

1. 표 1. Main Results (Top-K = 10, 고정)
| Group | Method                          | Top-K | EM(%) | F1(%) | Support@K(%) |
| ----: | ------------------------------- | ----: | ----: | ----: | ------------: |
|     A | RAG-Direct (1-pass)             |    10 |  66.7 |  69.6 |         90.0 |
|     B | RAG + Self-Rationale (2-pass)   |    10 |  68.8 |  72.4 |          0.0 |

2. 표2 Sensitivity to Top-K (간단 민감도/세부 결과)
| Group | Metric        | K=5 | K=10 | K=15 |
| ----: | ------------- | :-: | :--: | :--: |
|     A | EM(%)         |  —  | 66.7 |  —   |
|     A | Support@K(%)  |  —  | 90.0 |  —   |
|     B | EM(%)         |  —  | 68.8 |  —   |
|     B | Support@K(%)  |  —  | 0.0  |  —   |
|     C | EM(%)         |  —  |  —   |  —   |
|     C | Support@K(%)  |  —  |  —   |  —   |

3. 표 3. Explanation Quality by Group (BERTScore, Top-K = 10) — 33%씩 나눔
| Group | BERTScore 상 | BERTScore 중 | BERTScore 하 |
| ----: | -----------: | -----------: | -----------: |
|     A |        74.9 |        71.7 |        68.1 |
|     B |        75.4 |        71.8 |        67.4 |

4. 표 4. 정성 분석 (Qualitative Examples)

|  # | Group | Question (요약) | Prediction (요약) | Ground Truth (요약) | Explanation (요약) | Evidence OK? | 비고 |
| -: | ----: | --------------- | ----------------- | ------------------- | ------------------ | :----------: | ---- |
|  1 |     B | sample10과 sample9 사이에는 물리적 연결이 존재하지만, sample9 쪽 … | sample10, sample9, CE1, CE2 | sample10→sample7→sample8→sample9→CE2 | : sample10과 sample9 사이에는 물리적 연결이 존재하지만 sample9의 … |      ✘       |      |
|  2 |     B | CE1 관련 장애가 있어도 sample10 → sample8 최단 경로는 바뀌지 않습니… | sample10, sample8, (변경없음) | sample10→sample7→sample8,변경없음 | : CE1의 장애가 발생하더라도 sample10과 sample8 간의 경로는 변경되지 … |      ✘       |      |
|  3 |     B | OpenSSH를 사용해 sample9 → sample7 를 점프 호스트로 거쳐 samp… | ssh -J nso@172.16.1.130 nso@172.16.1.133 | ssh -J user@3.3.3.3,user@1.1.1.1 user@4.4.4.4 | : OpenSSH를 사용하여 sample9에서 sample7을 점프 호스트로 거쳐 sa… |      ✘       |      |

## 표 5: Task-wise Analysis
| Method | Task Type | Overall EM | Overall F1 |
|--------|-----------|-----------:|-----------:|
| RAG A_k=10 | Simple Lookup | 0.0000 | 0.0000 |
| RAG A_k=10 | Other Tasks | 0.6630 | 0.6961 |
| RAG B_k=10 | Simple Lookup | 0.0000 | 0.0000 |
| RAG B_k=10 | Other Tasks | 0.6851 | 0.7213 |
| RAG Bexp_k=10 | Simple Lookup | 0.0000 | 0.0000 |
| RAG Bexp_k=10 | Other Tasks | 0.0000 | 0.0000 |