# Experiment Comparison Report (Enhanced)

## 🔎 Highlights
- Best Overall EM: 0.3333 (*RAG k=5*)
- Best Overall F1: 0.3333 (*RAG k=5*)
- Gain vs Non-RAG baseline: EM +0.3333, F1 +0.0159

## 📊 Results Table
| Method | Setting | Overall EM | Overall F1 | Rule-based EM | Enhanced LLM GT EM |
|--------|---------|-----------:|-----------:|--------------:|--------------------:|
| Non-RAG | - | 0.0000 | 0.3175 | 0.0000 | 0.0000 |
| RAG | k=5 | **0.3333** | **0.3333** | 0.3333 | 0.0000 |
| RAG | k=10 | 0.0000 | 0.0741 | 0.0000 | 0.0000 |
| RAG | k=15 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |

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
Non-RAG & - & 0.0000 & 0.3175 & 0.0000 & 0.0000 \\
RAG & k=5 & \textbf{0.3333} & \textbf{0.3333} & 0.3333 & 0.0000 \\
RAG & k=10 & 0.0000 & 0.0741 & 0.0000 & 0.0000 \\
RAG & k=15 & 0.0000 & 0.0000 & 0.0000 & 0.0000 \\
\hline
\end{tabular}
\end{table}
```
