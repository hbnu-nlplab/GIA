# 🏗️ Project Context: Network Engineering Multi-Agent System (MAS)

## 1. Project Overview
We are building a **Multi-Agent System (MAS)** to answer complex network engineering questions. The core goal is to minimize hallucinations and maximize technical accuracy using a **2-Stage Debate Pipeline**.

## 2. Architecture Philosophy (The "Why")
Instead of a simple QA bot, we simulate a human review process:
* **Stage 1 (Refinement):** Fix the messy RAG context first. Don't answer yet.
* **Stage 2 (Verification):** Argue about the answer (Pro vs. Con) before deciding.

## 3. System Pipeline (LangGraph)
The system is built on **LangGraph** and flows as follows:

### 🔹 Stage 1: Context Refinement
* **Goal:** Turn raw passage into "Golden Context" & draft a candidate answer.
* **Agents Loop:**
    1.  **Engineer:** Fixes technical errors (IPs, Protocols).
    2.  **Auditor:** Removes hallucinations.
    3.  **Editor:** Improves readability.
* **Solver:** Generates a `candidate_answer` based on the refined passage.

### 🔹 Stage 2: Answer Verification
* **Goal:** Verify the candidate answer through adversarial debate.
* **Agents Flow:**
    1.  **Supporter:** Finds evidence *supporting* the answer.
    2.  **Skeptic:** Finds evidence *contradicting* the answer (Devil's Advocate).
    3.  **Judge:** Decides the `final_answer`.

## 4. Tech Stack & Implementation Details
* **Framework:** LangChain, LangGraph
* **Model Loading (Key Feature):**
    * Uses a **Singleton Pattern** in `config/model_loader.py`.
    * Supports Hybrid Mode: **OpenRouter API** OR **Local GPU (A5000)** via `USE_LOCAL` flag.
    * **Resource Optimization:** Loads 3 models into VRAM (4-bit quantized) and reuses them for different roles (Personas).

## 5. Directory Structure
```text
MultiAgent/
├── agents/
│   ├── debate1.py       # Stage 1 Nodes (Engineer, Auditor, Editor, Solver)
│   ├── debate2.py       # Stage 2 Nodes (Supporter, Skeptic, Judge)
│   ├── main.py          # LangGraph Workflow Definition & Execution
│   ├── model_loader.py  # Singleton Model Loader (Local/Cloud)
│   └── state.py         # Shared State Schema (TypedDict)
├── config/
│   └── load_env.py      # Environment Variables Manager
├── data/
│   ├── original/        # Input Datasets (JSON)
│   └── results/         # Final Outputs
└── ...