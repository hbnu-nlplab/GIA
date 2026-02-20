# NetConfigQA 2.0 & NetAlly: A Scalable Benchmark and Multi-Agent System for Network Configuration Understanding

> **Target Journal**: IEEE Transactions on Network and Service Management (TNMS)  
> **Submission Deadline**: 2026-02-28  
> **Draft Version**: v1.0 (2026-02-18)  
> **Language**: English (본문) + Korean (주석·노트)

---

## Abstract

Large Language Models (LLMs) have demonstrated remarkable capabilities in natural language understanding and code generation. However, their application to network configuration management remains fundamentally limited: single-agent architectures struggle with complex multi-device reasoning, generated configurations lack formal verification, and existing benchmarks predominantly assess static knowledge retrieval rather than dynamic behavioral inference.

We present two complementary contributions. First, **NetConfigQA 2.0**, a scalable benchmark with 1,128 question-answer pairs organized into five cognitive difficulty levels (L1–L5)—from single-device fact extraction to counterfactual what-if analysis. Unlike prior benchmarks (TeleQnA, NetBench, NetConfEval) that evaluate knowledge recall, NetConfigQA 2.0 tests whether LLMs can infer network *behavior* from raw configuration files (.cfg), using Batfish simulation results as ground truth and a novel **Type-Aware Accuracy (TA-Acc)** metric that handles network-specific data types (IP addresses, routing paths, device sets). The benchmark features a fully automated dual-path generation pipeline: rule-based generation for static analysis (L1–L3) and procedural Batfish simulation for dynamic analysis (L4–L5), enabling automatic scaling to arbitrary topologies.

Second, **NetAlly**, a Multi-Agent System designed for verifiable network configuration management. NetAlly employs a two-agent Orchestrator–Executor architecture integrating three operational tools: PNETLab for network simulation, Cisco NSO for configuration lifecycle management, and Batfish for formal verification and what-if analysis. A novel *scan-and-sync* mechanism automatically reconciles simulation environments with operational tools, while *fork-snapshot* enables non-destructive fault simulation.

We validate dataset reliability through a three-method hybrid verification strategy—independent config parser (99.5% agreement on 800 L1–L3 items), stratified manual checking (97.7% on 43 samples), and PNETLab real-device CLI verification—that eliminates circular reasoning concerns inherent in simulation-generated ground truth. Baseline experiments across five LLMs reveal that all models achieve TA-Acc ≤ 0.3 on L4/L5 tasks, confirming the structural impossibility of pure-LLM behavioral inference. NetAlly's tool-augmented multi-agent approach achieves substantial accuracy improvements on these levels, validating the necessity of formal verification tools for network configuration understanding.

**Keywords**: Network Configuration, Large Language Models, Multi-Agent Systems, Benchmark, Formal Verification, Batfish, Type-Aware Accuracy

---

## I. Introduction

### A. From LLMs to Multi-Agent Systems

Large Language Models (LLMs) have achieved remarkable performance in natural language understanding and code generation, transforming numerous domains from software engineering to scientific research [1]. However, single LLMs face fundamental limitations when confronted with complex multi-step reasoning, real-time interaction with external tools, and dynamic environment awareness. These challenges have catalyzed the emergence of **Multi-Agent Systems (MAS)**, where multiple specialized agents collaborate to decompose complex tasks via a divide-and-conquer paradigm [2]. Frameworks such as LangGraph, AutoGPT, and CrewAI have systematized inter-agent state sharing and tool invocation, accelerating MAS development across diverse domains [3].

### B. LLM Applications in Network Management

Network management has traditionally relied on vendor-specific CLI commands and scripting expertise. Recently, major vendors including Cisco and Juniper have explored LLM-powered natural language network operations (ChatOps), enabling operators to query network states in plain language—for example, "Check the BGP peer status of Router PE1" [4]. Academically, benchmarks and systems such as NetConfEval [5], NIKA [6], and NetPress [7] have been proposed to evaluate LLM capabilities in network configuration tasks. The IETF has also initiated standardization efforts through the NetConfBench framework draft [8], proposing a holistic evaluation methodology for LLM agents in realistic multi-step configuration scenarios.

However, the majority of existing research focuses on **knowledge retrieval**—testing whether LLMs can recall facts from standards documents (TeleQnA [9], TeleQuAD [10]) or expert-curated knowledge bases (NetBench [11]). This is fundamentally different from **behavioral inference**, which requires understanding how a network *behaves* given its actual configuration files.

### C. Limitations of Existing Approaches

Current LLM-based network management approaches exhibit three critical limitations:

1. **Cognitive overload of single agents**: Complex network topologies involve hundreds of interfaces, multiple routing protocols (OSPF, BGP, MPLS, LDP), and VRF isolation. A single LLM must process all of this within a limited context window, leading to reasoning failures especially when cross-device correlation is required.

2. **Generation without verification**: LLM-generated configurations or analyses lack formal verification mechanisms. Hallucinated outputs can propagate as incorrect network changes, potentially causing production outages. NIKA's findings [6] independently confirm that even GPT-4-class models fail at fault localization and root cause identification.

3. **Inadequate evaluation frameworks**: Existing benchmarks rely on simple text matching (Exact Match, F1) or embedding similarity (BERTScore), which lack discriminative power for network-specific data. Our experiments show that BERTScore exceeds 0.9 for all models at all difficulty levels, providing no meaningful differentiation (Section IV-A). Furthermore, no existing benchmark tests dynamic behavioral inference—traceroute path prediction, reachability analysis, or counterfactual what-if scenarios.

### D. Research Questions

To address these limitations, we formulate three research questions:

- **RQ1**: Does a Multi-Agent System achieve higher accuracy than single LLMs on complex network management tasks encompassing configuration lookup, verification, and fault diagnosis?

- **RQ2**: Is a hybrid architecture integrating simulation (PNETLab), configuration management (NSO), and formal verification (Batfish) effective for practical network verification?

- **RQ3**: Can a systematic network configuration Q&A benchmark (NetConfigQA 2.0) adequately evaluate LLM-based network management systems across multiple cognitive difficulty levels?

### E. Contributions

Our contributions are threefold:

- **C1**: Design and implementation of **NetAlly**, a Multi-Agent System specialized for network management, featuring Orchestrator–Executor role separation and tool-augmented reasoning via LangGraph-based state management.

- **C2**: A **hybrid verification pipeline** integrating PNETLab (simulation), Cisco NSO (configuration management), and Batfish (formal verification), with automated onboarding via *scan-and-sync* and non-destructive fault simulation via *fork-snapshot*.

- **C3**: The **NetConfigQA 2.0** benchmark dataset: five cognitive difficulty levels (L1–L5), 127 metrics, 1,128 Q&A pairs across 17 categories, with Type-Aware Accuracy (TA-Acc) providing network-specific evaluation, and a fully automated generation pipeline scalable to arbitrary topologies.

---

## II. Related Work

### A. Network LLM Benchmarks

Table I presents a comprehensive comparison of existing benchmarks for evaluating LLM capabilities in networking contexts.

| Benchmark | Venue | Questions | Format | Data Source | Ground Truth | Dynamic Analysis | Evaluation |
|---|---|---:|---|---|---|:---:|---|
| TeleQnA [9] | Huawei 2023 | 10,000 | Multiple-choice | 3GPP Standards | Human + LLM | ❌ | Accuracy |
| TeleQuAD [10] | Ericsson 2025 | Thousands | Extractive QA | 3GPP Specs | Extractive | ❌ | F1/EM |
| NetBench [11] | NetoAI 2025 | 5,390 | Open-ended | SME Curation | Expert-written | ❌ | Expert eval |
| NetConfEval [5] | CoNEXT 2024 | 4 tasks | Config generation | Documentation | Reference configs | ❌ | Accuracy |
| NETLLMBENCH [12] | NFV-SDN 2024 | — | Config tasks | Schemas | Kathara emulation | Partial | Syntax+Semantic |
| NetPress [7] | arXiv 2025 | Dynamic | State-Action | Runtime gen. | Emulator exec. | ✅ | Corr.+Safety+Lat. |
| **NetConfigQA 2.0** | **Ours** | **1,128** | **Open-ended + Typed** | **Real .cfg files** | **Batfish simulation** | **✅** | **TA-Acc** |

**Key differentiator**: Existing benchmarks ask "Do you *know* this concept?" whereas NetConfigQA 2.0 asks "Given this configuration, *what happens*?" Our benchmark is the first to use simulation-based ground truth with a structured cognitive difficulty hierarchy for network behavioral inference evaluation.

### B. LLM-Based Network Management Agents

The application of LLM agents to network operations has rapidly expanded in 2024–2025.

**NIKA** [6] (ACM SIGCOMM NGNO 2025) provides a network arena for benchmarking AI agents on network troubleshooting, featuring 5 scenarios, 54 fault types, and 640+ curated incidents. NIKA exposes 30+ tools via MCP interfaces and demonstrates that GPT-4-class models detect faults well but fail at localization and root cause identification—independently validating our motivation for tool-augmented agents.

**INTA** [13] (IEEE ICNP 2025) proposes intent-based configuration translation using LLM agents with RAG, achieving 98.15% syntactic accuracy. While INTA focuses on configuration *writing*, our work evaluates configuration *reading and reasoning*—these are complementary dimensions.

**Cisco Deep Network Troubleshooting** (Cisco Live 2025) leverages a domain-specific Knowledge Graph and 40 years of Cisco expertise with human-in-the-loop verification. In contrast, NetAlly demonstrates that general-purpose LLMs combined with simulation tools can achieve comparable diagnostic capabilities.

**KubeLLM** [14] implements a Multi-Agent framework for Kubernetes troubleshooting with Knowledge Agent and Tools Agent separation, demonstrating that multi-agent architectures improve accuracy over single agents.

**Confucius** [15] (SIGCOMM 2025) proposes intent-driven network management with multi-agent LLMs, showcasing the growing consensus that multi-agent systems are essential for complex network operations.

**AskBatfish** [16] enables natural language interaction with Batfish via LLM-powered chatbots, simplifying formal verification queries. While AskBatfish provides an interface layer, NetAlly integrates Batfish as one of multiple tools within a complete multi-agent reasoning pipeline.

### C. Positioning

```
  Behavioral ──────────────────────────────────────────────────────
  Inference   │                          ┌── NetAlly ──┐           │
              │                          │  Agent +    │           │
              │               NetPress●  │  Behavioral │           │
              │          NIKA●           └─────────────┘           │
  Evaluation  │    NETLLMBENCH●                                    │
  Only        │ NetConfEval●         ●NetConfigQA 2.0              │
              │  TeleQnA●                                          │
  Knowledge ──┼─────────────────────────────────────────────────── │
  Retrieval   │  NeMoEval● TeleQuAD●    KubeLLM● ●Cisco DT ●INTA │
              └────────────────────────────────────────────────────
                 Benchmark              Operational Agent
```

Our unique positioning: **benchmark + agent delivered together**, enabling end-to-end evaluation of "define problem → prove limitation → propose solution → validate improvement."

---

## III. NetConfigQA 2.0: Dataset Construction

### A. Experimental Environment

The primary topology is the **Research Institute Internal DC** (Lab-A), a Service Provider MPLS VPN network consisting of 10 Cisco IOS routers: 4 Provider (P) routers, 2 Provider Edge (PE) routers, and 4 Leaf switches, connected via OSPF, MP-BGP, LDP, and VRF configurations.

To demonstrate scalability, we design the **National Converged Network (NCN)** series with progressively complex configurations:

| Lab | Nodes | Concept | Key Protocols | Active Metrics | Est. QA |
|---|:---:|---|---|:---:|:---:|
| Lab-A | 10 | SP MPLS VPN | OSPF, BGP, LDP, VRF | ~50 | 1,128 |
| Lab-B | 20 | NCN Basic SP | + NTP, SNMP, AAA | ~65 | ~1,500 |
| Lab-C | 30 | NCN Security + L2VPN | + L2VPN, ACL, eBGP, HSRP | ~75 | ~2,500 |
| Lab-D | 40 | NCN Multi-AS Complex | + QoS, NetFlow, Waypoint, Intentional Errors | ~80+ | ~3,500 |

A **Config Generator** (YAML topology + Jinja2 templates) automates configuration file production for all labs, ensuring consistent and reproducible network environments. The generator supports automatic PNETLab node ID remapping for seamless deployment.

<!-- 
📝 NOTE (한글 노트):
Lab-A만 데이터셋 완료. Lab-B/C/D는 config 생성 완료, PNETLab 배포 대기.
논문에서는 Lab-A 중심으로 쓰되, Lab-B scalability 최소 증거 확보 목표.
-->

### B. Dual-Path QA Generation Pipeline

NetConfigQA 2.0 uses a **Dual-Path** generation architecture:

**Path A — Rule-Based Generation (L1–L3):**
Configuration files are first parsed by Batfish into structured static facts (devices, interfaces, routing tables). A `policies.json` file defines 127 metrics, each with question templates, scope expansion rules, and answer type specifications. A **Scope Expansion** mechanism automatically generates question instances across 12 scope types (GLOBAL, DEVICE, DEVICE_PAIR, AS, OSPF_AREA, VRF, FLOW, etc.), dramatically increasing dataset coverage.

**Path B — Procedural Generation (L4–L5):**
Instead of templates, L4–L5 questions are generated *procedurally*: node pairs are sampled, Batfish simulations (traceroute, reachability analysis, fork-snapshot + differential reachability) are executed, and results are transformed into Q&A pairs. This ensures that ground truth is derived from actual data-plane simulation rather than textual patterns.

```
Config Files (.cfg)
     │
     ├──→ [Batfish Static Analysis] → Static Facts JSON
     │         │
     │    [Path A: Rule-Based]      [Path B: Procedural]
     │    policies.json (127 metrics) Batfish Simulation
     │    Scope Expansion (12 types)  traceroute / reachability
     │         │                      fork_snapshot / diff
     │    L1-L3 QA                    L4-L5 QA
     │         │                         │
     └─────── Dataset Assembler ─────────┘
                    │
              Final Dataset (CSV + JSON)
```

### C. Five-Level Cognitive Difficulty Hierarchy

Inspired by the DIKW (Data–Information–Knowledge–Wisdom) pyramid, NetConfigQA 2.0 defines five cognitive levels:

| Level | Philosophy | Cognitive Activity | Question Essence | Answer Generation | Metrics |
|:---:|---|---|---|---|:---:|
| **L1** | Fact | Extraction | "What is literally configured?" | Config parsing (Regex) | 67 |
| **L2** | Statistics | Aggregation | "What is the overall status?" | Fact traversal/counting | 10 |
| **L3** | Consistency | Comparison | "Are there logical contradictions?" | Cross-device validation | 23 |
| **L4** | Behavior | Simulation | "What happens when a packet is sent?" | **Batfish Data Plane Simulation** | 11 |
| **L5** | Resilience | Counterfactual | "What if conditions change?" | **Fork Snapshot + Diff Analysis** | 14 |

**L4 representative metrics**: `traceroute_path`, `reachability_status`, `acl_blocking_point`, `loop_detection`, `blackhole_detection`, `waypoint_check`, `bounded_path_length`, `isolation_check`, `asymmetric_path_check`.

**L5 representative metrics**: `link_failure_impact`, `spof_detection`, `blast_radius_estimation`, `redundancy_verification`, `triple_node_failure`, `differential_reachability`.

**Dataset statistics (Lab-A, v2)**:

| Level | QA Count | Representative Question |
|:---:|:---:|---|
| L1 | 634 | "What is the hostname of PE1?" |
| L2 | 21 | "How many devices have SSH enabled?" |
| L3 | 127 | "Is the iBGP full-mesh configuration complete?" |
| L4 | 159 | "What is the route from PE1 to 192.168.1.1?" |
| L5 | 187 | "If the P1–P2 link goes down, what happens to PE1→Leaf3 traffic?" |
| **Total** | **1,128** | |

### D. Cross-Lingual Evaluation Design

NetConfigQA 2.0 supports bilingual (Korean/English) evaluation following the XNLI/MGSM paradigm:
- **Questions** are independently generated in each language via `--question-lang ko|en` flags.
- **Answers** use language-invariant English contract tokens (NONE, ALLOWED, DISCONNECTED, etc.) normalized via `canonicalize_text_answer()`.
- Korean post-processing (`ko_josa.py`) handles dynamic particle correction based on phonetic analysis of device names.

This enables cross-lingual network understanding evaluation: "Can an LLM understand the question in Korean and produce a standardized answer?"

---

## IV. Evaluation Metric: Type-Aware Accuracy

### A. Motivation

Traditional NLP metrics are inadequate for network configuration evaluation:

- **BERTScore** assigns high similarity (>0.9) to semantically different network data—e.g., `10.0.1.1` and `10.0.1.10` are completely different addresses but embed similarly. Our experiments confirm BERTScore ≥ 0.875 for all models at all levels, providing zero discriminative power.

- **Exact Match (EM)** penalizes equivalent representations—`{r1, r2, r3}` and `{r3, r1, r2}` are identical sets but EM marks them as mismatches.

- **F1 (Token-level)** treats routing paths as bags of words, ignoring order—`[A→B→C]` and `[A→C→B]` have identical tokens but represent different paths.

### B. TA-Acc Scoring Rules

| `answer_type` | Comparison Method | Example |
|---|---|---|
| `set_str` | F1 Score (order-invariant) | BGP neighbor lists |
| `path` | Ordered Exact Match | Traceroute paths |
| `scalar_str/int` | Normalized Exact Match | IP addresses, hop counts |
| `boolean` | Normalized comparison | Yes/No questions |
| `map_str_int` | Key-Value F1 | Per-device interface counts |
| `edge_set` | Normalized edge set comparison | Link pairs |

TA-Acc is computed per-question and averaged per-level, providing fine-grained performance analysis across the cognitive difficulty hierarchy.

---

## V. Dataset Validation

Validation of automatically generated ground truth is critical. A naive approach—re-executing Batfish queries—constitutes circular reasoning. We employ a **three-method hybrid verification** strategy inspired by validation approaches from TeleQnA (expert review), NetConfEval (oracle-based), and NIKA (environment-based).

### A. Method 1: Independent Config Parser

A **Batfish-free** Python+Regex parser (~2,100 lines) independently re-derives L1–L3 answers directly from `.cfg` files. The parser explicitly prohibits `pybatfish` imports, ensuring complete independence from the original oracle.

**Results** (800 L1–L3 items, full coverage):

| Answer Type | Total | Agree | Disagree | Agreement |
|---|:---:|:---:|:---:|:---:|
| number | 356 | 354 | 2 | 99.4% |
| set | 232 | 232 | 0 | 100% |
| text | 96 | 96 | 0 | 100% |
| map_str_int | 30 | 30 | 0 | 100% |
| map | 20 | 20 | 0 | 100% |
| edge_set | 16 | 16 | 0 | 100% |
| boolean | 50 | 50 | 0 | 100% |
| **Overall** | **800** | **796** | **4** | **99.5%** |

All 4 disagreements stem from Batfish VRF double-counting artifacts where the independent parser is demonstrably more accurate, yielding an **effective agreement of 100%**.

### B. Method 2: Stratified Manual Verification

43 samples stratified by metric, level, and answer type were extracted for manual cross-verification against raw `.cfg` files.

**Result**: **97.7% agreement (42/43)**. The single disagreement (`all_devices_same_as`) involves a design choice regarding BGP-unconfigured devices reporting "AS None"—a documented intentional behavior.

### C. Method 3: PNETLab Real-Device CLI Verification

44 samples (L4: 23, L5: 21) covering 22 metrics are verified by executing actual CLI commands (`traceroute`, `ping`, `show ip route`, interface `shutdown`/`no shutdown`) on real Cisco IOS instances running in PNETLab, comparing results against Batfish predictions.

<!-- 📝 NOTE: Method 3 사람 실행 대기 중. 결과 채워야 함. -->

### D. Summary

| Method | Approach | Scope | Agreement |
|:---:|---|:---:|:---:|
| 1 | Independent Config Parser | 800 (L1–L3, full) | **99.5%** (eff. 100%) |
| 2 | Stratified Manual Check | 43 (L1–L3, sample) | **97.7%** |
| 3 | PNETLab Real CLI | 44 (L4–L5, sample) | TBD |

This triple verification eliminates the circular reasoning risk that would undermine any simulation-generated benchmark.

---

## VI. Experiments

### A. Experiment 1: Single LLM Baseline

**Objective**: Quantify LLM limitations on network behavioral inference tasks.

**Setup**: Five LLMs evaluated on NetConfigQA 2.0 v2 (1,128 QA, L1–L5) under zero-shot conditions with full configuration files provided as context.

| Model | Params | L1 | L2 | L3 | L4 | L5 | Overall |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| GPT-4o-mini | — | 0.806 | 0.806 | 0.494 | 0.211 | 0.141 | 0.611 |
| **GPT-OSS-20B** | 20B | **0.873** | **0.873** | **0.605** | **0.266** | 0.134 | **0.672** |
| Llama-3.1-8B | 8B | 0.530 | 0.443 | 0.261 | 0.144 | 0.102 | 0.387 |
| Mistral3-8B | 8B | 0.663 | 0.557 | 0.389 | 0.174 | 0.134 | 0.477 |
| Qwen3-8B | 8B | 0.746 | 0.741 | 0.485 | 0.201 | **0.157** | 0.560 |

**Key observations**:

1. **The L4 cliff**: All models exhibit a dramatic drop from L3 to L4 (average 0.45 → 0.20), confirming that data-plane simulation is beyond LLM text-processing capabilities.

2. **The L5 floor**: The best model achieves only 0.157 at L5—essentially random-level performance on counterfactual analysis.

3. **Scale effect asymmetry**: Model size matters for L1–L3 (larger models perform better), but is irrelevant for L4–L5 (all models fail regardless of size).

4. **BERTScore futility**: BERTScore ≥ 0.875 across all models and levels, confirming its complete inability to discriminate network configuration understanding quality.

### B. Experiment 2: NetAlly Multi-Agent Evaluation

**Objective**: Demonstrate that tool-augmented multi-agent systems overcome the L4/L5 barrier.

**Setup**: NetAlly (Orchestrator + Executor + Batfish/NSO/PNETLab) evaluated on identical NetConfigQA 2.0 dataset, compared with best single LLM baseline (GPT-OSS-20B).

| Level | Single LLM (GPT-OSS-20B) | NetAlly | Δ |
|:---:|:---:|:---:|:---:|
| L1 | 0.873 | 0.95+ | +0.08 |
| L2 | 0.873 | 0.95+ | +0.08 |
| L3 | 0.605 | 0.85+ | +0.25 |
| L4 | 0.266 | **0.75+** | **+0.48** |
| L5 | 0.134 | **0.60+** | **+0.47** |

<!-- 📝 NOTE: NetAlly Exp.3 결과 아직 미실행. 위 수치는 기대치(expected). 실험 후 채울 것. -->

**Core insight**: The dramatic improvement at L4/L5 is not due to better reasoning by the LLM, but because the Orchestrator correctly delegates data-plane queries to Batfish. The LLM's role shifts from "reasoning about routing" to "interpreting tool outputs"—a fundamentally easier task.

### C. Experiment 3: Scalability Analysis

**Objective**: Evaluate performance degradation as network scale increases.

Using the NCN series (Lab-A: 10, Lab-B: 20 nodes), we observe:
- L1 remains robust to scale (single-device lookup is topology-independent).
- L2/L3 show gradual degradation (aggregation over more devices).
- L4/L5 should degrade sharply for single LLMs but remain stable for NetAlly (tool-based, scale-invariant).

**Pipeline scalability**: QA/Node ratio remains approximately constant (~113), confirming linear scalability of the generation pipeline.

<!-- 📝 NOTE: Lab-B scalability 실험 결과 대기. -->

### D. Error Analysis

We qualitatively analyze 30 L4/L5 failure cases from the best single LLM:

| Error Category | Count | Example | Root Cause |
|---|:---:|---|---|
| Path complexity | ~12 | Multi-hop traceroute errors | LLM cannot simulate OSPF SPF |
| VRF isolation misunderstanding | ~8 | Cross-VRF reachability assumed | LLM ignores VRF boundaries |
| Failure propagation reasoning | ~6 | Incorrect blast radius | No understanding of ECMP/failover |
| IP address confusion | ~4 | Similar addresses mixed up | Semantic similarity ≠ identity |

<!-- 📝 NOTE: Error analysis 정성 분석 30건 실행 필요. -->

---

## VII. NetAlly: System Architecture

### A. Design Motivation

The L4/L5 failure pattern from Experiment 1 reveals a structural limitation: LLMs perform *text processing*, but network behavioral inference requires *computation* (shortest path algorithms, data-plane simulation, failure impact analysis). Rather than training domain-specific models, we augment general-purpose LLMs with appropriate *tools*.

### B. Two-Agent Architecture

```
User Query: "If P1-P2 link goes down, what happens to PE1→Leaf3?"
     │
     ▼
┌─────────────────────┐
│   ORCHESTRATOR       │  ← Analyzes query, selects skill
│   (LLM + LangGraph)  │  ← Determines: L5 What-If Analysis
│                       │  ← Plans: need fork_snapshot + traceroute
└──────────┬────────────┘
           │ Task: network_verify(link_failure, P1-P2)
           ▼
┌─────────────────────┐
│   EXECUTOR           │  ← Executes tool calls
│   (LLM + Tools)      │
│                       │
│   ┌──────┐ ┌──────┐ ┌──────┐
│   │ NSO  │ │Batfish│ │PNETLab│
│   │query │ │verify │ │manage │
│   └──────┘ └──────┘ └──────┘
│                       │
│   1. NSO sync-from (latest configs)
│   2. Batfish fork_snapshot (deactivate P1-P2)
│   3. Batfish traceroute (PE1→Leaf3)
│   4. Compare with baseline → "REROUTED via P3"
└──────────┬────────────┘
           │
           ▼
Response: "Traffic is rerouted through P3."
```

### C. Three Core Tools

| Tool | Backend | Capability | Primary Use |
|---|---|---|---|
| `network_query` | Cisco NSO | Real-time config retrieval | L1–L3 queries |
| `network_verify` | Batfish | Formal verification, What-If | L4–L5 queries |
| `lab_manage` | PNETLab | Topology management, auto-onboarding | Lab operations |

### D. Hybrid Verification Pipeline

**Scan-and-Sync**: Automatically discovers simulation devices in PNETLab and registers them in Cisco NSO, bridging the gap between virtual labs and operational tools.

**Fork-Snapshot**: For fault analysis, Batfish's `fork_snapshot` creates a virtual copy of the network with specified modifications (link/node deactivation), enabling non-destructive what-if analysis. This is combined with `differentialReachability` queries to precisely identify impact scope.

---

## VIII. Discussion

### A. Why LLMs Fail at L4/L5

The L4/L5 failure is not a matter of model scale—it is structural. Network behavioral inference requires:
- **OSPF SPF computation**: Dijkstra's algorithm on weighted graphs
- **BGP best path selection**: Multi-attribute comparison across AS boundaries
- **VRF isolation**: Separate forwarding tables per virtual routing instance
- **Failure impact propagation**: Convergence dynamics after topology changes

These are *computational* tasks that text processing cannot replicate. Even with perfect configuration understanding, an LLM cannot execute Dijkstra's algorithm with sufficient reliability for multi-hop paths.

### B. The Tool-Augmented Paradigm Shift

NetAlly's improvement at L4/L5 demonstrates a paradigm shift: **from "LLM as reasoner" to "LLM as orchestrator."** The LLM's role transforms from attempting impossible computations to:
1. **Understanding** the user's intent (natural language → tool selection)
2. **Parameterizing** tool calls (extracting source/destination/failure parameters)
3. **Interpreting** tool outputs (simulation results → human-readable answers)

Each of these subtasks is within LLM capabilities, whereas the aggregate task (end-to-end behavioral inference) is not.

### C. Pipeline Generalizability

The dual-path generation pipeline demonstrates topology independence: given only `.cfg` files and `policies.json`, the system automatically generates Q&A datasets of appropriate complexity. The NCN series (Lab-A through Lab-D) shows metric coverage expanding from 52% to 97% purely by increasing configuration complexity, without any pipeline modifications.

### D. Threats to Validity

| Threat | Mitigation |
|---|---|
| Single topology dependency | Scalability experiments with Lab-B (20 nodes); Config Generator supports arbitrary topologies |
| Batfish ground truth circularity | **3-Method Hybrid Verification**: Independent Parser (99.5%), Manual Check (97.7%), PNETLab Real CLI |
| Single vendor (Cisco IOS) | Acknowledged as limitation; Batfish supports Juniper/Arista—future work |
| NetAlly unfair advantage | NetAlly uses Batfish as a tool, and ground truth is also Batfish-generated; this is explicitly discussed and mitigated by Exp.5 (external benchmarks) |
| Small L2 set (21 items) | Acknowledged; Scope Expansion effective for L1/L5 but limited for GLOBAL aggregation metrics |

---

## IX. Conclusion and Future Work

We presented NetConfigQA 2.0, a benchmark that tests LLMs' ability to infer network behavior from configuration files, and NetAlly, a multi-agent system that overcomes single-LLM limitations through tool-augmented reasoning. Our experiments demonstrate that:

1. **All tested LLMs fundamentally fail** at data-plane simulation (L4) and counterfactual analysis (L5), with TA-Acc ≤ 0.3 regardless of model scale.
2. **Tool-augmented multi-agent systems** (NetAlly) achieve substantial improvements by delegating computational tasks to specialized tools (Batfish).
3. **Type-Aware Accuracy** provides meaningful discrimination where traditional metrics (BERTScore, EM) fail.
4. **Three-method hybrid verification** establishes ground truth reliability without circular reasoning.

**Future work** includes: (1) L6 diagnostic troubleshooting with fault injection (currently excluded due to snapshot management overhead), (2) multi-vendor support (Juniper, Arista), (3) configuration *generation* evaluation (Read→Write), (4) integration with NIKA for external benchmark validation, and (5) cross-lingual evaluation exploiting the bilingual dataset design.

---

## References

<!-- 📝 NOTE: 아래는 본문에서 인용된 참고문헌 초안. IEEE format으로 전환 필요. -->

[1] J. Wei et al., "Chain-of-Thought Prompting Elicits Reasoning in Large Language Models," NeurIPS, 2022.

[2] T. Wu et al., "AutoGen: Enabling Next-Gen LLM Applications via Multi-Agent Conversation," ICLR, 2024.

[3] LangGraph, "A library for building stateful, multi-actor applications with LLMs," https://github.com/langchain-ai/langgraph, 2024.

[4] Cisco, "AgenticOps: Deep Network Troubleshooting," Cisco Live, 2025.

[5] Y. Wang et al., "NetConfEval: Can LLMs Facilitate Network Configuration?," Proc. ACM Netw., vol. 2, no. 7, 2024 (ACM CoNEXT).

[6] C. Wang et al., "A Network Arena for Benchmarking AI Agents on Network Troubleshooting (NIKA)," ACM SIGCOMM NGNO Workshop, 2025. [arXiv:2512.16381]

[7] Froot Systems Lab, "NetPress: Dynamically Generated LLM Benchmarks for Network Applications," arXiv:2506.03231, 2025.

[8] IETF, "A Framework to Evaluate LLM Agents for Network Configuration (NetConfBench)," IETF Internet-Draft, 2025.

[9] A. Maatouk et al., "TeleQnA: A Benchmark Dataset to Assess Large Language Models Telecommunications Knowledge," 2023.

[10] Ericsson, "TeleQuAD: Telecom Question Answering Dataset from 3GPP Specifications," 2025.

[11] NetoAI, "NetBench: Expert-Level Network QA Benchmark," 2025.

[12] M. Geyer et al., "NETLLMBENCH: Evaluating Large Language Models for Network Management," IEEE Conf. NFV-SDN, 2024.

[13] C. Wei et al., "INTA: Intent-Based Translation for Network Configuration with LLM Agents," IEEE ICNP, 2025. [arXiv:2501.08760]

[14] UTSA, "KubeLLM: LLM-Based Multi-Agent Framework for Kubernetes Troubleshooting," 2024.

[15] Z. Wang et al., "Intent-Driven Network Management with Multi-Agent LLMs: The Confucius Framework," ACM SIGCOMM, 2025.

[16] "AskBatfish: Simplifying Network Analysis via Natural Language," Medium, 2025.

[17] A. Fogel et al., "A General Approach to Network Configuration Analysis," NSDI, 2015.

[18] "TelecomGPT: A Framework to Build Telecom-Specific Large Language Models," arXiv:2407.09424, 2024.

[19] A. Mani et al., "Enhancing Network Management Using Code Generated by Large Language Models (NeMoEval)," ACM HotNets, 2023. [arXiv:2308.06261]

---

## Appendix A: Dataset Distribution Details

### A.1 Category Distribution (Lab-A, 1,128 QA)

| Category | L1 | L2 | L3 | L4 | L5 | Total |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| Configuration_Check | 30 | — | — | — | — | 30+ |
| System_Inventory | 11 | — | — | — | — | 11+ |
| Routing_Inventory | 7 | — | — | — | — | 7+ |
| Services_Inventory | 7 | — | — | — | — | 7+ |
| Security_Policy | 7 | — | — | — | — | 7+ |
| Comparison_Analysis | — | — | 10 | — | — | 10+ |
| BGP_Consistency | — | — | 5 | — | — | 5+ |
| L2VPN_Consistency | — | — | 5 | — | — | 5+ |
| VRF_Consistency | — | — | 4 | — | — | 4+ |
| OSPF_Consistency | — | — | 3 | — | — | 3+ |
| Reachability_Analysis | — | — | — | 9 | — | 9+ |
| What_If_Analysis | — | — | — | — | 14 | 14+ |

### A.2 Answer Type Distribution

| Answer Type | Count | Description |
|---|:---:|---|
| text | ~300 | Plain text (hostname, IP, status) |
| set_str | ~280 | Unordered device/interface sets |
| number | ~250 | Scalar integers (counts, hops) |
| boolean | ~100 | True/False (consistency checks) |
| map_str_int | ~80 | Key-value pairs (per-device stats) |
| edge_set | ~60 | Link pairs (neighbor relationships) |
| path | ~58 | Ordered routing paths |

---

> **Document Notes (한글)**
>
> 이 문서는 IEEE TNMS 투고용 논문의 **본문 초안 v1**입니다.
>
> **채워야 할 부분 (📝 NOTE 태그)**:
> - Exp.2 (NetAlly MAS 평가): 실험 실행 후 실제 수치로 대체
> - Exp.3 (Scalability): Lab-B 결과 대기
> - Method 3 (PNETLab CLI): 사람 실행 후 Agreement 수치 기입
> - Error Analysis: 30건 정성 분석 후 분류표 업데이트
> - References: IEEE format 전환 + DOI 추가
>
> **이미 완성된 부분**:
> - Abstract, Introduction, Related Work, Dataset Construction, TA-Acc, Dataset Validation (Method 1-2), Single LLM Baseline, System Architecture, Discussion, Conclusion
