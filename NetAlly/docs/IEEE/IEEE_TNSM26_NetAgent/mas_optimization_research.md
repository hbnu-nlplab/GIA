# MAS Optimization Techniques for LLM-based Applications
## Research Survey (March 2026)

Relevance: Optimizing the 5-agent debate pipeline (Collector -> Verifier -> Synthesizer -> Supporter -> Skeptic)

---

## 1. Adaptive Agent Routing / Early Exit

### 1.1 iMAD: Intelligent Multi-Agent Debate (Fan et al., 2025)
- **Paper**: https://arxiv.org/abs/2511.11306
- **Key idea**: Selectively triggers multi-agent debate ONLY when a single agent's answer is likely wrong. Extracts 41 interpretable hesitation features (hedging, contrast words, uncertainty cues) from a self-critique response, then uses a lightweight classifier to decide debate vs. skip.
- **Results**: Up to 92% token reduction, up to 13.5% accuracy improvement.
- **Application to our pipeline**: Before entering the full 5-agent debate, run Collector alone with self-critique. Extract hesitation features. If confidence is high, skip Verifier/Supporter/Skeptic entirely and go straight to Synthesizer. This avoids 3-5x token overhead for easy questions (L1-L2).
- **LangGraph compatible**: Yes. Add a conditional edge after Collector node that routes to either full debate or direct Synthesizer based on classifier output.

### 1.2 OI-MAS: Confidence-Aware Routing (Wang et al., 2026)
- **Paper**: https://arxiv.org/html/2601.04861v1
- **Key idea**: State-dependent routing that dynamically selects both agent roles AND model scales. High-confidence steps use small/cheap models; uncertain steps escalate to large models. Acts as a "conductor" — like an orchestra not needing every instrument at full volume.
- **Results**: Up to 12.88% accuracy improvement, up to 79.78% cost reduction.
- **Application to our pipeline**: Use different model sizes per agent role. Collector/Synthesizer use full GPT-4o; Supporter/Skeptic can use GPT-4o-mini when Verifier confidence is high. Dynamic model selection per debate round.
- **LangGraph compatible**: Yes. Use state metadata to carry confidence scores; conditional edges select model backend per node.

### 1.3 MasRouter: Multi-Agent System Routing (ACL 2025)
- **Paper**: https://arxiv.org/abs/2502.11133
- **Key idea**: Unified routing framework with 3 cascaded controllers: (1) collaboration mode determiner (single vs. multi-agent), (2) role allocator, (3) LLM router per role. Uses variational latent variable model.
- **Results**: 52% overhead reduction on HumanEval; plug-and-play with existing MAS frameworks.
- **Application to our pipeline**: Before debate starts, MasRouter-style classifier determines if the question needs full 5-agent pipeline or a simpler 2-3 agent subset. L1 questions might only need Collector+Synthesizer.
- **LangGraph compatible**: Yes. Router node at graph entry point.

---

## 2. Efficient Multi-Agent Debate

### 2.1 ICLR 2025 Blog: MAD Scaling Challenges
- **Source**: https://d2jud02ci9yv69.cloudfront.net/2025-04-28-mad-159/blog/mad/
- **Key finding**: MAD consumes 3-5x more tokens than CoT. Current MAD methods FAIL to consistently outperform simpler single-agent strategies, even with increased compute. No stable scaling law observed.
- **Implication for our pipeline**: The Supporter/Skeptic debate rounds may not always add value. Need empirical validation that debate actually improves accuracy per question level (L1-L5). Consider ablation study removing Supporter+Skeptic for lower levels.

### 2.2 Adaptive Heterogeneous Multi-Agent Debate (Springer 2025)
- **Source**: https://link.springer.com/article/10.1007/s44443-025-00353-3
- **Key idea**: Dynamic routing that activates different agent subsets depending on query type and intermediate debate outcomes. Reduces redundancy by allocating expertise only where needed.
- **Application to our pipeline**: For L1-L3 (fact extraction, aggregation), skip Supporter/Skeptic. For L4-L5 (simulation, what-if), activate full debate. Route based on question_type metadata.

### 2.3 Trust or Escalate (ICLR 2025)
- **Source**: https://proceedings.iclr.cc/paper_files/paper/2025/file/08dabd5345b37fffcbe335bd578b15a0-Paper-Conference.pdf
- **Key idea**: Cascaded selective evaluation — start with cheap judge, escalate to expensive one only when confidence threshold is not met. Risk-controlled cascade guarantees.
- **Application to our pipeline**: Verifier acts as first-pass judge. If Verifier confidence > threshold, skip Supporter+Skeptic debate entirely. Only escalate to full debate when Verifier flags uncertainty.
- **LangGraph compatible**: Yes. Conditional edge after Verifier node.

---

## 3. Tool-Augmented MAS Optimization

### 3.1 LLM Compiler Pattern
- **Source**: https://agent-patterns.readthedocs.io/en/stable/patterns/llm-compiler.html
- **Key idea**: Treats multi-tool workflows like a compiler DAG. A Planner constructs a directed acyclic graph of tool calls with explicit dependencies; a Task Fetching Unit schedules independent tools in parallel.
- **Results**: Up to 3.6x speedup for I/O-bound operations.
- **Application to our pipeline**: When Collector needs multiple Batfish queries (traceroute + interface info + routing table), compile them into a DAG and execute independent queries in parallel instead of sequentially.
- **LangGraph compatible**: Yes. Native Send API supports this pattern.

### 3.2 Framework Landscape (2025-2026 Comparisons)
- **LangGraph**: Best for stateful workflows with durable execution and human-in-the-loop. Graph-based state machines. Our current choice.
- **CrewAI**: Role-based teams, fastest setup, 5.7x faster deploy for structured tasks. Could replace role definitions.
- **AutoGen (now Microsoft Agent Framework)**: Merged with Semantic Kernel (Oct 2025). Production SLAs, multi-language support. M1-Parallel paper uses AutoGen's Magentic-One.
- **Recommendation**: Stay with LangGraph for the debate pipeline (stateful, conditional routing needed). Consider CrewAI patterns for role definition clarity.

---

## 4. Parallel Agent Execution

### 4.1 M1-Parallel (ICML 2025, Microsoft Research)
- **Paper**: https://arxiv.org/html/2507.08944v1
- **Key idea**: Runs multiple multi-agent teams in parallel exploring different solution paths. Two modes: (1) Early termination — first team to finish wins (2.2x speedup), (2) Aggregation — combine results for higher accuracy. Event-driven async messaging.
- **Application to our pipeline**: Run Supporter and Skeptic IN PARALLEL (they are independent — one argues for, one argues against). Synthesizer waits for both. This cuts one sequential step.
- **LangGraph compatible**: Yes. Fan-out from Verifier to [Supporter, Skeptic] simultaneously, fan-in at Synthesizer.

### 4.2 LangGraph Native Parallel Patterns
- **Source**: https://langchain-ai.github.io/langgraphjs/how-tos/map-reduce/
- **Key patterns**:
  - **Fan-out/Fan-in**: Multiple nodes execute simultaneously, downstream node waits for all.
  - **Send API**: Distribute different states to multiple node instances (map-reduce).
  - **defer=True**: Handles branches of different lengths.
  - **Conditional edges**: Route to parallel branches based on state.
- **Application to our pipeline**:
  ```
  Current:  Collector -> Verifier -> Supporter -> Skeptic -> Synthesizer (5 sequential)
  Proposed: Collector -> Verifier -> [Supporter || Skeptic] -> Synthesizer (4 steps, parallel debate)
  ```

### 4.3 Parallel Tool Calling
- **Source**: https://docs.letta.com/guides/agents/parallel-tool-calling/
- **Key idea**: OpenAI models support parallel_tool_calls parameter. Four 300ms calls complete in ~300ms total.
- **Application**: Collector's Batfish tool calls (get_interfaces, get_routes, traceroute) can run concurrently within a single agent step.

---

## 5. Key Frameworks and Their Optimization Strategies

### 5.1 AgentVerse (ICLR 2024)
- Assigns specific responsibilities to each agent, simulating human-like collaboration. Dynamic agent recruitment based on task needs.

### 5.2 MetaGPT
- Encodes Standard Operating Procedures (SOPs) into prompts to structure interactions. Verifies intermediate results before proceeding.
- **Relevant pattern**: SOP-driven verification is similar to our Verifier role.

### 5.3 ChatDev (ACL 2024)
- Cooperative communication through natural + programming language blend. Autonomous proposing and continuous refinement.
- **Relevant pattern**: Phase-based pipeline (Design -> Coding -> Testing) maps to our (Collect -> Verify -> Debate -> Synthesize).

### 5.4 Multi-Agent Collaboration Survey (Tran et al., 2025)
- **Paper**: https://arxiv.org/html/2501.06322v1
- Comprehensive taxonomy: actors, types (cooperation/competition/coopetition), structures (peer-to-peer/centralized/distributed), strategies (role-based/model-based), coordination protocols.
- **Key finding**: Primary bottleneck is planning and communication — as agents and rounds increase, token consumption grows substantially.

---

## Recommended Implementation Priority for NetAlly Pipeline

| Priority | Technique | Effort | Impact | Source |
|----------|-----------|--------|--------|--------|
| 1 | Parallel Supporter+Skeptic | Low | ~30% latency cut | M1-Parallel, LangGraph fan-out |
| 2 | Confidence-based early exit after Verifier | Medium | ~50-90% token save on easy Qs | iMAD, Trust-or-Escalate |
| 3 | Parallel Batfish tool calls within Collector | Low | ~2-3x tool call speedup | LLM Compiler, parallel_tool_calls |
| 4 | Level-based agent subset routing | Medium | Skip unnecessary agents for L1-L3 | OI-MAS, MasRouter |
| 5 | Heterogeneous model selection per role | Medium | ~40-80% cost reduction | OI-MAS |

---

## Proposed Optimized Pipeline (LangGraph)

```
                                    ┌─── Supporter ───┐
Question → Collector → Verifier ─┬──┤                 ├──→ Synthesizer → Answer
                                 │  └─── Skeptic ────┘
                                 │        (parallel)
                                 │
                                 └── [high confidence] ──→ Synthesizer → Answer
                                      (early exit)
```

Key changes from current sequential pipeline:
1. Conditional edge after Verifier (confidence-based early exit)
2. Fan-out to Supporter+Skeptic in parallel
3. Fan-in at Synthesizer
4. Level-based routing at entry (L1-L2 may skip debate entirely)
