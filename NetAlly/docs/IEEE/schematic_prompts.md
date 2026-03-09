# Scientific Schematics Prompts for IEEE Figures

These prompts are prepared for the `scientific-schematics` skill and target journal-quality outputs for the IEEE TNSM manuscript. Generate the figures with:

```bash
python C:\Users\sdlab\.codex\skills\scientific-schematics\scripts\generate_schematic.py "<prompt>" -o <output> --doc-type journal --iterations 2
```

## Fig. 1: Framework Overview

**Output**
`figures/fig1_framework_overview.png`

**Prompt**
```text
Journal-quality system overview diagram for a network configuration reasoning paper. Use a clean white background, sans-serif labels, and Okabe-Ito color palette. Landscape layout, left-to-right overall flow with three connected regions. Left region: "Real Cisco IOS .cfg files" flowing into "Dual-Path QA Generation Pipeline", then into "NetConfigQA 2.0 Dataset (9,462 QA, 4 Labs, L1-L5)". Center-right region: dataset flowing into "6 LLM Evaluation" and "TA-Acc Scoring". Bottom region: three side-by-side blocks labeled "Single LLM", "Pure MAS", and "NetAlly", connected to a final analysis block labeled "3-Way Comparison: Structure vs Tool Contribution". Add small subtitle labels showing C1 above the benchmark path, C2 above NetAlly, and C3 above the comparative analysis. Use soft blue/green/orange block colors, consistent arrow thickness, and balanced spacing. Make the figure publication-ready, readable at two-column journal width, and avoid decorative elements.
```

## Fig. 2: Dual-Path QA Generation Pipeline

**Output**
`figures/fig2_dual_path_pipeline.png`

**Prompt**
```text
Journal-quality flowchart for a dual-path QA generation pipeline in network configuration analysis. White background, crisp vector-style scientific schematic, sans-serif fonts, colorblind-safe palette. Start with a single input block labeled "Cisco IOS Configuration Files (.cfg)". Then split into two clearly separated branches. Upper branch labeled "Path A: Rule-Based (L1-L3)" with blocks "Batfish Parser", "Static Facts JSON", "policies.json + Scope Expansion", and "L1-L3 QA Pairs". Lower branch labeled "Path B: Simulation-Based (L4-L5)" with blocks "Batfish Simulation", "traceroute / reachability", "fork_snapshot / differentialReachability", and "L4-L5 QA Pairs". Merge both branches into a final block labeled "Dataset Assembler -> CSV / JSON". Visually emphasize the contrast between static extraction and simulation-based generation using different but harmonious colors. Use clean arrows, no overlaps, high readability, and publication-quality spacing.
```

## Fig. 3: NetAlly 3-Plane Architecture

**Output**
`figures/fig3_netally_architecture.png`

**Prompt**
```text
Journal-quality architecture diagram for a tool-augmented multi-agent network operations system called NetAlly. Use a clean white background, scientific publication style, sans-serif text, Okabe-Ito palette, and landscape layout. Top-left: user query enters an "Orchestrator" block labeled "task decomposition + skill selection". Arrow to an "Executor" block labeled "ReAct loop, max 10 steps". From the Executor, show bidirectional connections to three distinct tool planes aligned horizontally at the bottom: "PNETLab Plane" with labels "topology control, console access", "NSO Plane" with labels "RESTCONF config query / sync", and "Batfish Plane" with labels "verification, traceroute, what-if analysis". Include a visible loop from Executor back to itself labeled "observe -> reason -> act". Add an error recovery path from tool failures back into Executor labeled "structured error recovery". Show MCP or tool-binding layer subtly between Executor and the three planes if space allows. The final diagram should clearly communicate that NetAlly is more than a simple wrapper and should be legible at one-column journal size.
```

## Fig. 7: Difficulty Taxonomy (Optional)

**Output**
`figures/fig7_cognitive_difficulty.png`

**Prompt**
```text
Journal-quality conceptual diagram showing a five-level cognitive difficulty taxonomy for network configuration reasoning. White background, clean publication style, left-to-right staircase or ascending layered structure. Five stages labeled L1 Fact Extraction, L2 Aggregation, L3 Consistency Checking, L4 Path Simulation, L5 Counterfactual Failure Impact. Use increasing visual complexity from left to right. Place a dashed vertical divider between L3 and L4 labeled "Simulation Barrier". Under each level, add a small short phrase: L1 read local facts, L2 summarize global statistics, L3 compare cross-device consistency, L4 infer packet path, L5 infer failure impact. Use colorblind-safe colors and minimal icons if helpful, but keep the overall appearance rigorous and publication-ready.
```

## Execution Notes

- Use `--doc-type journal` for all four diagrams.
- Prefer PNG output first, then convert to PDF if needed for LaTeX inclusion.
- If regenerated images outperform the current figures, update `main.tex` to point to the new filenames.
- If the AI output is too crowded, simplify labels before adding more iterations.
