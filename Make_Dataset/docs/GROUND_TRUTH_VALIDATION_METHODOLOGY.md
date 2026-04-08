# Ground Truth Validation Methodology

## Goal

This project does not claim that any single oracle is infallible. Instead, it uses a layered validation strategy so that retained dataset rows are:

- internally consistent,
- replay-verifiable,
- externally spot-checked against emulated network behavior.

## Validation Layers

### Method 1: Independent Parser Verification

- Scope: `L1-L3`
- Oracle: pure Python config parser, independent from Batfish
- Coverage: exhaustive
- Purpose: verify that config-derived answers can be recomputed from raw device configuration files

### Method 2: Human Config Review

- Scope: `L1-L3`
- Oracle: human reviewer reading raw `.cfg` files
- Coverage: stratified sample
- Purpose: catch parser blind spots and policy interpretation mistakes

### Method 3: PNETLab External Validation

- Scope: `L4-L5`
- Oracle: actual emulated device behavior in PNETLab
- Coverage: stratified sample
- Purpose: test whether Batfish-derived semantic answers align with observable network behavior

Method 3 is intentionally sample-based. It is not the main exhaustive verifier; it is the external reality check.

### Method 4: Batfish Replay Verification

- Scope: `L4-L5`
- Oracle: Batfish replay from row-level contracts
- Coverage: exhaustive
- Purpose: verify that each retained `L4-L5` row can be reconstructed from stored scenario/query contracts without relying on generator-side hidden state

## Why Method 4 Is Necessary

Without replay verification, a dataset row may contain a plausible answer that was produced by a buggy generation path or polluted simulator state. Method 4 prevents that by requiring each `L4-L5` row to store enough information to replay the answer:

- metric
- scope
- scenario
- query contract
- verification contract

If a row cannot be replayed, it should be quarantined or excluded.

## Why Method 3 Is Still Necessary

Method 4 only proves that Batfish answers are reproducible from stored contracts. It does not prove that Batfish perfectly models real network behavior. Method 3 addresses that gap by checking a stratified subset in PNETLab.

In short:

- Method 4 checks `generator vs replayed Batfish`
- Method 3 checks `Batfish vs emulated network behavior`

## Paper-Safe Claims

Recommended claims:

- `L1-L3 rows are exhaustively verified by an independent parser.`
- `L4-L5 rows are exhaustively replay-verified using Batfish contracts.`
- `A stratified subset of L4-L5 rows is externally validated in PNETLab.`
- `Rows that cannot be replayed or validated are quarantined or excluded from paper-ready sets.`

Avoid claims such as:

- `all answers are guaranteed correct`
- `the dataset is error-free`
- `Batfish is always correct`

## Retained Dataset Policy

For paper-ready reporting, a row should be retained only if:

- schema validation passes,
- answer canonicalization passes,
- Method 1 passes for `L1-L3`, or
- Method 4 passes for `L4-L5`.

Method 2 and Method 3 provide supporting evidence and external quality assurance, but they are sample-based and should be reported as such.

## Operational Workflow

1. Generate dataset.
2. Run quality gate.
3. Run Method 1 for `L1-L3`.
4. Run Method 2 for sampled `L1-L3`.
5. Run Method 3 guide generation for sampled `L4-L5`.
6. Run Method 4 replay verification for `L4-L5`.
7. If available, ingest human-completed Method 3 results.
8. Publish `verification_summary.json` and `paper_ready_dataset.json`.

## Interpretation

The final dataset should be described as:

- contract-verified,
- replay-verifiable,
- partially externally validated,
- fail-closed for unverifiable cases.
