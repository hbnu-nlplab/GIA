# Method 2 — Manual Verification Protocol

## Purpose
Supplement Method 1 (Independent Parser) by manually tracing dataset answers
back to raw .cfg files. Focuses on complex L3 cross-device metrics, boundary
cases, and any Method 1 mismatches.

## Procedure (per QA)

1. Open the relevant .cfg file(s) in a text editor
2. Follow the `verification` field from policies.json step by step
3. Derive the expected answer independently
4. Compare with the dataset answer using TA-Acc comparison rules
5. Record AGREE or DISAGREE
6. If DISAGREE, classify as:
   - DATA_ERROR: Dataset answer is incorrect
   - PARSER_ERROR: Manual trace made an error
   - AMBIGUITY: Question or answer definition is ambiguous
   - FORMAT_MISMATCH: Same value, different representation
7. Document the reasoning with specific config file line references

## Sampling Strategy

- **Method 1 MISMATCH cases**: All verified (cross-reference)
- **L3 metrics**: 2 samples per metric (normal + boundary)
- **L2 metrics**: 1 sample per metric
- **L1 boundary cases**: 5 diverse cases
- **answer_type coverage**: At least 1 per type

## Comparison Rules (TA-Acc)

- `text`: normalize(lowercase, strip) → exact match
- `number`: int/float parse → value comparison
- `set`: parse set → F1 == 1.0
- `map`: key-value exact match
- `boolean`: normalize → exact match

## Output Files

- `manual_checklist.csv`: Full verification record
- `manual_disagreement_log.md`: Detailed analysis of any disagreements
- `manual_sample_selection.md`: Sample selection criteria and list
- `manual_verification_summary.json`: Statistics summary
