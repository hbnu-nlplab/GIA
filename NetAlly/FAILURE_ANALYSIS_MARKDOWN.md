
# NetAlly MAS Evaluation - Failure Analysis

## Quick Reference Table

| Question ID | Level | Type | Category | Gold | Pred | Failure Category | Root Cause | Fix Type |
|---|---|---|---|---|---|---|---|---|
| ROUTING_TABLE_ENTRY_COUNT_p4 | L1 | number | System_Inventory | 6 | 0 | Tool Failure | Batfish query incomplete | Tool Fix |
| INTERFACES_MISSING_DESCRIPTION_COUNT_leaf2 | L1 | number | Configuration_Check | 2 | 0 | Tool Failure | NSO missing field | Tool Fix |
| INTERFACE_STATUS_MAP_leaf7 | L1 | map | System_Inventory | {up,up} | {} | Tool Failure | Status not extracted | Tool Fix |
| AAA_ENABLED_DEVICES (5 instances) | L2 | set | Security_Policy | [pe1-4] | all/empty | LLM Interpretation | No device taxonomy | Prompt Fix |
| COMPARE_VRF_COUNT_leaf7_p5 | L3 | map | Comparison_Analysis | {diff:0,...} | {host:0,...} | Format Mismatch | Wrong schema | Prompt Fix |
| COMPARE_INTERFACE_COUNT_p8_pe2 | L3 | map | Comparison_Analysis | {diff:2,...} | {host:0,...} | Format Mismatch | Wrong schema | Prompt Fix |
| COMPARE_BGP_AS_leaf3_p6 | L3 | text | Comparison_Analysis | N/A | None | Format Mismatch | None vs N/A | Prompt Fix |
| L2VPN_MISMATCH_COUNT | L3 | number | L2VPN_Consistency | 0 | 4 | Data/LLM Mismatch | LLM hallucination | Data/Prompt Fix |
| IBGP_UNDER_PEERED_DEVICES_65000 | L3 | set | BGP_Consistency | [pe1-4] | [] | Tool Failure | BGP enum empty | Tool Fix |

## Summary Statistics

**Overall Accuracy:** 75.33% (37/50 correct)
**Total Failures:** 13

### By Fix Type
- **Prompt Fixes:** 8 failures (61.5%) → +16% accuracy gain
- **Tool Fixes:** 4 failures (30.8%) → +8% accuracy gain  
- **Data Fixes:** 1 failure (7.7%) → +2% accuracy gain

**Expected accuracy after all fixes: ~91%**

### By Category
- **Device Type Filtering (AAA_ENABLED):** 5 failures → Single fix impacts 38.5%
- **Comparison Schema:** 2 failures → Single fix impacts 15.4%
- **Tool Extraction Issues:** 4 failures → 4 separate tool fixes needed

## Implementation Priority

### Phase 1: Prompt Fixes (30 min, +16% gain)
1. Add device type taxonomy (PE vs Access vs Spine)
2. Add JSON schema templates for comparison answers
3. Clarify N/A vs None handling

### Phase 2: Tool Fixes (2-4 hours, +8% gain)
1. Debug Batfish routing table query
2. Add interface description filter (NSO)
3. Extract interface status mapping (NSO)
4. Fix BGP device enumeration (Batfish)

### Phase 3: Data Validation (30 min)
1. Verify L2VPN test data correctness

## Files to Modify

**Prompt Fixes:**
- `agent/system_prompt.py` - Add device taxonomy
- `agent/prompt_templates.py` - Add JSON schemas

**Tool Fixes:**
- `agent/clients/batfish.py` - Debug routing & BGP queries
- `agent/clients/nso.py` - Add interface extraction
