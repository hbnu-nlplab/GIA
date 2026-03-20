# Dataset Pipeline Code Review
**Files reviewed**: `Make_Dataset/src/main_batfish.py`, `Make_Dataset/src/core_batfish/builder_core.py`, `Make_Dataset/policies.json`
**Date**: 2026-03-19

---

## CRITICAL

### [C1] `resample` id/id_v2 collision — `main_batfish.py` line ~340
**Problem**: `enforce_min_per_category()` generates clone IDs as `f"{src['id']}__rs{idx + 1}"`. `idx` resets to 0 for each *category*. If two categories draw from the same source row (possible because a cloned row is appended to `by_cat` during the same loop and `random.choice` can pick it again), you get `<id>__rs1` twice across categories — the second write passes the `seen_ids` check because that check only runs in the main generation loop, not here.

Worse: the resample loop adds clones back to `by_cat[category]` mid-loop (`by_cat[category].append(clone)`), so a clone at `idx=0` can be chosen as `src` for `idx=1`, producing `<id>__rs1__rs2` as id_v2 — two clones with the *same payload* but confusing nested suffixes.

**Fix**: Track used clone IDs within `enforce_min_per_category`, and do not append clones back to `by_cat` until after the deficit loop for that category.

---

### [C2] `ibgp_fullmesh_ok` returns `AT_TEXT` but policies.json declares `answer_type: "text"` — fine — BUT `ibgp_missing_pairs_count` / `ibgp_under_peered_count` return `AT_SCALAR_INT` while `ground_truth_contracts.py` canonical alias maps `scalar_int → "number"`. `canonical_dataset_answer_type()` in `main_batfish.py` (line ~951) uses this alias, so the row's `answer_type` field is written as `"scalar_int"` (the raw AT_ constant), not `"number"`. The TA-Acc evaluator buckets on canonical types — if any evaluator calls `canonical_answer_type()` again it re-canonicalises, but if it reads raw `answer_type` from the CSV it gets `"scalar_int"`. **Mixed representation** depending on whether `canonical_dataset_answer_type()` or raw AT_ value was stored.

**Evidence**: `canonical_dataset_answer_type()` at line ~68:
```python
def canonical_dataset_answer_type(at, ...):
    return AT_ALIASES.get(at, at or "text")
```
AT_ALIASES maps `"scalar_int" → "scalar_int"` (not remapped). But `ground_truth_contracts._CANONICAL_TYPE_ALIASES` maps it to `"number"`. Two different alias tables.

**Fix**: Unify alias lookup to a single source of truth. Either use `ground_truth_contracts.canonical_answer_type()` throughout, or align `canonical_dataset_answer_type()` with that table.

---

### [C3] `NOT_CONFIGURED` false positive for count-zero answers — `main_batfish.py` lines 906–914
```python
elif isinstance(a_val, (int, float)) and a_val == 0:
    is_empty = True
    answer_status = "NOT_CONFIGURED"
```
This fires for **any L1/L2 Inventory or Configuration_Check metric returning 0**. Metrics such as `ibgp_missing_pairs_count`, `vrf_without_rt_count`, `l2vpn_mismatch_count`, or `ospf_area0_if_list` count *absence of problems* — returning 0 is a **correct, meaningful answer** ("no missing pairs"), not "not configured". Labelling these `NOT_CONFIGURED` corrupts the benchmark ground truth.

**Fix**: Apply this heuristic only to metrics whose zero-value means "feature absent" (e.g. `system_user_count`, `ssh_missing_count`). Add an allowlist, or check category substring more precisely (`"Hardware_Inventory"` but not `"BGP_Consistency"`).

---

## HIGH

### [H1] `id_v2` scope hash uses the *pre-merge* `scope` dict (contains `{host}` placeholder) for GLOBAL metrics — `main_batfish.py` line 946
For GLOBAL-scope metrics `inst = {}`, so `scope = scope_template.copy()` still contains `{"type": "GLOBAL"}` (and any extra template keys). The id_v2 becomes `metric_name:hash({"type":"GLOBAL"})` — identical across all runs for the same metric. This is intended for dedup, but if the template has extra non-instance keys, two semantically different intents could hash identically.

More critically: for DEVICE scope, `scope_template` may contain `{"type":"DEVICE","host":"{host}"}` (unresolved placeholder). After merging `inst` the `host` key is overwritten correctly, but the `type` key remains in `scope` — it's included in `make_scope_hash()`. This is benign but wasteful; filtering `type` from the hash would make id_v2 more portable across schema changes.

### [H2] `FLOW` / `LINK_FAILURE` scope uses unseeded `random.sample` — `main_batfish.py` lines 657–690
No random seed is set anywhere. Each pipeline run generates different FLOW instances, producing different QA rows with different hashes, making runs non-reproducible and `id_v2` unstable across re-runs. For a published benchmark this breaks reproducibility.

**Fix**: Set `random.seed(42)` (or a user-supplied `--seed` arg) before scope expansion.

### [H3] `compare_interface_count` uses raw `d.get("interfaces")` — `builder_core.py` line ~1163
```python
cnt1 = len(d1.get("interfaces") or []) if d1 else 0
```
`interfaces` from the parser is typically a *dict* (`{name: {...}}`), not a list. `len(dict)` returns number of keys which is correct, but if any parser returns a list this silently works differently. The other two compare metrics use dedicated counting helpers (`_count_bgp_neighbors_total`, `_count_vrfs_total`) — `compare_interface_count` should do the same for consistency and safety.

### [H4] `scope_template.copy()` is a shallow copy — `main_batfish.py` line 709
If `scope_template` contains nested dicts (e.g. `{"filters": {"proto": "TCP"}}`), mutations to `scope` inside the loop will corrupt `scope_template` for subsequent iterations. Standard pattern for DSL templates.

**Fix**: Use `copy.deepcopy(scope_template)` or `json.loads(json.dumps(scope_template))`.

### [H5] L45 errors counted against `len(dsl_items)` (L1–L5 total) not L4/L5 count — `main_batfish.py` line 993
```python
print(f"[WARN] L4/L5 generation: {l45_errors} errors out of {len(dsl_items)} metrics")
```
`dsl_items` includes all L1–L3 DSLs. The denominator is inflated, making the error rate look low. Count only L4/L5 dsl_items.

---

## MEDIUM

### [M1] `compare_bgp_neighbor_count` / `compare_interface_count` / `compare_vrf_count` return `map_str_int` with keys `host1_count`, `host2_count`, `difference` — but the question template presumably says "{host1} has N neighbors, {host2} has M". The map keys are **anonymous** (`host1_count` not `PE1_count`). Evaluators doing key-value F1 cannot match if they expect hostname-keyed results. This is a semantic representation issue.

### [M2] `ibgp_fullmesh_ok` truncates missing pairs to 5 with `sorted(miss)[:5]` — `builder_core.py` line ~1004
For L3 benchmark the answer must be deterministic and complete. Truncation makes two topologies with 6 vs 7 missing pairs produce identical answers if 5 overlap. The truncation should be removed for ground truth; it may be retained only for display.

### [M3] `_precompute()` is called per `compute()` call — `builder_core.py` line 352/384
`_precompute()` traverses all devices and computes BGP mesh, L2VPN pairs, OSPF data etc. It is called fresh for every single metric computation during the generation loop. With N devices × M metrics × K scope instances this is O(N×M×K) device traversals.

**Fix**: Cache the result: `self._pre = None` in `__init__`, lazy-init in `compute()`.

### [M4] `policies.json` structure mismatch — `policies["policies"]` is a list containing a single `__comment__` string
Actual metric definitions live in `policies["metrics_metadata"]` (a dict). The `policies` key is dead/legacy. Any code that tries to iterate `policies["policies"]` as a metric list silently gets nothing. Document or remove the dead key.

### [M5] `dsl.get("question_type", "unknown")` fallback — `main_batfish.py` line 975
If `RuleBasedGenerator.compile()` does not propagate `question_type` from `metrics_metadata`, all rows fall back to `"unknown"`. Verify the generator reads and forwards this field (not confirmed in reviewed code).

### [M6] `_infer_source_files()` IP extraction regex is too strict — `builder_core.py` line ~428
```python
if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', s):
```
Uses `re.match` (anchors only start) but does not anchor end — actually `$` is not present so a string `"10.0.0.1/24"` will not match (`.` after third octet). `re.match` does not require full-string match for pattern without `$`, so `10.0.0.1/24` would match and add the `/24` to the IP set. This produces incorrect file lookups. Use `re.fullmatch` or add `$`.

### [M7] `AnswerResult` vs `dict` dual-path — `main_batfish.py` lines ~838–880
The L1–L3 path returns a `dict` (from `builder.compute()`), L4/L5 returns an `AnswerResult` dataclass. The serialization branches are duplicated. `answer_status = "OK"` is hardcoded for dict results without checking `res.get("answer_type") == "error"` (that check is done earlier but only to `continue`, not to set status). If a future metric returns an error dict that passes the early check, `answer_status` will be `"OK"` with an error payload.

---

## LOW

### [L1] `make_scope_hash` uses SHA-1 truncated to 10 hex chars (40-bit) — `main_batfish.py` line 297–298
Birthday collision probability for ~10,000 rows: ≈ 1 − e^(−10000²/(2×16^10)) ≈ 0.03%. Negligible in practice, but upgrading to SHA-256[:16] would cost nothing.

### [L2] `PLACEHOLDER_PATTERN` regex `r"\{[a-zA-Z_][a-zA-Z0-9_]*\}"` — `main_batfish.py` line 64
The raw string uses double-backslash `\\{` (from the diff artifact shown). Verify the actual file uses single `\{` — if the file literally contains `\\{` the pattern never matches any placeholder and `has_placeholder_token()` always returns False, silently passing invalid evidence through.

### [L3] `all_hosts` sorted from `d["system"]["hostname"]` without null guard — `main_batfish.py` line ~588
```python
all_hosts = sorted(d["system"]["hostname"] for d in facts["devices"])
```
If any device has no `system` key or `hostname` is `None`, this raises `KeyError`/`TypeError`. The parser may guarantee this, but a defensive `.get()` is safer.

### [L4] `DEVICE_PAIR` scope is capped at 20 random pairs — `main_batfish.py` line 632–634
```python
if len(pairs) > 20: pairs = random.sample(pairs, 20)
```
Without a seed (see H2) this is non-reproducible. For N=10 hosts there are C(10,2)=45 pairs; 20 out of 45 are sampled, the remaining 25 comparisons never appear in the dataset — systematic coverage gap.

### [L5] `int(las)` coercion for ASN in builder — `builder_core.py` line ~839
ASNs stored as strings (`all_asns` is `set[str]`, scope uses `{"asn": "65000"}`), but `ibgp_*` metrics look up `pre["bgp_missing_pairs_by_as"].get(asn, set())`. If `_precompute` stores ASN keys as `int` and scope passes `str`, the lookup always misses → empty result → wrong answer.

---

## Summary Table

| ID | Severity | File | Lines | Issue |
|----|----------|------|-------|-------|
| C1 | CRITICAL | main_batfish.py | ~338–354 | Resample clone id collision within/across categories |
| C2 | CRITICAL | main_batfish.py + builder_core.py | ~68, ~951 | Dual alias tables: `scalar_int` stored raw vs canonical |
| C3 | CRITICAL | main_batfish.py | 906–914 | `NOT_CONFIGURED` false positive for zero-count consistency metrics |
| H1 | HIGH | main_batfish.py | 946 | id_v2 hash includes `type` key from scope_template |
| H2 | HIGH | main_batfish.py | 657–690 | No random seed → non-reproducible FLOW/LINK_FAILURE QAs |
| H3 | HIGH | builder_core.py | ~1163 | `compare_interface_count` uses raw `d.get("interfaces")` |
| H4 | HIGH | main_batfish.py | 709 | Shallow copy of scope_template; nested dict mutation risk |
| H5 | HIGH | main_batfish.py | 993 | L45 error rate denominator is total dsl_items not L4/L5 |
| M1 | MEDIUM | builder_core.py | ~1150–1180 | compare_* map keys are anonymous, not hostname-keyed |
| M2 | MEDIUM | builder_core.py | ~1004 | ibgp_fullmesh_ok truncates missing pairs to 5 |
| M3 | MEDIUM | builder_core.py | 352/384 | `_precompute()` not cached; re-run per compute() call |
| M4 | MEDIUM | policies.json | — | `policies` key is dead legacy; real data in `metrics_metadata` |
| M5 | MEDIUM | main_batfish.py | 975 | `question_type` may not propagate from RuleBasedGenerator |
| M6 | MEDIUM | builder_core.py | ~428 | IP extraction regex: `re.match` without `$` anchor |
| M7 | MEDIUM | main_batfish.py | ~838–880 | Dual AnswerResult/dict paths; hardcoded `answer_status="OK"` |
| L1 | LOW | main_batfish.py | 297–298 | SHA-1 10-char hash: minor collision risk |
| L2 | LOW | main_batfish.py | 64 | Verify placeholder regex is `\{` not `\\{` |
| L3 | LOW | main_batfish.py | ~588 | No null guard on `d["system"]["hostname"]` |
| L4 | LOW | main_batfish.py | 632–634 | DEVICE_PAIR cap=20 without seed → coverage gap |
| L5 | LOW | builder_core.py | ~839 | ASN type mismatch: str scope vs potential int precompute key |
