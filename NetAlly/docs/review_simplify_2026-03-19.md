# Simplify Code Review — NetAlly Agent Files
Date: 2026-03-19
Scope: runtime.py, graph.py, clients/batfish.py, clients/pnetlab.py, onboarding.py
Session base: 4bce51ab → baeaf7f9
(Already-fixed issues skipped per instructions.)

---

## CRITICAL

### C1 — `main.py` duplicates `runtime.py`'s `ainvoke → to_thread` fallback pattern
**File:** `NetAlly/main.py` lines 694–696
**Also at:** `NetAlly/agent/runtime.py` `_invoke_tool()`
The `/api/tool/invoke` endpoint re-implements the exact same `try: await tool.ainvoke() / except: asyncio.to_thread(tool.invoke)` pattern that already lives in `SingleExecutorRuntime._invoke_tool()`.
The endpoint should delegate to a shared helper (e.g., `runtime._invoke_tool_raw(name, args)`) instead of copy-pasting it.
**Category:** Code Reuse

---

## HIGH

### H1 — `onboarding.enable_ssh_all` is fully sequential — missed `asyncio.gather`
**File:** `NetAlly/agent/onboarding.py` lines 892–894
```python
for dev in devices:
    results[dev.name] = await enable_ssh_via_telnet(dev, gs)
```
Each SSH bootstrap takes 5–30 s of telnet I/O. With 10 nodes this serialises to 50–300 s.
`enable_ssh_via_telnet` is already `async`; switching to:
```python
coros = [enable_ssh_via_telnet(dev, gs) for dev in devices]
outcomes = await asyncio.gather(*coros, return_exceptions=True)
```
would make it fully concurrent (telnet ports are independent).
**Category:** Efficiency / Missed Concurrency

### H2 — `onboarding.scan_and_sync` NSO registration loop is sequential
**File:** `NetAlly/agent/onboarding.py` lines 992–1018
```python
for dev in devices:
    ...
    if nso.register_device(device_info):
```
`nso.register_device` is a blocking RESTCONF call. With 10 devices this adds unnecessary latency at startup. Each registration is independent — should use `asyncio.gather` + `asyncio.to_thread`.
**Category:** Efficiency / Missed Concurrency

### H3 — `graph.py` creates `logger` **inside the closure** on every invocation
**File:** `NetAlly/agent/graph.py` line 99
```python
logger = logging.getLogger(__name__)   # inside orchestrator_node() closure body
```
`logging.getLogger` is called on every LLM invocation. Should be a module-level singleton (like runtime.py already does correctly). Only caught in this session because the prior fix moved `import json/re` out but left the logger inside.
**Category:** Efficiency / Hot-path Bloat

---

## MEDIUM

### M1 — `pnetlab.py` re-imports `unquote` inside `set_session_from_browser`
**File:** `NetAlly/agent/clients/pnetlab.py` line 181
```python
from urllib.parse import unquote   # ← redundant; already imported at line 18
```
The module-level import at line 18 already makes this available everywhere. Remove the inline import.
**Category:** Code Quality / Dead Import

### M2 — `runtime.py` `DEFAULT_EXECUTOR_PROMPT` and `PURE_MAS_PROMPT` share ~60% identical preamble
**File:** `NetAlly/agent/runtime.py` lines 22–50
Both prompts start with "You are NetAlly…" and share the rules list; only the tool-availability paragraph differs. Extract the shared preamble into a constant and compose:
```python
_BASE_PROMPT = "You are NetAlly, …\n\nRules:\n1. …"
DEFAULT_EXECUTOR_PROMPT = _BASE_PROMPT + "\n\nYou have access to tools…\nanswer_type: {answer_type}"
PURE_MAS_PROMPT = _BASE_PROMPT + "\n\nNo external tools available…\nanswer_type: {answer_type}"
```
Any future rule change currently requires editing both strings.
**Category:** Code Reuse / Maintenance Risk

### M3 — `main.py /api/tool/invoke` silently swallows the `ainvoke` exception
**File:** `NetAlly/main.py` lines 694–696
```python
try:
    result = await tool.ainvoke(tool_args)
except Exception:            # ← bare, no log
    result = await asyncio.to_thread(tool.invoke, tool_args)
```
Unlike `runtime._invoke_tool()` (which was fixed this session to log `TOOL_OK_SYNC`), the endpoint version still has no logging on the fallback path. If `ainvoke` fails for a reason other than "sync-only tool", the error is silently swallowed.
**Category:** Code Quality / Silent Error

### M4 — `onboarding.py` uses both `dataclasses.replace` (fixed this session) and direct `DeviceInfo` field mutation elsewhere
**File:** `NetAlly/agent/onboarding.py` lines 411, 565
The session correctly fixed `gs.pnetlab_vm_ip =` → `dataclasses.replace(gs, …)`, but several `DeviceInfo` objects (e.g. `dev.oob_ip = …` patterns) in `assign_missing_oob_ips` still mutate the dataclass in-place. Inconsistent with the immutability fix applied to `GlobalSettings`.
**Category:** Code Quality / Immutability Inconsistency

---

## LOW

### L1 — `main.py` startup uses `print()` instead of `logger`
**File:** `NetAlly/main.py` lines 314, 345, 356
Three `print("[NetAlly] …")` calls in the lifespan handler bypass the structured logging system. Should be `logger.info(…)`.
**Category:** Code Quality / Inconsistent Logging

### L2 — `onboarding.py` `_prefix_to_netmask` duplicates stdlib one-liner
**File:** `NetAlly/agent/onboarding.py` lines 171–175
```python
def _prefix_to_netmask(prefix_len: int) -> str:
    try:
        return str(ipaddress.IPv4Network(f"0.0.0.0/{prefix_len}").netmask)
    except Exception:
        return "255.255.255.0"
```
Python's `ipaddress` already provides `IPv4Network(…).netmask` directly; the function is correct but the wrapping is redundant given that the only caller could inline `str(ipaddress.ip_network(f"0.0.0.0/{n}", strict=False).netmask)`. Minor, but is dead wrapper code.
**Category:** Code Reuse

---

## Summary Table

| ID | File | Line(s) | Category | Severity |
|----|------|---------|----------|----------|
| C1 | main.py | 694–696 | Code Reuse (dup of runtime._invoke_tool) | CRITICAL |
| H1 | onboarding.py | 892–894 | Efficiency — serial SSH bootstrap | HIGH |
| H2 | onboarding.py | 992–1018 | Efficiency — serial NSO register | HIGH |
| H3 | graph.py | 99 | Efficiency — logger in hot closure | HIGH |
| M1 | pnetlab.py | 181 | Code Quality — redundant import | MEDIUM |
| M2 | runtime.py | 22–50 | Code Reuse — duplicate prompt preamble | MEDIUM |
| M3 | main.py | 694–696 | Code Quality — silent fallback exception | MEDIUM |
| M4 | onboarding.py | 411, 565 | Code Quality — inconsistent immutability | MEDIUM |
| L1 | main.py | 314, 345, 356 | Code Quality — print vs logger | LOW |
| L2 | onboarding.py | 171–175 | Code Reuse — trivial wrapper | LOW |
