# Security Audit Report — GIA Repository
Date: 2026-03-19
Scope: Dead code, attack surface reduction, secrets, unsafe patterns

---

## CRITICAL

### C-1: Hardcoded SSH Root Password in Source Code
**Files:**
- `NetConfigQA3/tests/Danger_vm_ssh/debug_ssh_direct.py:17` — `password = "pnet"  # Confirmed working password`
- `NetConfigQA3/tests/Danger_vm_ssh/unsafe_gateway_configurator.py:17` — `password = "pnet"`
- `NetConfigQA3/tests/Danger_vm_ssh/regex_topology_injector.py:63` — `password = "pnet"`

**Issue:** Root SSH password for a live PNETLab VM is hardcoded and committed to git. The comment "Confirmed working password" confirms this is not a placeholder. The `Danger_vm_ssh/` directory name itself signals this was always known to be unsafe.

**Fix:** Delete this entire directory. It is dead code (CLAUDE.md marks NetConfigQA3 as legacy). If the scripts are ever needed again, load credentials from environment variables.

```bash
git rm -r NetConfigQA3/tests/Danger_vm_ssh/
```

---

### C-2: Real Tailscale IPs and Default Credentials Committed in `.env.tailscale`
**File:** `NetAlly/.env.tailscale`

**Issues:**
- Lines 13, 15, 29, 44, 47, 53: Real Tailscale IPs (`100.85.92.121`, `100.67.63.77`) committed to the repository
- Lines 30-31: `NSO_USERNAME=admin` / `NSO_PASSWORD=admin` committed
- Line 61: `PNETLAB_ADMIN_PASSWORD=admin` committed

**Issue:** This file is tracked by git (shown in `git status` as untracked but present). Anyone with repo access gets the network topology IPs and default credentials for NSO and PNETLab. The file is intended as a template but contains real values.

**Fix:**
1. Replace all real IPs with `CHANGE_ME_*` placeholders
2. Remove default credential values, leave keys empty
3. Confirm `.env.tailscale` is listed in `.gitignore` (check and add if missing)
4. Rotate the NSO/PNETLab passwords since they are now in git history

---

### C-3: Unauthenticated Settings API Allows Runtime Credential Injection
**File:** `NetAlly/main.py:1292` — `POST /api/settings`
**File:** `NetAlly/main.py:1210` — `POST /api/pnetlab/auth`

**Issue:** Both endpoints accept and store credentials (`OPENAI_API_KEY`, `NSO_PASSWORD`, `PNETLAB_PASSWORD`, `PNETLAB_COOKIES`) in live `os.environ` with zero authentication. Any client that can reach port 8111 can overwrite all API keys and credentials at runtime. `demo_up_local.sh:5` binds to `HOST="${NETALLY_HOST:-127.0.0.1}"` so local-only by default, but `deploy_to_pnetlab.sh` deploys to a remote VM.

**Fix:** Add an auth middleware or at minimum an API bearer token check on all `/api/settings` and `/api/pnetlab/auth` endpoints. At minimum:
```python
API_ADMIN_TOKEN = os.getenv("NETALLY_ADMIN_TOKEN")
if API_ADMIN_TOKEN and request.headers.get("X-Admin-Token") != API_ADMIN_TOKEN:
    raise HTTPException(status_code=403)
```

---

## HIGH

### H-1: `eval` Used with External Command String in Shell Script
**File:** `scripts/test_connectivity.sh:45`
```bash
if eval "timeout ${timeout} ${cmd}" &>/dev/null; then
```
**Issue:** `$cmd` is constructed from caller-supplied values (e.g. SSH hostnames sourced from `.env`). If `.env` is tampered with or the variable is set maliciously, `eval` will execute arbitrary shell commands. Use `bash -c` with a fixed prefix or restructure to use arrays.

**Fix:**
```bash
# Replace eval with direct execution using array expansion
if timeout "${timeout}" bash -c "${cmd}" &>/dev/null; then
```
Or better, refactor `check()` to accept an array argument to avoid string interpolation entirely.

---

### H-2: `curl | sh` Pattern for Tailscale and uv Installation
**Files:**
- `scripts/setup_ubuntu_vllm.sh:26` — `curl -fsSL https://tailscale.com/install.sh | sh`
- `scripts/setup_pnetlab_vm.sh:21` — `curl -fsSL https://tailscale.com/install.sh | sh`
- `scripts/setup_wsl_dev.sh:26` — `curl -fsSL https://tailscale.com/install.sh | sh`
- `scripts/setup_wsl_dev.sh:63` — `curl -LsSf https://astral.sh/uv/install.sh | sh`

**Issue:** Piping curl directly to sh executes remote code without integrity verification. A MITM or CDN compromise would result in arbitrary code execution on the host.

**Fix:** Download the installer, verify a checksum, then execute:
```bash
curl -fsSL https://tailscale.com/install.sh -o /tmp/tailscale_install.sh
sha256sum -c tailscale_install.sh.sha256  # Use published hash
sh /tmp/tailscale_install.sh
```

---

### H-3: Hardcoded `admin:admin` Credentials in Shell Script (echoed to terminal)
**File:** `scripts/setup_pnetlab_vm.sh:127`
```bash
echo "   curl -s -u admin:admin http://${TAILSCALE_IP}:8080/restconf/..."
```
**Issue:** While this is just an `echo` in a setup guide, it normalizes `admin:admin` as the expected NSO credential and will appear in terminal logs/history. Combined with C-2, this confirms `admin:admin` is the real deployed credential.

---

### H-4: Debug/Test Files in `NetAlly/` Root Are Part of the Deployed Package
**Files:**
- `NetAlly/debug_bf.py` — Batfish debug script with direct Batfish queries
- `NetAlly/test_scan_sync.py` — Live NSO scan test script
- `NetAlly/init_batfish.py` — Initialization script (not a test, but not behind auth)

**Issue:** These files sit in the same directory as `main.py` and are importable/runnable in the deployed container. `debug_bf.py` dumps raw Batfish query column data. `test_scan_sync.py` prints full NSO device inventory. Neither is needed in production.

**Fix:** Move debug/test scripts to `NetAlly/tests/` or delete them. Add to `.dockerignore`:
```
debug_bf.py
test_scan_sync.py
```

---

### H-5: Legacy `Make_Dataset/src/main.py` Coexists with Active `main_batfish.py`
**File:** `Make_Dataset/src/main.py`

**Issue:** Two entry points exist side-by-side. If `main.py` is legacy (pre-Batfish), it may import deprecated modules or execute unsafe logic when invoked accidentally. The CLAUDE.md pipeline docs only reference `main_batfish.py`.

**Fix:** Confirm `main.py` is dead code and remove it, or add a clear deprecation header and exclude it from the pipeline scripts.

---

## MEDIUM

### M-1: `Evaluation/pipeline_v1/pipeline_2_advanced.py` Sets API Keys via `os.environ` in Source
**File:** `Evaluation/pipeline_v1/pipeline_2_advanced.py:22-24`
```python
os.environ["GOOGLE_CSE_ID"] = "API_key"
os.environ["GOOGLE_API_KEY"] = "API_key"
os.environ["OPENAI_API_KEY"] = "API_key"
```
**Issue:** The literal string `"API_key"` is a placeholder, not a real key (false positive for actual secret). However, this pattern teaches bad practice and would silently override real environment variables if executed. The file is in `Evaluation/` (legacy directory).

**Fix:** Delete the file (it is in a legacy directory) or replace with `os.environ.get(...)` reads only.

---

### M-2: `print()` Statements in Production Agent Code May Leak Internal State
**Files:**
- `NetAlly/agent/tools.py:142,157,223` — prints NSO base_url and node IPs during bootstrap
- `NetAlly/agent/clients/nso.py:1221,1225-1226` — prints registered device list and device info
- `NetAlly/agent/clients/pnetlab.py:996,1013` — prints client initialization info
- `NetAlly/agent/graph.py:339-340` — prints raw question and answer

**Issue:** `print()` in production code bypasses the structured logger and cannot be filtered, rate-limited, or sanitized. Device IPs, topology data, and Q&A content appear in raw stdout/container logs.

**Fix:** Replace all `print()` in `agent/` with `logger.debug()` calls.

---

### M-3: `NetConfigQA3/tests/Danger_vm_ssh/deprecated_provision_ssh.py` and `deprecated_provision_telnet.py`
**Files:** `NetConfigQA3/tests/Danger_vm_ssh/deprecated_provision_*.py`

**Issue:** "deprecated" in the filename but still executable, contain SSH provisioning logic for live network devices, and import `paramiko`. Part of the same `Danger_vm_ssh` directory as C-1.

**Fix:** Delete with the rest of `Danger_vm_ssh/` (see C-1).

---

### M-4: `NetAlly/.env.tailscale` World-Readable
**Permissions:** `644` (group and other can read)

**Issue:** Contains real IPs and credentials (see C-2). Should be `600` (owner-only).

**Fix:**
```bash
chmod 600 NetAlly/.env.tailscale
```

---

## LOW

### L-1: `Make_Dataset/src/4-Config_Push_Telnet.py` Is Untracked and Imports Telnet
**File:** `Make_Dataset/src/4-Config_Push_Telnet.py` (untracked per git status)

**Issue:** Telnet is an insecure protocol. This file appears to push configs via Telnet to live devices. It is untracked (not yet committed), which is good, but if committed it would expand the attack surface.

**Fix:** Do not commit this file. Use SSH for config push (see `1-SSH_Enable.py` which already sets up SSH).

---

### L-2: `Experiment/data/teleQnA/evaluation_tools.py:8` Sets `openai.api_key = " "`
**File:** `Experiment/data/teleQnA/evaluation_tools.py:8`

**Issue:** Sets API key to a single space. Not a real credential, but will cause silent auth failures instead of a clear error. Low severity since this is a legacy experiment file.

---

## Summary Table

| ID | Severity | File | Issue |
|----|----------|------|-------|
| C-1 | CRITICAL | `NetConfigQA3/tests/Danger_vm_ssh/` | Hardcoded root SSH password `pnet` |
| C-2 | CRITICAL | `NetAlly/.env.tailscale` | Real IPs + `admin:admin` committed |
| C-3 | CRITICAL | `NetAlly/main.py:1292,1210` | Unauthenticated credential update API |
| H-1 | HIGH | `scripts/test_connectivity.sh:45` | `eval` with variable expansion |
| H-2 | HIGH | `scripts/setup_*.sh` | `curl \| sh` remote code execution |
| H-3 | HIGH | `scripts/setup_pnetlab_vm.sh:127` | `admin:admin` in echo/logs |
| H-4 | HIGH | `NetAlly/debug_bf.py`, `test_scan_sync.py` | Debug files in production package |
| H-5 | HIGH | `Make_Dataset/src/main.py` | Ambiguous legacy entry point |
| M-1 | MEDIUM | `Evaluation/pipeline_v1/pipeline_2_advanced.py` | `os.environ` key override pattern |
| M-2 | MEDIUM | `NetAlly/agent/tools.py`, `clients/*.py`, `graph.py` | `print()` leaks topology/device data |
| M-3 | MEDIUM | `NetConfigQA3/tests/Danger_vm_ssh/deprecated_*.py` | Deprecated but executable provisioning scripts |
| M-4 | MEDIUM | `NetAlly/.env.tailscale` | File permissions 644 (should be 600) |
| L-1 | LOW | `Make_Dataset/src/4-Config_Push_Telnet.py` | Untracked Telnet config push script |
| L-2 | LOW | `Experiment/data/teleQnA/evaluation_tools.py` | Whitespace API key string |

---

## Immediate Action Checklist

- [ ] **C-1**: `git rm -r NetConfigQA3/tests/Danger_vm_ssh/`
- [ ] **C-2**: Sanitize `.env.tailscale` (replace real IPs/passwords with placeholders), add to `.gitignore`, rotate NSO+PNETLab passwords
- [ ] **C-3**: Add token-based auth guard to `POST /api/settings` and `POST /api/pnetlab/auth`
- [ ] **H-1**: Replace `eval` in `scripts/test_connectivity.sh:45`
- [ ] **M-4**: `chmod 600 NetAlly/.env.tailscale`
- [ ] **H-4**: Add `debug_bf.py` and `test_scan_sync.py` to `.dockerignore`
