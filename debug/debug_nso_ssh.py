import subprocess
import sys

def run_nso_cmd(cmd):
    bash_script = f'cd ~/ncs-instance && source ~/nso-6.6/ncsrc && echo "{cmd}" | ncs_cli -C -u admin'
    result = subprocess.run(
        ["docker", "exec", "cisco-nso-dev", "bash", "-c", bash_script],
        capture_output=True, text=True
    )
    return result.stdout, result.stderr

print("=== Checking Configuration for P1 ===")
out, err = run_nso_cmd("show running-config devices device P1 | display xml")
print(out)

print("\n=== Attempting Fetch Host Keys ===")
out, err = run_nso_cmd("devices device P1 ssh fetch-host-keys")
print(out)
if err: print("STDERR:", err)

print("\n=== Attempting Connect ===")
out, err = run_nso_cmd("devices device P1 connect")
print(out)
if err: print("STDERR:", err)
