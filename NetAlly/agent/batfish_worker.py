#!/usr/bin/env python3
"""Batfish Worker — subprocess로 실행되는 Batfish 도구.

LangGraph event loop과 완전 독립된 프로세스에서 Batfish 함수를 실행.
pybatfish session thread-safety 문제 회피.

Usage:
    python -m agent.batfish_worker <function> <args_json>

    # Examples:
    python -m agent.batfish_worker traceroute '{"src":"p6","dst":"10.0.5.1"}'
    python -m agent.batfish_worker node_failure '{"node":"p5"}'
    python -m agent.batfish_worker link_failure '{"node1":"leaf1","node2":"leaf6","src":"leaf5","dst":"p7"}'
"""

import json
import os
import sys
import time

# Add paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
NETALLY_ROOT = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, NETALLY_ROOT)
sys.path.insert(0, os.path.join(os.path.dirname(NETALLY_ROOT), "Make_Dataset", "src"))

# Load env
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(NETALLY_ROOT, ".env"))
except ImportError:
    pass


def _get_bf_and_builder():
    """Initialize BatfishClient and load snapshot."""
    from agent.tools import get_batfish_client
    bf = get_batfish_client()
    if not bf._builder:
        snap = os.getenv("BATFISH_SNAPSHOT") or os.getenv("BATFISH_NETWORK") or "default"
        bf.load_snapshot(snap)
    if not bf._builder:
        raise RuntimeError("Batfish not initialized")
    return bf, bf._builder


def _unwrap(result):
    """Unwrap AnswerResult to dict."""
    if hasattr(result, 'value'):
        v = result.value
        return v if isinstance(v, dict) else {"result": str(v)}
    if isinstance(result, dict):
        return result
    return {"result": str(result)}


# ─── Functions ───────────────────────────────────────────────────────────────

def traceroute(src: str, dst: str):
    bf, _ = _get_bf_and_builder()
    return bf.traceroute(src=src, dst=dst)


def bgp_sessions(device: str = None):
    bf, _ = _get_bf_and_builder()
    return bf.get_bgp_sessions(device_filter=device)


def route_table(device: str):
    bf, _ = _get_bf_and_builder()
    return bf.get_route_table(device=device)


def reachability(src: str, dst: str, protocol: str = "icmp"):
    bf, _ = _get_bf_and_builder()
    return bf.check_reachability(src=src, dst=dst, protocol=protocol)


def acl_check(src_ip: str, dst_ip: str, dst_port: int = 80):
    _, builder = _get_bf_and_builder()
    return _unwrap(builder.acl_blocking_point(src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port))


def loop_check():
    _, builder = _get_bf_and_builder()
    return _unwrap(builder.loop_detection())


def blackhole_check(dst_prefix: str = "0.0.0.0/0"):
    _, builder = _get_bf_and_builder()
    return _unwrap(builder.blackhole_detection(dst_prefix=dst_prefix))


def waypoint_check(src_ip: str, dst_ip: str, waypoint: str):
    _, builder = _get_bf_and_builder()
    return _unwrap(builder.waypoint_check(src_ip=src_ip, dst_ip=dst_ip, waypoint_node=waypoint))


def link_failure(node1: str, node2: str, src: str = None, dst: str = None):
    _, builder = _get_bf_and_builder()
    return _unwrap(builder.link_failure_impact(
        node1=node1, node2=node2,
        test_src=src, test_dst=dst,
    ))


def multi_link_failure(link1_node1: str, link1_node2: str,
                       link2_node1: str, link2_node2: str,
                       src: str = "", dst: str = ""):
    _, builder = _get_bf_and_builder()
    edges = builder.bf.q.layer3Edges().answer(snapshot=builder.snapshot_name).frame()

    def _find_ifaces(n1, n2):
        for _, row in edges.iterrows():
            h1 = row['Interface'].hostname
            h2 = row['Remote_Interface'].hostname
            if (h1 == n1 and h2 == n2) or (h1 == n2 and h2 == n1):
                return str(row['Interface']), str(row['Remote_Interface'])
        return None, None

    l1i1, l1i2 = _find_ifaces(link1_node1, link1_node2)
    l2i1, l2i2 = _find_ifaces(link2_node1, link2_node2)
    if not l1i1 or not l2i1:
        return {"error": f"Link not found: {link1_node1}-{link1_node2} or {link2_node1}-{link2_node2}"}
    return _unwrap(builder.multi_link_failure_analysis(
        link1_iface1=l1i1, link1_iface2=l1i2,
        link2_iface1=l2i1, link2_iface2=l2i2,
        test_src=src, test_dst=dst,
    ))


def node_failure(node: str):
    _, builder = _get_bf_and_builder()
    return _unwrap(builder.blast_radius_estimation(failed_node=node))


def multi_node_failure(node1: str, node2: str):
    _, builder = _get_bf_and_builder()
    snapshot_name = f"failure_{node1}_{node2}_{int(time.time())}"
    try:
        builder.bf.fork_snapshot(
            base_name=builder.snapshot_name,
            name=snapshot_name,
            deactivate_nodes=[node1, node2],
            overwrite=True,
        )
        from pybatfish.datamodel.flow import HeaderConstraints
        diff = builder.bf.q.differentialReachability().answer(
            snapshot=snapshot_name,
            reference_snapshot=builder.snapshot_name,
        ).frame()
        blocked = set()
        if not diff.empty:
            for _, row in diff.iterrows():
                flow = row.get('Flow')
                if flow:
                    src = getattr(flow, 'srcIp', '?')
                    dst = getattr(flow, 'dstIp', '?')
                    proto = getattr(flow, 'ipProtocol', '?')
                    blocked.add(f"{src} -> {dst} ({proto})")
        blocked = sorted(blocked)
        return {"affected_count": len(blocked), "newly_blocked_flows": blocked}
    finally:
        try:
            builder.bf.delete_snapshot(snapshot_name)
        except Exception:
            pass


def spof_detection():
    _, builder = _get_bf_and_builder()
    return _unwrap(builder.spof_detection())


def find_blocker(src: str, dst: str):
    bf, _ = _get_bf_and_builder()
    result = bf.traceroute(src=src, dst=dst)
    if result.get("error"):
        return result
    path = result.get("path", [])
    disposition = result.get("disposition", "UNKNOWN")
    # Blocking device = last device that tried to forward but failed
    # If not ACCEPTED, the last hop in the path is the blocker
    # (Batfish path only includes reachable hops, not the unreachable destination)
    blocker = path[-1] if path else "unknown"
    return {
        "blocking_device": blocker,
        "disposition": disposition,
        "path": path,
        "path_str": " -> ".join(path) if path else "No path",
        "reachable": disposition == "ACCEPTED",
    }


# ─── Main ────────────────────────────────────────────────────────────────────

FUNCTIONS = {
    "traceroute": traceroute,
    "bgp_sessions": bgp_sessions,
    "route_table": route_table,
    "reachability": reachability,
    "acl_check": acl_check,
    "loop_check": loop_check,
    "blackhole_check": blackhole_check,
    "waypoint_check": waypoint_check,
    "link_failure": link_failure,
    "multi_link_failure": multi_link_failure,
    "node_failure": node_failure,
    "multi_node_failure": multi_node_failure,
    "spof_detection": spof_detection,
    "find_blocker": find_blocker,
}


if __name__ == "__main__":
    # Suppress pybatfish stdout logging — only our JSON goes to stdout
    import logging as _logging
    _logging.basicConfig(level=_logging.WARNING, stream=sys.stderr)
    # Redirect pybatfish's print-based output
    import io
    _real_stdout = sys.stdout
    sys.stdout = io.StringIO()  # capture any stray prints

    def _output(obj):
        """Write JSON to real stdout (not captured StringIO)."""
        _real_stdout.write(json.dumps(obj, ensure_ascii=False, default=str))
        _real_stdout.write("\n")
        _real_stdout.flush()

    if len(sys.argv) < 2:
        _output({"error": "Usage: python -m agent.batfish_worker <function> [args_json]"})
        sys.exit(1)

    func_name = sys.argv[1]
    args_json = sys.argv[2] if len(sys.argv) > 2 else "{}"

    try:
        args = json.loads(args_json)
    except json.JSONDecodeError:
        _output({"error": f"Invalid JSON args: {args_json}"})
        sys.exit(1)

    fn = FUNCTIONS.get(func_name)
    if fn is None:
        _output({"error": f"Unknown function: {func_name}. Available: {list(FUNCTIONS.keys())}"})
        sys.exit(1)

    try:
        result = fn(**args)
        _output(result)
    except Exception as e:
        _output({"error": f"{type(e).__name__}: {e}"})
        sys.exit(0)
