"""
tool_dispatch.py — MCP Tool Planning & Execution for agents_netally.

Provides:
- register_tools / get_registered_tools: module-level tool registry
- build_tool_catalog: serialize tool names/descriptions for LLM prompt
- plan_tool_calls: LLM generates tool call plan from question + catalog
- execute_tool_calls: dispatch async MCP tools, collect results
- format_tool_results: format results as structured context text
"""

import asyncio
import json
import re
import time
import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level tool registry (LangGraph state cannot hold function refs)
# ---------------------------------------------------------------------------
_TOOL_REGISTRY: Dict[str, Any] = {}


def register_tools(tools: Dict[str, Any]) -> None:
    """Register MCP tool callables. Called once by team_multi_bridge."""
    _TOOL_REGISTRY.update(tools)
    logger.info(f"Tool registry: {len(_TOOL_REGISTRY)} tools registered")


def get_registered_tools() -> Dict[str, Any]:
    """Get the current tool registry."""
    return dict(_TOOL_REGISTRY)


# ---------------------------------------------------------------------------
# Tool catalog for LLM prompt
# ---------------------------------------------------------------------------
def build_tool_catalog(tools: Dict[str, Any]) -> str:
    """Serialize tool names, descriptions, and parameters into a text catalog."""
    lines = []
    for name, tool_obj in tools.items():
        desc = getattr(tool_obj, 'description', '') or ''
        # Clean up MCP wrapper descriptions
        desc = desc.replace('[MCP] ', '')
        # Extract parameter info
        schema = getattr(tool_obj, 'args_schema', None)
        params_str = ""
        if schema:
            try:
                props = schema.schema().get('properties', {})
                params_str = ", ".join(
                    f"{k}: {v.get('type', 'any')}"
                    for k, v in props.items()
                )
            except Exception:
                pass
        lines.append(f"- {name}({params_str}): {desc}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# LLM-based tool planning
# ---------------------------------------------------------------------------
TOOL_PLANNING_PROMPT = """You are a Network Tool Planner.
Given a network question, select which tools to call to gather the information needed.

AVAILABLE TOOLS:
{tool_catalog}

QUESTION: {question}
QUESTION LEVEL: {level}
{feedback_section}

TOOL SELECTION GUIDE:
- Config queries (hostname, SSH, AAA, VRF, users, timezone, OSPF, BGP AS):
    → nso_get_device_info(device="X") for single device
    → nso_get_all_device_info() for all devices
- Interface details (IP, description, count, status):
    → nso_get_interfaces(device="X") or nso_get_all_interfaces()
- Routing table entries:
    → batfish_route_table(device="X") — NOT nso_get_device_info
- BGP sessions/neighbors/peering:
    → batfish_bgp_sessions() for full mesh analysis
    → nso_get_routing(device="X") for single device BGP config
- Path/reachability (L4):
    → batfish_traceroute(src="X", dst="Y")
    → batfish_reachability(src="X", dst="Y")
- Link failure (L5):
    → batfish_link_failure(node1="X", node2="Y")
- Node failure / blast radius (L5):
    → batfish_node_failure(node="X")
- Single point of failure (L5):
    → batfish_spof_detection()

STRICT RULES:
- Use the ABSOLUTE MINIMUM tools. 1 tool call is ideal, 2-3 max.
- Device names are UPPERCASE: PE1, P2, Leaf3. Always capitalize.
- If Critic feedback is given, focus on gathering the SPECIFIC missing information.

OUTPUT: A JSON array of tool calls. Each element: {{"tool": "<name>", "args": {{...}}}}
Output ONLY the JSON array, nothing else.
"""


TOOL_PLANNING_PROMPT_FAST = """Select tool for this network question. Output ONLY a JSON array.

TOOLS:
{tool_catalog}

QUESTION: {question}
LEVEL: {level}

RULES:
- L1: ONE call to nso_get_device_info(device="<name>"). Extract device name from question.
- L2: ONE call to nso_get_all_device_info() or nso_get_all_interfaces().
- IMPORTANT: Device names in NSO are UPPERCASE (PE1, P2, Leaf3). Always capitalize device names.

Output ONLY the JSON array, nothing else. Example: [{{"tool": "nso_get_device_info", "args": {{"device": "PE1"}}}}]
"""


def plan_tool_calls(
    llm: Any,
    question: str,
    tool_catalog: str,
    level: str = "",
    feedback: str = "",
) -> List[Dict]:
    """Use LLM to generate a tool call plan."""
    # L1/L2 without feedback: use shorter prompt for faster LLM response
    if level in ("L1", "L2") and not feedback:
        prompt = TOOL_PLANNING_PROMPT_FAST.format(
            tool_catalog=tool_catalog,
            question=question,
            level=level,
        )
    else:
        feedback_section = (
            f"CRITIC FEEDBACK (gather this specific info): {feedback}"
            if feedback else ""
        )
        prompt = TOOL_PLANNING_PROMPT.format(
            tool_catalog=tool_catalog,
            question=question,
            level=level or "unknown",
            feedback_section=feedback_section,
        )
    response = llm.invoke(prompt)
    text = response.content if hasattr(response, 'content') else str(response)

    # Strip <think> blocks (reasoning model support)
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
    # Strip markdown code fences
    text = re.sub(r"```json\s*", "", text)
    text = re.sub(r"```\s*", "", text)
    text = text.strip()

    try:
        plans = json.loads(text)
        if isinstance(plans, list):
            return plans
    except json.JSONDecodeError:
        # Try to find JSON array in text
        match = re.search(r'\[.*\]', text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                pass

    logger.warning(f"Tool planning failed to parse: {text[:200]}")
    return []


def _normalize_device_args(plans: List[Dict]) -> List[Dict]:
    """Normalize device names to match NSO registration (PE1, P2, Leaf3, ASBR1)."""
    # prefix → NSO canonical form (uppercase prefix + number)
    PREFIX_MAP = {
        "pe": "PE", "p": "P", "leaf": "Leaf",
        "asbr": "ASBR", "ce": "CE", "fw": "FW",
    }
    for plan in plans:
        args = plan.get("args", {})
        device = args.get("device", "")
        if not device:
            continue
        dl = device.lower()
        for prefix, canonical in sorted(PREFIX_MAP.items(), key=lambda x: -len(x[0])):
            if dl.startswith(prefix):
                suffix = device[len(prefix):]
                args["device"] = canonical + suffix
                break
    return plans


# ---------------------------------------------------------------------------
# Tool execution (sync — no nested event loop issues)
# ---------------------------------------------------------------------------
def execute_tool_calls(
    plans: List[Dict], tools: Dict[str, Any]
) -> List[Dict]:
    """Execute tool calls sequentially using sync invoke-in-thread.

    Avoids nested event loop issues by running each tool in a thread
    with its own asyncio.run(), one at a time.
    """
    if not plans:
        return []

    import concurrent.futures

    def _call_one(plan: Dict) -> Dict:
        tool_name = plan.get("tool", "")
        args = plan.get("args", {})
        tool_fn = tools.get(tool_name)
        if tool_fn is None:
            return {
                "tool": tool_name, "args": args,
                "result": f"ERROR: Unknown tool '{tool_name}'",
                "elapsed_ms": 0,
            }
        start = time.monotonic()
        try:
            # Run async tool in a fresh event loop in a separate thread
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                result = pool.submit(asyncio.run, tool_fn.ainvoke(args)).result(timeout=300)
            elapsed = (time.monotonic() - start) * 1000
            return {
                "tool": tool_name, "args": args,
                "result": result, "elapsed_ms": round(elapsed, 1),
            }
        except Exception as e:
            elapsed = (time.monotonic() - start) * 1000
            logger.error(f"Tool {tool_name} failed: {type(e).__name__}: {e}")
            return {
                "tool": tool_name, "args": args,
                "result": f"ERROR: {type(e).__name__}: {e}",
                "elapsed_ms": round(elapsed, 1),
            }

    return [_call_one(p) for p in plans]


# ---------------------------------------------------------------------------
# Result formatting
# ---------------------------------------------------------------------------
MAX_TOOL_OUTPUT_CHARS = 50000


def format_tool_results(results: List[Dict]) -> str:
    """Format tool results into structured context for downstream agents."""
    blocks = []
    for r in results:
        tool_name = r.get("tool", "unknown")
        args = r.get("args", {})
        result = r.get("result", "")
        args_str = ", ".join(
            f'{k}="{v}"' for k, v in args.items()
        ) if args else ""

        if isinstance(result, str):
            result_str = result
        else:
            result_str = json.dumps(result, ensure_ascii=False, indent=2)

        # Truncate per-tool output
        if len(result_str) > MAX_TOOL_OUTPUT_CHARS:
            result_str = result_str[:MAX_TOOL_OUTPUT_CHARS] + "\n... (truncated)"

        blocks.append(
            f"=== Tool: {tool_name}({args_str}) ===\n"
            f"{result_str}\n"
            f"=== End Tool ==="
        )
    return "\n\n".join(blocks)
