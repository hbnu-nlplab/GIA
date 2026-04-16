"""
main_netally.py — NetAlly MAS + MCP 통합 Entry Point
-----------------------------------------------------
team_multi_bridge.py가 build_graph() + init_models()를 호출.

환경변수:
  NETALLY_TEAM_MULTI_MODULE=agents_netally.main_netally
  NETALLY_AGENT_BACKEND=team_multi_adapter
"""

import sys
from pathlib import Path
from langgraph.graph import StateGraph, END

# Ensure agents_netally and agent are importable
CURRENT_DIR = Path(__file__).resolve().parent
NETALLY_ROOT = CURRENT_DIR.parent
for p in [str(NETALLY_ROOT), str(CURRENT_DIR)]:
    if p not in sys.path:
        sys.path.append(p)

from agents_netally.state import NetAgentState
from agents_netally.model_loader import init_models
import agents_netally.debate1 as d1
import agents_netally.debate2 as d2


def build_graph():
    """Build the 5-agent LangGraph with MCP tool support."""
    workflow = StateGraph(NetAgentState)

    workflow.add_node("Collector", d1.collector_node)
    workflow.add_node("Verifier", d1.verifier_node)
    workflow.add_node("Synthesizer", d1.synthesizer_node)
    workflow.add_node("Supporter", d2.supporter_node)
    workflow.add_node("Skeptic", d2.skeptic_node)

    workflow.set_entry_point("Collector")
    workflow.add_edge("Collector", "Verifier")
    workflow.add_edge("Verifier", "Synthesizer")
    workflow.add_edge("Synthesizer", "Supporter")

    def check_proponent_status(state):
        p_status = state.get("proponent_status", "DEFEND").upper()
        if p_status == "CONCEDE" and state.get("inner_turn_count", 0) < 3:
            return "re_synthesize"
        return "to_skeptic"

    workflow.add_conditional_edges(
        "Supporter", check_proponent_status,
        {"to_skeptic": "Skeptic", "re_synthesize": "Synthesizer"}
    )

    def check_debate_status(state):
        status = state.get("status", "ACCEPT").upper()
        inner = state.get("inner_turn_count", 0)
        outer = state.get("outer_loop_count", 0)

        if status == "ACCEPT":
            return "end"
        elif status == "CONTINUE_DEBATE":
            return "continue_inner" if inner < 2 else "end"
        elif status == "NEED_MORE_INFO":
            return "backtrack_outer" if outer < 2 else "end"
        return "end"

    workflow.add_conditional_edges(
        "Skeptic", check_debate_status,
        {"end": END, "continue_inner": "Supporter", "backtrack_outer": "Collector"}
    )

    return workflow.compile()
