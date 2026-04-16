"""
main_netally.py — NetAlly MAS + MCP 통합 Entry Point
-----------------------------------------------------
팀원 MAS 구조(main_netconfig.py)와 동일한 그래프 구조 + MCP 도구.

파이프라인 (full):
  Collector(+MCP) → Verifier(분기) → Synthesizer → Supporter → Critic
  - Verifier: verifier_status == IRRELEVANT → Collector 재호출 (최대 3회)
  - Critic:   status == REVISE → Synthesizer 재호출 (최대 3회)

ablation:
  "full"        : Collector → Verifier → Synthesizer → Supporter → Critic
  "no_verifier" : Collector → Synthesizer → Supporter → Critic
  "no_critic"   : Collector → Verifier → Synthesizer → END

환경변수:
  NETALLY_TEAM_MULTI_MODULE=agents_netally.main_netally
  NETALLY_AGENT_BACKEND=team_multi_adapter
  NETALLY_MAS_ABLATION=full|no_verifier|no_critic (default: full)
"""

import os
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


def build_graph(ablation: str = None):
    """Build MAS+MCP LangGraph.

    ablation:
        "full"        : 전체 파이프라인 (default)
        "no_verifier" : Verifier 제거
        "no_critic"   : Supporter+Critic 제거
    """
    if ablation is None:
        ablation = os.getenv("NETALLY_MAS_ABLATION", "full")

    workflow = StateGraph(NetAgentState)

    workflow.add_node("Collector", d1.collector_node)
    workflow.add_node("Synthesizer", d1.synthesizer_node)

    if ablation == "no_critic":
        # Collector → Verifier(분기) → Synthesizer → END
        workflow.add_node("Verifier", d1.verifier_node)
        workflow.set_entry_point("Collector")
        workflow.add_edge("Collector", "Verifier")

        def check_verifier_nc(state):
            v_status = state.get("verifier_status", "RELEVANT").upper()
            if v_status == "IRRELEVANT" and state.get("outer_loop_count", 0) < 3:
                return "re_collect"
            return "to_synthesizer"

        workflow.add_conditional_edges(
            "Verifier", check_verifier_nc,
            {"to_synthesizer": "Synthesizer", "re_collect": "Collector"}
        )
        workflow.add_edge("Synthesizer", END)

    elif ablation == "no_verifier":
        # Collector → Synthesizer → Supporter → Critic(분기)
        workflow.add_node("Supporter", d2.supporter_node)
        workflow.add_node("Critic", d2.skeptic_node)
        workflow.set_entry_point("Collector")
        workflow.add_edge("Collector", "Synthesizer")
        workflow.add_edge("Synthesizer", "Supporter")
        workflow.add_edge("Supporter", "Critic")

        def check_debate_nv(state):
            status = state.get("status", "ACCEPT").upper()
            if status == "ACCEPT":
                return "end"
            elif status in ("REVISE", "CONTINUE_DEBATE"):
                return "end" if state.get("inner_turn_count", 0) >= 3 else "revise"
            return "end"

        workflow.add_conditional_edges(
            "Critic", check_debate_nv,
            {"end": END, "revise": "Synthesizer"}
        )

    else:  # "full"
        # Collector → Verifier(분기) → Synthesizer → Supporter → Critic(분기)
        workflow.add_node("Verifier", d1.verifier_node)
        workflow.add_node("Supporter", d2.supporter_node)
        workflow.add_node("Critic", d2.skeptic_node)
        workflow.set_entry_point("Collector")
        workflow.add_edge("Collector", "Verifier")
        workflow.add_edge("Synthesizer", "Supporter")
        workflow.add_edge("Supporter", "Critic")

        def check_verifier_status(state):
            v_status = state.get("verifier_status", "RELEVANT").upper()
            if v_status == "IRRELEVANT" and state.get("outer_loop_count", 0) < 3:
                return "re_collect"
            return "to_synthesizer"

        workflow.add_conditional_edges(
            "Verifier", check_verifier_status,
            {"to_synthesizer": "Synthesizer", "re_collect": "Collector"}
        )

        def check_debate_status(state):
            status = state.get("status", "ACCEPT").upper()
            if status == "ACCEPT":
                return "end"
            elif status in ("REVISE", "CONTINUE_DEBATE"):
                return "end" if state.get("inner_turn_count", 0) >= 3 else "revise"
            return "end"

        workflow.add_conditional_edges(
            "Critic", check_debate_status,
            {"end": END, "revise": "Synthesizer"}
        )

    return workflow.compile()
