"""
main_single_mcp.py — Single LLM + MCP 도구 (debate 없음)
---------------------------------------------------------
Ablation 실험용: MAS 구조 없이 LLM 1개가 도구를 호출하여 직접 답변.
MCP 도구의 기여를 MAS와 분리하기 위한 실험.

그래프: Collector(도구 선택+호출) → PassThrough(raw→passage) → Synthesizer(답변) → END
- Verifier, Supporter, Skeptic 없음
- debate/검증 루프 없음
"""

import sys
from pathlib import Path
from langgraph.graph import StateGraph, END

CURRENT_DIR = Path(__file__).resolve().parent
NETALLY_ROOT = CURRENT_DIR.parent
for p in [str(NETALLY_ROOT), str(CURRENT_DIR)]:
    if p not in sys.path:
        sys.path.append(p)

from agents_netally.state import NetAgentState
from agents_netally.model_loader import init_models
import agents_netally.debate1 as d1


def _pass_through(state: NetAgentState) -> dict:
    """Verifier 대체: raw_data를 current_passage로 그대로 전달."""
    raw = state.get("raw_data", "").strip()
    return {"current_passage": raw}


def build_graph():
    """Build Single LLM + MCP graph (no debate)."""
    workflow = StateGraph(NetAgentState)

    workflow.add_node("Collector", d1.collector_node)
    workflow.add_node("PassThrough", _pass_through)
    workflow.add_node("Synthesizer", d1.synthesizer_node)

    workflow.set_entry_point("Collector")
    workflow.add_edge("Collector", "PassThrough")
    workflow.add_edge("PassThrough", "Synthesizer")
    workflow.add_edge("Synthesizer", END)

    return workflow.compile()
