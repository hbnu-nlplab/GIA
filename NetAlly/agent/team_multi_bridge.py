"""Bridge utilities for invoking the external MultiAgent stack."""

from __future__ import annotations

import importlib
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple


_GRAPH_CACHE: Dict[Tuple[str, str], Tuple[Any, Any]] = {}
_GRAPH_LOCK = threading.Lock()
_INVOKE_LOCK = threading.Lock()


def _repo_root() -> Path:
    # NetAlly/agent/team_multi_bridge.py -> <repo-root>/NetAlly/agent
    return Path(__file__).resolve().parents[2]


def _resolve_team_root() -> Path:
    raw = str(os.getenv("NETALLY_TEAM_MULTI_ROOT", "")).strip()
    if raw:
        return Path(raw).expanduser().resolve()
    return (_repo_root() / "MultiAgent").resolve()


def _team_module_name() -> str:
    value = str(os.getenv("NETALLY_TEAM_MULTI_MODULE", "agents.main_netconfig")).strip()
    return value or "agents.main_netconfig"


def _team_dataset_type() -> str:
    value = str(os.getenv("NETALLY_TEAM_MULTI_DATASET_TYPE", "netconfig")).strip().lower()
    return value or "netconfig"


def _ensure_team_root_on_path(team_root: Path) -> None:
    team_root_str = str(team_root)
    if team_root_str not in sys.path:
        # Append only. Never prepend, to avoid module shadowing.
        sys.path.append(team_root_str)


def _load_module(team_root: Path, module_name: str) -> Any:
    _ensure_team_root_on_path(team_root)
    # agents_netally lives inside NetAlly/, ensure it's importable
    if "agents_netally" in module_name:
        netally_root = str(Path(__file__).resolve().parents[1])
        if netally_root not in sys.path:
            sys.path.append(netally_root)
    importlib.invalidate_caches()
    return importlib.import_module(module_name)


def _load_cached_graph(team_root: Path, module_name: str) -> Tuple[Any, Any]:
    cache_key = (str(team_root), module_name)
    with _GRAPH_LOCK:
        cached = _GRAPH_CACHE.get(cache_key)
        if cached is not None:
            return cached

        module = _load_module(team_root, module_name)
        init_models = getattr(module, "init_models", None)
        if callable(init_models):
            init_models()

        build_graph = getattr(module, "build_graph", None)
        if not callable(build_graph):
            raise RuntimeError(f"Module '{module_name}' does not define build_graph()")

        app = build_graph()
        _GRAPH_CACHE[cache_key] = (module, app)
        return module, app


def _read_text_if_exists(path: Path) -> str:
    try:
        if path.exists() and path.is_file():
            return path.read_text(encoding="utf-8", errors="ignore").strip()
    except Exception:
        return ""
    return ""


def _history_to_context(history: List[Any]) -> str:
    lines: List[str] = []
    for item in history or []:
        if isinstance(item, Mapping):
            role = str(item.get("role", "user")).strip().lower() or "user"
            content = str(item.get("content", "")).strip()
        else:
            role = str(getattr(item, "role", "user")).strip().lower() or "user"
            content = str(getattr(item, "content", "")).strip()
        if not content:
            continue
        lines.append(f"{role}: {content}")

    if not lines:
        return ""
    return "Conversation history:\n" + "\n".join(lines)


def _resolve_context(
    team_root: Path,
    dataset_type: str,
    request_context: Optional[str],
    history: List[Any],
) -> str:
    if isinstance(request_context, str) and request_context.strip():
        return request_context.strip()

    env_context = str(os.getenv("NETALLY_TEAM_MULTI_CONTEXT", "")).strip()
    if env_context:
        return env_context

    env_context_path = str(os.getenv("NETALLY_TEAM_MULTI_CONTEXT_PATH", "")).strip()
    if env_context_path:
        text = _read_text_if_exists(Path(env_context_path).expanduser().resolve())
        if text:
            return text

    if dataset_type == "netconfig":
        default_cfg = team_root / "data" / "original" / "netconfig" / "configs.txt"
        text = _read_text_if_exists(default_cfg)
        if text:
            return text

    hist_context = _history_to_context(history)
    if hist_context:
        return hist_context

    return "[NONE]"


def _setup_mcp_tools_if_needed(module_name: str) -> str:
    """Register MCP tools and return tool catalog string for agents_netally."""
    if "agents_netally" not in module_name:
        return ""
    try:
        from agent.mcp_tools import CORE_TOOLS
        from agents_netally.tool_dispatch import register_tools, build_tool_catalog
        tool_dict = {t.name: t for t in CORE_TOOLS}
        register_tools(tool_dict)
        catalog = build_tool_catalog(tool_dict)
        return catalog
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(f"MCP tool setup failed: {e}")
        return ""


def _build_initial_state(
    question: str,
    answer_type: str,
    dataset_type: str,
    context: str,
    tool_catalog: str = "",
    level: str = "",
) -> Dict[str, Any]:
    q = question.strip()
    if answer_type and answer_type != "text":
        q = f"{q}\n\n[answer_type={answer_type}]"

    return {
        "question": q,
        "original_passage": "",
        "current_passage": "",
        "gold_answer": "",
        "options": "",
        "dataset_type": dataset_type,
        "context": context,
        "level": level,
        "answer_type": answer_type,
        "round_count": 0,
        "history": [],
        "candidate_answer": "",
        "pro_argument": "",
        "con_argument": "",
        "final_answer": "",
        # MCP tool integration (agents_netally)
        "tool_calls_log": [],
        "tool_results_raw": "",
        "tool_catalog": tool_catalog,
    }


def _extract_answer(output: Any) -> str:
    if isinstance(output, Mapping):
        for key in ("final_answer", "debate2_answer", "answer", "candidate_answer"):
            value = output.get(key)
            if value is not None and str(value).strip():
                return str(value).strip()
    if isinstance(output, str):
        return output.strip()
    return ""


def _preview_output(output: Any) -> Any:
    if isinstance(output, Mapping):
        preview: Dict[str, Any] = {}
        for key in ("final_answer", "candidate_answer", "current_passage"):
            if key in output:
                value = str(output.get(key, "") or "")
                preview[key] = value[:4000]
        if preview:
            return preview
        return dict(output)
    return str(output)


def run_team_multi_query(
    question: str,
    history: Optional[List[Any]] = None,
    answer_type: str = "text",
    *,
    module_name: Optional[str] = None,
    dataset_type: Optional[str] = None,
    context: Optional[str] = None,
    level: str = "",
) -> Dict[str, Any]:
    """Run a single query against the external MultiAgent graph."""
    started_at = time.perf_counter()
    history = history or []
    module_name = module_name or _team_module_name()
    dataset_type = (dataset_type or _team_dataset_type()).strip().lower() or "netconfig"
    team_root = _resolve_team_root()

    if not str(question or "").strip():
        return {
            "ok": False,
            "stage": "validate",
            "error": "Empty question",
            "answer": "",
            "meta": {
                "module_name": module_name,
                "dataset_type": dataset_type,
                "team_root": str(team_root),
                "duration_ms": int((time.perf_counter() - started_at) * 1000),
            },
        }

    try:
        _, app = _load_cached_graph(team_root, module_name)
    except Exception as exc:
        return {
            "ok": False,
            "stage": "load",
            "error": str(exc),
            "answer": "",
            "meta": {
                "module_name": module_name,
                "dataset_type": dataset_type,
                "team_root": str(team_root),
                "duration_ms": int((time.perf_counter() - started_at) * 1000),
            },
        }

    resolved_context = _resolve_context(team_root, dataset_type, context, history)
    tool_catalog = _setup_mcp_tools_if_needed(module_name)
    state = _build_initial_state(
        question=question,
        answer_type=answer_type,
        dataset_type=dataset_type,
        context=resolved_context,
        tool_catalog=tool_catalog,
        level=level,
    )

    try:
        # MultiAgent modules store model instances globally. Serialize invoke for stability.
        with _INVOKE_LOCK:
            output = app.invoke(state)
    except Exception as exc:
        return {
            "ok": False,
            "stage": "invoke",
            "error": str(exc),
            "answer": "",
            "meta": {
                "module_name": module_name,
                "dataset_type": dataset_type,
                "team_root": str(team_root),
                "context_chars": len(resolved_context),
                "duration_ms": int((time.perf_counter() - started_at) * 1000),
            },
        }

    answer = _extract_answer(output)

    # Extract MAS debug info from output state
    mas_debug = {
        "tool_calls_log": output.get("tool_calls_log", []) if isinstance(output, Mapping) else [],
        "outer_loop_count": output.get("outer_loop_count", 0) if isinstance(output, Mapping) else 0,
        "inner_turn_count": output.get("inner_turn_count", 0) if isinstance(output, Mapping) else 0,
        "status": output.get("status", "") if isinstance(output, Mapping) else "",
        "debate_rounds": (
            (output.get("inner_turn_count", 0) if isinstance(output, Mapping) else 0)
            + (output.get("outer_loop_count", 0) if isinstance(output, Mapping) else 0)
        ),
    }

    return {
        "ok": True,
        "stage": "done",
        "answer": answer,
        "result": _preview_output(output),
        "meta": {
            "module_name": module_name,
            "dataset_type": dataset_type,
            "team_root": str(team_root),
            "context_chars": len(resolved_context),
            "duration_ms": int((time.perf_counter() - started_at) * 1000),
            "mas_debug": mas_debug,
        },
    }
