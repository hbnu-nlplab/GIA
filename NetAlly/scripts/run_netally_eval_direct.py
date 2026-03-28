#!/usr/bin/env python3
"""
NetAlly Direct Evaluation Runner — Bypass Web Server
-----------------------------------------------------
Calls the MAS LangGraph directly via Python (no SSE, no HTTP).
MCP server must be running on port 8811 for tool calls.

Output format is compatible with analyze_results.py.

Features:
  - Level filtering (--include-levels / --exclude-levels)
  - Format stability measurement per answer_type
  - Retry with backoff (--max-retries, default 3)
  - Level-wise accuracy summary table at completion
  - OpenRouter API key fallback (OPENROUTER_API_KEY -> OPENAI_API_KEY)
  - Optional threaded execution (--max-workers, default 1 = serial)
  - Running accuracy in tqdm progress bar
  - Intermediate stats every 50 questions

Usage:
    python scripts/run_netally_eval_direct.py \
        --dataset /path/to/dataset_en.json \
        --lab Lab-B \
        --limit 10

    # Filter by level
    python scripts/run_netally_eval_direct.py \
        --dataset /path/to/dataset_en.json \
        --include-levels L4 L5

    # Exclude specific levels
    python scripts/run_netally_eval_direct.py \
        --dataset /path/to/dataset_en.json \
        --exclude-levels L6

    # Resume from existing output
    python scripts/run_netally_eval_direct.py \
        --dataset /path/to/dataset_en.json \
        --output results/netally_eval_direct_LabB_20260326_120000.json
"""

import argparse
import asyncio
import json
import logging
import os
import re
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Ensure NetAlly modules are importable
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
NETALLY_ROOT = SCRIPT_DIR.parent
for p in [str(NETALLY_ROOT), str(NETALLY_ROOT / "agents_netally")]:
    if p not in sys.path:
        sys.path.insert(0, p)

# Load .env before any module imports that read env vars
try:
    from dotenv import load_dotenv
    load_dotenv(NETALLY_ROOT / ".env")
except ImportError:
    pass

from langchain_core.callbacks import BaseCallbackHandler
from tqdm import tqdm


# ---------------------------------------------------------------------------
# Token Usage Tracking Callback
# ---------------------------------------------------------------------------

class TokenUsageCallback(BaseCallbackHandler):
    """Accumulates token usage across all LLM calls in a single graph run."""

    def __init__(self):
        super().__init__()
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.total_tokens = 0
        self.llm_calls = 0

    def on_llm_end(self, response, **kwargs):
        """Called after each LLM invocation. Extract token counts."""
        self.llm_calls += 1
        # LangChain ChatOpenAI stores usage in generation info or llm_output
        if hasattr(response, "llm_output") and response.llm_output:
            usage = response.llm_output.get("token_usage", {})
            self.prompt_tokens += usage.get("prompt_tokens", 0)
            self.completion_tokens += usage.get("completion_tokens", 0)
            self.total_tokens += usage.get("total_tokens", 0)
        # Also check generations for usage_metadata (newer LangChain)
        if hasattr(response, "generations"):
            for gen_list in response.generations:
                for gen in gen_list:
                    msg = getattr(gen, "message", None)
                    if msg and hasattr(msg, "usage_metadata") and msg.usage_metadata:
                        um = msg.usage_metadata
                        self.prompt_tokens += getattr(um, "input_tokens", 0)
                        self.completion_tokens += getattr(um, "output_tokens", 0)
                        self.total_tokens += getattr(um, "total_tokens", 0)

    def get_usage(self) -> Dict[str, int]:
        return {
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "llm_calls": self.llm_calls,
        }

# ---------------------------------------------------------------------------
# OpenRouter API key fallback
# ---------------------------------------------------------------------------
if not os.getenv("OPENAI_API_KEY") and os.getenv("OPENROUTER_API_KEY"):
    os.environ["OPENAI_API_KEY"] = os.environ["OPENROUTER_API_KEY"]
    os.environ.setdefault(
        "OPENAI_BASE_URL",
        os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"),
    )

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SAVE_INTERVAL = 20
DEFAULT_RECURSION_LIMIT = 60
DEFAULT_MAX_RETRIES = 3
DEFAULT_RETRY_BACKOFF_SEC = 5
INTERMEDIATE_STATS_INTERVAL = 50
MCP_SERVER_URL = os.getenv("NETALLY_MCP_SERVER_URL", "http://127.0.0.1:8811/mcp")

logger = logging.getLogger("netally_eval_direct")


# ---------------------------------------------------------------------------
# Prediction Cleaning (identical to run_netally_eval.py)
# ---------------------------------------------------------------------------

_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL)
_CODE_BLOCK_RE = re.compile(r"```(?:\w*\n)?(.*?)```", re.DOTALL)
_FINAL_ANSWER_RE = re.compile(
    r"(?:final\s*answer|answer)\s*[:：]\s*", re.IGNORECASE
)
_BOLD_RE = re.compile(r"\*\*(.*?)\*\*")


def clean_prediction(raw: str) -> str:
    """Strip markdown artifacts, think tags, 'Final Answer:' prefixes, etc."""
    if not raw:
        return ""
    text = _THINK_RE.sub("", raw)

    # If the entire answer is wrapped in a single code block, extract inner
    code_blocks = _CODE_BLOCK_RE.findall(text)
    if code_blocks and text.strip().startswith("```"):
        text = code_blocks[0].strip()

    # Remove "Final Answer:" or "Answer:" prefix
    text = _FINAL_ANSWER_RE.sub("", text).strip()

    # Remove bold markers
    text = _BOLD_RE.sub(r"\1", text)

    # Remove leading/trailing quotes if they wrap the whole string
    if len(text) >= 2 and text[0] == text[-1] and text[0] in ("'", '"', "`"):
        text = text[1:-1]

    return text.strip()


# ---------------------------------------------------------------------------
# Format Stability Measurement
# ---------------------------------------------------------------------------

def measure_format_stability(pred: str, answer_type: str) -> Dict[str, Any]:
    """Check if prediction matches expected format for the answer_type."""
    parseable = False
    completeness = 0.0
    at = answer_type.lower()

    if at in ("set_str", "set", "edge_set"):
        try:
            v = json.loads(pred)
            parseable = isinstance(v, list)
            completeness = 1.0 if parseable else 0.0
        except (json.JSONDecodeError, TypeError, ValueError):
            pass
    elif at in ("map_str_str", "map_str_int", "map"):
        try:
            v = json.loads(pred)
            parseable = isinstance(v, dict)
            completeness = 1.0 if parseable else 0.0
        except (json.JSONDecodeError, TypeError, ValueError):
            pass
    elif at in ("number", "scalar_int", "numeric"):
        try:
            float(pred.strip())
            parseable = True
            completeness = 1.0
        except (ValueError, AttributeError):
            pass
    elif at in ("bool", "boolean"):
        parseable = pred.strip().lower() in ("true", "false")
        completeness = 1.0 if parseable else 0.0
    elif at == "path":
        parseable = "->" in pred or "\u2192" in pred or len(pred.split()) == 1
        completeness = 1.0 if parseable else 0.0
    else:  # text, scalar_str
        parseable = bool(pred.strip())
        completeness = 1.0 if parseable else 0.0

    return {"parseable": parseable, "completeness": completeness}


# ---------------------------------------------------------------------------
# Dataset Loading
# ---------------------------------------------------------------------------

def load_dataset(path: str) -> Dict[str, Any]:
    """Load dataset JSON and return the full dict."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if "questions" not in data:
        raise ValueError(f"Dataset missing 'questions' key: {path}")
    return data


# ---------------------------------------------------------------------------
# Resume Support
# ---------------------------------------------------------------------------

def load_existing_results(output_path: str) -> Dict[str, Dict]:
    """Load already-processed question_ids from an existing output file."""
    if not os.path.exists(output_path):
        return {}
    try:
        with open(output_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return {r["question_id"]: r for r in data.get("results", [])}
    except (json.JSONDecodeError, KeyError):
        return {}


# ---------------------------------------------------------------------------
# Save
# ---------------------------------------------------------------------------

def save_output(output_path: str, meta: Dict, results: List[Dict]) -> None:
    """Atomically write results to JSON."""
    tmp_path = output_path + ".tmp"
    payload = {"meta": meta, "results": results}
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    os.replace(tmp_path, output_path)


# ---------------------------------------------------------------------------
# MCP Health Check
# ---------------------------------------------------------------------------

def check_mcp_server() -> bool:
    """Verify MCP server is reachable by listing tools."""
    from agent.mcp_client import MCPClient

    client = MCPClient(server_url=MCP_SERVER_URL)
    try:
        result = asyncio.run(client.health_check())
        if result.get("ok"):
            tool_count = result.get("tool_count", 0)
            logger.info(
                f"MCP server OK: {MCP_SERVER_URL} ({tool_count} tools)"
            )
            return True
        else:
            logger.error(f"MCP health check failed: {result.get('error')}")
            return False
    except Exception as e:
        logger.error(f"MCP server unreachable at {MCP_SERVER_URL}: {e}")
        return False


# ---------------------------------------------------------------------------
# Graph Setup (one-time)
# ---------------------------------------------------------------------------

def setup_graph():
    """Initialize models, register tools, build graph. Returns (graph, tool_catalog).

    Uses DIRECT_TOOLS (bypass MCP HTTP) for faster evaluation.
    Falls back to CORE_TOOLS (MCP proxy) if direct import fails.
    """
    from agents_netally.main_netally import build_graph, init_models
    from agents_netally.tool_dispatch import register_tools, build_tool_catalog

    # 1. Init LLM models
    init_models()

    # 2. Register tools — prefer direct (no HTTP overhead)
    try:
        from agent.direct_tools import DIRECT_TOOLS
        tool_list = DIRECT_TOOLS
        logger.info("Using DIRECT_TOOLS (bypass MCP HTTP)")
    except ImportError:
        from agent.mcp_tools import CORE_TOOLS
        tool_list = CORE_TOOLS
        logger.info("Falling back to CORE_TOOLS (MCP HTTP proxy)")

    tool_dict = {t.name: t for t in tool_list}
    register_tools(tool_dict)

    # 3. Build tool catalog text for LLM prompts
    tool_catalog = build_tool_catalog(tool_dict)

    # 4. Compile LangGraph
    graph = build_graph()

    # 5. Pre-load Batfish snapshot (avoid cold-start on first L4/L5 question)
    try:
        import os
        from agent.clients.batfish import get_batfish_client
        bf = get_batfish_client()
        if not bf._builder:
            snap = os.getenv("BATFISH_SNAPSHOT") or os.getenv("BATFISH_NETWORK") or "default"
            if bf.load_snapshot(snap):
                logger.info(f"Batfish snapshot pre-loaded: {snap}")
            else:
                logger.warning("Batfish snapshot pre-load failed (L4/L5 will auto-load)")
        else:
            logger.info("Batfish snapshot already loaded")
    except Exception as e:
        logger.warning(f"Batfish pre-load skipped: {e}")

    logger.info(
        f"Graph compiled with {len(tool_dict)} tools registered"
    )
    return graph, tool_catalog


# ---------------------------------------------------------------------------
# Build initial state for a single question
# ---------------------------------------------------------------------------

def build_initial_state(
    question: str,
    level: str,
    answer_type: str,
    tool_catalog: str,
) -> Dict[str, Any]:
    """Create the full NetAgentState dict for graph.invoke()."""
    return {
        # 1. Basic input
        "question": question,
        "context": "",  # empty -- tools will fetch
        "dataset_type": "netconfig",
        "options": None,
        "level": level,
        "answer_type": answer_type,
        # 2. Shared agent data
        "raw_data": "",
        "current_passage": "",
        "candidate_answer": "",
        "final_answer": "",
        "debate1_answer": "",
        "proponent_responses": [],
        "critic_feedbacks": [],
        "pro_argument": "",
        "proponent_status": "",
        "con_argument": "",
        # 3. Loop control
        "hop_count": 0,
        "inner_turn_count": 0,
        "outer_loop_count": 0,
        # 4. Debate status
        "status": "",
        "critic_feedback": "",
        "feedback_to_collector": "",
        # 5. History & compat
        "history": [],
        "device_db": {},
        "next_hop_device": None,
        # 6. MCP tool integration
        "tool_calls_log": [],
        "tool_results_raw": "",
        "tool_catalog": tool_catalog,
    }


# ---------------------------------------------------------------------------
# Evaluate a single question
# ---------------------------------------------------------------------------

def evaluate_one(
    graph: Any,
    tool_catalog: str,
    question: str,
    level: str,
    answer_type: str,
    recursion_limit: int = DEFAULT_RECURSION_LIMIT,
    max_retries: int = DEFAULT_MAX_RETRIES,
    retry_backoff_sec: int = DEFAULT_RETRY_BACKOFF_SEC,
) -> Dict[str, Any]:
    """Run graph.invoke() for a single question with retry logic.

    Retries up to *max_retries* times on failure with exponential-ish backoff.
    Returns result dict.
    """
    state = build_initial_state(question, level, answer_type, tool_catalog)
    start = time.perf_counter()
    last_error: Optional[str] = None

    for attempt in range(max_retries):
        try:
            token_cb = TokenUsageCallback()
            output = graph.invoke(
                state,
                config={
                    "recursion_limit": recursion_limit,
                    "callbacks": [token_cb],
                },
            )
            elapsed_ms = int((time.perf_counter() - start) * 1000)

            # Extract answer: prefer final_answer, fallback to candidate_answer
            answer = (
                output.get("final_answer")
                or output.get("candidate_answer", "")
            )
            return {
                "answer": answer,
                "error": None,
                "latency_ms": elapsed_ms,
                "tool_calls_log": output.get("tool_calls_log", []),
                "outer_loop_count": output.get("outer_loop_count", 0),
                "inner_turn_count": output.get("inner_turn_count", 0),
                "status": output.get("status", ""),
                "attempts": attempt + 1,
                "token_usage": token_cb.get_usage(),
            }
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            if attempt < max_retries - 1:
                wait = retry_backoff_sec * (attempt + 1)
                logger.warning(
                    f"Attempt {attempt + 1}/{max_retries} failed: {last_error}. "
                    f"Retrying in {wait}s..."
                )
                time.sleep(wait)

    elapsed_ms = int((time.perf_counter() - start) * 1000)
    return {
        "answer": "",
        "error": last_error,
        "latency_ms": elapsed_ms,
        "tool_calls_log": [],
        "outer_loop_count": 0,
        "inner_turn_count": 0,
        "status": "ERROR",
        "attempts": max_retries,
        "token_usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0, "llm_calls": 0},
    }


# ---------------------------------------------------------------------------
# Intermediate Stats Helper
# ---------------------------------------------------------------------------

def _print_intermediate_stats(
    level_correct: Dict[str, int],
    level_total: Dict[str, int],
    processed: int,
) -> None:
    """Print current accuracy per level every N questions."""
    lines = [f"\n--- Intermediate stats ({processed} questions processed) ---"]
    for lvl in sorted(level_total.keys()):
        total = level_total[lvl]
        correct = level_correct.get(lvl, 0)
        acc = correct / total * 100 if total > 0 else 0.0
        lines.append(f"  {lvl}: {correct}/{total} = {acc:.1f}%")
    overall_total = sum(level_total.values())
    overall_correct = sum(level_correct.values())
    overall_acc = overall_correct / overall_total * 100 if overall_total > 0 else 0.0
    lines.append(f"  OVERALL: {overall_correct}/{overall_total} = {overall_acc:.1f}%")
    lines.append("---")
    print("\n".join(lines))


# ---------------------------------------------------------------------------
# Main Evaluation Loop
# ---------------------------------------------------------------------------

def run_eval(args: argparse.Namespace) -> None:
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
    )

    # 1. Check if direct tools are available (skip MCP check if so)
    use_direct = False
    try:
        from agent.direct_tools import DIRECT_TOOLS  # noqa: F401
        use_direct = True
        logger.info("Direct tools available — skipping MCP server check")
    except ImportError:
        pass

    if not use_direct:
        logger.info("Checking MCP server connectivity...")
        if not check_mcp_server():
            print(
                f"\nERROR: MCP server is not reachable at {MCP_SERVER_URL}\n"
                "Start the MCP server first:\n"
                "  cd NetAlly && python -m agent.mcp_server\n"
                "Or set NETALLY_MCP_SERVER_URL to a running instance.\n"
            )
            sys.exit(1)

    # 2. Load dataset
    dataset = load_dataset(args.dataset)
    questions = dataset["questions"]
    dataset_meta = dataset.get("meta", {})

    # Level filtering
    if args.include_levels:
        include_set = {l.upper() for l in args.include_levels}
        before = len(questions)
        questions = [q for q in questions if q.get("level", "").strip().upper() in include_set]
        logger.info(f"Level include filter ({include_set}): {before} -> {len(questions)}")
    if args.exclude_levels:
        exclude_set = {l.upper() for l in args.exclude_levels}
        before = len(questions)
        questions = [q for q in questions if q.get("level", "").strip().upper() not in exclude_set]
        logger.info(f"Level exclude filter ({exclude_set}): {before} -> {len(questions)}")

    if args.limit and args.limit > 0:
        questions = questions[: args.limit]

    # Derive lab info
    dataset_path = Path(args.dataset)
    lab_folder = dataset_meta.get("lab_folder", dataset_path.parent.parent.name)
    lab_label = args.lab or dataset_meta.get("lab", lab_folder)

    # Output path
    if args.output:
        output_path = args.output
    else:
        results_dir = NETALLY_ROOT / "results"
        results_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = str(
            results_dir / f"netally_eval_direct_{lab_folder}_{ts}.json"
        )

    # Resume
    existing = load_existing_results(output_path)
    if existing:
        print(f"[resume] Found {len(existing)} existing results in {output_path}")

    # 3. Setup graph + tools (one-time)
    logger.info("Initializing MAS graph and MCP tools...")
    graph, tool_catalog = setup_graph()

    # Meta
    start_time = time.time()
    meta: Dict[str, Any] = {
        "model": "NetAlly-MAS+MCP",
        "model_tag": args.model_tag,
        "backend": "netally-direct",
        "lab": lab_label,
        "lab_folder": lab_folder,
        "date": datetime.now().isoformat(),
        "duration_sec": 0,
        "total_samples": len(questions),
        "dataset": dataset_path.name,
        "dataset_path": str(dataset_path),
        "mcp_server_url": MCP_SERVER_URL,
        "recursion_limit": args.recursion_limit,
        "max_retries": args.max_retries,
        "max_workers": args.max_workers,
        "include_levels": args.include_levels,
        "exclude_levels": args.exclude_levels,
    }

    results: List[Dict] = list(existing.values())
    processed_ids = set(existing.keys())
    new_count = 0

    # Helper: simple normalization for correctness check
    def _normalize_for_match(val: str) -> str:
        return val.strip().lower().replace(" ", "")

    # Helper: evaluate one item (used by both serial and threaded paths)
    def _process_item(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        qid = item.get("question_id", item.get("id", ""))
        if not qid:
            qid = f"q_{questions.index(item)}"
        if qid in processed_ids:
            return None

        question_text = item["question"]
        gold = item.get("answer", item.get("gold", ""))
        level = item.get("level", "")
        category = item.get("category", "")
        answer_type = item.get("answer_type", "text")

        resp = evaluate_one(
            graph=graph,
            tool_catalog=tool_catalog,
            question=question_text,
            level=level,
            answer_type=answer_type,
            recursion_limit=args.recursion_limit,
            max_retries=args.max_retries,
            retry_backoff_sec=DEFAULT_RETRY_BACKOFF_SEC,
        )

        raw_pred = resp["answer"]
        pred = clean_prediction(raw_pred)
        error = resp["error"]

        # Format stability measurement
        if error:
            fmt = {"parseable": False, "completeness": 0.0}
        else:
            fmt = measure_format_stability(pred, answer_type)

        # Extract tool names from tool_calls_log
        tool_calls_log = resp.get("tool_calls_log", [])
        tools_used = [
            tc.get("tool", "") for tc in tool_calls_log if isinstance(tc, dict)
        ]

        # Token usage
        token_usage = resp.get("token_usage", {})

        result_entry: Dict[str, Any] = {
            "question_id": qid,
            "question": question_text,
            "gold": str(gold),
            "raw_pred": raw_pred,
            "pred": pred,
            "level": level,
            "category": category,
            "answer_type": answer_type,
            "answer_status": "ERROR" if error else "OK",
            "tools_used": tools_used,
            "tool_count": len(tools_used),
            "latency_ms": resp["latency_ms"],
            "format_parseable": fmt["parseable"],
            "format_completeness": fmt["completeness"],
            "attempts": resp.get("attempts", 1),
            # Token usage
            "prompt_tokens": token_usage.get("prompt_tokens", 0),
            "completion_tokens": token_usage.get("completion_tokens", 0),
            "total_tokens": token_usage.get("total_tokens", 0),
            "llm_calls": token_usage.get("llm_calls", 0),
            # MAS debug info
            "mas_outer_loops": resp.get("outer_loop_count", 0),
            "mas_inner_turns": resp.get("inner_turn_count", 0),
            "mas_tool_calls": tool_calls_log,
            "mas_status": resp.get("status", ""),
        }
        if error:
            result_entry["error"] = error

        return result_entry

    # 4. Evaluation loop
    max_workers = args.max_workers
    if max_workers > 1:
        logger.warning(
            f"--max-workers={max_workers}: MCP async tools may cause issues "
            "with concurrent graph.invoke() calls. Each worker creates its own "
            "event loop via _run_async. Monitor for deadlocks."
        )

    # Tracking for running accuracy
    level_correct: Dict[str, int] = defaultdict(int)
    level_total: Dict[str, int] = defaultdict(int)

    if max_workers <= 1:
        # --- Serial execution (default, safest for MCP) ---
        pbar = tqdm(questions, desc="NetAlly Direct Eval", unit="q")
        for item in pbar:
            qid = item.get("question_id", item.get("id", ""))
            level = item.get("level", "")
            if qid in processed_ids:
                pbar.set_postfix({"status": "skip", "level": level})
                continue

            result_entry = _process_item(item)
            if result_entry is None:
                continue

            results.append(result_entry)
            processed_ids.add(result_entry["question_id"])
            new_count += 1

            # Track running accuracy
            lvl = result_entry["level"]
            level_total[lvl] += 1
            gold_norm = _normalize_for_match(result_entry["gold"])
            pred_norm = _normalize_for_match(result_entry["pred"])
            if gold_norm == pred_norm:
                level_correct[lvl] += 1

            # Running accuracy for progress bar
            total_done = sum(level_total.values())
            total_correct = sum(level_correct.values())
            acc = total_correct / total_done * 100 if total_done > 0 else 0.0
            pbar.set_postfix({
                "qid": str(result_entry["question_id"])[:16],
                "level": lvl,
                "acc": f"{acc:.1f}%",
            })

            # Intermediate save
            if new_count % SAVE_INTERVAL == 0:
                meta["duration_sec"] = round(time.time() - start_time, 1)
                save_output(output_path, meta, results)
                logger.info(
                    f"Checkpoint saved: {new_count} new results "
                    f"({len(results)} total)"
                )

            # Intermediate stats every N questions
            if new_count % INTERMEDIATE_STATS_INTERVAL == 0:
                _print_intermediate_stats(level_correct, level_total, new_count)
    else:
        # --- Threaded execution ---
        pending = [
            item for item in questions
            if (item.get("question_id", item.get("id", "")) or f"q_{questions.index(item)}")
            not in processed_ids
        ]
        logger.info(f"Running {len(pending)} items with {max_workers} workers")

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(_process_item, item): item
                for item in pending
            }
            pbar = tqdm(
                as_completed(futures),
                total=len(futures),
                desc="NetAlly Direct Eval (threaded)",
                unit="q",
            )
            for future in pbar:
                result_entry = future.result()
                if result_entry is None:
                    continue

                results.append(result_entry)
                processed_ids.add(result_entry["question_id"])
                new_count += 1

                lvl = result_entry["level"]
                level_total[lvl] += 1
                gold_norm = _normalize_for_match(result_entry["gold"])
                pred_norm = _normalize_for_match(result_entry["pred"])
                if gold_norm == pred_norm:
                    level_correct[lvl] += 1

                total_done = sum(level_total.values())
                total_correct = sum(level_correct.values())
                acc = total_correct / total_done * 100 if total_done > 0 else 0.0
                pbar.set_postfix({
                    "qid": str(result_entry["question_id"])[:16],
                    "level": lvl,
                    "acc": f"{acc:.1f}%",
                })

                if new_count % SAVE_INTERVAL == 0:
                    meta["duration_sec"] = round(time.time() - start_time, 1)
                    save_output(output_path, meta, results)
                    logger.info(
                        f"Checkpoint saved: {new_count} new results "
                        f"({len(results)} total)"
                    )

                if new_count % INTERMEDIATE_STATS_INTERVAL == 0:
                    _print_intermediate_stats(level_correct, level_total, new_count)

    # Final save — include token usage summary in meta
    meta["duration_sec"] = round(time.time() - start_time, 1)
    meta["date_completed"] = datetime.now().isoformat()
    meta["token_usage_total"] = {
        "prompt_tokens": sum(r.get("prompt_tokens", 0) for r in results),
        "completion_tokens": sum(r.get("completion_tokens", 0) for r in results),
        "total_tokens": sum(r.get("total_tokens", 0) for r in results),
        "llm_calls": sum(r.get("llm_calls", 0) for r in results),
    }
    save_output(output_path, meta, results)

    # --- Level-wise summary table ---
    print(f"\n{'=' * 70}")
    print(f"  NetAlly Direct Evaluation Complete")
    print(f"{'=' * 70}")

    # Build level-wise stats from ALL results (including resumed)
    all_level_stats: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"count": 0, "correct": 0, "total_ms": 0}
    )
    for r in results:
        lvl = r.get("level", "?")
        st = all_level_stats[lvl]
        st["count"] += 1
        st["total_ms"] += r.get("latency_ms", 0)
        if _normalize_for_match(r.get("gold", "")) == _normalize_for_match(r.get("pred", "")):
            st["correct"] += 1

    header = f"  {'Level':<8}| {'Count':>6} | {'Correct':>8} | {'Accuracy':>9} | {'Avg Time':>10}"
    print(header)
    print(f"  {'-' * 8}+{'-' * 8}+{'-' * 10}+{'-' * 11}+{'-' * 12}")
    for lvl in sorted(all_level_stats.keys()):
        st = all_level_stats[lvl]
        cnt = st["count"]
        cor = st["correct"]
        acc = cor / cnt * 100 if cnt > 0 else 0.0
        avg_t = st["total_ms"] / cnt / 1000 if cnt > 0 else 0.0
        print(f"  {lvl:<8}| {cnt:>6} | {cor:>8} | {acc:>8.1f}% | {avg_t:>8.1f}s")

    ok_count = sum(1 for r in results if r["answer_status"] == "OK")
    err_count = sum(1 for r in results if r["answer_status"] == "ERROR")
    ok_results = [r for r in results if r["answer_status"] == "OK"]
    avg_latency = (
        sum(r["latency_ms"] for r in ok_results) / max(ok_count, 1)
    )
    avg_tools = (
        sum(r["tool_count"] for r in ok_results) / max(ok_count, 1)
    )
    avg_outer = (
        sum(r.get("mas_outer_loops", 0) for r in ok_results) / max(ok_count, 1)
    )
    avg_inner = (
        sum(r.get("mas_inner_turns", 0) for r in ok_results) / max(ok_count, 1)
    )

    # Token usage stats
    total_prompt_tokens = sum(r.get("prompt_tokens", 0) for r in results)
    total_completion_tokens = sum(r.get("completion_tokens", 0) for r in results)
    total_all_tokens = sum(r.get("total_tokens", 0) for r in results)
    total_llm_calls = sum(r.get("llm_calls", 0) for r in results)
    avg_tokens_per_q = total_all_tokens / max(len(results), 1)
    avg_llm_calls_per_q = total_llm_calls / max(len(results), 1)

    total_correct = sum(st["correct"] for st in all_level_stats.values())
    total_count = sum(st["count"] for st in all_level_stats.values())
    overall_acc = total_correct / total_count * 100 if total_count > 0 else 0.0

    print(f"  {'-' * 8}+{'-' * 8}+{'-' * 10}+{'-' * 11}+{'-' * 12}")
    print(f"  {'TOTAL':<8}| {total_count:>6} | {total_correct:>8} | {overall_acc:>8.1f}% |")
    print()
    print(f"  Processed (new) : {new_count}")
    print(f"  OK / Error      : {ok_count} / {err_count}")
    print(f"  Avg latency     : {avg_latency:,.0f} ms")
    print(f"  Avg tools/q     : {avg_tools:.1f}")
    print(f"  Avg outer loops : {avg_outer:.1f}")
    print(f"  Avg inner turns : {avg_inner:.1f}")
    print()
    print(f"  --- Token Usage ---")
    print(f"  Total prompt    : {total_prompt_tokens:,}")
    print(f"  Total completion: {total_completion_tokens:,}")
    print(f"  Total tokens    : {total_all_tokens:,}")
    print(f"  Total LLM calls : {total_llm_calls:,}")
    print(f"  Avg tokens/q    : {avg_tokens_per_q:,.0f}")
    print(f"  Avg LLM calls/q : {avg_llm_calls_per_q:.1f}")
    print()
    print(f"  Duration        : {meta['duration_sec']:.1f} sec")
    print(f"  Output          : {output_path}")
    print(f"{'=' * 70}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="NetAlly Direct Eval — bypass web server, call MAS graph directly",
    )
    parser.add_argument(
        "--dataset",
        required=True,
        help="Path to dataset JSON file (must have 'questions' key)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output JSON path (default: auto-generated in results/)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Process only first N questions (0 = all)",
    )
    parser.add_argument(
        "--lab",
        default=None,
        help="Lab label (e.g. 'Lab-B'). Auto-detected if omitted.",
    )
    parser.add_argument(
        "--model-tag",
        default="netally-mas-mcp-direct",
        help="Model tag for result metadata (default: netally-mas-mcp-direct)",
    )
    parser.add_argument(
        "--recursion-limit",
        type=int,
        default=DEFAULT_RECURSION_LIMIT,
        help=f"LangGraph recursion limit (default: {DEFAULT_RECURSION_LIMIT})",
    )
    parser.add_argument(
        "--include-levels",
        nargs="+",
        default=None,
        help="Only include these levels (e.g. --include-levels L4 L5)",
    )
    parser.add_argument(
        "--exclude-levels",
        nargs="+",
        default=None,
        help="Exclude these levels (e.g. --exclude-levels L6)",
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=DEFAULT_MAX_RETRIES,
        help=f"Max retry attempts per question on failure (default: {DEFAULT_MAX_RETRIES})",
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=1,
        help=(
            "Number of parallel workers (default: 1 = serial). "
            "WARNING: MCP async tools may cause issues with >1 workers. "
            "Each worker creates its own event loop."
        ),
    )
    return parser.parse_args()


if __name__ == "__main__":
    run_eval(parse_args())
