"""
Experiment Runner for Exp.4 (Pure MAS) and Exp.5 (NetAlly MAS).

Sends benchmark questions to NetAlly /api/chat endpoint via SSE,
collects answers + tool usage, outputs JSON compatible with analyze_results.py.

Usage:
  # Exp.4 (Pure MAS, no tools)
  NETALLY_TOOL_BACKEND=none python -m eval.experiment_runner \
    --dataset Data/Pnetlab/LabB_.../Dataset/dataset.csv \
    --output results/exp4_pure_mas.json

  # Exp.5 (Full NetAlly with tools)
  python -m eval.experiment_runner \
    --dataset Data/Pnetlab/LabB_.../Dataset/dataset.csv \
    --output results/exp5_netally_mas.json

  # With limit
  python -m eval.experiment_runner --limit 10 --output test.json
"""

import argparse
import asyncio
import csv
import json
import logging
import os
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

@dataclass
class ToolCall:
    name: str
    args: Dict[str, Any] = field(default_factory=dict)
    output: str = ""
    error: str = ""
    latency_ms: float = 0.0

@dataclass
class EvalResult:
    question_id: str
    question: str
    gold: str
    pred: str
    level: str
    answer_type: str
    category: str = ""
    tools_used: List[ToolCall] = field(default_factory=list)
    latency_ms: float = 0.0
    status: str = ""
    llm_calls: int = 0
    steps: int = 0

class ExperimentRunner:
    def __init__(self, base_url: str = "http://localhost:8111",
                 timeout: float = 120.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _parse_sse_line(self, line: str) -> Optional[tuple]:
        """Parse SSE line into (event_type, data_dict)."""
        # Handle 'event: X' and 'data: {...}' lines
        # Return None for empty/comment lines
        line = line.strip()
        if not line or line.startswith(":"):
            return None
        if line.startswith("event:"):
            return ("_event_name", line[6:].strip())
        if line.startswith("data:"):
            raw = line[5:].strip()
            try:
                return ("data", json.loads(raw))
            except json.JSONDecodeError:
                return ("data", {"raw": raw})
        return None

    async def ask(self, question: str, answer_type: str = "") -> dict:
        """Send question to NetAlly /api/chat and collect SSE response."""
        payload = {
            "message": question,
            "answer_type": answer_type,
        }

        answer = ""
        tools = []
        metrics = {}
        current_event = ""
        start = time.monotonic()

        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(self.timeout)) as client:
                async with client.stream(
                    "POST", f"{self.base_url}/api/chat",
                    json=payload,
                    headers={"Accept": "text/event-stream"}
                ) as resp:
                    async for line in resp.aiter_lines():
                        parsed = self._parse_sse_line(line)
                        if parsed is None:
                            continue
                        key, val = parsed
                        if key == "_event_name":
                            current_event = val
                            continue
                        if key == "data":
                            evt_type = val.get("type", current_event)

                            if evt_type == "tool_call":
                                tools.append(ToolCall(
                                    name=val.get("tool", val.get("name", "")),
                                    args=val.get("input", val.get("args", {})),
                                    latency_ms=0.0,
                                ))
                                # Track tool start time
                                tools[-1]._start = time.monotonic()
                            elif evt_type == "tool_output":
                                if tools:
                                    content = val.get("content", val.get("output", ""))
                                    tools[-1].output = str(content)[:500]
                                    # Calculate per-tool latency
                                    if hasattr(tools[-1], '_start'):
                                        tools[-1].latency_ms = (time.monotonic() - tools[-1]._start) * 1000
                            elif evt_type == "tool_error":
                                if tools:
                                    tools[-1].error = val.get("error", "")
                                    if hasattr(tools[-1], '_start'):
                                        tools[-1].latency_ms = (time.monotonic() - tools[-1]._start) * 1000
                            elif evt_type == "answer":
                                answer = val.get("content", "")
                                metrics = val.get("metrics", {})
                            elif evt_type == "error":
                                answer = f"[ERROR] {val.get('message', '')}"
                            elif evt_type == "complete":
                                break
                            # Reset event name after processing data
                            current_event = ""
        except Exception as e:
            answer = f"[CONN_ERROR] {e}"
            logger.error("ask() failed: %s", e)

        elapsed = (time.monotonic() - start) * 1000
        return {
            "answer": answer,
            "tools": tools,
            "latency_ms": elapsed,
            "llm_calls": metrics.get("llm_calls", 0),
            "steps": metrics.get("steps", 0),
        }

    async def run_batch(self, dataset: List[dict],
                        output_path: str,
                        checkpoint_every: int = 10) -> List[dict]:
        """Run all questions sequentially, checkpoint periodically."""
        results = []
        total = len(dataset)
        start_all = time.monotonic()

        for i, row in enumerate(dataset):
            question = row.get("question", "")
            answer_type = row.get("answer_type", "")

            resp = await self.ask(question, answer_type)

            result = EvalResult(
                question_id=row.get("question_id", f"q_{i}"),
                question=question,
                gold=row.get("answer", row.get("gold", "")),
                pred=resp["answer"],
                level=row.get("level", ""),
                answer_type=answer_type,
                category=row.get("category", ""),
                tools_used=resp["tools"],
                latency_ms=resp["latency_ms"],
                status=row.get("status", ""),
                llm_calls=resp["llm_calls"],
                steps=resp["steps"],
            )
            results.append(result)

            # Progress
            elapsed = time.monotonic() - start_all
            rate = (i + 1) / elapsed if elapsed > 0 else 0
            eta = (total - i - 1) / rate if rate > 0 else 0
            logger.info("[%d/%d] %s %.0fms (%.1f req/s, ETA %.0fs)",
                       i + 1, total, result.level, resp["latency_ms"], rate, eta)

            # Checkpoint
            if checkpoint_every and (i + 1) % checkpoint_every == 0:
                self._save(results, output_path, partial=True)
                logger.info("Checkpoint saved: %d results", len(results))

        self._save(results, output_path, partial=False)
        return results

    def _save(self, results: List[EvalResult], path: str, partial: bool = False):
        """Save results in analyze_results.py compatible format + paper-ready metrics."""
        tool_calls_total = sum(len(r.tools_used) for r in results)
        tool_questions = sum(1 for r in results if r.tools_used)
        tool_errors = sum(1 for r in results for t in r.tools_used if t.error)

        # ── Level별 tool 메트릭 (Table 7용) ──
        by_level: Dict[str, dict] = {}
        for r in results:
            lv = r.level or "unknown"
            if lv not in by_level:
                by_level[lv] = {"questions": 0, "with_tools": 0, "tool_count": 0,
                                "tool_errors": 0, "total_latency": 0.0}
            bl = by_level[lv]
            bl["questions"] += 1
            bl["total_latency"] += r.latency_ms
            if r.tools_used:
                bl["with_tools"] += 1
                bl["tool_count"] += len(r.tools_used)
                bl["tool_errors"] += sum(1 for t in r.tools_used if t.error)

        level_metrics = {}
        for lv, bl in sorted(by_level.items()):
            q = bl["questions"]
            tc = bl["tool_count"]
            level_metrics[lv] = {
                "questions": q,
                "tool_call_rate": bl["with_tools"] / q if q else 0,
                "avg_tools_per_question": tc / q if q else 0,
                "tool_success_rate": (tc - bl["tool_errors"]) / tc if tc else 1.0,
                "avg_latency_ms": bl["total_latency"] / q if q else 0,
            }

        # ── Tool별 빈도/성능 (Table 8용) ──
        tool_freq: Dict[str, dict] = {}
        for r in results:
            for t in r.tools_used:
                if t.name not in tool_freq:
                    tool_freq[t.name] = {"calls": 0, "errors": 0, "total_latency": 0.0}
                tf = tool_freq[t.name]
                tf["calls"] += 1
                if t.error:
                    tf["errors"] += 1
                tf["total_latency"] += t.latency_ms

        tool_frequency = {}
        for name, tf in sorted(tool_freq.items(), key=lambda x: -x[1]["calls"]):
            c = tf["calls"]
            tool_frequency[name] = {
                "calls": c,
                "success_rate": (c - tf["errors"]) / c if c else 1.0,
                "avg_latency_ms": tf["total_latency"] / c if c else 0,
            }

        output = {
            "meta": {
                "model": os.getenv("NETALLY_EXECUTOR_LLM_MODEL", "unknown"),
                "model_tag": os.getenv("NETALLY_EXECUTOR_LLM_MODEL", "unknown"),
                "backend": f"netally_{'pure_mas' if os.getenv('NETALLY_TOOL_BACKEND') == 'none' else 'mas'}",
                "lab": self._detect_lab(results),
                "total_samples": len(results),
                "partial": partial,
                "tool_metrics": {
                    "total_tool_calls": tool_calls_total,
                    "questions_with_tools": tool_questions,
                    "tool_call_rate": tool_questions / len(results) if results else 0,
                    "tool_error_count": tool_errors,
                    "tool_success_rate": (tool_calls_total - tool_errors) / tool_calls_total if tool_calls_total else 1.0,
                    "avg_latency_ms": sum(r.latency_ms for r in results) / len(results) if results else 0,
                },
                "by_level": level_metrics,
                "by_tool": tool_frequency,
            },
            "results": [
                {
                    "question_id": r.question_id,
                    "question": r.question,
                    "gold": r.gold,
                    "pred": r.pred,
                    "level": r.level,
                    "answer_type": r.answer_type,
                    "category": r.category,
                    "status": r.status,
                    "tools_used": [asdict(t) for t in r.tools_used],
                    "latency_ms": r.latency_ms,
                    "llm_calls": r.llm_calls,
                    "steps": r.steps,
                }
                for r in results
            ],
        }

        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(output, f, ensure_ascii=False, indent=2)

    @staticmethod
    def _detect_lab(results):
        """Detect lab name from question_ids or dataset path."""
        for r in results:
            qid = r.question_id or ""
            for lab in ["LabA", "LabB", "LabC", "LabD",
                        "Lab-A", "Lab-B", "Lab-C", "Lab-D"]:
                if lab.lower().replace("-", "") in qid.lower().replace("-", ""):
                    return lab.replace("-", "")
        return "unknown"


def load_dataset(path: str, limit: int = 0) -> List[dict]:
    """Load CSV or JSON dataset."""
    p = Path(path)
    if p.suffix == ".csv":
        with open(p, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
    elif p.suffix == ".json":
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
            rows = data if isinstance(data, list) else data.get("results", data.get("questions", []))
    else:
        raise ValueError(f"Unsupported format: {p.suffix}")

    if limit > 0:
        rows = rows[:limit]
    return rows


async def main():
    parser = argparse.ArgumentParser(description="NetAlly Experiment Runner (Exp.4/5)")
    parser.add_argument("--dataset", required=True, help="Dataset CSV or JSON path")
    parser.add_argument("--output", required=True, help="Output JSON path")
    parser.add_argument("--base-url", default="http://localhost:8111")
    parser.add_argument("--limit", type=int, default=0, help="Limit number of questions")
    parser.add_argument("--timeout", type=float, default=120.0, help="Per-question timeout (sec)")
    parser.add_argument("--checkpoint", type=int, default=10, help="Save every N questions")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    dataset = load_dataset(args.dataset, args.limit)
    logger.info("Loaded %d questions from %s", len(dataset), args.dataset)

    runner = ExperimentRunner(base_url=args.base_url, timeout=args.timeout)

    # Health check
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.get(f"{args.base_url}/api/health")
            logger.info("Health: %s", r.json())
    except Exception as e:
        logger.warning("Health check failed: %s — continuing anyway", e)

    results = await runner.run_batch(dataset, args.output, args.checkpoint)

    logger.info("Done: %d results saved to %s", len(results), args.output)

    # Summary
    by_level = {}
    for r in results:
        by_level.setdefault(r.level, []).append(r)
    for level in sorted(by_level):
        items = by_level[level]
        tool_rate = sum(1 for r in items if r.tools_used) / len(items)
        avg_lat = sum(r.latency_ms for r in items) / len(items)
        print(f"  {level}: {len(items)} questions, tool_rate={tool_rate:.0%}, avg_latency={avg_lat:.0f}ms")


if __name__ == "__main__":
    asyncio.run(main())
