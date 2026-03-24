#!/usr/bin/env python3
"""
Run a fast Lab-D / L5 probe for multiple models end-to-end.

For each model, this script:
1. Runs `run_eval_vllm_offline.py`
2. Runs `analyze_results.py` on the newest raw result
3. Summarizes truncation / finish_reason / TA-Acc into CSV + Markdown
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import importlib.util
import json
import statistics
import subprocess
import sys
from pathlib import Path


ROOT = Path("/home/kilab_pyj/codespace/GIA")
BASE_DIR = ROOT / "Experiment" / "code" / "NetConfigQA2_2"
EVAL_SCRIPT = BASE_DIR / "run_eval_vllm_offline.py"
ANALYZE_SCRIPT = BASE_DIR / "analyze_results.py"
RESULTS_DIR = BASE_DIR / "results"
DEFAULT_PYTHON = ROOT / "NetAlly" / ".venv" / "bin" / "python"

DEFAULT_MODELS = [
    "Qwen3.5-4B",
    "Qwen3.5-9B",
    "gpt-oss:20b",
    "qwen3-coder:30b-a3b-AWQ",
    "Nemotron-Cascade-2-30B-A3B-AWQ",
    "Foundation-Sec-8B",
]


def load_eval_config():
    spec = importlib.util.spec_from_file_location("run_eval_vllm_offline", EVAL_SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Failed to load {EVAL_SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.Config


def clean_display_name(display_name: str) -> str:
    return display_name.replace(" ", "_").replace("/", "_")


def newest_matching_file(directory: Path, pattern: str, started_at: dt.datetime) -> Path | None:
    candidates = [p for p in directory.glob(pattern) if dt.datetime.fromtimestamp(p.stat().st_mtime) >= started_at]
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)


def run_command(cmd: list[str]) -> None:
    print(f"\n$ {' '.join(cmd)}\n", flush=True)
    subprocess.run(cmd, check=True)


def summarize_probe(raw_file: Path, analyzed_file: Path) -> dict:
    raw_obj = json.loads(raw_file.read_text(encoding="utf-8"))
    analyzed_obj = json.loads(analyzed_file.read_text(encoding="utf-8"))

    results = raw_obj.get("results", [])
    total = len(results)
    trunc_count = sum(1 for r in results if r.get("truncated_flag"))
    length_count = sum(1 for r in results if str(r.get("finish_reason") or "").lower() == "length")
    parseable_count = sum(1 for r in results if r.get("format_parseable"))
    output_tokens = [r.get("output_tokens") for r in results if isinstance(r.get("output_tokens"), int)]

    stats = analyzed_obj.get("stats", {})
    accuracy = stats.get("accuracy")
    by_level = stats.get("by_level", {})
    trad = stats.get("traditional_metrics", {})

    return {
        "model": raw_obj.get("meta", {}).get("model_tag") or raw_obj.get("meta", {}).get("model"),
        "display_model": raw_obj.get("meta", {}).get("model"),
        "lab": raw_obj.get("meta", {}).get("lab"),
        "samples": total,
        "ta_acc": round(float(accuracy) * 100, 2) if accuracy is not None else None,
        "l5_acc": round(float(by_level.get("L5", 0.0)) * 100, 2),
        "truncated_count": trunc_count,
        "truncated_rate": round((trunc_count / total) * 100, 2) if total else 0.0,
        "length_finish_count": length_count,
        "length_finish_rate": round((length_count / total) * 100, 2) if total else 0.0,
        "format_parse_rate": round((parseable_count / total) * 100, 2) if total else 0.0,
        "avg_output_tokens": round(statistics.mean(output_tokens), 2) if output_tokens else None,
        "avg_request_max_tokens": round(
            statistics.mean([r.get("request_max_tokens") for r in results if isinstance(r.get("request_max_tokens"), int)]),
            2,
        ) if results else None,
        "exact_match": round(float(trad.get("exact_match", 0.0)) * 100, 2) if trad.get("exact_match") is not None else None,
        "token_f1": round(float(trad.get("token_f1", 0.0)) * 100, 2) if trad.get("token_f1") is not None else None,
        "raw_file": str(raw_file),
        "analyzed_file": str(analyzed_file),
    }


def write_outputs(rows: list[dict], output_prefix: Path) -> tuple[Path, Path]:
    csv_path = output_prefix.with_suffix(".csv")
    md_path = output_prefix.with_suffix(".md")

    fieldnames = [
        "model",
        "display_model",
        "lab",
        "samples",
        "ta_acc",
        "l5_acc",
        "truncated_count",
        "truncated_rate",
        "length_finish_count",
        "length_finish_rate",
        "format_parse_rate",
        "avg_output_tokens",
        "avg_request_max_tokens",
        "exact_match",
        "token_f1",
        "raw_file",
        "analyzed_file",
    ]

    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    lines = [
        "# Lab D L5 Probe Summary",
        "",
        "| Model | Samples | TA-Acc | L5 Acc | Truncated | Finish=length | Parse Rate | Avg Output Tok | Raw |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    for row in rows:
        lines.append(
            "| {display_model} | {samples} | {ta_acc}% | {l5_acc}% | {truncated_rate}% | "
            "{length_finish_rate}% | {format_parse_rate}% | {avg_output_tokens} | {raw_file} |".format(
                **{
                    **row,
                    "avg_output_tokens": row["avg_output_tokens"] if row["avg_output_tokens"] is not None else "NA",
                }
            )
        )

    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return csv_path, md_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Lab-D L5 probe end-to-end for multiple models.")
    parser.add_argument("--models", nargs="+", default=DEFAULT_MODELS)
    parser.add_argument("--lab", default="D")
    parser.add_argument("--level", default="L5")
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--l4-max-tokens", type=int, default=None)
    parser.add_argument("--l5-max-tokens", type=int, default=8192)
    parser.add_argument("--max-model-len", default="auto")
    parser.add_argument("--gpu-util", type=float, default=0.90)
    parser.add_argument("--python", default=str(DEFAULT_PYTHON))
    args = parser.parse_args()

    py = str(Path(args.python))
    Config = load_eval_config()

    timestamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = RESULTS_DIR / "_probes"
    out_dir.mkdir(parents=True, exist_ok=True)

    rows = []
    for model_key in args.models:
        if model_key not in Config.MODEL_DICT:
            print(f"[WARN] Unknown model tag, skipping: {model_key}")
            continue

        display = Config.MODEL_DICT[model_key]["display"]
        result_dir = RESULTS_DIR / clean_display_name(display) / f"Lab{args.lab.upper()}"
        result_dir.mkdir(parents=True, exist_ok=True)

        started_at = dt.datetime.now()
        eval_cmd = [
            py,
            str(EVAL_SCRIPT),
            "--model", model_key,
            "--lab", args.lab.upper(),
            "--include-levels", args.level.upper(),
            "--limit", str(args.limit),
            "--gpu_util", str(args.gpu_util),
        ]
        if args.max_model_len is not None:
            eval_cmd.extend(["--max-model-len", str(args.max_model_len)])
        if args.l4_max_tokens is not None:
            eval_cmd.extend(["--l4-max-tokens", str(args.l4_max_tokens)])
        if args.l5_max_tokens is not None:
            eval_cmd.extend(["--l5-max-tokens", str(args.l5_max_tokens)])

        run_command(eval_cmd)

        raw_file = newest_matching_file(result_dir, "results_raw_vllm_*.json", started_at)
        if raw_file is None:
            raise RuntimeError(f"Could not find fresh raw result for {model_key} in {result_dir}")

        analyze_cmd = [
            py,
            str(ANALYZE_SCRIPT),
            str(raw_file),
            "--include_levels", args.level.upper(),
        ]
        run_command(analyze_cmd)

        analyzed_file = Path(str(raw_file).replace("results_raw_vllm_", "results_analyzed_vllm_"))
        if not analyzed_file.exists():
            raise RuntimeError(f"Expected analyzed file not found: {analyzed_file}")

        rows.append(summarize_probe(raw_file, analyzed_file))

    output_prefix = out_dir / f"lab{args.lab.lower()}_{args.level.lower()}_probe_{timestamp}"
    csv_path, md_path = write_outputs(rows, output_prefix)

    print("\n" + "=" * 80)
    print("[DONE] Lab D L5 probe finished")
    print(f"CSV: {csv_path}")
    print(f"MD : {md_path}")
    print("=" * 80)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
