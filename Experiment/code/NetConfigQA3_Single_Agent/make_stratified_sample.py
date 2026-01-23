import argparse
import json
import random
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Tuple


def _load_questions(path: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, list):
        return {"questions": data}, data
    if isinstance(data, dict) and "questions" in data and isinstance(data["questions"], list):
        return data, data["questions"]
    if isinstance(data, dict) and "results" in data and isinstance(data["results"], list):
        # allow passing results_agent_*.json by accident
        return {"questions": data["results"]}, data["results"]
    raise ValueError("Unsupported input schema. Expected a list or a dict with key 'questions'.")


def _get_field(row: Dict[str, Any], *keys: str, default: str) -> str:
    for k in keys:
        v = row.get(k)
        if v is not None and str(v).strip() != "":
            return str(v)
    return default


def _summarize(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    levels = Counter(_get_field(r, "level", default="L1") for r in rows)
    types = Counter(_get_field(r, "answer_type", "type", default="text") for r in rows)
    status = Counter(_get_field(r, "status", "answer_status", default="OK") for r in rows)
    return {"n": len(rows), "levels": dict(levels), "answer_type": dict(types), "status": dict(status)}


def stratified_sample(
    rows: List[Dict[str, Any]],
    total: int,
    seed: int,
    types: Optional[List[str]] = None,
    levels: Optional[List[str]] = None,
    min_per_type: int = 0,
    min_per_level: int = 0,
    only_status: Optional[str] = None,
) -> List[Dict[str, Any]]:
    rng = random.Random(seed)

    pool = rows[:]
    rng.shuffle(pool)

    if only_status is not None:
        pool = [r for r in pool if _get_field(r, "status", "answer_status", default="OK") == only_status]

    if types is not None:
        types_set = set(types)
        pool = [r for r in pool if _get_field(r, "answer_type", "type", default="text") in types_set]

    if levels is not None:
        levels_set = set(levels)
        pool = [r for r in pool if _get_field(r, "level", default="L1") in levels_set]

    if total > len(pool):
        raise ValueError(f"Requested total={total} but pool only has n={len(pool)} after filtering.")

    selected: List[Dict[str, Any]] = []
    used_keys = set()

    def take_if_new(r: Dict[str, Any]) -> bool:
        # IMPORTANT: dataset often reuses the same template id across devices
        # (e.g., INTERFACE_STATUS_MAP appears many times). Dedup must be based on
        # the full question text (and id if present), not id alone.
        qid = _get_field(r, "id", "question_id", default="")
        qtext = _get_field(r, "question", "input", default=str(r))
        key = f"{qid}||{qtext}"
        if key in used_keys:
            return False
        used_keys.add(key)
        selected.append(r)
        return True

    # 1) ensure minimum per answer_type
    if min_per_type > 0:
        # count available per type
        by_type = defaultdict(list)
        for r in pool:
            t = _get_field(r, "answer_type", "type", default="text")
            by_type[t].append(r)
        want_types = types if types is not None else sorted(by_type.keys())
        for t in want_types:
            avail = by_type.get(t, [])
            if len(avail) < min_per_type:
                raise ValueError(f"Not enough samples for answer_type='{t}': need {min_per_type}, have {len(avail)}")
            for r in avail:
                if len([x for x in selected if _get_field(x, 'answer_type', 'type', default='text') == t]) >= min_per_type:
                    break
                take_if_new(r)

    # 2) ensure minimum per level (from remaining pool)
    if min_per_level > 0:
        by_level = defaultdict(list)
        for r in pool:
            lvl = _get_field(r, "level", default="L1")
            by_level[lvl].append(r)
        want_lvls = levels if levels is not None else sorted(by_level.keys())
        for lvl in want_lvls:
            avail = by_level.get(lvl, [])
            if len(avail) < min_per_level:
                raise ValueError(f"Not enough samples for level='{lvl}': need {min_per_level}, have {len(avail)}")
            for r in avail:
                if len([x for x in selected if _get_field(x, 'level', default='L1') == lvl]) >= min_per_level:
                    break
                take_if_new(r)

    if len(selected) > total:
        raise ValueError(
            f"Selected {len(selected)} due to constraints but total={total}. "
            f"Reduce min_per_type/min_per_level or increase total."
        )

    # 3) fill the rest uniformly from pool
    for r in pool:
        if len(selected) >= total:
            break
        take_if_new(r)

    if len(selected) != total:
        raise RuntimeError(f"Failed to reach total={total}, got {len(selected)}.")

    return selected


def main():
    ap = argparse.ArgumentParser(description="Create a stratified sample questions JSON for NetConfigQA experiments.")
    ap.add_argument("--input", required=True, help="Path to dataset questions JSON (dict with 'questions' or list).")
    ap.add_argument("--output", required=True, help="Output path for sampled questions JSON.")
    ap.add_argument("--total", type=int, default=200)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--min_per_type", type=int, default=0, help="Minimum samples per answer_type.")
    ap.add_argument("--min_per_level", type=int, default=0, help="Minimum samples per level.")
    ap.add_argument(
        "--types",
        default=None,
        help="Comma-separated answer types to include (e.g., text,number,numeric,set,map). Default: all present.",
    )
    ap.add_argument(
        "--levels",
        default=None,
        help="Comma-separated levels to include (e.g., L1,L2,L3,L4,L5). Default: all present.",
    )
    ap.add_argument(
        "--only_status",
        default="OK",
        help="Filter by status/answer_status (default: OK). Use 'ALL' to disable filtering.",
    )
    args = ap.parse_args()

    base_obj, rows = _load_questions(args.input)
    before = _summarize(rows)

    types = [t.strip() for t in args.types.split(",")] if args.types else None
    levels = [l.strip() for l in args.levels.split(",")] if args.levels else None
    only_status = None if (args.only_status is None or args.only_status.upper() == "ALL") else args.only_status

    sampled = stratified_sample(
        rows=rows,
        total=args.total,
        seed=args.seed,
        types=types,
        levels=levels,
        min_per_type=args.min_per_type,
        min_per_level=args.min_per_level,
        only_status=only_status,
    )

    after = _summarize(sampled)

    out = dict(base_obj)
    out["questions"] = sampled
    out["meta"] = {
        "source": args.input,
        "seed": args.seed,
        "total": args.total,
        "min_per_type": args.min_per_type,
        "min_per_level": args.min_per_level,
        "types": types,
        "levels": levels,
        "only_status": only_status,
        "before": before,
        "after": after,
    }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)

    print("[OK] wrote:", args.output)
    print("[before]", before)
    print("[after ]", after)


if __name__ == "__main__":
    main()


