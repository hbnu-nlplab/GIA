#!/usr/bin/env python3
"""실험 결과 통합 분석 (pipeline_v2)

Non-RAG 및 RAG JSON 결과를 입력받아 리치 리포트(Markdown)와 LaTeX 표를 생성합니다.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Dict, List, Tuple


def _load_json(p: str | Path):
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)


def _preprocess_text(text: str) -> str:
    """텍스트 전처리: 마크다운 요소 및 특수 문자 제거"""
    if not isinstance(text, str):
        return str(text)
    
    # 마크다운 볼드 표시 제거 (**text**)
    text = re.sub(r'\*\*(.*?)\*\*', r'\1', text)
    
    # 마크다운 이탤릭 표시 제거 (*text*)
    text = re.sub(r'\*(.*?)\*', r'\1', text)
    
    # 기타 마크다운 요소들 제거
    text = re.sub(r'`(.*?)`', r'\1', text)  # 백틱
    text = re.sub(r'_(.*?)_', r'\1', text)  # 언더스코어
    
    # 여러 공백을 하나로 통합
    text = re.sub(r'\s+', ' ', text)
    
    return text.strip()


def _fmt(x) -> str:
    try:
        # 전처리 후 숫자 변환
        if isinstance(x, str):
            x = _preprocess_text(x)
        return f"{float(x):.4f}"
    except Exception:
        return _preprocess_text(str(x))


def _pick_non_rag(non_rag_path: Path) -> Dict:
    if non_rag_path.is_file():
        return _load_json(non_rag_path)
    cand = sorted(non_rag_path.rglob("*.json"), reverse=True)
    for p in cand:
        try:
            d = _load_json(p)
            if "evaluation" in d and "results" in d:
                return d
        except Exception:
            continue
    raise RuntimeError("Non-RAG JSON을 찾을 수 없습니다.")


def _pick_rag(rag_path: Path) -> Dict:
    if rag_path.is_file():
        return _load_json(rag_path)
    # prefer rag_all_results.json
    f = rag_path / "rag_all_results.json"
    if f.exists():
        return _load_json(f)
    cand = sorted(rag_path.rglob("*.json"), reverse=True)
    for p in cand:
        try:
            d = _load_json(p)
            if "experiments" in d:
                return d
        except Exception:
            continue
    raise RuntimeError("RAG JSON을 찾을 수 없습니다.")


def _collect_rows(non_eval: Dict, rag_exps: Dict) -> Tuple[List[Dict], Dict, Dict]:
    """표 생성용 row 수집 및 '최고 성능' 계산에 필요한 인덱스 반환"""
    rows: List[Dict] = []
    # Non-RAG baseline
    if non_eval:
        overall = non_eval.get("overall", {})
        overall_relaxed = non_eval.get("overall_relaxed", overall)  # fallback to strict if no relaxed
        rows.append(
            {
                "method": "Non-RAG",
                "setting": "-",
                "overall_em": _preprocess_text(str(overall.get("exact_match", 0))),
                "overall_f1": _preprocess_text(str(overall.get("f1_score", 0))),
                "overall_em_relaxed": _preprocess_text(str(overall_relaxed.get("exact_match", 0))),
                "overall_f1_relaxed": _preprocess_text(str(overall_relaxed.get("f1_score", 0))),
                "rule_em": _preprocess_text(str(non_eval["rule_based"]["exact_match"])),
                "enh_gt_em": _preprocess_text(str(non_eval["enhanced_llm"]["ground_truth"]["exact_match"])),
            }
        )
    # RAG variants
    for k, obj in rag_exps.items():
        ev = obj.get("evaluation") or {}
        if not ev:
            continue
        overall = ev.get("overall", {})
        overall_relaxed = ev.get("overall_relaxed", overall)  # fallback to strict if no relaxed
        rows.append(
            {
                "method": "RAG",
                "setting": k.replace("top_k_", "k="),
                "overall_em": _preprocess_text(str(overall.get("exact_match", 0))),
                "overall_f1": _preprocess_text(str(overall.get("f1_score", 0))),
                "overall_em_relaxed": _preprocess_text(str(overall_relaxed.get("exact_match", 0))),
                "overall_f1_relaxed": _preprocess_text(str(overall_relaxed.get("f1_score", 0))),
                "rule_em": _preprocess_text(str(ev["rule_based"]["exact_match"])),
                "enh_gt_em": _preprocess_text(str(ev["enhanced_llm"]["ground_truth"]["exact_match"])),
            }
        )

    # best by EM and F1 (both strict and relaxed)
    best_em = max(rows, key=lambda r: (float(r["overall_em"]), float(r["overall_f1"]))) if rows else None
    best_f1 = max(rows, key=lambda r: (float(r["overall_f1"]), float(r["overall_em"]))) if rows else None
    best_em_relaxed = max(rows, key=lambda r: (float(r["overall_em_relaxed"]), float(r["overall_f1_relaxed"]))) if rows else None
    best_f1_relaxed = max(rows, key=lambda r: (float(r["overall_f1_relaxed"]), float(r["overall_em_relaxed"]))) if rows else None
    baseline = next((r for r in rows if r["method"] == "Non-RAG"), None)

    return rows, {
        "best_em": best_em, 
        "best_f1": best_f1,
        "best_em_relaxed": best_em_relaxed,
        "best_f1_relaxed": best_f1_relaxed
    }, {"baseline": baseline}


def _markdown_report(rows: List[Dict], best: Dict, baseline_info: Dict) -> str:
    lines: List[str] = []
    lines.append("# Experiment Comparison Report (Enhanced)")
    lines.append("")
    # Highlights
    be = best.get("best_em")
    bf = best.get("best_f1")
    ber = best.get("best_em_relaxed")
    bfr = best.get("best_f1_relaxed")
    base = baseline_info.get("baseline")
    lines.append("## 🔎 Highlights")
    if be:
        lines.append(
            f"- Best Overall EM (Strict): {_fmt(be['overall_em'])} (*{be['method']} {be['setting']}*)"
        )
    if bf:
        lines.append(
            f"- Best Overall F1 (Strict): {_fmt(bf['overall_f1'])} (*{bf['method']} {bf['setting']}*)"
        )
    if ber:
        lines.append(
            f"- Best Overall EM (Relaxed): {_fmt(ber['overall_em_relaxed'])} (*{ber['method']} {ber['setting']}*)"
        )
    if bfr:
        lines.append(
            f"- Best Overall F1 (Relaxed): {_fmt(bfr['overall_f1_relaxed'])} (*{bfr['method']} {bfr['setting']}*)"
        )
    if base and be:
        delta_em = float(be["overall_em"]) - float(base["overall_em"]) if base else 0.0
        delta_f1 = float(be["overall_f1"]) - float(base["overall_f1"]) if base else 0.0
        lines.append(
            f"- Gain vs Non-RAG baseline (Strict): EM +{_fmt(delta_em)}, F1 +{_fmt(delta_f1)}"
        )
    if base and ber:
        delta_em_r = float(ber["overall_em_relaxed"]) - float(base["overall_em_relaxed"]) if base else 0.0
        delta_f1_r = float(bfr["overall_f1_relaxed"]) - float(base["overall_f1_relaxed"]) if base else 0.0
        lines.append(
            f"- Gain vs Non-RAG baseline (Relaxed): EM +{_fmt(delta_em_r)}, F1 +{_fmt(delta_f1_r)}"
        )
    lines.append("")

    # Summary table (Markdown) - strict and relaxed
    lines.append("## 📊 Results Table (Strict Evaluation)")
    lines.append("| Method | Setting | Overall EM | Overall F1 | Rule-based EM | Enhanced LLM GT EM |")
    lines.append("|--------|---------|-----------:|-----------:|--------------:|--------------------:|")
    for r in rows:
        m = r["method"]
        s = r["setting"]
        em = _fmt(r["overall_em"]) 
        f1 = _fmt(r["overall_f1"]) 
        rem = _fmt(r["rule_em"]) 
        eh = _fmt(r["enh_gt_em"]) 
        # Bold best cells
        if best.get("best_em") is r:
            em = f"**{em}**"
        if best.get("best_f1") is r:
            f1 = f"**{f1}**"
        lines.append(f"| {m} | {s} | {em} | {f1} | {rem} | {eh} |")

    lines.append("")
    lines.append("## 📊 Results Table (Relaxed Evaluation - Order-insensitive)")
    lines.append("| Method | Setting | Overall EM | Overall F1 | Rule-based EM | Enhanced LLM GT EM |")
    lines.append("|--------|---------|-----------:|-----------:|--------------:|--------------------:|")
    for r in rows:
        m = r["method"]
        s = r["setting"]
        em_r = _fmt(r["overall_em_relaxed"]) 
        f1_r = _fmt(r["overall_f1_relaxed"]) 
        rem = _fmt(r["rule_em"]) 
        eh = _fmt(r["enh_gt_em"]) 
        # Bold best cells for relaxed
        if best.get("best_em_relaxed") is r:
            em_r = f"**{em_r}**"
        if best.get("best_f1_relaxed") is r:
            f1_r = f"**{f1_r}**"
        lines.append(f"| {m} | {s} | {em_r} | {f1_r} | {rem} | {eh} |")

    lines.append("")
    # LaTeX block preview
    lines.append("## 🧪 LaTeX Table (copy-paste ready)")
    latex = _latex_table(rows, best)
    lines.append("```")
    lines.append(latex)
    lines.append("```")
    lines.append("")
    return "\n".join(lines)


def _latex_table(rows: List[Dict], best: Dict) -> str:
    """Non-RAG / RAG 성능 테이블 LaTeX 코드 생성"""
    def b(s: str, cond: bool) -> str:
        return f"\\textbf{{{s}}}" if cond else s

    header = (
        "\\begin{table}[t]\n"
        "\\centering\n"
        "\\caption{Non-RAG vs. RAG Performance (Overall EM/F1).}\n"
        "\\label{tab:rag_nonrag_results}\n"
        "\\begin{tabular}{llcccc}\n"
        "\\hline\n"
        "Method & Setting & Overall EM & Overall F1 & Rule-based EM & Enhanced LLM GT EM \\\\ \n"
        "\\hline\n"
    )
    body_lines: List[str] = []
    be = best.get("best_em")
    bf = best.get("best_f1")
    for r in rows:
        em = _fmt(r["overall_em"]) 
        f1 = _fmt(r["overall_f1"]) 
        rem = _fmt(r["rule_em"]) 
        eh = _fmt(r["enh_gt_em"]) 
        em = b(em, r is be)
        f1 = b(f1, r is bf)
        body_lines.append(
            f"{r['method']} & {r['setting']} & {em} & {f1} & {rem} & {eh} \\\\"  # noqa: E501
        )
    footer = "\\hline\n\\end{tabular}\n\\end{table}"
    return header + "\n".join(body_lines) + "\n" + footer


def main():
    parser = argparse.ArgumentParser(description="Compare experiment results (rich report + LaTeX)")
    parser.add_argument("--non-rag", required=True, help="Non-RAG 결과 JSON 파일 (또는 디렉토리)")
    parser.add_argument("--rag", required=True, help="RAG 결과 JSON 파일 (또는 디렉토리)")
    parser.add_argument("--output", default="comparison_report.md")
    parser.add_argument("--latex-output", default=None, help="LaTeX 표 저장 경로 (미지정 시 output과 동일 basename .tex)")
    args = parser.parse_args()

    non_rag_path = Path(args.non_rag)
    rag_path = Path(args.rag)
    non_rag_data = _pick_non_rag(non_rag_path)
    rag_data = _pick_rag(rag_path)

    non_eval = non_rag_data.get("evaluation", {})
    rag_exps = rag_data.get("experiments", {})

    rows, best, base = _collect_rows(non_eval, rag_exps)
    md = _markdown_report(rows, best, base)

    out_md = Path(args.output)
    out_md.write_text(md, encoding="utf-8")

    # Save LaTeX table separately as file, too
    latex_path = Path(args.latex_output) if args.latex_output else out_md.with_suffix(".tex")
    latex_path.write_text(_latex_table(rows, best), encoding="utf-8")

    print(f"✅ 비교 리포트 저장: {out_md}")
    print(f"✅ LaTeX 표 저장: {latex_path}")


if __name__ == "__main__":
    main()
