"""
네트워크 Q&A 데이터셋 생성 (LLM 미사용, 순수 규칙 기반)

NOTE:
    Agent 기반 모듈(`Make_Dataset/src/agents/*`)은 현재 메인 파이프라인에서 사용하지 않습니다.
    향후 하이브리드 검증 등이 필요할 때를 대비해 보존만 하고 있습니다.
"""

import argparse
import json
import random
import csv
import re
from collections import defaultdict
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Tuple

from core.parser import UniversalParser
from core.rule_based_generator import RuleBasedGenerator, RuleBasedGeneratorConfig
from core.builder_core import BuilderCore


def _get_all_categories(policies_path: str) -> List[str]:
    """policies.json에서 모든 카테고리 추출"""
    with open(policies_path, 'r', encoding='utf-8') as f:
        policies_data = json.load(f)

    categories = set()
    for policy in policies_data.get("policies", []):
        category = policy.get("category")
        if category:
            categories.add(category)

    return sorted(list(categories))


def _normalize_to_text(value: Any) -> str:
    """간단한 평문화: dict/list/기타를 사람이 읽을 수 있는 문자열로 변환"""
    if value is None:
        return "정보 없음"

    if isinstance(value, (set, tuple)):
        value = list(value)

    if isinstance(value, list):
        if not value:
            return "없음"
        try:
            items = sorted(list({str(x) for x in value}))
        except Exception:
            items = [str(x) for x in value]
        return ", ".join(items)
    if isinstance(value, dict):
        if not value:
            return "없음"
        try:
            pairs = sorted((str(k), str(v)) for k, v in value.items())
        except Exception:
            pairs = [(str(k), str(v)) for k, v in value.items()]
        return ", ".join([f"{k}={v}" for k, v in pairs])
    if isinstance(value, bool):
        return "true" if value else "false"
    text = str(value)
    return text if text else "정보 없음"


def _split_dataset(items: List[Dict[str, Any]], seed: int = 42, shuffle: bool = False) -> Dict[str, List[Dict[str, Any]]]:
    """간단한 8:1:1 분할 (선택적 셔플)"""
    items_copy = list(items)
    if shuffle:
        random.Random(seed).shuffle(items_copy)
    n = len(items_copy)
    n_train = int(n * 0.8)
    n_val = int(n * 0.1)
    train = items_copy[:n_train]
    val = items_copy[n_train:n_train + n_val]
    test = items_copy[n_train + n_val:]
    return {"train": train, "validation": val, "test": test}


TAG_PREFIX = re.compile(r"^\s*\[[^\]]+\]\s*")


def _strip_tag_prefix(q: str) -> str:
    if not isinstance(q, str):
        return str(q)
    return TAG_PREFIX.sub("", q).strip()


def _build_explanation(metric: str, scope: Dict[str, Any], value: Any) -> str:
    scope_pairs = []
    for key, val in sorted((scope or {}).items()):
        if isinstance(val, (list, dict)):
            scope_pairs.append(f"{key}={json.dumps(val, ensure_ascii=False)}")
        else:
            scope_pairs.append(f"{key}={val}")
    scope_str = ", ".join(scope_pairs) if scope_pairs else "global"
    return f"metric `{metric}` on {scope_str} → {_normalize_to_text(value)}"


ANSWER_TYPE_HINT = {
    "boolean": "true/false (소문자)",
    "numeric": "정수 숫자",
    "set": "쉼표로 구분된 항목 목록 (없으면 '없음')",
    "list": "쉼표로 구분된 항목 목록 (없으면 '없음')",
    "map": "키=값 형식 목록 (없으면 '없음')",
    "text": "단답 텍스트 (없으면 '정보 없음')"
}


def _ensure_raw_answer(item: Dict[str, Any], raw_value: Any) -> None:
    """ground_truth 문자열로 변환하기 전 원본 값을 함께 보관"""
    if raw_value is None:
        item["ground_truth_raw"] = None
    elif isinstance(raw_value, (list, dict, set, tuple)):
        if isinstance(raw_value, set):
            raw = sorted(list(raw_value))
        elif isinstance(raw_value, tuple):
            raw = list(raw_value)
        else:
            raw = raw_value
        item["ground_truth_raw"] = raw
    else:
        item["ground_truth_raw"] = raw_value


def _write_csv(rows: List[Dict[str, Any]], csv_path: Path) -> None:
    header = [
        "id", "category", "answer_type", "level",
        "question", "ground_truth", "explanation", "source_files"
    ]
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with open(csv_path, 'w', newline='', encoding='utf-8-sig') as f:
        w = csv.DictWriter(f, fieldnames=header)
        w.writeheader()
        w.writerows(rows)


def main():
    parser = argparse.ArgumentParser(
        description='네트워크 Q&A 데이터셋 생성 (규칙 기반, LLM 비사용)'
    )

    # 기본 인자
    parser.add_argument('--xml-dir', default='data/raw/XML_Data', help='네트워크 설정 XML 파일 디렉토리')
    # 스크립트 위치 기준 기본 경로 설정
    default_policies = str((Path(__file__).resolve().parents[1] / 'policies.json'))
    parser.add_argument('--policies', default=default_policies, help='정책 파일 경로 (JSON)')
    parser.add_argument('--categories', nargs='+', help='생성할 카테고리 목록 (미지정 시 policies.json 전체)')
    parser.add_argument('--output-dir', default='output/logic_only', help='출력 디렉토리')
    parser.add_argument('--no-split', action='store_true', help='train/val/test 분할 없이 단일 리스트로 저장')
    parser.add_argument(
        '--shuffle',
        action='store_true',
        help='train/val/test 분할 시 항목을 무작위로 섞습니다 (기본: 정렬 순서 유지)'
    )

    # 생성 옵션 (참고: 향상 수는 현재 무의미. 전부 규칙 기반 동일 로직으로 생성)
    parser.add_argument('--basic-per-category', type=int, default=0, help='카테고리당 최대 질문 수 제한(0=무제한)')
    parser.add_argument('--verbose', action='store_true', help='상세 출력')

    args = parser.parse_args()

    # 카테고리 결정
    all_categories = _get_all_categories(args.policies)
    target_categories = args.categories or all_categories

    print("=" * 70)
    print("🚀 네트워크 Q&A 데이터셋 생성 (규칙 기반)")
    print("=" * 70)
    print(f"  • XML 디렉토리: {args.xml_dir}")
    print(f"  • 카테고리: {', '.join(target_categories)}")
    print(f"  • 출력 디렉토리: {args.output_dir}")
    print("-" * 70)

    try:
        # 1) XML → Facts 로드
        parser_u = UniversalParser()
        facts = parser_u.parse_dir(args.xml_dir)
        if args.verbose:
            print(f"[DEBUG] Loaded devices: {len(facts.get('devices', []))}")

        # 1-1) Facts 저장
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_dir = Path(args.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        facts_file = out_dir / f"facts_{timestamp}.json"
        with open(facts_file, 'w', encoding='utf-8') as f:
            json.dump(facts, f, ensure_ascii=False, indent=2)
        if args.verbose:
            print(f"[DEBUG] Saved facts: {facts_file}")

        # 2) 정책 → DSL 컴파일 (LLM 미사용)
        rb_cfg = RuleBasedGeneratorConfig(policies_path=args.policies)
        rb = RuleBasedGenerator(rb_cfg)
        dsl = rb.compile(capabilities=facts, categories=target_categories)
        if args.verbose:
            print(f"[DEBUG] DSL items: {len(dsl)}")

        # 3) DSL → 질문/정답 확장 (BuilderCore)
        core = BuilderCore(facts.get("devices", []))
        by_cat = core.expand_from_dsl(dsl)

        # 4) 후처리: ground_truth/explanation/id 재구성
        per_cat: Dict[str, List[Dict[str, Any]]] = {}
        id_counter: defaultdict[Tuple[str, str], int] = defaultdict(int)
        for cat in sorted(by_cat.keys()):
            arr = by_cat[cat]
            keep: List[Dict[str, Any]] = []
            seen_q: set[str] = set()
            arr_sorted = sorted(
                arr,
                key=lambda x: (
                    (x.get("evidence_hint") or {}).get("metric", ""),
                    (x.get("question") or "")
                )
            )
            for t in arr_sorted:
                qa = dict(t)
                evidence = qa.get("evidence_hint") or {}
                metric = evidence.get("metric") or "metric"
                scope = evidence.get("scope") or {}

                if qa.get("question"):
                    qa["question"] = _strip_tag_prefix(qa["question"])

                exp_value = (qa.get("expected_answer") or {}).get("value")
                _ensure_raw_answer(qa, exp_value)
                qa["ground_truth"] = _normalize_to_text(exp_value)
                qa["explanation"] = _build_explanation(metric, scope, exp_value)

                if qa.get("question") and "{host}" in qa["question"]:
                    hosts = []
                    raw_host = scope.get("host")
                    if isinstance(raw_host, str):
                        hosts.append(raw_host)
                    scoped_hosts = scope.get("hosts")
                    if isinstance(scoped_hosts, list):
                        hosts.extend(str(h) for h in scoped_hosts)
                    if not hosts:
                        src_hosts = {Path(f).stem for f in (qa.get("source_files") or []) if f}
                        if src_hosts:
                            hosts = sorted(src_hosts)
                    host_text = ", ".join(hosts) if hosts else "관련"
                    qa["question"] = qa["question"].replace("{host}", host_text)

                hint = ANSWER_TYPE_HINT.get((qa.get("answer_type") or "").lower())
                if hint and qa.get("question") and "[답변 형식:" not in qa["question"]:
                    qa["question"] = f"{qa['question']}\n[답변 형식: {hint}]"

                qtext = (qa.get("question") or "").strip()
                if qtext in seen_q:
                    continue
                seen_q.add(qtext)

                key = (cat, metric)
                id_counter[key] += 1
                qa["id"] = f"{metric.upper()}_{id_counter[key]:04d}"

                qa.pop("test_id", None)
                qa.pop("origin", None)
                qa.pop("expected_answer", None)

                keep.append(qa)

            if args.basic_per_category and args.basic_per_category > 0:
                keep = keep[: args.basic_per_category]
            per_cat[cat] = keep

        # 5) 전체 플랫리스트로 통합 후 정렬 및 전역 중복 제거
        all_items: List[Dict[str, Any]] = []
        for cat in sorted(per_cat.keys()):
            all_items.extend(per_cat[cat])
        all_items.sort(
            key=lambda it: (
                it.get("category", ""),
                (it.get("evidence_hint") or {}).get("metric", ""),
                it.get("question", "")
            )
        )
        seen_global: set[str] = set()
        filtered_items: List[Dict[str, Any]] = []
        for it in all_items:
            q = (it.get("question") or "").strip()
            if q in seen_global:
                continue
            seen_global.add(q)
            filtered_items.append(it)
        all_items = filtered_items

        # 분할 옵션 처리 및 저장
        if args.no_split:
            final_dataset: Any = all_items
            dataset_file = out_dir / f"dataset_logic_only_single_{timestamp}.json"
            with open(dataset_file, 'w', encoding='utf-8') as f:
                json.dump(final_dataset, f, ensure_ascii=False, indent=2)
            total_samples = len(all_items)
        else:
            # 기본은 정렬된 순서를 유지하지만, 필요 시 --shuffle 옵션으로 랜덤 분할 가능
            final_dataset = _split_dataset(all_items, shuffle=args.shuffle)
            dataset_file = out_dir / f"dataset_logic_only_{timestamp}.json"
            with open(dataset_file, 'w', encoding='utf-8') as f:
                json.dump(final_dataset, f, ensure_ascii=False, indent=2)
            total_samples = sum(len(final_dataset.get(split, [])) for split in ("train", "validation", "test"))

        # CSV 변환 수행
        def _iter_rows(ds: Any) -> List[Dict[str, Any]]:
            items: List[Dict[str, Any]] = []
            if isinstance(ds, dict):
                for split_name in ("train", "validation", "test"):
                    for it in ds.get(split_name, []) or []:
                        items.append(it)
            elif isinstance(ds, list):
                items = ds
            rows: List[Dict[str, Any]] = []
            for it in items:
                rows.append({
                    "id": it.get("id"),
                    "category": it.get("category"),
                    "answer_type": it.get("answer_type"),
                    "level": it.get("level"),
                    "question": it.get("question"),
                    "ground_truth": it.get("ground_truth"),
                    "explanation": it.get("explanation"),
                    "source_files": ", ".join(it.get("source_files") or [])
                })
            return rows

        csv_file = out_dir / f"dataset_logic_only_{timestamp}.csv"
        _write_csv(_iter_rows(final_dataset), csv_file)

        # 요약 출력
        print("\n" + "=" * 70)
        print("✅ 완료!")
        print("=" * 70)
        print(f"  • 총 질문 수: {total_samples}개")
        if not args.no_split and isinstance(final_dataset, dict):
            print(f"    - 훈련용: {len(final_dataset.get('train', []))}개")
            print(f"    - 검증용: {len(final_dataset.get('validation', []))}개")
            print(f"    - 테스트용: {len(final_dataset.get('test', []))}개")
        print(f"  • Facts: {facts_file}")
        print(f"  • Dataset(JSON): {dataset_file}")
        print(f"  • Dataset(CSV): {csv_file}")

        return 0

    except Exception as e:
        print(f"\n❌ 오류 발생: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit(main())
