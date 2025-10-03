"""
네트워크 Q&A 데이터셋 생성 (LLM 미사용, 순수 규칙 기반)
"""

import argparse
import json
import random
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List

from parsers.universal_parser import UniversalParser
from generators.rule_based_generator import RuleBasedGenerator, RuleBasedGeneratorConfig
from utils.builder_core import BuilderCore


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
        return ""
    if isinstance(value, list):
        try:
            items = sorted(list({str(x) for x in value}))
        except Exception:
            items = [str(x) for x in value]
        return ", ".join(items)
    if isinstance(value, dict):
        try:
            pairs = sorted((str(k), str(v)) for k, v in value.items())
        except Exception:
            pairs = [(str(k), str(v)) for k, v in value.items()]
        return ", ".join([f"{k}: {v}" for k, v in pairs])
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _split_dataset(items: List[Dict[str, Any]], seed: int = 42) -> Dict[str, List[Dict[str, Any]]]:
    """간단한 8:1:1 분할"""
    rnd = random.Random(seed)
    items_copy = list(items)
    rnd.shuffle(items_copy)
    n = len(items_copy)
    n_train = int(n * 0.8)
    n_val = int(n * 0.1)
    train = items_copy[:n_train]
    val = items_copy[n_train:n_train + n_val]
    test = items_copy[n_train + n_val:]
    return {"train": train, "validation": val, "test": test}


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

    # 생성 옵션 (참고: 향상 수는 현재 무의미. 전부 규칙 기반 동일 로직으로 생성)
    parser.add_argument('--basic-per-category', type=int, default=0, help='카테고리당 최대 질문 수 제한(0=무제한)')
    parser.add_argument('--enhanced-per-category', type=int, default=0, help='[호환용] 미사용, 0으로 두세요')
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

        # 2) 정책 → DSL 컴파일 (LLM 미사용)
        rb_cfg = RuleBasedGeneratorConfig(policies_path=args.policies)
        rb = RuleBasedGenerator(rb_cfg)
        dsl = rb.compile(capabilities=facts, categories=target_categories)
        if args.verbose:
            print(f"[DEBUG] DSL items: {len(dsl)}")

        # 3) DSL → 질문/정답 확장 (BuilderCore)
        core = BuilderCore(facts.get("devices", []))
        by_cat = core.expand_from_dsl(dsl)

        # 4) 후처리: expected_answer.value → ground_truth 로 평문화, id 부여
        per_cat: Dict[str, List[Dict[str, Any]]] = {}
        for cat, arr in by_cat.items():
            keep: List[Dict[str, Any]] = []
            for t in arr:
                qa = dict(t)
                qa["id"] = qa.get("test_id") or qa.get("id")
                exp = (qa.get("expected_answer") or {}).get("value")
                qa["ground_truth"] = _normalize_to_text(exp)
                qa.setdefault("explanation", f"Derived from metric {((qa.get('evidence_hint') or {}).get('metric') or '')}.")
                # 기존 expected_answer 필드는 선택 사항이므로 유지하지 않음 (간결화)
                qa.pop("expected_answer", None)
                keep.append(qa)
            # 카테고리별 최대 개수 제한 (0=무제한)
            if args.basic_per_category and args.basic_per_category > 0:
                keep = keep[: args.basic_per_category]
            per_cat[cat] = keep

        # 5) 전체 플랫리스트로 통합 후 분할
        all_items: List[Dict[str, Any]] = []
        for cat, arr in per_cat.items():
            all_items.extend(arr)

        final_dataset = _split_dataset(all_items)

        # 저장
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_dir = Path(args.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        dataset_file = out_dir / f"dataset_logic_only_{timestamp}.json"
        with open(dataset_file, 'w', encoding='utf-8') as f:
            json.dump(final_dataset, f, ensure_ascii=False, indent=2)

        # 요약 출력
        total_samples = sum(len(final_dataset.get(split, [])) for split in ("train", "validation", "test"))
        print("\n" + "=" * 70)
        print("✅ 완료!")
        print("=" * 70)
        print(f"  • 총 질문 수: {total_samples}개")
        print(f"    - 훈련용: {len(final_dataset.get('train', []))}개")
        print(f"    - 검증용: {len(final_dataset.get('validation', []))}개")
        print(f"    - 테스트용: {len(final_dataset.get('test', []))}개")
        print(f"\n📁 결과 파일: {dataset_file}")

        return 0

    except Exception as e:
        print(f"\n❌ 오류 발생: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit(main())
