"""
policies.json을 CSV 형식으로 변환하는 스크립트

출력 CSV 컬럼:
- level: L1~L5
- category: 카테고리명
- metric: 메트릭 ID
- goal: extraction, compliance, consistency 등
- target: DEVICE, GLOBAL, FLOW 등
- notes: 비고/설명
- academic_reference: 학술적 근거 (L4/L5)
"""

import json
import csv
from pathlib import Path


def policies_to_csv(json_path: str, csv_path: str):
    """
    policies.json 파일을 읽어 메트릭 목록 CSV로 변환합니다.
    
    Args:
        json_path: policies.json 파일 경로
        csv_path: 출력 CSV 파일 경로
    """
    print(f"📖 {json_path} 로딩 중...")
    
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    policies = data.get("policies", [])
    
    # CSV 헤더 정의
    header = [
        "level", "category", "metric", "goal", "target", 
        "notes", "academic_reference"
    ]
    
    rows = []
    
    for policy in policies:
        category = policy.get("category", "")
        levels = policy.get("levels", {})
        
        for level, items in levels.items():
            for item in items:
                metric = item.get("primary_metric", "")
                goal = item.get("goal", "")
                targets = item.get("targets", [])
                target_str = ", ".join(targets) if isinstance(targets, list) else str(targets)
                notes = item.get("notes", "")
                academic_ref = item.get("academic_reference", "")
                
                rows.append({
                    "level": level,
                    "category": category,
                    "metric": metric,
                    "goal": goal,
                    "target": target_str,
                    "notes": notes,
                    "academic_reference": academic_ref
                })
    
    # CSV 파일 저장
    output_path = Path(csv_path)
    output_path.parent.mkdir(exist_ok=True, parents=True)
    
    with open(output_path, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=header)
        writer.writeheader()
        writer.writerows(rows)
    
    # 통계 출력
    level_counts = {}
    for row in rows:
        lvl = row["level"]
        level_counts[lvl] = level_counts.get(lvl, 0) + 1
    
    print(f"\n✅ CSV 변환 완료! {len(rows)}개 메트릭이 저장되었습니다.")
    print(f"📁 출력 파일: {csv_path}")
    print("\n📊 레벨별 메트릭 수:")
    for lvl in sorted(level_counts.keys()):
        print(f"   {lvl}: {level_counts[lvl]}개")


if __name__ == '__main__':
    # 기본 경로 설정
    script_dir = Path(__file__).parent
    json_path = script_dir / "policies.json"
    csv_path = script_dir / "output" / "policies_metrics.csv"
    
    policies_to_csv(str(json_path), str(csv_path))
