import csv
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List
import json

class DatasetReportGenerator:
    """데이터셋 분석 및 HTML 보고서 생성 (CSV 기반)"""

    def __init__(self, csv_path: str = "output_dataset/dataset_for_evaluation.csv"):
        self.csv_path = Path(csv_path)
        self.output_dir = self.csv_path.parent
        self.report_data: Dict[str, Any] = {}

    def generate_report(self) -> str:
        """종합 보고서 생성"""
        print("📊 데이터셋 보고서 생성 시작...")

        if not self.csv_path.exists():
            print(f"❌ 오류: CSV 파일을 찾을 수 없습니다 - {self.csv_path}")
            return ""

        # [수정] CSV에서 데이터 수집
        self._collect_data_from_csv()

        # HTML 생성
        html_content = self._generate_html()

        # 파일 저장
        report_path = self.output_dir / "dataset_report.html"
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        print(f"✅ 보고서 생성 완료: {report_path}")
        return str(report_path)

    def _collect_data_from_csv(self):
        """[수정] CSV 파일에서 데이터를 읽고 통계를 계산합니다."""
        samples = []
        try:
            with open(self.csv_path, "r", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # level을 정수형으로 변환
                    try:
                        row['level'] = int(row.get('level', 1))
                    except (ValueError, TypeError):
                        row['level'] = 1
                    samples.append(row)
        except Exception as e:
            print(f"❌ CSV 파일 읽기 오류: {e}")
            return

        total_samples = len(samples)
        
        # 통계 계산
        stats = {
            "total_samples": total_samples,
            "generation_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "origin_distribution": self._calculate_distribution(samples, "origin"),
            "complexity_distribution": self._calculate_distribution(samples, "complexity"),
            "persona_distribution": self._calculate_distribution(samples, "persona"),
            "task_category_distribution": self._calculate_distribution(samples, "task_category"),
            "answer_type_distribution": self._calculate_distribution(samples, "answer_type"),
        }
        
        self.report_data = {
            "metadata": stats,
            "samples": samples
        }
        print(f"🔍 {total_samples}개의 샘플을 CSV에서 로드하여 분석했습니다.")

    def _calculate_distribution(self, samples: List[Dict[str, Any]], key: str) -> Dict[str, int]:
        """데이터 분포를 계산하는 헬퍼 함수"""
        distribution = {}
        for sample in samples:
            value = sample.get(key) or "N/A"
            distribution[value] = distribution.get(value, 0) + 1
        return dict(sorted(distribution.items(), key=lambda item: item[1], reverse=True))

    def _generate_html(self) -> str:
        # ... (이하 _generate_html, _get_template, _get_script 함수는 기존 코드와 동일하게 사용 가능합니다)
        # ... 단, self.report_data['samples']가 이제 CSV에서 직접 온 데이터라는 점만 다릅니다.
        # ... 아래 코드는 기존 코드와 거의 동일하게 작동합니다.
        
        metadata = self.report_data.get("metadata", {})
        samples_json = json.dumps(self.report_data.get("samples", []), ensure_ascii=False)
        
        template = self._get_template()
        script = self._get_script()
        
        # 통계 데이터 HTML 테이블 생성
        stats_html = "<ul>"
        for key, value in metadata.items():
            if isinstance(value, dict):
                dist_html = "<ul>" + "".join(f"<li><b>{k}:</b> {v}</li>" for k, v in value.items()) + "</ul>"
                stats_html += f"<li><strong>{key.replace('_', ' ').title()}:</strong>{dist_html}</li>"
            else:
                stats_html += f"<li><strong>{key.replace('_', ' ').title()}:</strong> {value}</li>"
        stats_html += "</ul>"

        return template.format(
            title="네트워크 QA 데이터셋 분석 보고서",
            stats_summary=stats_html,
            total_count=metadata.get("total_samples", 0),
            dataset_json=samples_json,
            script_content=script
        )
        
    def _get_template(self) -> str:
        # 이 함수는 기존 파일의 내용과 동일합니다.
        return """



    
    {title}
    
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 20px; <xt-mark w="background" style="border-bottom: 1px dashed #ff8861 !important">background</xt-mark>-color: #f9f9f9; }}
        /* ... (이하 기존 CSS 스타일) ... */
    


    container">
        📊 {title}
        
            종합 통계
            {stats_summary}
        
        
            데이터 탐색기 (0 / {total_count})
            
    
    
        const DATASET = {dataset_json};
        {script_content}
    


        """

    def _get_script(self) -> str:
        # 이 함수는 기존 파일의 내용과 동일합니다.
        return """
(function() {{
    const state = {{ page: 1, perPage: 10 }};
    const data = DATASET;
    // ... (이하 기존 JavaScript 로직) ...
}})();
        """.replace("{{", "{").replace("}}", "}")

if __name__ == '__main__':
    # 보고서 생성기 실행
    report_generator = DatasetReportGenerator(csv_path="output_dataset/dataset_for_evaluation.csv")
    report_generator.generate_report()