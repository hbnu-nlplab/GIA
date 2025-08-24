"""
네트워크 설정 데이터셋 HTML 보고서 생성기
인터랙티브한 시각화와 종합적인 데이터 분석 제공 (경량 버전)
"""
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List
import json
import os


class DatasetReportGenerator:
    """데이터셋 분석 및 HTML 보고서 생성"""

    def __init__(self, output_dir: str = "demo_output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.report_data: Dict[str, Any] = {}

    def generate_report(self) -> str:
        """종합 보고서 생성"""
        print("📊 데이터셋 보고서 생성 시작...")

        # 데이터 수집
        self._collect_data()

        # HTML 생성
        html_content = self._generate_html()

        # 파일 저장
        report_path = self.output_dir / "dataset_report.html"
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        print(f"✅ 보고서 생성 완료: {report_path}")
        return str(report_path)

    def _safe_load_json(self, path: Path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    def _collect_data(self):
        """출력 디렉토리에서 데이터 수집"""
        data: Dict[str, Any] = {}

        # 메타데이터 로드
        metadata_path = self.output_dir / "metadata.json"
        metadata = self._safe_load_json(metadata_path) if metadata_path.exists() else None
        if metadata:
            data["metadata"] = metadata

        # 데이터셋 파일들 로드
        dataset_files = [
            "train.json",
            "validation.json",
            "test.json",
            "basic_dataset.json",
            "enhanced_dataset.json",
            "network_config_qa_dataset.json",
        ]
        data["datasets"] = {}
        for file_name in dataset_files:
            p = self.output_dir / file_name
            if p.exists():
                content = self._safe_load_json(p)
                # 배열 형식만 길이를 카운트
                count = len(content) if isinstance(content, list) else (len(content.get("data", [])) if isinstance(content, dict) else 0)
                data["datasets"][file_name] = {
                    "path": str(p),
                    "exists": True,
                    "count": count,
                    "size": p.stat().st_size,
                    "mtime": p.stat().st_mtime,
                    "sample": (content[0] if isinstance(content, list) and content else None),
                }
            else:
                data["datasets"][file_name] = {"path": str(p), "exists": False, "count": 0}

        # 케이스 파일들 로드 (있다면 개수만)
        cases_dir = self.output_dir / "cases"
        if cases_dir.exists() and cases_dir.is_dir():
            case_files = list(cases_dir.glob("*.json"))
            data["cases"] = {"count": len(case_files), "files": [str(c) for c in case_files]}

        # 파일 목록 생성
        data["file_list"] = self._get_file_list()

        self.report_data = data

    def _get_file_list(self) -> List[Dict[str, Any]]:
        """출력 파일 목록과 정보 생성"""
        files: List[Dict[str, Any]] = []
        for file_path in self.output_dir.rglob("*"):
            if file_path.is_file():
                try:
                    stat = file_path.stat()
                    files.append(
                        {
                            "name": file_path.name,
                            "path": str(file_path),
                            "relpath": str(file_path.relative_to(self.output_dir)),
                            "size": stat.st_size,
                            "mtime": stat.st_mtime,
                            "ext": file_path.suffix.lower(),
                        }
                    )
                except Exception:
                    continue
        return sorted(files, key=lambda x: x["size"], reverse=True)

    def _format_bytes(self, size: int) -> str:
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024 or unit == "GB":
                return f"{size:.0f}{unit}" if unit == "B" else f"{size/1024:.1f}{unit}" if unit == "KB" else f"{size/1024/1024:.1f}{unit}" if unit == "MB" else f"{size/1024/1024/1024:.2f}{unit}"
            size /= 1024
        return f"{size:.1f}B"

    def _generate_html(self) -> str:
        """HTML 보고서 생성"""
        stats = self._calculate_stats()
        samples = self._extract_samples()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        html = f"""
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>GIA-Re 데이터셋 보고서</title>
    <style>
        {self._get_css()}
    </style>
</head>
<body>
    <div class="container">
        {self._generate_header(stats, now)}
        {self._generate_overview(stats)}
        {self._generate_pipeline_section(stats)}
        {self._generate_dataset_section(stats)}
        {self._generate_samples_section(samples)}
        {self._generate_files_section(stats)}
        {self._generate_footer(now)}
    </div>
    {self._generate_scripts(samples)}
</body>
</html>
        """
        return html

    def _get_css(self) -> str:
        """CSS 스타일 (경량, 가독성 중심)"""
        return """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Tahoma,Arial,sans-serif;color:#222;background:#f6f8fb;line-height:1.55}
.container{max-width:1100px;margin:24px auto;padding:0 16px}
.header{background:#ffffff;border:1px solid #e9eef5;border-radius:14px;padding:22px 24px;margin-bottom:18px}
.h-title{font-size:22px;font-weight:700;color:#304153;margin-bottom:6px}
.h-sub{font-size:13px;color:#6b7a90}
.kv{display:flex;flex-wrap:wrap;gap:10px;margin-top:8px}
.kv .tag{font-size:12px;background:#f1f5fb;color:#3c4b61;border:1px solid #e2e8f0;border-radius:999px;padding:6px 10px}
.section{background:#ffffff;border:1px solid #e9eef5;border-radius:14px;padding:18px 18px;margin:14px 0}
.s-title{font-size:16px;font-weight:700;color:#314055;margin-bottom:14px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}
.card{background:#f8fbff;border:1px solid #e1e8f4;border-radius:12px;padding:14px}
.card .num{font-size:24px;font-weight:800;color:#2e5aac}
.card .lbl{font-size:12px;color:#6a7a90;margin-top:2px}
.badge{display:inline-block;padding:4px 8px;border-radius:999px;font-size:11px;border:1px solid #e1e8f4;color:#2f4156;background:#f3f7fd;margin-right:6px}
.badge.ok{background:#e7f7ee;color:#106a37;border-color:#bfe8cf}
.badge.fail{background:#fde8ea;color:#8b1a2b;border-color:#f6c7cd}
.kv-table{width:100%;border-collapse:collapse}
.kv-table th,.kv-table td{border-bottom:1px solid #eef2f7;padding:10px 6px;text-align:left;font-size:13px}
.kv-table th{color:#50637a;font-weight:700;background:#fafcff}
.progress{height:8px;background:#eef3fb;border-radius:6px;overflow:hidden}
.progress > span{display:block;height:100%;background:#2f6ef2}
.q{border:1px solid #e5ecf7;border-radius:10px;padding:12px;margin-bottom:12px;background:#fbfdff}
.q .q-title{font-weight:700;color:#2b3a52;margin-bottom:6px}
.q .meta{font-size:12px;color:#6b7a90;margin-top:6px}
.small{font-size:12px;color:#6b7a90}
.files{width:100%;border-collapse:collapse}
.files th,.files td{border-bottom:1px solid #eef2f7;padding:8px 6px;text-align:left;font-size:13px}
.files th{color:#50637a;background:#fafcff}
.footer{color:#6b7a90;font-size:12px;text-align:center;margin-top:10px}
.filters{display:flex;flex-wrap:wrap;gap:8px;margin:8px 0 12px}
.filters input[type="text"], .filters select{padding:8px 10px;border:1px solid #dbe4f0;border-radius:8px;background:#fff;font-size:13px}
.filters button{padding:8px 12px;border:1px solid #dbe4f0;border-radius:8px;background:#f6f9ff;color:#2e5aac;font-size:13px;cursor:pointer}
.filters button:hover{background:#edf4ff}
.pagination{display:flex;gap:6px;justify-content:center;margin-top:10px}
.pagination button{padding:6px 10px;border:1px solid #dbe4f0;border-radius:8px;background:#fff;cursor:pointer;font-size:13px}
.pagination button.active{background:#2f6ef2;color:#fff;border-color:#2f6ef2}
        """

    def _generate_header(self, stats: Dict[str, Any], now: str) -> str:
        meta = stats.get("meta", {})
        name = meta.get("dataset_name", "GIA-Re Dataset")
        desc = meta.get("description", "네트워크 설정 파악 성능 평가 데이터셋")
        version = meta.get("version", "-")
        return f"""
<div class="header">
  <div class="h-title">{name} <span class="badge">v{version}</span></div>
  <div class="h-sub">{desc}</div>
  <div class="kv">
    <span class="tag">생성: {now}</span>
    <span class="tag">경로: {self.output_dir}</span>
  </div>
</div>
        """

    def _generate_overview(self, stats: Dict[str, Any]) -> str:
        return f"""
<div class="section">
  <div class="s-title">📊 데이터셋 개요</div>
  <div class="grid">
    <div class="card"><div class="num">{stats.get('total_questions', 0)}</div><div class="lbl">총 질문 수</div></div>
    <div class="card"><div class="num">{stats.get('categories_count', 0)}</div><div class="lbl">카테고리 수</div></div>
    <div class="card"><div class="num">{stats.get('device_count', 0)}</div><div class="lbl">네트워크 장비</div></div>
    <div class="card"><div class="num">{stats.get('pipeline_success_rate_pct', '0%')}</div><div class="lbl">파이프라인 성공률</div></div>
    <div class="card"><div class="num">{stats.get('avg_quality_score', '-')}</div><div class="lbl">평균 품질 점수</div></div>
    <div class="card"><div class="num">{stats.get('total_data_size', '-')}</div><div class="lbl">총 데이터 크기</div></div>
  </div>
</div>
        """

    def _generate_pipeline_section(self, stats: Dict[str, Any]) -> str:
        steps = stats.get("pipeline_steps", [])
        items_html = []
        for s in steps:
            badge_cls = "ok" if s.get("success") else "fail"
            detail = s.get("detail", "")
            extra = f"<span class=\"small\">{detail}</span>" if detail else ""
            items_html.append(
                f"<tr><td>{s.get('name')}</td><td><span class=\"badge {badge_cls}\">{'성공' if s.get('success') else '실패'}</span></td><td>{extra}</td></tr>"
            )
        return f"""
<div class="section">
  <div class="s-title">🧩 파이프라인 상태</div>
  <table class="kv-table">
    <thead><tr><th>단계</th><th>상태</th><th>요약</th></tr></thead>
    <tbody>
      {''.join(items_html)}
    </tbody>
  </table>
</div>
        """

    def _generate_dataset_section(self, stats: Dict[str, Any]) -> str:
        train = stats.get("subset_counts", {}).get("train", 0)
        val = stats.get("subset_counts", {}).get("validation", 0)
        test = stats.get("subset_counts", {}).get("test", 0)
        total = max(1, train + val + test)
        w = lambda x: int((x / total) * 100)

        comp = stats.get("complexity_distribution", {})
        comp_rows = "".join(
            f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in comp.items()
        )
        ans = stats.get("answer_type_distribution", {})
        ans_rows = "".join(f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in ans.items())

        return f"""
<div class="section">
  <div class="s-title">🗂 데이터셋 구성</div>
  <div class="grid">
    <div class="card">
      <div class="lbl">Train ({train})</div>
      <div class="progress" title="{train} / {total}"><span style="width:{w(train)}%"></span></div>
    </div>
    <div class="card">
      <div class="lbl">Validation ({val})</div>
      <div class="progress" title="{val} / {total}"><span style="width:{w(val)}%"></span></div>
    </div>
    <div class="card">
      <div class="lbl">Test ({test})</div>
      <div class="progress" title="{test} / {total}"><span style="width:{w(test)}%"></span></div>
    </div>
  </div>

  <div style="height:10px"></div>

  <div class="grid" style="grid-template-columns:1fr 1fr;">
    <div class="card">
      <div class="lbl" style="margin-bottom:6px">복잡도 분포</div>
      <table class="kv-table"><tbody>{comp_rows or '<tr><td colspan=2>데이터 없음</td></tr>'}</tbody></table>
    </div>
    <div class="card">
      <div class="lbl" style="margin-bottom:6px">정답 유형 분포</div>
      <table class="kv-table"><tbody>{ans_rows or '<tr><td colspan=2>데이터 없음</td></tr>'}</tbody></table>
    </div>
  </div>
</div>
        """

    def _generate_samples_section(self, samples: List[Dict[str, Any]]) -> str:
        # 필터/검색/페이징 UI 및 렌더 컨테이너만 제공, 실제 렌더는 JS에서 수행
        return f"""
<div class="section">
  <div class="s-title">📝 샘플 Q/A</div>
  <div class="filters">
    <input type="text" id="searchInput" placeholder="질문/답변/컨텍스트 검색" />
    <select id="filterSubset"></select>
    <select id="filterCategory"></select>
    <select id="filterComplexity"></select>
    <select id="filterAnswerType"></select>
    <select id="filterPersona"></select>
    <button id="resetFilters">초기화</button>
  </div>
  <div id="samplesCount" class="small"></div>
  <div id="samplesContainer"></div>
  <div id="pagination" class="pagination"></div>
</div>
        """

    def _describe_file(self, relpath: str, name: str, ext: str) -> str:
        # 특정 파일에 대한 설명 매핑
        if relpath == "metadata.json":
            return "메타데이터 및 파이프라인 요약"
        if relpath == "train.json":
            return "학습 세트"
        if relpath == "validation.json":
            return "검증 세트"
        if relpath == "test.json":
            return "테스트 세트"
        if relpath == "basic_dataset.json":
            return "규칙 기반 기본 생성 결과"
        if relpath == "enhanced_dataset.json":
            return "고도화 LLM 생성 결과"
        if relpath == "network_config_qa_dataset.json":
            return "통합 데이터셋(JSON)"
        if relpath.startswith("cases/"):
            return "케이스 변형/결과"
        if name.startswith("assembled_") and ext == ".json":
            return "어셈블된 샘플 묶음"
        if name == "parsed_facts.json":
            return "파싱된 사실 정보"
        if name == "validated_dataset.json":
            return "검증 결과 요약"
        if name == "dataset_for_evaluation.csv":
            return "평가용 CSV"
        if name == "dataset_report.html":
            return "이 보고서"
        if ext == ".json":
            return "JSON 데이터 파일"
        if ext == ".html":
            return "HTML 문서"
        if ext == ".csv":
            return "CSV 데이터 파일"
        return "파일"

    def _generate_files_section(self, stats: Dict[str, Any]) -> str:
        files = self.report_data.get("file_list", [])
        rows = []
        for f in files:
            desc = self._describe_file(f.get("relpath", ""), f.get("name", ""), f.get("ext", ""))
            rows.append(
                f"<tr><td>{f['relpath']}</td><td>{self._format_bytes(f['size'])}</td><td>{desc}</td></tr>"
            )
        return f"""
<div class="section">
  <div class="s-title">📁 파일 목록</div>
  <table class="files">
    <thead><tr><th>파일</th><th>크기</th><th>설명</th></tr></thead>
    <tbody>
      {''.join(rows)}
    </tbody>
  </table>
</div>
        """

    def _generate_footer(self, now: str) -> str:
        return f"""
<div class="footer">생성 시각: {now} · 경량 리포트 · GIA-Re</div>
        """

    def _calculate_stats(self) -> Dict[str, Any]:
        meta = self.report_data.get("metadata", {}) or {}
        datasets = self.report_data.get("datasets", {}) or {}

        # 질문 수 추정: metadata.total_samples → 없으면 train/val/test 합
        total_questions = (
            meta.get("total_samples")
            or sum(datasets.get(n, {}).get("count", 0) for n in ["train.json", "validation.json", "test.json"])
            or meta.get("pipeline_results", {})
            .get("evaluation", {})
            .get("batch_statistics", {})
            .get("total_dataset_size", 0)
        )

        # 카테고리 수
        categories = meta.get("categories") or (
            meta.get("pipeline_results", {})
            .get("evaluation", {})
            .get("batch_statistics", {})
            .get("category_distribution", {})
        )
        if isinstance(categories, dict):
            categories_count = len(categories.keys())
        elif isinstance(categories, list):
            categories_count = len(categories)
        else:
            categories_count = 0

        # 장비 수
        device_count = (
            meta.get("pipeline_results", {})
            .get("parsing", {})
            .get("device_count", 0)
        )

        # 파이프라인 단계 성공률
        pipeline = meta.get("pipeline_results", {})
        step_defs = [
            ("파싱", pipeline.get("parsing")),
            ("기본 생성", pipeline.get("basic_generation")),
            ("고도화 생성", pipeline.get("enhanced_generation")),
            ("어셈블리", pipeline.get("assembly")),
            ("검증", pipeline.get("validation")),
            ("평가", pipeline.get("evaluation")),
        ]
        step_successes = [bool((s or {}).get("success")) for _, s in step_defs if s is not None]
        success_rate = (sum(step_successes) / len(step_successes)) if step_successes else 0.0

        # 평균 품질 점수
        batch_stats = (
            pipeline.get("evaluation", {})
            .get("batch_statistics", {})
        )
        avg_overall = batch_stats.get("average_overall_score")

        # 데이터 크기
        size_bytes = 0
        for n in ["train.json", "validation.json", "test.json", "basic_dataset.json", "enhanced_dataset.json", "network_config_qa_dataset.json"]:
            if datasets.get(n, {}).get("exists"):
                size_bytes += datasets[n]["size"]
        total_data_size = self._format_bytes(size_bytes)

        # 서브셋 카운트
        subset_counts = {
            "train": datasets.get("train.json", {}).get("count", 0),
            "validation": datasets.get("validation.json", {}).get("count", 0),
            "test": datasets.get("test.json", {}).get("count", 0),
        }

        # 분포
        complexity_dist = (
            batch_stats.get("complexity_distribution")
            or meta.get("complexity_counts")
            or {}
        )
        answer_type_dist = batch_stats.get("answer_type_distribution", {})

        # 파이프라인 단계 상세
        pipeline_steps = []
        for name, s in step_defs:
            if s is None:
                continue
            detail = []
            if name == "기본 생성":
                if "question_count" in s:
                    detail.append(f"{s['question_count']}개")
                if s.get("categories"):
                    detail.append(f"카테고리 {len(s['categories'])}개")
            if name == "고도화 생성":
                if "question_count" in s:
                    detail.append(f"{s['question_count']}개")
                if s.get("complexities"):
                    detail.append(f"복잡도 {len(s['complexities'])}종")
            if name == "어셈블리":
                if "deduplicated_count" in s:
                    detail.append(f"중복제거 {s['deduplicated_count']}")
                if "validated_count" in pipeline.get("validation", {}):
                    detail.append(f"검증 {pipeline['validation']['validated_count']}")
            pipeline_steps.append(
                {
                    "name": name,
                    "success": bool(s.get("success")),
                    "detail": ", ".join(detail),
                }
            )

        return {
            "meta": {
                "dataset_name": meta.get("dataset_name"),
                "version": meta.get("version"),
                "description": meta.get("description"),
            },
            "total_questions": int(total_questions or 0),
            "categories_count": int(categories_count or 0),
            "device_count": int(device_count or 0),
            "pipeline_success_rate": success_rate,
            "pipeline_success_rate_pct": f"{success_rate*100:.1f}%",
            "avg_quality_score": f"{avg_overall:.2f}" if isinstance(avg_overall, (int, float)) else "-",
            "total_data_size": total_data_size,
            "subset_counts": subset_counts,
            "complexity_distribution": complexity_dist,
            "answer_type_distribution": answer_type_dist,
            "quality": batch_stats,
            "pipeline_steps": pipeline_steps,
        }

    def _extract_samples(self) -> List[Dict[str, Any]]:
        """샘플 Q/A 전체 수집(Train/Val/Test) 및 서브셋 정보 포함, 질문/답변 전체 표시"""
        samples: List[Dict[str, Any]] = []
        for name in ["train.json", "validation.json", "test.json"]:
            info = self.report_data.get("datasets", {}).get(name)
            if not info or not info.get("exists"):
                continue
            content = self._safe_load_json(Path(info["path"]))
            if not isinstance(content, list):
                continue
            subset = name.replace(".json", "")
            for item in content:
                if not isinstance(item, dict):
                    continue
                samples.append(
                    {
                        "id": item.get("id"),
                        "question": item.get("question"),
                        "answer": item.get("answer"),
                        "context": item.get("context"),
                        "answer_type": item.get("answer_type"),
                        "category": item.get("category"),
                        "complexity": item.get("complexity"),
                        "level": item.get("level"),
                        "persona": item.get("persona"),
                        "scenario": item.get("scenario"),
                        "subset": subset,
                    }
                )
        return samples

    def _generate_scripts(self, samples: List[Dict[str, Any]]) -> str:
        # 샘플 JSON을 페이지에 주입하고, 검색/필터/페이징을 처리하는 경량 JS 추가
        data_json = json.dumps(samples, ensure_ascii=False)
        script = """
<script id="samples-data" type="application/json">__DATA__</script>
<script>
(function(){
  const PAGE_SIZE = 20;
  const allSamples = JSON.parse(document.getElementById('samples-data').textContent || '[]');
  const el = (id) => document.getElementById(id);
  const container = el('samplesContainer');
  const countEl = el('samplesCount');
  const pagination = el('pagination');
  const input = el('searchInput');
  const fSubset = el('filterSubset');
  const fCat = el('filterCategory');
  const fComp = el('filterComplexity');
  const fType = el('filterAnswerType');
  const fPersona = el('filterPersona');
  const resetBtn = el('resetFilters');

  function uniq(arr) { return Array.from(new Set(arr.filter(Boolean))).sort(); }
  function vals(key){ return uniq(allSamples.map(s => s[key]).filter(v => v !== null && v !== undefined && v !== '')); }
  function optHtml(values, labelAll){
    const opts = [`<option value="">${labelAll}</option>`].concat(values.map(v => `<option value="${String(v)}">${String(v)}</option>`));
    return opts.join('');
  }

  fSubset.innerHTML = optHtml(vals('subset'), '전체 Subset');
  fCat.innerHTML    = optHtml(vals('category'), '전체 카테고리');
  fComp.innerHTML   = optHtml(vals('complexity'), '전체 복잡도');
  fType.innerHTML   = optHtml(vals('answer_type'), '전체 유형');
  fPersona.innerHTML= optHtml(vals('persona'), '전체 Persona');

  let state = { page: 1 };

  function matches(sample){
    const t = (input.value || '').toLowerCase().trim();
    if (fSubset.value && sample.subset !== fSubset.value) return false;
    if (fCat.value && sample.category !== fCat.value) return false;
    if (fComp.value && sample.complexity !== fComp.value) return false;
    if (fType.value && sample.answer_type !== fType.value) return false;
    if (fPersona.value && sample.persona !== fPersona.value) return false;
    if (t) {
      const hay = [sample.id, sample.question, sample.answer, sample.context].map(x => (x||'').toLowerCase());
      if (!hay.some(x => x.includes(t))) return false;
    }
    return true;
  }

  function render(){
    const filtered = allSamples.filter(matches);
    const total = filtered.length;
    const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
    if (state.page > totalPages) state.page = totalPages;
    const start = (state.page - 1) * PAGE_SIZE;
    const pageItems = filtered.slice(start, start + PAGE_SIZE);

    countEl.textContent = `총 ${total}건 · 페이지 ${state.page}/${totalPages}`;

    // Render items
    container.innerHTML = pageItems.map(s => {
      const meta = [
        s.id ? `ID: ${s.id}` : '',
        s.subset ? `Subset: ${s.subset}` : '',
        s.category ? `카테고리: ${s.category}` : '',
        s.complexity ? `복잡도: ${s.complexity}` : '',
        s.answer_type ? `유형: ${s.answer_type}` : '',
        s.persona ? `Persona: ${s.persona}` : '',
        (s.level !== undefined && s.level !== null) ? `Level: ${s.level}` : ''
      ].filter(Boolean).join(' | ');
      return `
      <div class="q">
        <div class="q-title">❓ ${s.question || '(질문 없음)'} </div>
        ${s.context ? `<div class="small" style="white-space:pre-wrap;margin:6px 0 10px">${s.context}</div>` : ''}
        ${s.answer ? `<div style="white-space:pre-wrap">${s.answer}</div>` : ''}
        <div class="meta">${meta}</div>
      </div>`;
    }).join('');

    // Render pagination
    const pages = [];
    function btn(p, label, active=false){
      return `<button data-page="${p}" class="${active?'active':''}">${label}</button>`;
    }
    pages.push(btn(Math.max(1, state.page-1), '이전'));
    const windowSize = 7;
    let startPage = Math.max(1, state.page - Math.floor(windowSize/2));
    let endPage = Math.min(totalPages, startPage + windowSize - 1);
    if (endPage - startPage + 1 < windowSize) {
      startPage = Math.max(1, endPage - windowSize + 1);
    }
    for (let p=startPage; p<=endPage; p++) pages.push(btn(p, String(p), p===state.page));
    pages.push(btn(Math.min(totalPages, state.page+1), '다음'));
    pagination.innerHTML = pages.join('');

    Array.from(pagination.querySelectorAll('button')).forEach(b => {
      b.addEventListener('click', () => {
        const p = parseInt(b.getAttribute('data-page'));
        if (!isNaN(p)) { state.page = p; render(); }
      });
    });
  }

  [input, fSubset, fCat, fComp, fType, fPersona].forEach(elm => {
    elm.addEventListener('input', () => { state.page = 1; render(); });
    elm.addEventListener('change', () => { state.page = 1; render(); });
  });

  resetBtn.addEventListener('click', () => {
    input.value = '';
    [fSubset, fCat, fComp, fType, fPersona].forEach(s => s.value = '');
    state.page = 1; render();
  });

  render();
})();
</script>
        """
        return script.replace("__DATA__", data_json)
       

# 사용 예시 및 통합 함수
def generate_dataset_report(output_dir: str = "demo_output") -> str:
    """데이터셋 보고서 생성 함수"""
    generator = DatasetReportGenerator(output_dir)
    return generator.generate_report()


if __name__ == "__main__":
    # 직접 실행 시 보고서 생성
    report_path = generate_dataset_report()
    print(f"📊 데이터셋 보고서가 생성되었습니다: {report_path}")
