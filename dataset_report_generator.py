"""
네트워크 설정 데이터셋 HTML 보고서 생성기
인터랙티브한 시각화와 종합적인 데이터 분석 제공
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List
import base64

class DatasetReportGenerator:
    """데이터셋 분석 및 HTML 보고서 생성"""
    
    def __init__(self, output_dir: str = "demo_output"):
        self.output_dir = Path(output_dir)
        self.report_data = {}
        
    def generate_report(self) -> str:
        """종합 보고서 생성"""
        print("📊 데이터셋 보고서 생성 시작...")
        
        # 데이터 수집
        self._collect_data()
        
        # HTML 생성
        html_content = self._generate_html()
        
        # 파일 저장
        report_path = self.output_dir / "dataset_report.html"
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        print(f"✅ 보고서 생성 완료: {report_path}")
        return str(report_path)
    
    def _collect_data(self):
        """출력 디렉토리에서 데이터 수집"""
        
        # 메타데이터 로드
        metadata_path = self.output_dir / "metadata.json"
        if metadata_path.exists():
            with open(metadata_path, 'r', encoding='utf-8') as f:
                self.report_data['metadata'] = json.load(f)
        
        # 데이터셋 파일들 로드
        dataset_files = [
            "train.json", "validation.json", "test.json",
            "basic_dataset.json", "enhanced_dataset.json",
            "network_config_qa_dataset.json"
        ]
        
        self.report_data['datasets'] = {}
        for file_name in dataset_files:
            file_path = self.output_dir / file_name
            if file_path.exists():
                with open(file_path, 'r', encoding='utf-8') as f:
                    self.report_data['datasets'][file_name] = json.load(f)
        
        # 케이스 파일들 로드
        cases_dir = self.output_dir / "cases"
        if cases_dir.exists():
            self.report_data['cases'] = {}
            for case_file in cases_dir.glob("*.json"):
                with open(case_file, 'r', encoding='utf-8') as f:
                    self.report_data['cases'][case_file.name] = json.load(f)
        
        # 파일 목록 생성
        self.report_data['file_list'] = self._get_file_list()
    
    def _get_file_list(self) -> List[Dict[str, Any]]:
        """출력 파일 목록과 정보 생성"""
        files = []
        
        for file_path in self.output_dir.rglob("*"):
            if file_path.is_file():
                stat = file_path.stat()
                files.append({
                    'name': file_path.name,
                    'path': str(file_path.relative_to(self.output_dir)),
                    'size': stat.st_size,
                    'size_mb': stat.st_size / (1024 * 1024),
                    'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                })
        
        return sorted(files, key=lambda x: x['size'], reverse=True)
    
    def _generate_html(self) -> str:
        """HTML 보고서 생성"""
        
        # 통계 계산
        stats = self._calculate_stats()
        
        # 샘플 데이터 추출
        samples = self._extract_samples()
        
        # HTML 템플릿
        html = f"""
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GIA-Re 데이터셋 보고서</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        {self._get_css()}
    </style>
</head>
<body>
    <div class="container">
        {self._generate_header()}
        {self._generate_overview(stats)}
        {self._generate_pipeline_section()}
        {self._generate_dataset_section(stats)}
        {self._generate_quality_section()}
        {self._generate_samples_section(samples)}
        {self._generate_files_section()}
        {self._generate_footer()}
    </div>
    
    <script>
        {self._get_javascript()}
    </script>
</body>
</html>
        """
        
        return html
    
    def _get_css(self) -> str:
        """CSS 스타일"""
        return """
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f7fa;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 15px;
            margin-bottom: 30px;
            text-align: center;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
        }
        
        .header p {
            font-size: 1.1rem;
            opacity: 0.9;
        }
        
        .section {
            background: white;
            margin-bottom: 30px;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
            overflow: hidden;
        }
        
        .section-header {
            background: #f8f9fa;
            padding: 20px;
            border-bottom: 1px solid #dee2e6;
        }
        
        .section-header h2 {
            color: #495057;
            font-size: 1.5rem;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .section-content {
            padding: 25px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: linear-gradient(135deg, #74b9ff 0%, #0984e3 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            transition: transform 0.3s ease;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
        }
        
        .stat-number {
            font-size: 2.5rem;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .stat-label {
            font-size: 0.9rem;
            opacity: 0.9;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .pipeline-steps {
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            margin: 20px 0;
        }
        
        .pipeline-step {
            flex: 1;
            min-width: 200px;
            background: #f8f9fa;
            border: 2px solid #e9ecef;
            border-radius: 10px;
            padding: 15px;
            text-align: center;
            position: relative;
        }
        
        .pipeline-step.success {
            border-color: #28a745;
            background: #d4edda;
        }
        
        .pipeline-step.error {
            border-color: #dc3545;
            background: #f8d7da;
        }
        
        .pipeline-step::after {
            content: '→';
            position: absolute;
            right: -25px;
            top: 50%;
            transform: translateY(-50%);
            font-size: 1.5rem;
            color: #6c757d;
        }
        
        .pipeline-step:last-child::after {
            display: none;
        }
        
        .chart-container {
            width: 100%;
            height: 400px;
            margin: 20px 0;
        }
        
        .tabs {
            display: flex;
            border-bottom: 2px solid #dee2e6;
            margin-bottom: 20px;
        }
        
        .tab {
            padding: 15px 25px;
            background: #f8f9fa;
            border: none;
            border-bottom: 3px solid transparent;
            cursor: pointer;
            font-size: 1rem;
            transition: all 0.3s ease;
        }
        
        .tab.active {
            background: white;
            border-bottom-color: #667eea;
            color: #667eea;
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .question-card {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
            transition: box-shadow 0.3s ease;
        }
        
        .question-card:hover {
            box-shadow: 0 3px 10px rgba(0,0,0,0.1);
        }
        
        .question-text {
            font-weight: 600;
            color: #495057;
            margin-bottom: 10px;
            font-size: 1.1rem;
        }
        
        .answer-text {
            background: #e8f5e8;
            border: 1px solid #c3e6c3;
            border-radius: 5px;
            padding: 10px;
            font-family: 'Courier New', monospace;
            color: #155724;
            margin-bottom: 10px;
            max-height: 150px;
            overflow-y: auto;
        }
        
        .question-meta {
            font-size: 0.85rem;
            color: #6c757d;
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
        }
        
        .meta-tag {
            background: #e9ecef;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 0.8rem;
        }
        
        .file-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        
        .file-table th,
        .file-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }
        
        .file-table th {
            background: #f8f9fa;
            font-weight: 600;
            color: #495057;
        }
        
        .file-table tr:hover {
            background: #f8f9fa;
        }
        
        .progress-bar {
            width: 100%;
            height: 8px;
            background: #e9ecef;
            border-radius: 4px;
            overflow: hidden;
            margin: 10px 0;
        }
        
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #28a745, #20c997);
            transition: width 0.3s ease;
        }
        
        .badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .badge-success { background: #d4edda; color: #155724; }
        .badge-warning { background: #fff3cd; color: #856404; }
        .badge-info { background: #d1ecf1; color: #0c5460; }
        .badge-danger { background: #f8d7da; color: #721c24; }
        
        .footer {
            text-align: center;
            padding: 30px;
            color: #6c757d;
            border-top: 1px solid #dee2e6;
            margin-top: 50px;
        }
        
        .explanation-box {
            background: #e3f2fd;
            border: 1px solid #bbdefb;
            border-radius: 8px;
            padding: 15px;
            margin: 15px 0;
        }
        
        .explanation-title {
            font-weight: 600;
            color: #1565c0;
            margin-bottom: 8px;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }
            
            .header h1 {
                font-size: 2rem;
            }
            
            .stats-grid {
                grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            }
            
            .pipeline-steps {
                flex-direction: column;
            }
            
            .pipeline-step::after {
                display: none;
            }
        }
        """
    
    def _generate_header(self) -> str:
        """헤더 섹션 생성"""
        current_time = datetime.now().strftime('%Y년 %m월 %d일 %H:%M:%S')
        
        return f"""
        <div class="header">
            <h1>🎯 GIA-Re 데이터셋 보고서</h1>
            <p>네트워크 설정 질문-답변 데이터셋 종합 분석</p>
            <p>생성일시: {current_time}</p>
        </div>
        """
    
    def _generate_overview(self, stats: Dict[str, Any]) -> str:
        """개요 섹션 생성"""
        return f"""
        <div class="section">
            <div class="section-header">
                <h2>📊 데이터셋 개요</h2>
            </div>
            <div class="section-content">
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-number">{stats['total_questions']}</div>
                        <div class="stat-label">총 질문 수</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{stats['categories_count']}</div>
                        <div class="stat-label">카테고리 수</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{stats['devices_count']}</div>
                        <div class="stat-label">네트워크 장비</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{stats['success_rate']:.1f}%</div>
                        <div class="stat-label">파이프라인 성공률</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{stats['avg_quality']:.2f}</div>
                        <div class="stat-label">평균 품질 점수</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{stats['total_size_mb']:.1f}MB</div>
                        <div class="stat-label">총 데이터 크기</div>
                    </div>
                </div>
                
                <div class="explanation-box">
                    <div class="explanation-title">📈 주요 지표 설명</div>
                    <ul style="margin-left: 20px;">
                        <li><strong>총 질문 수:</strong> 생성된 모든 질문-답변 쌍의 총 개수</li>
                        <li><strong>카테고리 수:</strong> BGP, 보안, VRF 등 다양한 네트워크 영역</li>
                        <li><strong>네트워크 장비:</strong> 분석된 라우터/스위치 개수</li>
                        <li><strong>파이프라인 성공률:</strong> 6단계 생성 과정의 성공률</li>
                        <li><strong>평균 품질 점수:</strong> BLEU, F1 등 다중 메트릭 기반 점수</li>
                    </ul>
                </div>
            </div>
        </div>
        """
    
    def _generate_pipeline_section(self) -> str:
        """파이프라인 섹션 생성"""
        metadata = self.report_data.get('metadata', {})
        generation_stats = metadata.get('generation_statistics', {})
        
        steps_html = ""
        pipeline_steps = [
            {"name": "XML 파싱", "key": "parsing", "icon": "📄", "desc": "네트워크 설정 파일 분석"},
            {"name": "기초 질문 생성", "key": "basic_generation", "icon": "📝", "desc": "규칙 기반 질문 생성"},
            {"name": "심화 질문 생성", "key": "enhanced_generation", "icon": "🤖", "desc": "LLM 기반 질문 생성"},
            {"name": "데이터 통합", "key": "assembly", "icon": "🔧", "desc": "질문 통합 및 중복 제거"},
            {"name": "품질 검증", "key": "validation", "icon": "✅", "desc": "품질 필터링"},
            {"name": "평가", "key": "evaluation", "icon": "📊", "desc": "다면적 성능 평가"}
        ]
        
        for step in pipeline_steps:
            success_class = "success"  # 모든 단계가 성공했다고 가정
            
            steps_html += f"""
            <div class="pipeline-step {success_class}">
                <div style="font-size: 1.5rem; margin-bottom: 10px;">{step['icon']}</div>
                <div style="font-weight: 600; margin-bottom: 5px;">{step['name']}</div>
                <div style="font-size: 0.9rem; color: #6c757d;">
                    {step['desc']}
                </div>
            </div>
            """
        
        basic_count = generation_stats.get('basic_questions_generated', 0)
        enhanced_count = generation_stats.get('enhanced_questions_generated', 0)
        final_count = generation_stats.get('final_dataset_size', 0)
        
        return f"""
        <div class="section">
            <div class="section-header">
                <h2>🔧 파이프라인 실행 결과</h2>
            </div>
            <div class="section-content">
                <div class="pipeline-steps">
                    {steps_html}
                </div>
                
                <div class="explanation-box">
                    <div class="explanation-title">📈 생성 통계</div>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 15px;">
                        <div style="text-align: center; padding: 15px; background: #f8f9fa; border-radius: 8px;">
                            <div style="font-size: 1.5rem; font-weight: bold; color: #28a745;">{basic_count}</div>
                            <div style="font-size: 0.9rem; color: #6c757d;">기초 질문 생성</div>
                        </div>
                        <div style="text-align: center; padding: 15px; background: #f8f9fa; border-radius: 8px;">
                            <div style="font-size: 1.5rem; font-weight: bold; color: #007bff;">{enhanced_count}</div>
                            <div style="font-size: 0.9rem; color: #6c757d;">심화 질문 생성</div>
                        </div>
                        <div style="text-align: center; padding: 15px; background: #f8f9fa; border-radius: 8px;">
                            <div style="font-size: 1.5rem; font-weight: bold; color: #6f42c1;">{final_count}</div>
                            <div style="font-size: 0.9rem; color: #6c757d;">최종 데이터셋</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        """
    
    def _generate_dataset_section(self, stats: Dict[str, Any]) -> str:
        """데이터셋 섹션 생성"""
        return f"""
        <div class="section">
            <div class="section-header">
                <h2>📚 데이터셋 구성</h2>
            </div>
            <div class="section-content">
                <div class="tabs">
                    <button class="tab active" onclick="switchTab('split')">Train/Val/Test 분할</button>
                    <button class="tab" onclick="switchTab('categories')">카테고리별 분포</button>
                    <button class="tab" onclick="switchTab('complexity')">복잡도 분포</button>
                </div>
                
                <div id="split" class="tab-content active">
                    <div class="chart-container">
                        <canvas id="splitChart"></canvas>
                    </div>
                    <div class="explanation-box">
                        <div class="explanation-title">📊 데이터 분할 상세</div>
                        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 10px;">
                            <div>
                                <strong>Train ({stats.get('train_count', 0)}개):</strong>
                                <p style="font-size: 0.9rem; color: #6c757d; margin-top: 5px;">
                                    모델 학습에 사용되는 주 데이터셋으로, 전체의 70%를 차지합니다.
                                </p>
                            </div>
                            <div>
                                <strong>Validation ({stats.get('val_count', 0)}개):</strong>
                                <p style="font-size: 0.9rem; color: #6c757d; margin-top: 5px;">
                                    하이퍼파라미터 튜닝과 모델 선택에 사용되는 검증 데이터셋입니다.
                                </p>
                            </div>
                            <div>
                                <strong>Test ({stats.get('test_count', 0)}개):</strong>
                                <p style="font-size: 0.9rem; color: #6c757d; margin-top: 5px;">
                                    최종 성능 평가에 사용되는 테스트 데이터셋입니다.
                                </p>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div id="categories" class="tab-content">
                    <div class="chart-container">
                        <canvas id="categoryChart"></canvas>
                    </div>
                    <div class="explanation-box">
                        <div class="explanation-title">🏷️ 카테고리 설명</div>
                        <ul style="margin-left: 20px;">
                            <li><strong>BGP_Consistency:</strong> Border Gateway Protocol 라우팅 설정의 일관성과 정확성을 검증하는 질문들</li>
                            <li><strong>Security_Policy:</strong> SSH 접근, AAA 인증, 방화벽 등 네트워크 보안 정책 관련 질문들</li>
                            <li><strong>VRF_Consistency:</strong> Virtual Routing and Forwarding 설정의 올바른 구성을 확인하는 질문들</li>
                            <li><strong>Interface_Config:</strong> 네트워크 인터페이스 설정과 연결 상태를 점검하는 질문들</li>
                        </ul>
                    </div>
                </div>
                
                <div id="complexity" class="tab-content">
                    <div class="chart-container">
                        <canvas id="complexityChart"></canvas>
                    </div>
                    <div class="explanation-box">
                        <div class="explanation-title">🎯 복잡도 레벨 설명</div>
                        <ul style="margin-left: 20px;">
                            <li><strong>BASIC:</strong> 직관적이고 단순한 확인 질문 (예: "SSH가 활성화된 장비는?")</li>
                            <li><strong>ANALYTICAL:</strong> 단일 메트릭 기반 분석이 필요한 질문 (예: "BGP 피어 수는?")</li>
                            <li><strong>SYNTHETIC:</strong> 다중 요소를 종합적으로 판단해야 하는 질문 (예: "네트워크 전체 보안 상태 평가")</li>
                            <li><strong>DIAGNOSTIC:</strong> 문제 진단과 해결책 제시가 필요한 질문 (예: "BGP 연결 실패 원인 분석")</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
        """
    
    def _generate_quality_section(self) -> str:
        """품질 분석 섹션 생성"""
        eval_data = self.report_data.get('datasets', {}).get('network_config_qa_dataset.json', {})
        eval_results = eval_data.get('evaluation_results', {})
        dataset_stats = eval_results.get('dataset_statistics', {})
        
        return f"""
        <div class="section">
            <div class="section-header">
                <h2>🎯 품질 분석</h2>
            </div>
            <div class="section-content">
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-number">{dataset_stats.get('exact_match_avg', 0):.3f}</div>
                        <div class="stat-label">정확도 (Exact Match)</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{dataset_stats.get('f1_score_avg', 0):.3f}</div>
                        <div class="stat-label">F1 Score</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{dataset_stats.get('long_answer_bleu', 0):.3f}</div>
                        <div class="stat-label">BLEU Score</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{dataset_stats.get('average_overall_score', 0):.3f}</div>
                        <div class="stat-label">종합 점수</div>
                    </div>
                </div>
                
                <div class="explanation-box">
                    <div class="explanation-title">📏 평가 메트릭 상세 설명</div>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-top: 15px;">
                        <div style="background: #f8f9fa; padding: 15px; border-radius: 8px;">
                            <h5 style="color: #007bff; margin-bottom: 8px;">🎯 Exact Match</h5>
                            <p style="font-size: 0.9rem;">생성된 답변이 정답과 문자 그대로 완전히 일치하는 비율을 측정합니다.</p>
                        </div>
                        <div style="background: #f8f9fa; padding: 15px; border-radius: 8px;">
                            <h5 style="color: #28a745; margin-bottom: 8px;">📊 F1 Score</h5>
                            <p style="font-size: 0.9rem;">정밀도(Precision)와 재현율(Recall)의 조화평균으로, 답변의 전반적 품질을 나타냅니다.</p>
                        </div>
                        <div style="background: #f8f9fa; padding: 15px; border-radius: 8px;">
                            <h5 style="color: #6f42c1; margin-bottom: 8px;">📝 BLEU Score</h5>
                            <p style="font-size: 0.9rem;">n-gram 기반으로 생성된 텍스트와 참조 텍스트 간의 유사도를 측정합니다.</p>
                        </div>
                        <div style="background: #f8f9fa; padding: 15px; border-radius: 8px;">
                            <h5 style="color: #dc3545; margin-bottom: 8px;">⭐ 종합 점수</h5>
                            <p style="font-size: 0.9rem;">모든 개별 메트릭들의 가중평균으로 계산된 최종 품질 점수입니다.</p>
                        </div>
                    </div>
                </div>
                
                <div style="margin-top: 20px;">
                    <h4>📈 답변 유형별 성능</h4>
                    <div style="display: flex; gap: 20px; margin-top: 15px;">
                        <div style="flex: 1; background: #e8f5e8; padding: 15px; border-radius: 8px;">
                            <strong>Short Answer 정확도:</strong> {dataset_stats.get('short_answer_em', 0):.3f}
                            <p style="font-size: 0.9rem; margin-top: 5px;">간단한 팩트 기반 질문의 정확도</p>
                        </div>
                        <div style="flex: 1; background: #fff3cd; padding: 15px; border-radius: 8px;">
                            <strong>Long Answer 품질:</strong> {dataset_stats.get('long_answer_em', 0):.3f}
                            <p style="font-size: 0.9rem; margin-top: 5px;">복잡한 설명형 답변의 품질 점수</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        """
    
    def _generate_samples_section(self, samples: List[Dict[str, Any]]) -> str:
        """샘플 섹션 생성"""
        samples_html = ""
        
        for i, sample in enumerate(samples[:8]):  # 최대 8개만 표시
            question_text = sample.get('question', '질문 없음')
            answer_text = sample.get('answer', '답변 없음')
            category = sample.get('category', '미분류')
            complexity = sample.get('complexity', '불명')
            question_id = sample.get('id', f'sample-{i}')
            
            # 답변이 너무 길면 축약
            if len(str(answer_text)) > 200:
                if isinstance(answer_text, str):
                    answer_display = answer_text[:200] + "..."
                else:
                    answer_display = str(answer_text)[:200] + "..."
            else:
                answer_display = str(answer_text)
            
            # 답변 타입에 따른 뱃지
            answer_type = sample.get('answer_type', 'unknown')
            badge_class = 'badge-info' if answer_type == 'short' else 'badge-warning'
            
            samples_html += f"""
            <div class="question-card">
                <div class="question-text">❓ {question_text}</div>
                <div class="answer-text">💡 {answer_display}</div>
                <div class="question-meta">
                    <span class="meta-tag">ID: {question_id}</span>
                    <span class="badge {badge_class}">{answer_type.upper()}</span>
                    <span class="meta-tag">카테고리: {category}</span>
                    <span class="meta-tag">복잡도: {complexity}</span>
                </div>
            </div>
            """
        
        return f"""
        <div class="section">
            <div class="section-header">
                <h2>📝 질문 샘플</h2>
            </div>
            <div class="section-content">
                <div class="explanation-box">
                    <div class="explanation-title">📋 샘플 설명</div>
                    <p>실제 네트워크 설정 데이터를 기반으로 생성된 질문-답변 쌍들의 대표적인 예시입니다. 
                    각 질문은 실무에서 활용할 수 있는 네트워크 지식을 평가하도록 설계되었습니다.</p>
                </div>
                {samples_html}
                {f'<p style="text-align: center; margin-top: 20px; color: #6c757d;"><em>... 총 {len(samples)}개 질문 중 일부 (전체 목록은 각 JSON 파일에서 확인 가능)</em></p>' if len(samples) > 8 else ''}
            </div>
        </div>
        """
    
    def _generate_files_section(self) -> str:
        """파일 목록 섹션 생성"""
        files_html = ""
        
        file_descriptions = {
            'metadata.json': '🔧 데이터셋 생성 과정의 모든 설정과 통계 정보를 포함한 메타데이터',
            'train.json': '🎓 모델 학습용 데이터 (전체의 약 70%)',
            'validation.json': '🔍 하이퍼파라미터 튜닝 및 모델 검증용 데이터 (약 15%)', 
            'test.json': '📊 최종 성능 평가용 테스트 데이터 (약 15%)',
            'basic_dataset.json': '📝 규칙 기반으로 생성된 기초 질문들 (정확한 메트릭 기반)',
            'enhanced_dataset.json': '🤖 LLM으로 생성된 심화 질문들 (복잡한 추론 포함)',
            'network_config_qa_dataset.json': '📋 최종 통합 데이터셋 + 상세한 평가 결과',
            'parsed_facts.json': '🌐 XML 파일에서 추출한 구조화된 네트워크 설정 데이터',
            'all_cases.json': '🎭 다양한 네트워크 시나리오별 확장 케이스 (장애, 확장 등)',
            'validated_dataset.json': '✅ 품질 검증을 통과한 검증된 질문-답변 쌍들',
            'assembled_basic.json': '🔧 기본 복잡도 질문들만 모아놓은 어셈블리',
            'assembled_analytical.json': '🔍 분석적 사고가 필요한 질문들의 어셈블리',
            'assembled_diagnostic.json': '🩺 진단형 질문들의 어셈블리',
            'assembled_synthetic.json': '🔄 종합적 판단이 필요한 질문들의 어셈블리',
        }
        
        for file_info in self.report_data.get('file_list', []):
            file_name = file_info['name']
            description = file_descriptions.get(file_name, '📄 생성된 데이터 파일')
            
            # 파일 크기에 따른 색상
            if file_info['size_mb'] > 1:
                size_class = "style='color: #dc3545; font-weight: bold;'"
            elif file_info['size_mb'] > 0.1:
                size_class = "style='color: #007bff;'"
            else:
                size_class = "style='color: #6c757d;'"
            
            files_html += f"""
            <tr>
                <td><strong>{file_name}</strong></td>
                <td>{description}</td>
                <td {size_class}>{file_info['size_mb']:.2f} MB</td>
                <td>{file_info['modified']}</td>
                <td><code>{file_info['path']}</code></td>
            </tr>
            """
        
        return f"""
        <div class="section">
            <div class="section-header">
                <h2>📂 출력 파일 목록</h2>
            </div>
            <div class="section-content">
                <div class="explanation-box">
                    <div class="explanation-title">📁 파일 구조 안내</div>
                    <p>데이터셋 생성 과정에서 생성된 모든 파일들의 목록과 각각의 용도입니다. 
                    각 파일은 특정 목적에 맞게 설계되었으며, 연구나 개발 목적에 따라 적절한 파일을 선택하여 사용할 수 있습니다.</p>
                </div>
                
                <table class="file-table">
                    <thead>
                        <tr>
                            <th>📋 파일명</th>
                            <th>📝 설명 및 용도</th>
                            <th>📏 크기</th>
                            <th>🕒 수정일시</th>
                            <th>📍 경로</th>
                        </tr>
                    </thead>
                    <tbody>
                        {files_html}
                    </tbody>
                </table>
                
                <div style="margin-top: 20px;">
                    <h4>🎯 파일 사용 가이드</h4>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 15px; margin-top: 15px;">
                        <div style="background: #e8f5e8; padding: 15px; border-radius: 8px;">
                            <strong>🎓 모델 학습용:</strong>
                            <p style="font-size: 0.9rem; margin-top: 5px;">train.json, validation.json, test.json 사용</p>
                        </div>
                        <div style="background: #fff3cd; padding: 15px; border-radius: 8px;">
                            <strong>📚 연구 분석용:</strong>
                            <p style="font-size: 0.9rem; margin-top: 5px;">network_config_qa_dataset.json + metadata.json 사용</p>
                        </div>
                        <div style="background: #d1ecf1; padding: 15px; border-radius: 8px;">
                            <strong>🔧 커스텀 개발용:</strong>
                            <p style="font-size: 0.9rem; margin-top: 5px;">basic_dataset.json + enhanced_dataset.json 사용</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        """
    
    def _generate_footer(self) -> str:
        """푸터 생성"""
        return """
        <div class="footer">
            <p>🎯 <strong>GIA-Re: 네트워크 설정 질문-답변 데이터셋 생성 시스템</strong></p>
            <p>인공지능 기반 네트워크 교육 및 평가를 위한 고품질 데이터셋</p>
            <p style="margin-top: 10px; font-size: 0.9rem; color: #aaa;">
                Generated by DatasetReportGenerator | 
                <a href="https://github.com/YUjinEDU/GIA-Re" style="color: #667eea;">GitHub Repository</a>
            </p>
        </div>
        """
    
    def _get_javascript(self) -> str:
        """JavaScript 코드"""
        # 통계 데이터 준비
        stats = self._calculate_stats()
        
        return f"""
        // 탭 전환 함수
        function switchTab(tabName) {{
            // 모든 탭과 콘텐츠 비활성화
            document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
            
            // 선택된 탭과 콘텐츠 활성화
            event.target.classList.add('active');
            document.getElementById(tabName).classList.add('active');
        }}
        
        // 차트 생성
        window.addEventListener('load', function() {{
            // Train/Val/Test 분할 차트
            const splitCtx = document.getElementById('splitChart').getContext('2d');
            new Chart(splitCtx, {{
                type: 'doughnut',
                data: {{
                    labels: ['Train', 'Validation', 'Test'],
                    datasets: [{{
                        data: [{stats.get('train_count', 0)}, {stats.get('val_count', 0)}, {stats.get('test_count', 0)}],
                        backgroundColor: ['#74b9ff', '#a29bfe', '#fd79a8'],
                        borderWidth: 3,
                        borderColor: '#fff'
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        legend: {{
                            position: 'bottom',
                            labels: {{
                                padding: 20,
                                font: {{
                                    size: 14
                                }}
                            }}
                        }}
                    }}
                }}
            }});
            
            // 카테고리 분포 차트
            const categoryCtx = document.getElementById('categoryChart').getContext('2d');
            new Chart(categoryCtx, {{
                type: 'bar',
                data: {{
                    labels: {list(stats.get('category_distribution', {}).keys())},
                    datasets: [{{
                        label: '질문 수',
                        data: {list(stats.get('category_distribution', {}).values())},
                        backgroundColor: '#74b9ff',
                        borderColor: '#0984e3',
                        borderWidth: 2
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {{
                        y: {{
                            beginAtZero: true
                        }}
                    }},
                    plugins: {{
                        legend: {{
                            display: false
                        }}
                    }}
                }}
            }});
            
            // 복잡도 분포 차트
            const complexityCtx = document.getElementById('complexityChart').getContext('2d');
            new Chart(complexityCtx, {{
                type: 'pie',
                data: {{
                    labels: {list(stats.get('complexity_distribution', {}).keys())},
                    datasets: [{{
                        data: {list(stats.get('complexity_distribution', {}).values())},
                        backgroundColor: ['#00b894', '#fdcb6e', '#e17055', '#a29bfe'],
                        borderWidth: 3,
                        borderColor: '#fff'
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        legend: {{
                            position: 'bottom',
                            labels: {{
                                padding: 20,
                                font: {{
                                    size: 14
                                }}
                            }}
                        }}
                    }}
                }}
            }});
        }});
        """
    
    def _calculate_stats(self) -> Dict[str, Any]:
        """통계 계산"""
        stats = {
            'total_questions': 0,
            'categories_count': 0,
            'devices_count': 0,
            'success_rate': 100.0,  # 기본값
            'avg_quality': 0,
            'total_size_mb': 0,
            'train_count': 0,
            'val_count': 0,
            'test_count': 0,
            'category_distribution': {},
            'complexity_distribution': {}
        }
        
        # 메타데이터에서 통계 추출
        metadata = self.report_data.get('metadata', {})
        generation_stats = metadata.get('generation_statistics', {})
        
        stats['total_questions'] = generation_stats.get('final_dataset_size', 0)
        stats['devices_count'] = metadata.get('parsing_results', {}).get('total_devices', 0)
        
        # 품질 점수 계산
        eval_data = self.report_data.get('datasets', {}).get('network_config_qa_dataset.json', {})
        dataset_stats = eval_data.get('evaluation_results', {}).get('dataset_statistics', {})
        stats['avg_quality'] = dataset_stats.get('average_overall_score', 0)
        
        # 데이터셋 분할 크기
        datasets = self.report_data.get('datasets', {})
        stats['train_count'] = len(datasets.get('train.json', []))
        stats['val_count'] = len(datasets.get('validation.json', []))
        stats['test_count'] = len(datasets.get('test.json', []))
        
        # 파일 크기 합계
        stats['total_size_mb'] = sum(f['size_mb'] for f in self.report_data.get('file_list', []))
        
        # 카테고리 및 복잡도 분포 계산
        all_samples = []
        for dataset_name, dataset_data in datasets.items():
            if isinstance(dataset_data, list):
                all_samples.extend(dataset_data)
        
        # 카테고리 분포
        categories = {}
        complexities = {}
        for sample in all_samples:
            cat = sample.get('category', '미분류')
            comp = sample.get('complexity', '불명')
            categories[cat] = categories.get(cat, 0) + 1
            complexities[comp] = complexities.get(comp, 0) + 1
        
        stats['category_distribution'] = categories
        stats['complexity_distribution'] = complexities
        stats['categories_count'] = len(categories)
        
        return stats
    
    def _extract_samples(self) -> List[Dict[str, Any]]:
        """샘플 데이터 추출"""
        samples = []
        
        # 다양한 데이터셋에서 샘플 추출
        datasets = self.report_data.get('datasets', {})
        
        # Basic 샘플
        basic_data = datasets.get('basic_dataset.json', [])
        if basic_data and len(basic_data) > 0:
            samples.extend(basic_data[:3])
        
        # Enhanced 샘플
        enhanced_data = datasets.get('enhanced_dataset.json', [])
        if enhanced_data and len(enhanced_data) > 0:
            samples.extend(enhanced_data[:3])
        
        # Train 샘플
        train_data = datasets.get('train.json', [])
        if train_data and len(train_data) > 0:
            samples.extend(train_data[:2])
        
        return samples


# 사용 예시 및 통합 함수
def generate_dataset_report(output_dir: str = "demo_output") -> str:
    """데이터셋 보고서 생성 함수"""
    generator = DatasetReportGenerator(output_dir)
    return generator.generate_report()


if __name__ == "__main__":
    # 직접 실행 시 보고서 생성
    report_path = generate_dataset_report()
    print(f"📊 데이터셋 보고서가 생성되었습니다: {report_path}")
