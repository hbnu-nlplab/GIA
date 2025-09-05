"""
실험 로깅 및 모니터링 시스템
"""

import os
import json
import time
import logging
import pandas as pd
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
import sqlite3
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots

@dataclass
class ExperimentResult:
    """실험 결과 데이터 구조"""
    experiment_id: str
    timestamp: str
    model_name: str
    question: str
    predicted_answer: str
    ground_truth: str
    
    # 성능 메트릭
    exact_match: float
    f1_score: float
    bert_score: float
    rouge_l: float
    
    # 실험 설정
    use_rag: bool
    top_k: Optional[int]
    temperature: float
    max_tokens: int
    
    # 시스템 메트릭
    response_time: float
    tokens_used: Optional[int]
    cost_estimate: Optional[float]
    
    # 추가 정보
    retrieval_docs: Optional[List[str]]
    error_message: Optional[str]
    success: bool

class ExperimentLogger:
    """실험 로깅 시스템"""
    
    def __init__(self, log_dir: str = "experiments"):
        self.log_dir = log_dir
        self.db_path = os.path.join(log_dir, "experiments.db")
        
        # 디렉토리 생성
        os.makedirs(log_dir, exist_ok=True)
        os.makedirs(os.path.join(log_dir, "logs"), exist_ok=True)
        os.makedirs(os.path.join(log_dir, "figures"), exist_ok=True)
        os.makedirs(os.path.join(log_dir, "reports"), exist_ok=True)
        
        # 데이터베이스 초기화
        self._init_database()
        
        # 로깅 설정
        self._setup_logging()
    
    def _init_database(self):
        """SQLite 데이터베이스 초기화"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS experiments (
                    experiment_id TEXT,
                    timestamp TEXT,
                    model_name TEXT,
                    question TEXT,
                    predicted_answer TEXT,
                    ground_truth TEXT,
                    exact_match REAL,
                    f1_score REAL,
                    bert_score REAL,
                    rouge_l REAL,
                    use_rag BOOLEAN,
                    top_k INTEGER,
                    temperature REAL,
                    max_tokens INTEGER,
                    response_time REAL,
                    tokens_used INTEGER,
                    cost_estimate REAL,
                    retrieval_docs TEXT,
                    error_message TEXT,
                    success BOOLEAN
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS experiment_metadata (
                    experiment_id TEXT PRIMARY KEY,
                    description TEXT,
                    config_file TEXT,
                    dataset_path TEXT,
                    total_questions INTEGER,
                    start_time TEXT,
                    end_time TEXT,
                    status TEXT
                )
            """)
    
    def _setup_logging(self):
        """로깅 설정"""
        log_file = os.path.join(self.log_dir, "logs", f"experiment_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        
        self.logger = logging.getLogger(__name__)
    
    def log_result(self, result: ExperimentResult):
        """실험 결과 로깅"""
        with sqlite3.connect(self.db_path) as conn:
            # ExperimentResult를 딕셔너리로 변환
            data = asdict(result)
            
            # 리스트를 JSON 문자열로 변환
            if data['retrieval_docs']:
                data['retrieval_docs'] = json.dumps(data['retrieval_docs'])
            
            # 데이터베이스에 삽입
            placeholders = ', '.join(['?' for _ in data])
            columns = ', '.join(data.keys())
            
            conn.execute(
                f"INSERT INTO experiments ({columns}) VALUES ({placeholders})",
                list(data.values())
            )
    
    def log_experiment_metadata(self, experiment_id: str, description: str, 
                              config_file: str, dataset_path: str, total_questions: int):
        """실험 메타데이터 로깅"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO experiment_metadata 
                (experiment_id, description, config_file, dataset_path, total_questions, start_time, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (experiment_id, description, config_file, dataset_path, total_questions, 
                  datetime.now().isoformat(), "running"))
    
    def update_experiment_status(self, experiment_id: str, status: str):
        """실험 상태 업데이트"""
        with sqlite3.connect(self.db_path) as conn:
            end_time = datetime.now().isoformat() if status == "completed" else None
            conn.execute("""
                UPDATE experiment_metadata 
                SET status = ?, end_time = ?
                WHERE experiment_id = ?
            """, (status, end_time, experiment_id))
    
    def get_experiment_results(self, experiment_id: str = None) -> pd.DataFrame:
        """실험 결과 조회"""
        query = "SELECT * FROM experiments"
        params = []
        
        if experiment_id:
            query += " WHERE experiment_id = ?"
            params.append(experiment_id)
        
        with sqlite3.connect(self.db_path) as conn:
            return pd.read_sql_query(query, conn, params=params)
    
    def get_experiment_summary(self) -> pd.DataFrame:
        """실험 요약 통계"""
        query = """
        SELECT 
            experiment_id,
            model_name,
            use_rag,
            COUNT(*) as total_questions,
            AVG(exact_match) as avg_exact_match,
            AVG(f1_score) as avg_f1_score,
            AVG(bert_score) as avg_bert_score,
            AVG(response_time) as avg_response_time,
            SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful_queries
        FROM experiments
        GROUP BY experiment_id, model_name, use_rag
        """
        
        with sqlite3.connect(self.db_path) as conn:
            return pd.read_sql_query(query, conn)

class ExperimentVisualizer:
    """실험 결과 시각화"""
    
    def __init__(self, logger: ExperimentLogger):
        self.logger = logger
        self.figures_dir = os.path.join(logger.log_dir, "figures")
        
        # 스타일 설정
        plt.style.use('default')
        sns.set_palette("husl")
    
    def plot_model_comparison(self, experiment_id: str = None, save: bool = True):
        """모델별 성능 비교 차트"""
        df = self.logger.get_experiment_results(experiment_id)
        
        if df.empty:
            print("No data available for plotting")
            return
        
        # 모델별 평균 성능 계산
        metrics = ['exact_match', 'f1_score', 'bert_score', 'rouge_l']
        model_performance = df.groupby('model_name')[metrics].mean()
        
        # 서브플롯 생성
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        fig.suptitle('Model Performance Comparison', fontsize=16)
        
        for i, metric in enumerate(metrics):
            ax = axes[i//2, i%2]
            model_performance[metric].plot(kind='bar', ax=ax)
            ax.set_title(metric.replace('_', ' ').title())
            ax.set_ylabel('Score')
            ax.tick_params(axis='x', rotation=45)
        
        plt.tight_layout()
        
        if save:
            plt.savefig(os.path.join(self.figures_dir, 'model_comparison.png'), 
                       dpi=300, bbox_inches='tight')
            plt.close()
        else:
            plt.show()
    
    def plot_rag_impact(self, save: bool = True):
        """RAG 사용 여부에 따른 성능 비교"""
        df = self.logger.get_experiment_results()
        
        if df.empty:
            return
        
        # RAG vs No RAG 비교
        rag_comparison = df.groupby(['model_name', 'use_rag'])[['exact_match', 'f1_score', 'bert_score']].mean().reset_index()
        
        fig = make_subplots(
            rows=1, cols=3,
            subplot_titles=('Exact Match', 'F1 Score', 'BERT Score')
        )
        
        metrics = ['exact_match', 'f1_score', 'bert_score']
        
        for i, metric in enumerate(metrics):
            for model in rag_comparison['model_name'].unique():
                model_data = rag_comparison[rag_comparison['model_name'] == model]
                
                fig.add_trace(
                    go.Bar(
                        name=f"{model}",
                        x=[f"No RAG", f"RAG"],
                        y=[
                            model_data[model_data['use_rag'] == False][metric].iloc[0] if not model_data[model_data['use_rag'] == False].empty else 0,
                            model_data[model_data['use_rag'] == True][metric].iloc[0] if not model_data[model_data['use_rag'] == True].empty else 0
                        ]
                    ),
                    row=1, col=i+1
                )
        
        fig.update_layout(height=500, showlegend=True, title_text="RAG Impact on Performance")
        
        if save:
            fig.write_html(os.path.join(self.figures_dir, 'rag_impact.html'))
        else:
            fig.show()
    
    def plot_response_time_analysis(self, save: bool = True):
        """응답 시간 분석"""
        df = self.logger.get_experiment_results()
        
        if df.empty:
            return
        
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
        
        # 모델별 응답 시간 박스플롯
        sns.boxplot(data=df, x='model_name', y='response_time', ax=ax1)
        ax1.set_title('Response Time by Model')
        ax1.set_ylabel('Time (seconds)')
        ax1.tick_params(axis='x', rotation=45)
        
        # RAG 사용 여부에 따른 응답 시간
        sns.boxplot(data=df, x='use_rag', y='response_time', ax=ax2)
        ax2.set_title('Response Time: RAG vs No RAG')
        ax2.set_ylabel('Time (seconds)')
        
        plt.tight_layout()
        
        if save:
            plt.savefig(os.path.join(self.figures_dir, 'response_time_analysis.png'), 
                       dpi=300, bbox_inches='tight')
            plt.close()
        else:
            plt.show()
    
    def plot_top_k_performance(self, save: bool = True):
        """Top-K 설정에 따른 성능 변화"""
        df = self.logger.get_experiment_results()
        
        # RAG 사용하는 실험만 필터링
        rag_df = df[df['use_rag'] == True]
        
        if rag_df.empty:
            return
        
        # Top-K별 성능 평균
        topk_performance = rag_df.groupby('top_k')[['exact_match', 'f1_score', 'bert_score', 'response_time']].mean().reset_index()
        
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=('Exact Match', 'F1 Score', 'BERT Score', 'Response Time')
        )
        
        metrics = ['exact_match', 'f1_score', 'bert_score', 'response_time']
        positions = [(1,1), (1,2), (2,1), (2,2)]
        
        for i, (metric, pos) in enumerate(zip(metrics, positions)):
            fig.add_trace(
                go.Scatter(
                    x=topk_performance['top_k'],
                    y=topk_performance[metric],
                    mode='lines+markers',
                    name=metric.replace('_', ' ').title(),
                    line=dict(width=3),
                    marker=dict(size=8)
                ),
                row=pos[0], col=pos[1]
            )
        
        fig.update_layout(height=600, title_text="Performance vs Top-K Settings")
        
        if save:
            fig.write_html(os.path.join(self.figures_dir, 'topk_performance.html'))
        else:
            fig.show()
    
    def generate_experiment_report(self, experiment_id: str = None):
        """종합 실험 리포트 생성"""
        df = self.logger.get_experiment_results(experiment_id)
        summary = self.logger.get_experiment_summary()
        
        report_path = os.path.join(self.logger.log_dir, "reports", 
                                 f"experiment_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Experiment Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .metric {{ font-weight: bold; color: #2E86C1; }}
            </style>
        </head>
        <body>
            <h1>LLM Benchmark Experiment Report</h1>
            <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            
            <h2>Experiment Summary</h2>
            {summary.to_html(index=False, classes='summary-table')}
            
            <h2>Key Findings</h2>
            <ul>
                <li><span class="metric">Best Performing Model:</span> {summary.loc[summary['avg_exact_match'].idxmax(), 'model_name'] if not summary.empty else 'N/A'}</li>
                <li><span class="metric">RAG Impact:</span> {'Positive' if summary[summary['use_rag'] == True]['avg_exact_match'].mean() > summary[summary['use_rag'] == False]['avg_exact_match'].mean() else 'Negative' if not summary.empty else 'N/A'}</li>
                <li><span class="metric">Average Response Time:</span> {df['response_time'].mean():.2f}s if not df.empty else 'N/A'</li>
                <li><span class="metric">Total Questions Evaluated:</span> {len(df) if not df.empty else 0}</li>
            </ul>
            
            <h2>Detailed Results</h2>
            <p>See generated charts in the figures/ directory for detailed visualizations.</p>
            
        </body>
        </html>
        """
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"Report generated: {report_path}")
        return report_path

# 사용 예시
if __name__ == "__main__":
    # 로거 초기화
    logger = ExperimentLogger()
    
    # 시각화 도구 초기화
    visualizer = ExperimentVisualizer(logger)
    
    # 예시 실험 결과 로깅
    result = ExperimentResult(
        experiment_id="exp_001",
        timestamp=datetime.now().isoformat(),
        model_name="gpt-4o-mini",
        question="What is BGP?",
        predicted_answer="BGP is Border Gateway Protocol...",
        ground_truth="BGP (Border Gateway Protocol) is...",
        exact_match=0.85,
        f1_score=0.92,
        bert_score=0.88,
        rouge_l=0.90,
        use_rag=True,
        top_k=10,
        temperature=0.1,
        max_tokens=2000,
        response_time=2.5,
        tokens_used=150,
        cost_estimate=0.01,
        retrieval_docs=["doc1.txt", "doc2.txt"],
        error_message=None,
        success=True
    )
    
    logger.log_result(result)
    
    # 시각화 생성
    visualizer.plot_model_comparison()
    visualizer.generate_experiment_report()
