"""
고급 실험 로깅 및 분석 시스템
벤치마크 실험의 모든 측면을 추적하고 시각화합니다.
"""

import os
import json
import sqlite3
import pandas as pd
import numpy as np
from datetime import datetime
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
import hashlib

# 시각화 라이브러리
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots

# 평가 메트릭
from rouge_score import rouge_scorer
from bert_score import score as bert_score
import re


@dataclass
class ExperimentResult:
    """실험 결과 데이터 클래스"""
    experiment_id: str
    model_id: str
    question_id: str
    question: str
    ground_truth: str
    prediction: str
    input_tokens: int
    output_tokens: int
    latency: float
    cost: float
    timestamp: str
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


@dataclass
class EvaluationMetrics:
    """평가 메트릭 데이터 클래스"""
    exact_match: float
    bert_precision: float
    bert_recall: float
    bert_f1: float
    rouge1_precision: float
    rouge1_recall: float
    rouge1_f1: float
    rouge2_precision: float
    rouge2_recall: float
    rouge2_f1: float
    rougeL_precision: float
    rougeL_recall: float
    rougeL_f1: float
    average_latency: float
    total_cost: float
    tokens_per_second: float


class AdvancedExperimentLogger:
    """고급 실험 로깅 시스템"""
    
    def __init__(self, db_path: str = "experiments.db", log_path: str = "experiment.log"):
        self.db_path = db_path
        self.log_path = log_path
        
        # 로깅 설정
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_path, encoding='utf-8'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # 데이터베이스 초기화
        self.init_database()
        
        # ROUGE 스코어러
        self.rouge_scorer = rouge_scorer.RougeScorer(
            ['rouge1', 'rouge2', 'rougeL'], 
            use_stemmer=True
        )
    
    def init_database(self):
        """SQLite 데이터베이스 초기화"""
        with sqlite3.connect(self.db_path) as conn:
            # 실험 결과 테이블
            conn.execute("""
                CREATE TABLE IF NOT EXISTS experiment_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    experiment_id TEXT NOT NULL,
                    model_id TEXT NOT NULL,
                    question_id TEXT NOT NULL,
                    question TEXT NOT NULL,
                    ground_truth TEXT NOT NULL,
                    prediction TEXT NOT NULL,
                    input_tokens INTEGER,
                    output_tokens INTEGER,
                    latency REAL,
                    cost REAL,
                    timestamp TEXT NOT NULL,
                    metadata TEXT,
                    UNIQUE(experiment_id, model_id, question_id)
                )
            """)
            
            # 실험 메타데이터 테이블
            conn.execute("""
                CREATE TABLE IF NOT EXISTS experiment_metadata (
                    experiment_id TEXT PRIMARY KEY,
                    description TEXT,
                    config TEXT,
                    start_time TEXT,
                    end_time TEXT,
                    status TEXT
                )
            """)
            
            # 평가 메트릭 테이블
            conn.execute("""
                CREATE TABLE IF NOT EXISTS evaluation_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    experiment_id TEXT NOT NULL,
                    model_id TEXT NOT NULL,
                    exact_match REAL,
                    bert_precision REAL,
                    bert_recall REAL,
                    bert_f1 REAL,
                    rouge1_precision REAL,
                    rouge1_recall REAL,
                    rouge1_f1 REAL,
                    rouge2_precision REAL,
                    rouge2_recall REAL,
                    rouge2_f1 REAL,
                    rougeL_precision REAL,
                    rougeL_recall REAL,
                    rougeL_f1 REAL,
                    average_latency REAL,
                    total_cost REAL,
                    tokens_per_second REAL,
                    timestamp TEXT NOT NULL,
                    UNIQUE(experiment_id, model_id)
                )
            """)
    
    def log_experiment_start(
        self, 
        experiment_id: str, 
        description: str, 
        config: Dict[str, Any]
    ):
        """실험 시작 로깅"""
        timestamp = datetime.now().isoformat()
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO experiment_metadata 
                (experiment_id, description, config, start_time, status)
                VALUES (?, ?, ?, ?, ?)
            """, (experiment_id, description, json.dumps(config), timestamp, 'running'))
        
        self.logger.info(f"실험 시작: {experiment_id} - {description}")
    
    def log_result(self, result: ExperimentResult):
        """실험 결과 로깅"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO experiment_results 
                (experiment_id, model_id, question_id, question, ground_truth, 
                 prediction, input_tokens, output_tokens, latency, cost, 
                 timestamp, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                result.experiment_id, result.model_id, result.question_id,
                result.question, result.ground_truth, result.prediction,
                result.input_tokens, result.output_tokens, result.latency,
                result.cost, result.timestamp, json.dumps(result.metadata)
            ))
    
    def log_experiment_end(self, experiment_id: str):
        """실험 종료 로깅"""
        timestamp = datetime.now().isoformat()
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                UPDATE experiment_metadata 
                SET end_time = ?, status = 'completed'
                WHERE experiment_id = ?
            """, (timestamp, experiment_id))
        
        self.logger.info(f"실험 완료: {experiment_id}")
    
    def calculate_metrics(
        self, 
        experiment_id: str, 
        model_id: str
    ) -> EvaluationMetrics:
        """평가 메트릭 계산"""
        # 실험 결과 조회
        with sqlite3.connect(self.db_path) as conn:
            df = pd.read_sql_query("""
                SELECT * FROM experiment_results 
                WHERE experiment_id = ? AND model_id = ?
            """, conn, params=(experiment_id, model_id))
        
        if df.empty:
            raise ValueError(f"실험 결과를 찾을 수 없습니다: {experiment_id}, {model_id}")
        
        predictions = df['prediction'].tolist()
        ground_truths = df['ground_truth'].tolist()
        
        # 1. Exact Match 계산
        exact_matches = [
            self._normalize_text(pred) == self._normalize_text(gt)
            for pred, gt in zip(predictions, ground_truths)
        ]
        exact_match = np.mean(exact_matches)
        
        # 2. BERT Score 계산
        try:
            bert_p, bert_r, bert_f1 = bert_score(
                predictions, ground_truths, lang='ko', verbose=False
            )
            bert_precision = bert_p.mean().item()
            bert_recall = bert_r.mean().item()
            bert_f1_score = bert_f1.mean().item()
        except Exception as e:
            self.logger.warning(f"BERT Score 계산 실패: {e}")
            bert_precision = bert_recall = bert_f1_score = 0.0
        
        # 3. ROUGE Score 계산
        rouge_scores = [
            self.rouge_scorer.score(gt, pred)
            for gt, pred in zip(ground_truths, predictions)
        ]
        
        rouge1_scores = [score['rouge1'] for score in rouge_scores]
        rouge2_scores = [score['rouge2'] for score in rouge_scores]
        rougeL_scores = [score['rougeL'] for score in rouge_scores]
        
        # 평균 계산
        rouge1_p = np.mean([s.precision for s in rouge1_scores])
        rouge1_r = np.mean([s.recall for s in rouge1_scores])
        rouge1_f = np.mean([s.fmeasure for s in rouge1_scores])
        
        rouge2_p = np.mean([s.precision for s in rouge2_scores])
        rouge2_r = np.mean([s.recall for s in rouge2_scores])
        rouge2_f = np.mean([s.fmeasure for s in rouge2_scores])
        
        rougeL_p = np.mean([s.precision for s in rougeL_scores])
        rougeL_r = np.mean([s.recall for s in rougeL_scores])
        rougeL_f = np.mean([s.fmeasure for s in rougeL_scores])
        
        # 4. 효율성 메트릭
        avg_latency = df['latency'].mean()
        total_cost = df['cost'].sum()
        total_tokens = df['output_tokens'].sum()
        total_time = df['latency'].sum()
        tokens_per_second = total_tokens / total_time if total_time > 0 else 0
        
        metrics = EvaluationMetrics(
            exact_match=exact_match,
            bert_precision=bert_precision,
            bert_recall=bert_recall,
            bert_f1=bert_f1_score,
            rouge1_precision=rouge1_p,
            rouge1_recall=rouge1_r,
            rouge1_f1=rouge1_f,
            rouge2_precision=rouge2_p,
            rouge2_recall=rouge2_r,
            rouge2_f1=rouge2_f,
            rougeL_precision=rougeL_p,
            rougeL_recall=rougeL_r,
            rougeL_f1=rougeL_f,
            average_latency=avg_latency,
            total_cost=total_cost,
            tokens_per_second=tokens_per_second
        )
        
        # 메트릭 저장
        self._save_metrics(experiment_id, model_id, metrics)
        
        return metrics
    
    def _normalize_text(self, text: str) -> str:
        """텍스트 정규화"""
        # 공백 정규화
        text = re.sub(r'\s+', ' ', text.strip())
        # 특수문자 및 따옴표 제거
        text = re.sub(r'["\'\[\]]', '', text)
        return text.lower()
    
    def _save_metrics(
        self, 
        experiment_id: str, 
        model_id: str, 
        metrics: EvaluationMetrics
    ):
        """메트릭을 데이터베이스에 저장"""
        timestamp = datetime.now().isoformat()
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO evaluation_metrics 
                (experiment_id, model_id, exact_match, bert_precision, bert_recall, bert_f1,
                 rouge1_precision, rouge1_recall, rouge1_f1,
                 rouge2_precision, rouge2_recall, rouge2_f1,
                 rougeL_precision, rougeL_recall, rougeL_f1,
                 average_latency, total_cost, tokens_per_second, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                experiment_id, model_id,
                metrics.exact_match, metrics.bert_precision, metrics.bert_recall, metrics.bert_f1,
                metrics.rouge1_precision, metrics.rouge1_recall, metrics.rouge1_f1,
                metrics.rouge2_precision, metrics.rouge2_recall, metrics.rouge2_f1,
                metrics.rougeL_precision, metrics.rougeL_recall, metrics.rougeL_f1,
                metrics.average_latency, metrics.total_cost, metrics.tokens_per_second,
                timestamp
            ))
    
    def generate_comparison_report(
        self, 
        experiment_ids: List[str], 
        output_dir: str = "reports"
    ):
        """모델 성능 비교 리포트 생성"""
        os.makedirs(output_dir, exist_ok=True)
        
        # 메트릭 데이터 수집
        all_metrics = []
        with sqlite3.connect(self.db_path) as conn:
            for exp_id in experiment_ids:
                df = pd.read_sql_query("""
                    SELECT * FROM evaluation_metrics 
                    WHERE experiment_id = ?
                """, conn, params=(exp_id,))
                df['experiment_id'] = exp_id
                all_metrics.append(df)
        
        if not all_metrics:
            self.logger.warning("비교할 메트릭 데이터가 없습니다.")
            return
        
        metrics_df = pd.concat(all_metrics, ignore_index=True)
        
        # 1. 성능 비교 히트맵
        self._create_performance_heatmap(metrics_df, output_dir)
        
        # 2. 모델별 성능 비교 차트
        self._create_model_comparison_charts(metrics_df, output_dir)
        
        # 3. 비용-성능 분석
        self._create_cost_performance_analysis(metrics_df, output_dir)
        
        # 4. 상세 분석 리포트
        self._create_detailed_report(metrics_df, output_dir)
        
        self.logger.info(f"비교 리포트 생성 완료: {output_dir}")
    
    def _create_performance_heatmap(self, df: pd.DataFrame, output_dir: str):
        """성능 메트릭 히트맵 생성"""
        # 주요 메트릭 선택
        key_metrics = [
            'exact_match', 'bert_f1', 'rouge1_f1', 'rouge2_f1', 'rougeL_f1'
        ]
        
        heatmap_data = df.pivot_table(
            values=key_metrics,
            index='model_id',
            columns='experiment_id',
            aggfunc='mean'
        )
        
        # Matplotlib 히트맵
        fig, axes = plt.subplots(2, 3, figsize=(18, 12))
        axes = axes.flatten()
        
        for i, metric in enumerate(key_metrics):
            if i < len(axes):
                sns.heatmap(
                    heatmap_data[metric],
                    annot=True,
                    fmt='.3f',
                    cmap='YlOrRd',
                    ax=axes[i],
                    cbar_kws={'label': 'Score'}
                )
                axes[i].set_title(f'{metric.replace("_", " ").title()}')
        
        # 빈 subplot 제거
        if len(key_metrics) < len(axes):
            for j in range(len(key_metrics), len(axes)):
                fig.delaxes(axes[j])
        
        plt.tight_layout()
        plt.savefig(f'{output_dir}/performance_heatmap.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        # Plotly 인터랙티브 히트맵
        fig = make_subplots(
            rows=2, cols=3,
            subplot_titles=[m.replace('_', ' ').title() for m in key_metrics],
            specs=[[{"secondary_y": False}]*3]*2
        )
        
        for i, metric in enumerate(key_metrics):
            row = i // 3 + 1
            col = i % 3 + 1
            
            heatmap_trace = go.Heatmap(
                z=heatmap_data[metric].values,
                x=heatmap_data[metric].columns,
                y=heatmap_data[metric].index,
                colorscale='Reds',
                showscale=True
            )
            
            fig.add_trace(heatmap_trace, row=row, col=col)
        
        fig.update_layout(
            title="모델 성능 비교 히트맵",
            height=800,
            showlegend=False
        )
        
        fig.write_html(f'{output_dir}/performance_heatmap.html')
    
    def _create_model_comparison_charts(self, df: pd.DataFrame, output_dir: str):
        """모델별 성능 비교 차트"""
        # 주요 메트릭별 막대 차트
        key_metrics = ['exact_match', 'bert_f1', 'rouge1_f1', 'average_latency', 'total_cost']
        
        fig, axes = plt.subplots(2, 3, figsize=(18, 12))
        axes = axes.flatten()
        
        for i, metric in enumerate(key_metrics):
            if i < len(axes):
                df_pivot = df.pivot_table(
                    values=metric,
                    index='model_id',
                    columns='experiment_id',
                    aggfunc='mean'
                )
                
                df_pivot.plot(kind='bar', ax=axes[i], rot=45)
                axes[i].set_title(f'{metric.replace("_", " ").title()}')
                axes[i].legend(title='Experiment')
        
        # 빈 subplot 제거
        if len(key_metrics) < len(axes):
            for j in range(len(key_metrics), len(axes)):
                fig.delaxes(axes[j])
        
        plt.tight_layout()
        plt.savefig(f'{output_dir}/model_comparison.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        # Plotly 인터랙티브 차트
        fig = go.Figure()
        
        for experiment in df['experiment_id'].unique():
            exp_data = df[df['experiment_id'] == experiment]
            
            fig.add_trace(go.Bar(
                x=exp_data['model_id'],
                y=exp_data['bert_f1'],
                name=f'Experiment {experiment}',
                text=exp_data['bert_f1'].round(3),
                textposition='auto'
            ))
        
        fig.update_layout(
            title="모델별 BERT F1 점수 비교",
            xaxis_title="모델",
            yaxis_title="BERT F1 점수",
            barmode='group'
        )
        
        fig.write_html(f'{output_dir}/model_comparison.html')
    
    def _create_cost_performance_analysis(self, df: pd.DataFrame, output_dir: str):
        """비용-성능 분석"""
        # 비용 대비 성능 스캐터 플롯
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
        
        # 비용 vs BERT F1
        scatter1 = ax1.scatter(
            df['total_cost'], 
            df['bert_f1'], 
            c=df['average_latency'], 
            cmap='viridis',
            alpha=0.7,
            s=100
        )
        ax1.set_xlabel('총 비용 ($)')
        ax1.set_ylabel('BERT F1 점수')
        ax1.set_title('비용 vs 성능 (색상: 지연시간)')
        plt.colorbar(scatter1, ax=ax1, label='평균 지연시간 (초)')
        
        # 모델별 라벨
        for i, row in df.iterrows():
            ax1.annotate(
                row['model_id'], 
                (row['total_cost'], row['bert_f1']),
                xytext=(5, 5), 
                textcoords='offset points',
                fontsize=8
            )
        
        # 속도 vs 성능
        ax2.scatter(
            df['tokens_per_second'], 
            df['exact_match'], 
            alpha=0.7,
            s=100
        )
        ax2.set_xlabel('토큰/초')
        ax2.set_ylabel('정확 일치율')
        ax2.set_title('처리 속도 vs 정확도')
        
        for i, row in df.iterrows():
            ax2.annotate(
                row['model_id'], 
                (row['tokens_per_second'], row['exact_match']),
                xytext=(5, 5), 
                textcoords='offset points',
                fontsize=8
            )
        
        plt.tight_layout()
        plt.savefig(f'{output_dir}/cost_performance_analysis.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def _create_detailed_report(self, df: pd.DataFrame, output_dir: str):
        """상세 분석 리포트 생성"""
        report = []
        report.append("# 네트워크 LLM 벤치마크 분석 리포트\n")
        report.append(f"생성 날짜: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # 실험 개요
        report.append("## 실험 개요\n")
        report.append(f"- 총 실험 수: {df['experiment_id'].nunique()}\n")
        report.append(f"- 평가 모델 수: {df['model_id'].nunique()}\n")
        report.append(f"- 실험 모델: {', '.join(df['model_id'].unique())}\n\n")
        
        # 최고 성능 모델
        report.append("## 주요 결과\n")
        
        best_bert = df.loc[df['bert_f1'].idxmax()]
        best_exact = df.loc[df['exact_match'].idxmax()]
        most_efficient = df.loc[df['tokens_per_second'].idxmax()]
        most_cost_effective = df.loc[df['total_cost'].idxmin()]
        
        report.append(f"### 최고 BERT F1 점수\n")
        report.append(f"- 모델: {best_bert['model_id']}\n")
        report.append(f"- 점수: {best_bert['bert_f1']:.4f}\n")
        report.append(f"- 실험: {best_bert['experiment_id']}\n\n")
        
        report.append(f"### 최고 정확 일치율\n")
        report.append(f"- 모델: {best_exact['model_id']}\n")
        report.append(f"- 점수: {best_exact['exact_match']:.4f}\n")
        report.append(f"- 실험: {best_exact['experiment_id']}\n\n")
        
        report.append(f"### 최고 처리 속도\n")
        report.append(f"- 모델: {most_efficient['model_id']}\n")
        report.append(f"- 속도: {most_efficient['tokens_per_second']:.2f} 토큰/초\n")
        report.append(f"- 실험: {most_efficient['experiment_id']}\n\n")
        
        report.append(f"### 최고 비용 효율성\n")
        report.append(f"- 모델: {most_cost_effective['model_id']}\n")
        report.append(f"- 비용: ${most_cost_effective['total_cost']:.6f}\n")
        report.append(f"- 실험: {most_cost_effective['experiment_id']}\n\n")
        
        # 상세 성능 표
        report.append("## 상세 성능 메트릭\n")
        report.append("| 모델 | 실험 | EM | BERT-F1 | ROUGE-1 | ROUGE-L | 지연시간 | 비용 |\n")
        report.append("|------|------|----|---------|---------|---------|---------|----- |\n")
        
        for _, row in df.iterrows():
            report.append(
                f"| {row['model_id']} | {row['experiment_id']} | "
                f"{row['exact_match']:.3f} | {row['bert_f1']:.3f} | "
                f"{row['rouge1_f1']:.3f} | {row['rougeL_f1']:.3f} | "
                f"{row['average_latency']:.2f}s | ${row['total_cost']:.6f} |\n"
            )
        
        report.append("\n")
        
        # 권장사항
        report.append("## 권장사항\n")
        report.append("1. **정확도 우선**: BERT F1 점수가 가장 높은 모델 사용\n")
        report.append("2. **속도 우선**: 토큰/초가 가장 높은 모델 사용\n")
        report.append("3. **비용 효율성**: 비용 대비 성능이 가장 좋은 모델 사용\n")
        report.append("4. **균형잡힌 선택**: 모든 메트릭을 종합적으로 고려한 모델 선택\n\n")
        
        # 파일 저장
        with open(f'{output_dir}/detailed_analysis_report.md', 'w', encoding='utf-8') as f:
            f.writelines(report)
    
    def get_experiment_summary(self, experiment_id: str) -> Dict[str, Any]:
        """특정 실험의 요약 정보 반환"""
        with sqlite3.connect(self.db_path) as conn:
            # 기본 정보
            metadata = pd.read_sql_query("""
                SELECT * FROM experiment_metadata WHERE experiment_id = ?
            """, conn, params=(experiment_id,))
            
            # 메트릭 정보
            metrics = pd.read_sql_query("""
                SELECT * FROM evaluation_metrics WHERE experiment_id = ?
            """, conn, params=(experiment_id,))
            
            # 결과 통계
            results = pd.read_sql_query("""
                SELECT COUNT(*) as total_questions,
                       COUNT(DISTINCT model_id) as total_models,
                       AVG(latency) as avg_latency,
                       SUM(cost) as total_cost
                FROM experiment_results WHERE experiment_id = ?
            """, conn, params=(experiment_id,))
        
        return {
            'metadata': metadata.to_dict('records')[0] if not metadata.empty else {},
            'metrics': metrics.to_dict('records'),
            'statistics': results.to_dict('records')[0] if not results.empty else {}
        }


# 사용 예시
def main():
    """실험 로거 사용 예시"""
    logger = AdvancedExperimentLogger()
    
    # 실험 시작
    experiment_id = f"network_bench_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    logger.log_experiment_start(
        experiment_id,
        "네트워크 설정 Q&A 벤치마크",
        {"models": ["gpt-4", "claude-3"], "dataset": "network_qa_v1"}
    )
    
    # 가상의 실험 결과 로깅
    sample_result = ExperimentResult(
        experiment_id=experiment_id,
        model_id="gpt-4",
        question_id="q001",
        question="BGP 피어링이란 무엇인가요?",
        ground_truth="BGP 피어링은 서로 다른 AS 간의 라우팅 정보 교환을 위한 연결입니다.",
        prediction="BGP 피어링은 두 라우터 간의 BGP 세션을 설정하는 과정입니다.",
        input_tokens=50,
        output_tokens=30,
        latency=2.5,
        cost=0.001,
        timestamp=datetime.now().isoformat()
    )
    
    logger.log_result(sample_result)
    
    # 메트릭 계산
    try:
        metrics = logger.calculate_metrics(experiment_id, "gpt-4")
        print(f"계산된 메트릭: {metrics}")
    except ValueError as e:
        print(f"메트릭 계산 실패: {e}")
    
    # 실험 종료
    logger.log_experiment_end(experiment_id)


if __name__ == "__main__":
    main()
