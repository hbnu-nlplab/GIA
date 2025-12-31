"""
NetBench 데이터셋 전용 모듈
============================================
- ~5,390개 전문가 수준 QA (20개 통신/네트워크 카테고리)
- 자유형 답변 (설명, 설정, 코드 등)
- 코드블록/설정 보존 필수!
- 대표 메트릭: Token F1

데이터 형식 (CSV):
| Main Category | Category | Scenario_ID | Context | Question | Answer |

Answer 특성:
- 긴 설명 (여러 문장)
- 기술적 reasoning 포함
- 때로는 설정 예시 포함 (CLI, YAML 등)
"""

import re
import pandas as pd
from typing import List, Dict, Any
from .base import BaseDataset, DataItem, SamplingConfig


class NetBenchDataset(BaseDataset):
    """NetBench: Network SME Intelligence Benchmark"""
    
    name = "netbench"
    description = "NetBench - ~5,390 expert-level QA pairs across 20 telecom/network categories"
    
    # 대표 메트릭: Token F1
    primary_metric = "F1"
    
    # 샘플링 설정: 설명이 필요하므로 길게
    sampling_config = SamplingConfig(
        temperature=0.0,
        top_p=1.0,
        max_tokens=512,       # 답변이 길 수 있음 (설명 + 예시)
        stop=["---", "###", "\n\nQuestion:", "\n\nContext:"],
        # 주의: stop을 너무 강하게 걸면 설명이 잘림
        use_structured_output=False,  # 자유형 답변이므로 structured output 불필요
    )
    
    def load(self, path: str) -> List[DataItem]:
        """NetBench CSV 로드"""
        df = pd.read_csv(path)
        
        items = []
        for idx, row in df.iterrows():
            scenario_id = str(row.get("Scenario_ID", idx))
            
            items.append(DataItem(
                id=scenario_id,
                question=str(row.get("Question", "")),
                context=str(row.get("Context", "")),
                gold=str(row.get("Answer", "")),
                metadata={
                    "main_category": str(row.get("Main Category", "")),
                    "category": str(row.get("Category", "")),
                }
            ))
        
        self._items = items
        return items
    
    def get_system_prompt(self) -> str:
        """NetBench 시스템 프롬프트"""
        return """You are a Senior Network Engineer with expertise across routing, switching, security, and telecom.

TASK: Answer the question based on the given context.

RULES:
1. Provide expert-level technical answers.
2. Include relevant reasoning and best practices.
3. If the answer involves configurations:
   - Output the exact config commands/syntax
   - Use proper formatting (CLI commands, YAML, JSON as appropriate)
4. Reference standards and protocols when relevant (BGP, OSPF, MPLS, etc.).
5. Be concise but complete - cover the key technical points."""
    
    def build_user_prompt(self, item: DataItem) -> str:
        """NetBench 사용자 프롬프트"""
        return f"""Context:
{item.context}

Question:
{item.question}

Answer:"""
    
    def parse_response(self, response: str) -> str:
        """
        NetBench 응답 파싱
        - 코드블록 보존 필수!
        - 코드블록이 있으면 그 내용을 우선 답으로 사용
        """
        if not response or not isinstance(response, str):
            return ""
        
        response = response.strip()
        
        # <think> 태그 제거 (Qwen3 등)
        response = re.sub(r'<think>.*?</think>', '', response, flags=re.DOTALL).strip()
        
        # === 핵심: 코드블록 있으면 텍스트 + 코드블록 모두 보존 ===
        # 코드블록 삭제하면 안 됨! (답이 config로 나올 수 있음)
        
        # verbose 마커만 제거
        response = re.sub(r'^analysis[:\s]*', '', response, flags=re.IGNORECASE).strip()
        response = re.sub(r'^assistantfinal[:\s]*', '', response, flags=re.IGNORECASE).strip()
        
        # "Answer:" 접두사 제거 (있다면)
        match = re.match(r'^(?:Answer|A)[:\s]+', response, re.IGNORECASE)
        if match:
            response = response[match.end():].strip()
        
        # 전체 응답 반환 (truncate 없음 - NetBench는 긴 답변이 정상)
        return response
    
    def compute_f1(self, pred: str, gold: str) -> float:
        """
        NetBench F1: 정규화 포함 (코드블록 보존)
        """
        def netbench_normalize(text: str) -> str:
            """NetBench용 정규화 (코드블록 내용 보존)"""
            if not text:
                return ""
            
            # 코드블록 내용 추출 (있으면 별도 처리)
            code_blocks = re.findall(r'```(?:\w+)?\s*(.*?)```', text, flags=re.DOTALL)
            
            # 일반 텍스트 정규화
            text_clean = re.sub(r'```(?:\w+)?\s*.*?```', '', text, flags=re.DOTALL)
            text_clean = text_clean.lower()
            # 기술 용어에서 중요한 문자 보존 (하이픈, 슬래시, 콜론, 점)
            text_clean = re.sub(r'[^\w\s\-\./:,]', '', text_clean)
            text_clean = ' '.join(text_clean.split())
            
            # 코드블록 내용도 추가 (정규화 최소화)
            for block in code_blocks:
                # 코드는 대소문자 구분이 중요할 수 있으므로 원본 유지
                block_clean = ' '.join(block.split())
                text_clean += ' ' + block_clean.lower()
            
            return text_clean.strip()
        
        pred_norm = netbench_normalize(pred)
        gold_norm = netbench_normalize(gold)
        
        pred_tokens = pred_norm.split()
        gold_tokens = gold_norm.split()
        
        if not pred_tokens or not gold_tokens:
            return 0.0
        
        common = set(pred_tokens) & set(gold_tokens)
        if not common:
            return 0.0
        
        num_common = sum(min(pred_tokens.count(t), gold_tokens.count(t)) for t in common)
        precision = num_common / len(pred_tokens)
        recall = num_common / len(gold_tokens)
        
        if precision + recall == 0:
            return 0.0
        return 2 * (precision * recall) / (precision + recall)
    
    def compute_all_metrics(self, predictions: List[str], references: List[str]) -> Dict[str, float]:
        """NetBench 메트릭: F1 중심 + 전체 메트릭"""
        em_scores = []
        f1_scores = []
        
        for pred, ref in zip(predictions, references):
            em_scores.append(self.compute_em(pred, ref))
            f1_scores.append(self.compute_f1(pred, ref))
        
        return {
            "F1": sum(f1_scores) / len(f1_scores) * 100 if f1_scores else 0.0,
            "EM": sum(em_scores) / len(em_scores) * 100 if em_scores else 0.0,
            "Total": len(predictions),
        }
