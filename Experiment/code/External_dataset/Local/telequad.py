"""
TeleQuAD 데이터셋 전용 모듈
============================================
- 4,485개 QA 문제 (3GPP Specs, ShareTechNote 기반)
- SQuAD 스타일 추출형 QA
- 대표 메트릭: Token F1

데이터 형식:
{
    "version": "TeleQuAD-v4-full",
    "data": [
        {
            "docid": "1",
            "title": "3GPP-Specs#...",
            "paragraphs": [
                {
                    "context": "...",
                    "qas": [
                        {
                            "id": "uuid",
                            "type": "SHORT" | "LONG",
                            "question": "...",
                            "answers": [{"text": "...", "answer_start": N, "answer_end": M}],
                            "is_impossible": false
                        }
                    ]
                }
            ]
        }
    ]
}
"""

import json
import re
from typing import List, Dict, Any
from .base import BaseDataset, DataItem, SamplingConfig


class TeleQuADDataset(BaseDataset):
    """TeleQuAD: Telecom Question Answering Dataset (SQuAD 스타일)"""
    
    name = "telequad"
    description = "TeleQuAD - 4,485 QA pairs from 3GPP and ShareTechNote"
    
    # 대표 메트릭: Token F1 (SQuAD 스타일)
    primary_metric = "F1"
    
    # 샘플링 설정: 짧은 추출형 답변
    sampling_config = SamplingConfig(
        temperature=0.0,
        top_p=1.0,
        max_tokens=128,       # SHORT 타입은 짧지만 LONG도 있으므로 여유있게
        stop=["\n\n", "---", "###", "Question:", "Context:"],
        use_structured_output=False,  # 추출형은 structured output 불필요
    )
    
    def load(self, path: str) -> List[DataItem]:
        """TeleQuAD JSON 로드"""
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        
        items = []
        
        for doc in raw.get("data", []):
            doc_id = doc.get("docid", "")
            doc_title = doc.get("title", "")
            doc_source = doc.get("source", "")
            
            for para in doc.get("paragraphs", []):
                context = para.get("context", "")
                
                for qa in para.get("qas", []):
                    qa_id = qa.get("id", "")
                    question = qa.get("question", "")
                    q_type = qa.get("type", "SHORT")  # SHORT or LONG
                    is_impossible = qa.get("is_impossible", False)
                    
                    # 답변 처리
                    answers = qa.get("answers", [])
                    if answers:
                        # 첫 번째 답변 사용
                        gold = answers[0]["text"]
                        all_answers = [a["text"] for a in answers]
                    else:
                        gold = ""
                        all_answers = []
                    
                    # is_impossible인 경우 스킵하거나 빈 답변 처리
                    if is_impossible:
                        gold = ""
                    
                    items.append(DataItem(
                        id=qa_id,
                        question=question,
                        context=context,
                        gold=gold,
                        metadata={
                            "doc_id": doc_id,
                            "doc_title": doc_title,
                            "doc_source": doc_source,
                            "question_type": q_type,
                            "is_impossible": is_impossible,
                            "all_answers": all_answers,
                        }
                    ))
        
        self._items = items
        return items
    
    def get_system_prompt(self) -> str:
        """TeleQuAD 시스템 프롬프트"""
        return """You are a Telecommunications Expert. Extract the answer from the given context.

RULES:
1. Read the context carefully.
2. Find the exact answer span in the context.
3. Output ONLY the extracted text - no explanations.
4. Keep answers concise: technical values, parameters, or short phrases.
5. If asked about numbers with units, include both (e.g., "100 Mbps").
6. Do NOT paraphrase - use exact wording from context when possible."""
    
    def build_user_prompt(self, item: DataItem) -> str:
        """TeleQuAD 사용자 프롬프트"""
        return f"""Context:
{item.context}

Question:
{item.question}

Answer:"""
    
    def parse_response(self, response: str) -> str:
        """
        TeleQuAD 응답 파싱
        - 불필요한 설명 제거
        - 핵심 답변만 추출
        """
        if not response or not isinstance(response, str):
            return ""
        
        response = response.strip()
        
        # <think> 태그 제거 (Qwen3 등)
        response = re.sub(r'<think>.*?</think>', '', response, flags=re.DOTALL).strip()
        
        # 코드 블록 내용 추출 (있다면)
        code_match = re.search(r'```(?:\w+)?\s*(.*?)```', response, flags=re.DOTALL)
        if code_match:
            return code_match.group(1).strip()
        
        # 인라인 코드 제거 (백틱만 제거, 내용은 유지)
        response = re.sub(r'`([^`]+)`', r'\1', response).strip()
        
        # Pattern 1: "Answer: ..." 형식
        match = re.search(r'^(?:Answer|A)[:\s]+(.+)', response, re.IGNORECASE | re.MULTILINE)
        if match:
            return match.group(1).strip()
        
        # Pattern 2: "The answer is..." 형식
        match = re.search(r'(?:the\s+)?answer\s+is[:\s]+["\']?([^"\']+)["\']?', response, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        
        # Pattern 3: 따옴표 안의 텍스트 (짧은 것 우선)
        matches = re.findall(r'"([^"]{1,200})"', response)
        if matches:
            # 가장 짧은 것 선택 (보통 정답)
            shortest = min(matches, key=len)
            if len(shortest) < 150:
                return shortest.strip()
        
        # Pattern 4: 첫 문장만 추출 (마침표 기준)
        first_sentence = re.split(r'[.!?]\s+', response)[0]
        if len(first_sentence) < 200:
            return first_sentence.strip()
        
        # Fallback: 첫 줄 (150자 제한)
        first_line = response.split('\n')[0].strip().strip('"\'')
        return first_line[:150]
    
    def compute_f1(self, pred: str, gold: str) -> float:
        """
        TeleQuAD F1: SQuAD 스타일 정규화 적용
        """
        def squad_normalize(text: str) -> str:
            """SQuAD 스타일 정규화"""
            if not text:
                return ""
            text = text.lower()
            # Remove articles
            text = re.sub(r'\b(a|an|the)\b', ' ', text)
            # Remove punctuation (but keep hyphens for compound terms)
            text = re.sub(r'[^\w\s\-]', '', text)
            # Remove extra whitespace
            text = ' '.join(text.split())
            return text
        
        pred_norm = squad_normalize(pred)
        gold_norm = squad_normalize(gold)
        
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
        """TeleQuAD 메트릭: F1 중심 + 전체 메트릭"""
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
