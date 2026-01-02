"""
TeleQnA 데이터셋 전용 모듈
============================================
- 10,000개 객관식 문제 (5개 카테고리)
- Lexicon(500), Research Overview(2000), Research Publications(4500), 
  Standards Overview(1000), Standards Specifications(2000)
- 대표 메트릭: Accuracy (= option 번호 일치)

데이터 형식:
{
    "question X": {
        "question": "...",
        "option 1": "...",
        "option 2": "...",
        ...
        "answer": "option X: 내용",
        "explanation": "...",
        "category": "..."
    }
}
"""

import json
import re
from typing import List, Dict, Any
from .base import BaseDataset, DataItem, SamplingConfig


# TeleQnA용 Structured Output 스키마 (vLLM guided generation)
TELEQNA_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "option": {
            "type": "integer",
            "minimum": 1,
            "maximum": 6,
            "description": "선택한 옵션 번호 (1-6)"
        }
    },
    "required": ["option"]
}


class TeleQnADataset(BaseDataset):
    """TeleQnA: Telecom QA 객관식 데이터셋"""
    
    name = "teleqna"
    description = "TeleQnA - 10,000 multiple-choice questions for telecom knowledge assessment"
    
    # 대표 메트릭: Accuracy (객관식이므로 option 번호 일치 여부)
    primary_metric = "Accuracy"
    
    # 샘플링 설정: 객관식은 짧은 응답이 필요하지만, 추론 모델을 위해 토큰 대폭 상향
    sampling_config = SamplingConfig(
        temperature=0.0,      # 결정적 생성 필수
        top_p=1.0,
        max_tokens=8192,      # Qwen3, GPT-OSS 등 추론 모델을 위해 충분한 공간 확보
        stop=["---", "###", "Question:", "Explanation:"], # \n\n 제거 (Reasoning 모델 대응)
        # Structured Output 옵션 (선택적)
        use_structured_output=False,
        response_schema=TELEQNA_RESPONSE_SCHEMA,
    )

    def load(self, path: str) -> List[DataItem]:
        """TeleQnA JSON 로드"""
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        
        items = []
        
        # TeleQnA는 {"question 0": {...}, "question 1": {...}} 형식
        if isinstance(raw, dict):
            iterator = raw.items()
        else:
            iterator = enumerate(raw)
        
        for key, item in iterator:
            if isinstance(key, str) and key.startswith("question"):
                # "question 123" → "123"
                item_id = key.replace("question ", "").strip()
            else:
                item_id = str(key)
            
            if "question" not in item:
                continue
            
            # 옵션 추출 및 정렬 (option 1 ~ option 6까지 가능)
            options = {k: v for k, v in item.items() if k.startswith("option ")}
            sorted_keys = sorted(
                options.keys(), 
                key=lambda x: int(x.split()[-1]) if x.split()[-1].isdigit() else 99
            )
            options_str = "\n".join([f"{k}: {options[k]}" for k in sorted_keys])
            
            # 정답에서 option 번호 추출
            answer = str(item.get("answer", ""))
            
            items.append(DataItem(
                id=item_id,
                question=item["question"],
                context=options_str,  # 옵션들을 context로 사용
                gold=answer.lower(),
                metadata={
                    "category": item.get("category", ""),
                    "explanation": item.get("explanation", ""),
                    "options": options,
                    "num_options": len(options),
                }
            ))
        
        self._items = items
        return items
    
    def get_system_prompt(self) -> str:
        """TeleQnA 시스템 프롬프트 (Few-shot + 정답 강제)"""
        return """You are a Senior Telecommunications Engineer taking a multiple-choice exam.

RULES:
1. Select the single best answer from the given options.
2. Use your expert knowledge of telecom standards (3GPP, IEEE, etc.).
3. Output ONLY your answer in this exact format: "option N: [answer text]"
4. Do NOT include any reasoning, thoughts, or explanations. 
5. Start your response immediately with "option"."""
    
    def build_user_prompt(self, item: DataItem) -> str:
        """TeleQnA 사용자 프롬프트 (Local 버전)"""
        return f"""Question:
{item.question}

Options:
{item.context}

Your answer:"""
    
    def parse_response(self, response: str) -> str:
        """
        TeleQnA 응답 파싱
        - "option X: ..." 형식 추출
        - 번호만 있어도 허용
        """
        if not response or not isinstance(response, str):
            return ""
        
        response = response.strip()
        
        # 1. <think> 태그 제거 (Qwen3 등)
        response = re.sub(r'<think>.*?</think>', '', response, flags=re.DOTALL).strip()
        
        # 2. Reasoning 모델의 특수 키워드 처리 (Mistral, GPT-OSS 등)
        # "assistant", "final", "analysis", "thought" 등의 키워드 이후의 내용만 취함
        for marker in ["assistant", "final", "Answer:", "Result:"]:
            if marker.lower() in response.lower():
                # 마지막 발생 지점 이후를 답변으로 간주
                parts = re.split(re.escape(marker), response, flags=re.IGNORECASE)
                if len(parts) > 1:
                    response = parts[-1].strip()
        
        # "analysis", "thought" 등으로 시작하는 경우 해당 문구 제거
        response = re.sub(r'^(?:analysis|thought|reasoning)[:\s]*', '', response, flags=re.IGNORECASE).strip()
        
        # JSON 응답 처리 (structured output 사용 시)
        if response.startswith("{"):
            try:
                import json
                data = json.loads(response)
                if "option" in data:
                    return f"option {data['option']}"
            except:
                pass
        
        # Pattern 1: "option X: content" 형식 (정확한 형식)
        match = re.search(r'option\s*(\d+)\s*:\s*(.+?)(?:\n|$)', response, re.IGNORECASE)
        if match:
            return f"option {match.group(1)}: {match.group(2).strip()}"
        
        # Pattern 2: "option X" 만 있는 경우
        match = re.search(r'option\s*(\d+)', response, re.IGNORECASE)
        if match:
            return f"option {match.group(1)}"
        
        # Pattern 3: 숫자만 있는 경우 (1, 2, 3...)
        match = re.search(r'^[\s\*\-]*(\d+)[\s\.\)]*', response)
        if match and 1 <= int(match.group(1)) <= 6:
            return f"option {match.group(1)}"
        
        # Pattern 4: "The answer is option X" / "correct answer is X"
        match = re.search(r'(?:answer|correct)\s*(?:is)?\s*(?:option)?\s*(\d+)', response, re.IGNORECASE)
        if match:
            return f"option {match.group(1)}"
        
        # Pattern 5: "(A)" 또는 "A)" 형식 → option 번호로 변환
        match = re.search(r'\(?\s*([A-F])\s*\)?', response)
        if match:
            letter = match.group(1).upper()
            num = ord(letter) - ord('A') + 1
            return f"option {num}"
        
        # Fallback: 첫 100자
        return response[:100]
    
    def compute_em(self, pred: str, gold: str) -> float:
        """
        TeleQnA EM: option 번호만 비교
        - "option 1: xxx" vs "option 1: yyy" → 1.0 (번호 일치)
        """
        pred_match = re.search(r'option\s*(\d+)', pred.lower())
        gold_match = re.search(r'option\s*(\d+)', gold.lower())
        
        if pred_match and gold_match:
            return 1.0 if pred_match.group(1) == gold_match.group(1) else 0.0
        return 0.0
    
    def compute_all_metrics(self, predictions: List[str], references: List[str]) -> Dict[str, float]:
        """TeleQnA 메트릭: Accuracy 중심 + 전체 메트릭"""
        em_scores = []
        f1_scores = []
        
        for pred, ref in zip(predictions, references):
            em = self.compute_em(pred, ref)
            f1 = self.compute_f1(pred, ref)
            em_scores.append(em)
            f1_scores.append(f1)
        
        accuracy = sum(em_scores) / len(em_scores) * 100 if em_scores else 0.0
        
        return {
            "Accuracy": accuracy,
            "EM": accuracy,  # TeleQnA에서는 EM = Accuracy
            "F1": sum(f1_scores) / len(f1_scores) * 100 if f1_scores else 0.0,
            "Correct": int(sum(em_scores)),
            "Total": len(predictions),
        }
