import json
import sys
import os
from typing import TypedDict, Literal
from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage
from langgraph.graph import StateGraph, END

sys.path.append('../')
from load_env import load_louter

QUESTION_DIR = "../../data/qa_paragraph/paragraphs_1.json"
OUTPUT_DIR = "../../data/qa_paragraph/knowledge_debate_results.json"

api_key, base_url, model1, model2, model3 = load_louter()

class DebateState(TypedDict):
    question: str
    paragraph: str 
    result: str    
    iteration: int

llm_gpt = ChatOpenAI(api_key=api_key, base_url=base_url, model=model1, temperature=0.7)
llm_claude = ChatOpenAI(api_key=api_key, base_url=base_url, model=model2, temperature=0.7)
llm_gemini = ChatOpenAI(api_key=api_key, base_url=base_url, model=model3, temperature=0.5)

def parse_json_response(content, default_paragraph, default_result):
    try:
        clean_content = content.replace("```json", "").replace("```", "").strip()
        data = json.loads(clean_content)
        return data.get("paragraph", default_paragraph), data.get("result", default_result)
    except Exception:
        return default_paragraph, default_result

def node_gpt(state: DebateState):
    question = state["question"]
    paragraph = state["paragraph"]
    result = state["result"]
    
    prompt_text = f"""
    당신은 네트워크 관리자(GPT-4o-mini)입니다.
    
    # 목표
    1. Paragraph(지식): 질문을 해결하기 위해 필요한 배경 지식과 기술적 맥락을 확장하고 보강하세요. (정답 자체가 아니라 정답을 도출하기 위한 지식 베이스입니다.)
    2. Result(정답): 위에서 보강된 지식을 바탕으로 질문에 대한 구체적인 정답을 도출하거나 수정하세요.
    
    # 입력
    - 질문: {question}
    - 현재 지식(Paragraph): {paragraph}
    - 이전 정답(Result): {result if result else "없음 (초기 상태)"}
    
    # 출력 형식 (JSON)
    {{
        "paragraph": "보강된 배경 지식 텍스트...",
        "result": "도출된 정답 텍스트..."
    }}
    """
    
    messages = [
        SystemMessage(content="You are a JSON-speaking network expert."),
        HumanMessage(content=prompt_text)
    ]
    response = llm_gpt.invoke(messages)
    new_p, new_r = parse_json_response(response.content, paragraph, result)
    
    return {"paragraph": new_p, "result": new_r}

def node_claude(state: DebateState):
    question = state["question"]
    paragraph = state["paragraph"]
    result = state["result"]
    
    prompt_text = f"""
    당신은 네트워크 관리자(Claude 3.5 Haiku)입니다.
    
    # 목표
    1. Paragraph(지식): GPT가 확장한 지식에 기술적 오류나 누락이 있는지 검토하고 더 정교하게 다듬으세요.
    2. Result(정답): 현재 지식을 근거로 GPT가 도출한 정답이 논리적으로 타당한지 비판하고 개선하세요.
    
    # 입력
    - 질문: {question}
    - 현재 지식(Paragraph): {paragraph}
    - 현재 정답(Result): {result}
    
    # 출력 형식 (JSON)
    {{
        "paragraph": "검토 및 수정된 배경 지식...",
        "result": "개선된 정답..."
    }}
    """

    messages = [
        SystemMessage(content="You are a JSON-speaking network expert."),
        HumanMessage(content=prompt_text)
    ]
    response = llm_claude.invoke(messages)
    new_p, new_r = parse_json_response(response.content, paragraph, result)
    
    return {"paragraph": new_p, "result": new_r}

def node_gemini(state: DebateState):
    question = state["question"]
    paragraph = state["paragraph"]
    result = state["result"]
    iteration = state["iteration"]

    prompt_text = f"""
    당신은 네트워크 관리자(Gemini 1.5 Flash)입니다. 이번 회차를 마무리합니다.
    
    # 목표
    1. Paragraph(지식): 질문에 완벽하게 대응할 수 있도록 지식 베이스를 최종 정리하세요.
    2. Result(정답): 정리된 지식을 바탕으로 현 시점에서 가장 정확한 최적의 정답을 확정하세요.
    
    # 입력
    - 질문: {question}
    - 현재 지식(Paragraph): {paragraph}
    - 현재 정답(Result): {result}
    
    # 출력 형식 (JSON)
    {{
        "paragraph": "최종 정리된 배경 지식...",
        "result": "최종 도출된 정답..."
    }}
    """

    messages = [
        SystemMessage(content="You are a JSON-speaking network expert."),
        HumanMessage(content=prompt_text)
    ]
    
    response = llm_gemini.invoke(messages)
    new_p, new_r = parse_json_response(response.content, paragraph, result)

    return {
        "paragraph": new_p,
        "result": new_r,
        "iteration": iteration + 1
    }

def check_loop(state: DebateState) -> Literal["gpt", "end"]:
    if state["iteration"] < 3:
        return "gpt"
    return "end"

workflow = StateGraph(DebateState)

workflow.add_node("gpt", node_gpt)
workflow.add_node("claude", node_claude)
workflow.add_node("gemini", node_gemini)

workflow.set_entry_point("gpt")

workflow.add_edge("gpt", "claude")
workflow.add_edge("claude", "gemini")

workflow.add_conditional_edges(
    "gemini",
    check_loop,
    {
        "gpt": "gpt",
        "end": END
    }
)

graph = workflow.compile()

def run_knowledge_debate():
    if not os.path.exists(QUESTION_DIR):
        print(f"File not found: {QUESTION_DIR}")
        return

    with open(QUESTION_DIR, 'r', encoding='utf-8') as f:
        data_list = json.load(f)

    results = []
    
    print(f"Starting Knowledge Augmentation Loop ({len(data_list)} items)...")

    for item in data_list:
        question = item.get('question', '')
        paragraph = item.get('paragraph', '') # 초기 지식
        
        initial_state = {
            "question": question,
            "paragraph": paragraph,
            "result": "", # 초기 정답 없음
            "iteration": 0
        }

        final_state = graph.invoke(initial_state)

        results.append({
            "question": question,
            "final_knowledge_paragraph": final_state["paragraph"],
            "final_answer_result": final_state["result"],
            "iterations": final_state["iteration"]
        })
        print(f"Completed: {question[:30]}...")

    os.makedirs(os.path.dirname(OUTPUT_DIR), exist_ok=True)
    with open(OUTPUT_DIR, 'w', encoding='utf-8') as f:
        json.dump(results, f, ensure_ascii=False, indent=4)
    
    print(f"Saved to {OUTPUT_DIR}")

if __name__ == "__main__":
    run_knowledge_debate()