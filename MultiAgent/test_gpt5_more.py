import os
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage

def test_model():
    load_dotenv()
    api_key = os.getenv("OPENROUTER_API_KEY")
    base_url = "https://openrouter.ai/api/v1"
    model_id = "openai/gpt-5-nano"
    
    chat = ChatOpenAI(
        model=model_id,
        api_key=api_key,
        base_url=base_url,
        temperature=0,
        max_tokens=1000 # Increased tokens
    )
    
    try:
        messages = [
            HumanMessage(content="Explain the Alamouti scheme briefly.")
        ]
        res = chat.invoke(messages)
        print(f"Content: '{res.content}'")
        print(f"Reasoning Tokens: {res.response_metadata.get('token_usage', {}).get('completion_tokens_details', {}).get('reasoning_tokens')}")
        print(f"Finish Reason: {res.response_metadata.get('finish_reason')}")
    except Exception as e:
        print(e)

if __name__ == "__main__":
    test_model()
