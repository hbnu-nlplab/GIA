import os
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage

def test_model():
    load_dotenv()
    api_key = os.getenv("OPENROUTER_API_KEY")
    base_url = os.getenv("OPENROUTER_BASE_URL")
    # model_id = os.getenv("OPENROUTER_MODEL4") # This was openai/gpt-5-nano
    model_id = "openai/gpt-5-nano"
    
    print(f"Testing model: {model_id}")
    print(f"Base URL: {base_url}")
    
    chat = ChatOpenAI(
        model=model_id,
        api_key=api_key,
        base_url=base_url,
        temperature=0,
        max_tokens=100
    )
    
    try:
        messages = [
            SystemMessage(content="You are a helpful assistant."),
            HumanMessage(content="Hello, what is your name?")
        ]
        res = chat.invoke(messages)
        print("--- Response Received ---")
        print(f"Content: '{res.content}'")
        print(f"Additional Info: {res.additional_kwargs}")
        print(f"Response Metadata: {res.response_metadata}")
    except Exception as e:
        print(f"--- Error Occurred ---")
        print(e)

if __name__ == "__main__":
    test_model()
