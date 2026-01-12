import sys
import requests
import json
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent))
from config.load_env import load_louter

try:
    api_key, base_url, m1, m2, m3 = load_louter()
    print(f"Testing API Key: {api_key[:10]}...")
    print(f"Base URL: {base_url}")
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "HTTP-Referer": "https://github.com/hbnu-nlplab/GIA",
        "X-Title": "GIA MultiAgent",
        "Content-Type": "application/json"
    }
    
    data = {
        "model": m1,
        "messages": [
            {"role": "user", "content": "Hello, simply say 'ok'."}
        ]
    }
    
    # LangChain ChatOpenAI appends /chat/completions automatically, but here we do it manually.
    # Check if base_url already has it or not. Usually base_url is ".../v1".
    url = f"{base_url}/chat/completions"
    
    print(f"Sending request to: {url}")
    response = requests.post(url, headers=headers, json=data)
    
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.text}")

except Exception as e:
    print(f"Error: {e}")
