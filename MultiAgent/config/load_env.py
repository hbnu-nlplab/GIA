import os
from pathlib import Path
from dotenv import load_dotenv

# MultiAgent 루트의 .env를 명시적으로 로드 (nika/.env보다 우선)
_ROOT_ENV = Path(__file__).resolve().parent.parent / ".env"

def load_louter():
    load_dotenv(dotenv_path=_ROOT_ENV, override=True)
    api_key = os.getenv("OPENROUTER_API_KEY")
    base_url = os.getenv("OPENROUTER_BASE_URL")
    model1 = os.getenv("OPENROUTER_MODEL1")
    model2 = os.getenv("OPENROUTER_MODEL2")
    # model3 = os.getenv("OPENROUTER_MODEL3") 
    # model4 = os.getenv("OPENROUTER_MODEL4")
    # model5 = os.getenv("OPENROUTER_MODEL5")
    # return api_key, base_url, model1, model2, model3, model4, model5
    return api_key, base_url, model1, model2
    
def load_api_key():
    load_dotenv()
    api_key = os.getenv("OPEN_API_KEY")
    return api_key