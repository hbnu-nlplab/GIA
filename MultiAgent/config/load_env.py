import os
from dotenv import load_dotenv

def load_louter():
    load_dotenv()
    api_key = os.getenv("OPENROUTER_API_KEY")
    base_url = os.getenv("OPENROUTER_BASE_URL")
    model1 = os.getenv("OPENROUTER_MODEL1")
    model2 = os.getenv("OPENROUTER_MODEL2")
    model3 = os.getenv("OPENROUTER_MODEL3") 
    model4 = os.getenv("OPENROUTER_MODEL4")
    model5 = os.getenv("OPENROUTER_MODEL5")
    return api_key, base_url, model1, model2, model3, model4, model5
    
def load_api_key():
    load_dotenv()
    api_key = os.getenv("OPEN_API_KEY")
    return api_key