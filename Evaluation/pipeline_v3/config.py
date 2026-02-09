import os
from pathlib import Path

def load_env_file():
    current_dir = Path(__file__).parent
    env_file = current_dir / "openai_key.env"
    if env_file.exists():
        print(f"📁 .env 파일 로드 중: {env_file}")
        loaded_keys = 0
        with open(env_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip().strip('"').strip("'")
                    
                    value = ''.join(value.split())
                    
                    if not os.getenv(key) and value:
                        os.environ[key] = value
                        if key.startswith('OPENAI_API_KEY'):
                            loaded_keys += 1
                            print(f"✅ {key}: 로드됨 (...{value[-8:]})")
        
        if loaded_keys > 0:
            print(f"🔑 총 {loaded_keys}개 API 키 로드 완료")
    else:
        print(f"⚠️ .env 파일을 찾을 수 없습니다: {env_file}")