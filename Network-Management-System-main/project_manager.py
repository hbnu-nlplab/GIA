#!/usr/bin/env python3
"""
Network LLM Benchmark 프로젝트 관리 유틸리티
설치, 설정, 실행, 모니터링을 위한 통합 도구
"""

import os
import sys
import subprocess
import json
import argparse
from pathlib import Path
from typing import List, Dict, Any
import shutil


class ProjectManager:
    """프로젝트 관리 클래스"""
    
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.config_files = [
            'enhanced_llm_configs.json',
            'enhanced_benchmark_config.json'
        ]
        
    def setup_environment(self):
        """환경 설정 및 의존성 설치"""
        print("🚀 Network LLM Benchmark 환경 설정 시작...")
        
        # 1. Python 버전 확인
        print("✅ Python 버전 확인...")
        python_version = sys.version_info
        if python_version.major < 3 or python_version.minor < 8:
            print("❌ Python 3.8 이상이 필요합니다.")
            return False
        print(f"   Python {python_version.major}.{python_version.minor}.{python_version.micro}")
        
        # 2. 가상환경 생성 권장
        print("\n📦 가상환경 사용을 권장합니다:")
        print("   python -m venv network_llm_env")
        print("   # Windows: network_llm_env\\Scripts\\activate")
        print("   # Linux/Mac: source network_llm_env/bin/activate")
        
        # 3. 의존성 설치
        print("\n📚 의존성 패키지 설치 중...")
        try:
            subprocess.run([
                sys.executable, "-m", "pip", "install", "-r", "enhanced_requirements.txt"
            ], check=True, cwd=self.project_root)
            print("✅ 의존성 설치 완료")
        except subprocess.CalledProcessError:
            print("❌ 의존성 설치 실패. requirements.txt를 확인해주세요.")
            return False
        
        # 4. 설정 파일 초기화
        self.init_config_files()
        
        # 5. 디렉토리 구조 생성
        self.create_directories()
        
        print("\n🎉 환경 설정 완료!")
        print("\n다음 단계:")
        print("1. API 키 설정: python project_manager.py setup-keys")
        print("2. 데이터셋 확인: python project_manager.py check-data") 
        print("3. 첫 실험 실행: python project_manager.py run-demo")
        
        return True
    
    def init_config_files(self):
        """설정 파일 초기화"""
        print("\n⚙️ 설정 파일 초기화...")
        
        for config_file in self.config_files:
            if not (self.project_root / config_file).exists():
                print(f"❌ {config_file}이 없습니다. 템플릿을 먼저 생성해주세요.")
            else:
                print(f"✅ {config_file} 확인됨")
    
    def create_directories(self):
        """필요한 디렉토리 생성"""
        directories = [
            'reports',
            'logs',
            'experiments',
            'models',
            'temp',
            'chroma_network_db'
        ]
        
        print("\n📁 디렉토리 구조 생성...")
        for dir_name in directories:
            dir_path = self.project_root / dir_name
            dir_path.mkdir(exist_ok=True)
            print(f"✅ {dir_name}/ 생성")
    
    def setup_api_keys(self):
        """API 키 설정 도우미"""
        print("\n🔑 API 키 설정...")
        
        env_file = self.project_root / '.env'
        
        # 기존 .env 파일 읽기
        env_vars = {}
        if env_file.exists():
            with open(env_file, 'r') as f:
                for line in f:
                    if '=' in line and not line.startswith('#'):
                        key, value = line.strip().split('=', 1)
                        env_vars[key] = value
        
        # API 키 입력 받기
        api_keys = {
            'OPENAI_API_KEY': 'OpenAI API 키 (GPT 모델용)',
            'ANTHROPIC_API_KEY': 'Anthropic API 키 (Claude 모델용)',
            'GOOGLE_API_KEY': 'Google API 키 (검색용)',
            'GOOGLE_CSE_ID': 'Google Custom Search Engine ID',
            'HUGGINGFACE_TOKEN': 'HuggingFace 토큰 (선택사항)'
        }
        
        for key, description in api_keys.items():
            current_value = env_vars.get(key, '')
            if current_value:
                print(f"✅ {key}: 설정됨 ({'*' * min(8, len(current_value))})")
                continue
                
            print(f"\n{description}")
            value = input(f"{key} 입력 (건너뛰려면 Enter): ").strip()
            
            if value:
                env_vars[key] = value
                print(f"✅ {key} 설정됨")
            else:
                print(f"⏭️ {key} 건너뜀")
        
        # .env 파일 저장
        with open(env_file, 'w') as f:
            f.write("# Network LLM Benchmark API Keys\n")
            f.write("# 이 파일을 Git에 커밋하지 마세요!\n\n")
            for key, value in env_vars.items():
                f.write(f"{key}={value}\n")
        
        print(f"\n✅ API 키 설정이 {env_file}에 저장되었습니다.")
        print("⚠️ 주의: .env 파일을 Git에 커밋하지 마세요!")
    
    def check_dataset(self):
        """데이터셋 상태 확인"""
        print("\n📊 데이터셋 상태 확인...")
        
        dataset_path = self.project_root / 'dataset' / 'test.csv'
        
        if not dataset_path.exists():
            print(f"❌ 데이터셋을 찾을 수 없습니다: {dataset_path}")
            print("다음 위치에서 데이터셋을 복사해주세요:")
            print("- dataset/test.csv")
            return False
        
        try:
            # 기본적인 파일 정보
            file_size = dataset_path.stat().st_size
            print(f"✅ 데이터셋 파일 발견: {file_size} bytes")
            
            # 첫 몇 줄 읽기
            with open(dataset_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                
            if len(lines) > 0:
                print(f"   총 라인 수: {len(lines)}")
                print(f"   헤더: {lines[0].strip()}")
                
                if len(lines) > 1:
                    print(f"   샘플: {lines[1][:100]}...")
            
            # pandas 사용 가능하면 상세 정보
            try:
                import pandas as pd
                df = pd.read_csv(dataset_path)
                print(f"✅ 상세 분석: {len(df)}개 질문")
                print(f"   컬럼: {list(df.columns)}")
            except Exception as e:
                print(f"⚠️ 상세 분석 실패 (pandas 문제): {e}")
            
            return True
            
        except Exception as e:
            print(f"❌ 데이터셋 확인 실패: {e}")
            return False
    
    def check_models(self):
        """사용 가능한 모델 확인"""
        print("\n🤖 모델 상태 확인...")
        
        try:
            # LLM 설정 로드
            config_path = self.project_root / 'enhanced_llm_configs.json'
            with open(config_path, 'r', encoding='utf-8') as f:
                configs = json.load(f)
            
            print(f"✅ {len(configs)}개 모델 설정 발견:")
            
            for model_id, config in configs.items():
                provider = config.get('provider', 'unknown')
                model_name = config.get('model_name', 'unknown')
                description = config.get('description', '')
                
                # API 키 확인 (환경변수)
                key_status = "❓"
                if provider == 'openai':
                    key_status = "✅" if os.getenv('OPENAI_API_KEY') else "❌"
                elif provider == 'anthropic':
                    key_status = "✅" if os.getenv('ANTHROPIC_API_KEY') else "❌"
                elif provider in ['huggingface', 'ollama']:
                    key_status = "🔓"  # API 키 불필요
                
                print(f"   {key_status} {model_id} ({provider}): {description}")
            
            return True
            
        except Exception as e:
            print(f"❌ 모델 설정 확인 실패: {e}")
            return False
    
    def run_demo(self):
        """데모 실험 실행"""
        print("\n🎬 데모 실험 실행...")
        
        # 사전 조건 확인
        if not self.check_dataset():
            return False
        
        if not self.check_models():
            return False
        
        print("\n작은 샘플로 빠른 테스트를 실행합니다...")
        
        # 간단한 테스트 실행
        try:
            cmd = [
                sys.executable, 
                "enhanced_benchmark_runner.py",
                "--models", "gpt-3.5-turbo",  # 빠르고 저렴한 모델
                "--experiments", "baseline",   # 간단한 실험
                "--sample-sizes", "5",         # 작은 샘플
                "--output-dir", "demo_reports"
            ]
            
            print(f"실행 명령: {' '.join(cmd)}")
            subprocess.run(cmd, cwd=self.project_root, check=True)
            
            print("\n🎉 데모 실험 완료!")
            print("결과는 demo_reports/ 디렉토리에서 확인할 수 있습니다.")
            
        except subprocess.CalledProcessError as e:
            print(f"❌ 데모 실행 실패: {e}")
            print("로그를 확인하고 설정을 다시 검토해주세요.")
            return False
        
        return True
    
    def system_info(self):
        """시스템 정보 표시"""
        print("\n💻 시스템 정보:")
        
        # Python 정보
        print(f"Python: {sys.version}")
        
        # GPU 정보
        try:
            import torch
            if torch.cuda.is_available():
                print(f"CUDA: {torch.version.cuda}")
                print(f"GPU: {torch.cuda.get_device_name()}")
                print(f"GPU 메모리: {torch.cuda.get_device_properties(0).total_memory // 1024**3}GB")
            else:
                print("CUDA: 사용 불가")
        except (ImportError, AttributeError) as e:
            print(f"PyTorch: 미설치 또는 호환성 문제 ({e})")
        
        # 메모리 정보
        try:
            import psutil
            memory = psutil.virtual_memory()
            print(f"RAM: {memory.total // 1024**3}GB (사용가능: {memory.available // 1024**3}GB)")
        except ImportError:
            print("메모리 정보: 확인 불가")
        
        # 디스크 공간
        try:
            disk = shutil.disk_usage(self.project_root)
            print(f"디스크 여유공간: {disk.free // 1024**3}GB")
        except:
            print("디스크 정보: 확인 불가")
    
    def clean_temp_files(self):
        """임시 파일 정리"""
        print("\n🧹 임시 파일 정리...")
        
        temp_patterns = [
            '__pycache__',
            '*.pyc',
            '.pytest_cache',
            'temp/*',
            'logs/*.log'
        ]
        
        import glob
        
        for pattern in temp_patterns:
            files = glob.glob(str(self.project_root / pattern), recursive=True)
            for file_path in files:
                try:
                    if os.path.isdir(file_path):
                        shutil.rmtree(file_path)
                    else:
                        os.remove(file_path)
                    print(f"✅ 삭제됨: {file_path}")
                except Exception as e:
                    print(f"❌ 삭제 실패 {file_path}: {e}")
        
        print("🎉 정리 완료!")


def main():
    manager = ProjectManager()
    
    parser = argparse.ArgumentParser(description='Network LLM Benchmark 프로젝트 관리자')
    parser.add_argument('command', choices=[
        'setup', 'setup-keys', 'check-data', 'check-models', 
        'run-demo', 'system-info', 'clean'
    ], help='실행할 명령')
    
    args = parser.parse_args()
    
    print("🌐 Network LLM Benchmark 프로젝트 관리자")
    print("=" * 50)
    
    if args.command == 'setup':
        manager.setup_environment()
    elif args.command == 'setup-keys':
        manager.setup_api_keys()
    elif args.command == 'check-data':
        manager.check_dataset()
    elif args.command == 'check-models':
        manager.check_models()
    elif args.command == 'run-demo':
        manager.run_demo()
    elif args.command == 'system-info':
        manager.system_info()
    elif args.command == 'clean':
        manager.clean_temp_files()


if __name__ == "__main__":
    main()
