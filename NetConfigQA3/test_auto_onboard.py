"""
Auto Onboard 테스트 스크립트

PNETLab Lab을 NSO에 자동으로 등록하는 전체 워크플로우 테스트

Usage:
    # 전체 프로세스 (SSH 설정 포함)
    python test_auto_onboard.py

    # SSH 스킵 (이미 SSH가 설정된 경우)
    python test_auto_onboard.py --skip-ssh

    # Lab 이름 지정
    python test_auto_onboard.py --lab-name "MyLab"

    # 디버그 모드
    python test_auto_onboard.py --debug
"""

import asyncio
import argparse
import logging
import sys
from pathlib import Path
import os

# 현재 디렉토리를 path에 추가
sys.path.insert(0, str(Path(__file__).parent))

from clients.pnetlab import PnetlabClient
from clients.nso import NSOClient
from config.settings import settings
from automation.onboard import auto_onboard_lab, print_onboard_summary


def setup_logging(debug: bool = False):
    """로깅 설정"""
    level = logging.DEBUG if debug else logging.INFO
    
    # 포맷 설정
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    # 콘솔 핸들러
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(logging.Formatter(log_format))
    
    # 파일 핸들러
    log_file = Path(__file__).parent / "logs" / "auto_onboard.log"
    log_file.parent.mkdir(exist_ok=True)
    
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(log_format))
    
    # 루트 로거 설정
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)
    
    # 로그 파일 위치 출력
    if debug:
        print(f"[LOG] 로그 파일: {log_file}\n")


def parse_args():
    """명령행 인자 파싱"""
    parser = argparse.ArgumentParser(
        description='PNETLab Lab을 NSO에 자동 등록',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  # 전체 프로세스
  python test_auto_onboard.py

  # SSH 설정 스킵
  python test_auto_onboard.py --skip-ssh

  # Lab 이름 지정
  python test_auto_onboard.py --lab-name "MyLab"

  # 디버그 모드
  python test_auto_onboard.py --debug
        """
    )
    
    parser.add_argument(
        '--skip-ssh',
        action='store_true',
        help='SSH 설정을 스킵합니다 (이미 설정된 경우)'
    )
    
    parser.add_argument(
        '--lab-name',
        type=str,
        default=None,
        help='Lab 이름을 지정합니다 (기본값: 자동 감지)'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='디버그 모드로 실행합니다'
    )
    
    parser.add_argument(
        '--no-save',
        action='store_true',
        help='Inventory 파일을 저장하지 않습니다'
    )
    
    return parser.parse_args()


async def main():
    """메인 함수"""
    # 인자 파싱
    args = parse_args()

    # Windows PowerShell(cp949)에서 이모지/특수문자 출력 시 UnicodeEncodeError 방지
    # (가능하면 UTF-8로 재설정)
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
            sys.stderr.reconfigure(encoding="utf-8")
        except Exception:
            pass
    
    # 로깅 설정
    setup_logging(debug=args.debug)
    logger = logging.getLogger(__name__)
    
    print("\n" + "="*70)
    print("NetConfigQA3 - 자동 온보딩")
    print("="*70)
    print(f"\nPNETLab: {settings.pnetlab.base_url}")
    print(f"NSO: {settings.nso.base_url}")
    
    if args.skip_ssh:
        print("\n[주의] SSH 설정을 스킵합니다. 장비에 SSH가 이미 설정되어 있어야 합니다.")
    
    if args.lab_name:
        print(f"\nLab 이름: {args.lab_name}")
    else:
        print(f"\nLab 이름: 자동 감지")
    
    print("\n시작 중...\n")
    
    try:
        # 클라이언트 생성
        logger.info("클라이언트 초기화...")
        
        pnetlab_client = PnetlabClient(
            base_url=settings.pnetlab.base_url,
            username=settings.pnetlab.username,
            password=settings.pnetlab.password,
            timeout=settings.pnetlab.timeout
        )
        
        nso_client = NSOClient(
            base_url=settings.nso.base_url,
            username=settings.nso.username,
            password=settings.nso.password
        )
        
        logger.info("✅ 클라이언트 초기화 완료")
        
        # 자동 온보딩 실행
        result = await auto_onboard_lab(
            pnetlab_client=pnetlab_client,
            nso_client=nso_client,
            lab_name=args.lab_name,
            skip_ssh=args.skip_ssh,
            save_inventory=not args.no_save
        )
        
        # 결과 출력
        print_onboard_summary(result)
        
        # 종료 코드 결정
        status = result.get("status", "failed")
        if status == "completed":
            return 0
        elif status == "partial":
            return 1
        else:
            return 2
            
    except KeyboardInterrupt:
        print("\n\n[중단] 사용자에 의해 중단되었습니다.")
        logger.info("사용자 중단")
        return 130
        
    except Exception as e:
        print(f"\n❌ 예외 발생: {e}")
        logger.exception("예외 발생")
        
        if args.debug:
            import traceback
            print("\n" + "="*70)
            print("디버그 정보:")
            print("="*70)
            traceback.print_exc()
        
        return 3


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
