import subprocess
import sys
import os
import json

# ==========================================
# ▼▼▼ 사용자 설정 (JSON 파일에서 로드) ▼▼▼
# ==========================================

# 설정 파일 경로
CONFIG_FILE = r"c:\Users\Yujin\CodeSpace\GIA\Data\Pnetlab\L2VPN\device_info.json"

def load_config(filepath):
    print(f"[DEBUG] 설정 파일 로드 중: {filepath}")
    if not os.path.exists(filepath):
        print(f"[Error] 설정 파일을 찾을 수 없습니다: {filepath}")
        sys.exit(1)
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)
    print(f"[DEBUG] JSON 로드 성공")
    return data

# JSON 로드
try:
    config_data = load_config(CONFIG_FILE)
    global_settings = config_data.get('global_settings', {})
    devices_data = config_data.get('devices', [])
    print(f"[DEBUG] 로드된 장비 수: {len(devices_data)}")
except Exception as e:
    print(f"[Error] JSON 파일 로드 중 오류 발생: {e}")
    import traceback
    print(f"[DEBUG] 상세 오류:\n{traceback.format_exc()}")
    sys.exit(1)

# 1. NSO 도커 컨테이너 이름
CONTAINER_NAME = "cisco-nso-dev"

# 2. 추출된 설정을 저장할 내 PC의 경로 (JSON 파일이 있는 폴더)
OUTPUT_DIR = os.path.dirname(CONFIG_FILE)
print(f"[DEBUG] 출력 디렉토리: {OUTPUT_DIR}")

# 3. 추출할 장비 목록 (JSON에서 가져옴)
TARGET_DEVICES = [d['name'] for d in devices_data]
print(f"[DEBUG] 대상 장비: {TARGET_DEVICES}")

# ==========================================

def run_nso_cmd(cmd_input):
    """
    NSO CLI 명령어를 Docker 컨테이너 내부에서 실행하고 결과를 반환하는 함수
    """
    full_cmd = f'docker exec {CONTAINER_NAME} bash -c "cd ~/ncs-instance && source ~/nso-6.6/ncsrc && echo \\"{cmd_input}\\" | ncs_cli -C -u admin"'
    print(f"  [DEBUG] 실행 명령: {cmd_input[:80]}...")
    try:
        result = subprocess.run(full_cmd, shell=True, capture_output=True, text=True, encoding='utf-8')
        print(f"  [DEBUG] Return code: {result.returncode}")
        if result.returncode != 0:
            print(f"  [WARNING] Stderr: {result.stderr[:200]}")
        return result.stdout
    except Exception as e:
        print(f"[Error] Docker 명령어 실행 실패: {e}")
        sys.exit(1)

def get_all_devices():
    """NSO에 등록된 모든 장비 이름을 동적으로 가져옵니다."""
    print("[DEBUG] NSO에서 장비 목록을 조회 중...")
    output = run_nso_cmd("show devices list")
    
    devices = []
    lines = output.splitlines()
    print(f"[DEBUG] NSO 출력 라인 수: {len(lines)}")
    for line in lines:
        parts = line.split()
        if len(parts) >= 2 and parts[0] not in ["NAME", "admin@ncs#", "System"]:
             if not parts[0].startswith("-"): 
                devices.append(parts[0])
                print(f"  [DEBUG] 발견된 장비: {parts[0]}")
    
    return sorted(list(set(devices)))

def clean_config(raw_config):
    """
    NSO live-status에서 가져온 실제 장비 설정을 Batfish 형식으로 정제합니다.
    """
    print(f"  [DEBUG] 설정 정제 시작 (원본 길이: {len(raw_config)} bytes)")
    lines = raw_config.splitlines()
    cleaned_lines = []
    skip_until_config = True

    for line in lines:
        if "admin@ncs#" in line or "admin@ncs%" in line:
            continue
        if "live-status exec" in line or "devices device" in line:
            continue
        if line.strip().startswith("result"):
            skip_until_config = False
            continue
        if line.strip().endswith("#") and len(line.strip().split()) == 1:
            continue
        if skip_until_config and not line.strip():
            continue
        if line.strip() and (line.startswith("!") or "version" in line or "Building configuration" in line or "Current configuration" in line):
            skip_until_config = False
        
        if not skip_until_config:
            cleaned_lines.append(line)

    result = "\n".join(cleaned_lines)
    print(f"  [DEBUG] 정제 완료 (정제 후 길이: {len(result)} bytes, {len(cleaned_lines)} lines)")
    return result

def main():
    print("\n" + "="*60)
    print("=== Batfish용 설정 추출 시작 ===")
    print("="*60 + "\n")
    
    # 1. 저장할 디렉토리 구조 생성 (configs, xml 폴더)
    configs_dir = os.path.join(OUTPUT_DIR, "configs")
    xml_dir = os.path.join(OUTPUT_DIR, "xml")
    
    print(f"[1단계] 디렉토리 구조 생성")
    print(f"  - CFG 폴더: {configs_dir}")
    print(f"  - XML 폴더: {xml_dir}")
    
    for directory in [configs_dir, xml_dir]:
        if not os.path.exists(directory):
            try:
                os.makedirs(directory)
                print(f"  ✓ 폴더 생성 완료: {directory}")
            except OSError as e:
                print(f"  ✗ 폴더 생성 실패: {e}")
                sys.exit(1)
        else:
            print(f"  ✓ 저장 경로 확인: {directory}")

    # 2. 장비 목록 확보
    print(f"\n[2단계] 장비 목록 확보")
    if TARGET_DEVICES:
        device_list = TARGET_DEVICES
        print(f"  ✓ JSON 설정 파일에서 {len(device_list)}개 장비를 로드했습니다.")
        print(f"  장비 목록: {device_list}")
    else:
        print(f"  [INFO] JSON에 장비가 없어 NSO에서 조회합니다...")
        device_list = get_all_devices()
        print(f"  ✓ NSO에서 {len(device_list)}개 장비를 발견했습니다: {device_list}")

    if not device_list:
        print("[Warning] 추출할 장비가 없습니다.")
        return

    # 3. 각 장비 설정 추출 및 저장 (CFG + XML)
    print(f"\n[3단계] 설정 추출 및 저장")
    print(f"{'='*60}")
    success_count = 0
    
    for i, device in enumerate(device_list, 1):
        print(f"\n[{i}/{len(device_list)}] {device} 처리 중...")
        print(f"{'-'*60}")
        
        # 3-1. CFG 형식 (show running-config)
        print(f"  [CFG] 설정 다운로드 중...")
        cmd_cfg = f"devices device {device} live-status exec show running-config"
        raw_output_cfg = run_nso_cmd(cmd_cfg)
        
        print(f"  [DEBUG] CFG 출력 길이: {len(raw_output_cfg)} bytes")
        
        if "syntax error" in raw_output_cfg or "Error" in raw_output_cfg:
             print(f"  ✗ [CFG Fail] 설정을 가져오지 못했습니다.")
             print(f"  [DEBUG] 출력 내용: {raw_output_cfg[:200]}")
             continue

        final_config = clean_config(raw_output_cfg)
        
        # CFG 파일 저장
        cfg_path = os.path.join(configs_dir, f"{device}.cfg")
        try:
            with open(cfg_path, "w", encoding="utf-8") as f:
                f.write(final_config)
            print(f"  ✓ [CFG Success] 저장 완료: {cfg_path}")
            print(f"    파일 크기: {len(final_config)} bytes")
        except IOError as e:
             print(f"  ✗ [CFG Fail] 파일 쓰기 실패: {e}")
             continue
        
        # 3-2. XML 형식 (show running-config | display xml)
        print(f"  [XML] 설정 다운로드 중...")
        cmd_xml = f"devices device {device} live-status exec show running-config | display xml"
        raw_output_xml = run_nso_cmd(cmd_xml)
        
        print(f"  [DEBUG] XML 출력 길이: {len(raw_output_xml)} bytes")
        
        if "syntax error" in raw_output_xml or "Error" in raw_output_xml:
             print(f"  ✗ [XML Fail] 설정을 가져오지 못했습니다.")
             print(f"  [DEBUG] 출력 내용: {raw_output_xml[:200]}")
             # CFG는 성공했으므로 계속 진행
        else:
            # XML 파일 저장 (정제 없이 그대로 저장)
            xml_path = os.path.join(xml_dir, f"{device}.xml")
            try:
                with open(xml_path, "w", encoding="utf-8") as f:
                    f.write(raw_output_xml)
                print(f"  ✓ [XML Success] 저장 완료: {xml_path}")
                print(f"    파일 크기: {len(raw_output_xml)} bytes")
            except IOError as e:
                 print(f"  ✗ [XML Fail] 파일 쓰기 실패: {e}")
        
        success_count += 1
        print(f"  ✓ {device} 처리 완료!")

    print(f"\n{'='*60}")
    print(f"=== 작업 완료 ===")
    print(f"총 {len(device_list)}개 중 {success_count}개 장비 처리 성공")
    print(f"CFG 파일: {configs_dir}")
    print(f"XML 파일: {xml_dir}")
    print(f"{'='*60}\n")

if __name__ == "__main__":
    print("[DEBUG] 스크립트 시작\n")
    main()
    print("[DEBUG] 스크립트 종료")