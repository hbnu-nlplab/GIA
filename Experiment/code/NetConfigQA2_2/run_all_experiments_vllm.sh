#!/bin/bash
# NetConfigQA2.0 VLLM Offline 전체 실험 실행 스크립트
#
# A5000 등 VLLM을 지원하는 GPU 서버에서 직접 실행합니다.
# 이미 Ollama로 진행되었거나 기존 결과가 있는 실험은 건너뜁니다.
#
# 사용법:
#   bash Experiment/code/NetConfigQA2_2/run_all_experiments_vllm.sh

set -euo pipefail
export PYTHONUTF8=1

# === 마스터 로그 파일 설정 (전체 stdout+stderr 자동 저장) ===
LOG_BASE_DIR="$(cd "$(dirname "$0")" && pwd)/logs"
mkdir -p "${LOG_BASE_DIR}"
MASTER_LOG="${LOG_BASE_DIR}/vllm_all_$(date '+%Y%m%d_%H%M%S').log"
exec > >(tee -a "${MASTER_LOG}") 2>&1
echo "[LOG] 전체 실행 로그: ${MASTER_LOG}"

ROOT_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
EVAL_SCRIPT="${ROOT_DIR}/Experiment/code/NetConfigQA2_2/run_eval_vllm_offline.py"
RESULT_DIR="${ROOT_DIR}/Experiment/code/NetConfigQA2_2/results"

# Python 바이너리
if [[ -x "${ROOT_DIR}/.venv/Scripts/python.exe" ]]; then
    PYTHON="${ROOT_DIR}/.venv/Scripts/python.exe"
elif [[ -x "${ROOT_DIR}/.venv/bin/python" ]]; then
    PYTHON="${ROOT_DIR}/.venv/bin/python"
else
    PYTHON="python3"
fi

# VLLM 스크립트에서 사용하는 모델 목록 (HuggingFace 경로 기반 내부 매핑 사용)
MODELS=(
    "gpt-oss:20b"
    "qwen3-coder:30b-a3b-AWQ"
    # "gemma3:27b-it-AWQ"
    "glm-4.7-flash-AWQ"
    "Qwen3.5-27B-AWQ"
    "gpt-4o-mini"
)

LABS=("A" "B" "C" "D")

# Display name 매핑 (결과 디렉토리 확인용)
declare -A DISPLAY_NAMES
DISPLAY_NAMES["gpt-oss:20b"]="GPT-OSS-20B"
DISPLAY_NAMES["qwen3-coder:30b-a3b-AWQ"]="Qwen3-Coder"
# DISPLAY_NAMES["gemma3:27b-it-AWQ"]="Gemma-3-27B"
DISPLAY_NAMES["glm-4.7-flash-AWQ"]="GLM-4.7-Flash"
DISPLAY_NAMES["Qwen3.5-27B-AWQ"]="Qwen3.5-27B"
DISPLAY_NAMES["gpt-4o-mini"]="GPT-4o-mini"

TOTAL=$(( ${#MODELS[@]} * ${#LABS[@]} ))
CURRENT=0
SKIPPED=0
COMPLETED=0
FAILED=0

echo "============================================================"
echo "  NetConfigQA2.0 VLLM Offline 전체 실험"
echo "  모델: ${#MODELS[@]}개 × Lab: ${#LABS[@]}개 = ${TOTAL}회"
echo "  시작: $(date '+%Y-%m-%d %H:%M:%S')"
echo "============================================================"
echo ""

START_TIME=$(date +%s)

for MODEL in "${MODELS[@]}"; do
    DISPLAY="${DISPLAY_NAMES[$MODEL]}"
    LABS_TO_RUN=()

    # 모델 별로 실행해야 할 Lab 필터링 (불필요한 모델 로딩 방지)
    for LAB in "${LABS[@]}"; do
        CURRENT=$((CURRENT + 1))
        
        # 이미 결과 파일(VLLM 또는 Ollama)이 있는지 확인
        RESULT_CHECK="${RESULT_DIR}/${DISPLAY}/Lab${LAB}"
        if [[ -d "$RESULT_CHECK" ]] && (ls "${RESULT_CHECK}"/results_raw_*.json 1>/dev/null 2>&1); then
            echo "[${CURRENT}/${TOTAL}] ${DISPLAY} × Lab-${LAB} — 이미 완료, 건너뜀"
            SKIPPED=$((SKIPPED + 1))
        else
            LABS_TO_RUN+=("$LAB")
        fi
    done

    # 실행할 Lab이 하나라도 있으면 이 모델에 대해 VLLM 스크립트 실행
    if [ ${#LABS_TO_RUN[@]} -gt 0 ]; then
        echo ""
        echo "============================================================"
        echo ">> 모델 시작: ${DISPLAY} (대상 Labs: ${LABS_TO_RUN[*]})"
        echo "   시작: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "============================================================"
        
        # 모델 단위로 실행하여 VLLM 엔진을 메모리에 한 번만 올리도록 함
        if "${PYTHON}" "${EVAL_SCRIPT}" --model "${MODEL}" --lab "${LABS_TO_RUN[@]}" 2>&1 | tee -a "${ROOT_DIR}/Experiment/code/NetConfigQA2_2/logs/vllm_experiments_${DISPLAY}.log"; then
            COMPLETED=$((COMPLETED + ${#LABS_TO_RUN[@]}))
            echo "[OK] ${DISPLAY} 완료"
        else
            # 일부 성공/실패 여부를 정확히 세려면 파이썬 자체의 반환값에 의존해야 하나, 
            # 일단 에러 발생시 이 모델의 나머지 Lab들이 모두 실패했다고 간주
            FAILED=$((FAILED + ${#LABS_TO_RUN[@]}))
            echo "[FAIL] ${DISPLAY} 평가 중 오류 발생"
        fi
        
        # 다음 모델을 위해 잠시 대기
        echo "GPU 메모리 정리 대기 중 (15초)..."
        sleep 15
    fi
done

END_TIME=$(date +%s)
DURATION=$(( (END_TIME - START_TIME) / 60 ))

echo ""
echo "============================================================"
echo "  전체 VLLM 실험 완료"
echo "  총 성공(Lab기준): ${COMPLETED} / 실패: ${FAILED} / 건너뜀: ${SKIPPED}"
echo "  총 소요 시간: ${DURATION}분"
echo "  종료: $(date '+%Y-%m-%d %H:%M:%S')"
echo "============================================================"
echo ""
echo "다음 단계:"
echo "  채점: python analyze_results.py results/*/Lab*/results_raw_*.json"
