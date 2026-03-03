#!/bin/bash
# NetConfigQA2.0 전체 실험 실행 스크립트
# 6모델 × 4Lab = 24회 순차 실행
#
# 사용법:
#   bash Experiment/code/NetConfigQA2_2/run_all_experiments.sh
#
# GPT-OSS-20B × Lab-A가 이미 완료되었으면 건너뜁니다.
# 실행 도중 Ctrl+C로 중단 후 다시 실행하면, 이미 결과가 있는 조합은 건너뜁니다.

set -euo pipefail
export PYTHONUTF8=1

ROOT_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
EVAL_SCRIPT="${ROOT_DIR}/Experiment/code/NetConfigQA2_2/run_eval.py"
RESULT_DIR="${ROOT_DIR}/Experiment/code/NetConfigQA2_2/results"

# Python 바이너리
if [[ -x "${ROOT_DIR}/.venv/Scripts/python.exe" ]]; then
    PYTHON="${ROOT_DIR}/.venv/Scripts/python.exe"
elif [[ -x "${ROOT_DIR}/.venv/bin/python" ]]; then
    PYTHON="${ROOT_DIR}/.venv/bin/python"
else
    PYTHON="python3"
fi

# 모델 목록 (Ollama 태그)
MODELS=(
    "gpt-oss:20b"
    "qwen3-coder:30b-a3b-q4_K_M"
    "gemma3:27b-it-q4_K_M"
    "glm-4.7-flash:q4_K_M"
    "qwen3.5:27b"
)
# GPT-4o-mini는 OpenAI API — 별도 실행 필요
# MODELS+=("gpt-4o-mini")

# Lab 목록
LABS=("A" "B" "C" "D")

# Display name 매핑 (결과 폴더 확인용)
declare -A DISPLAY_NAMES
DISPLAY_NAMES["gpt-oss:20b"]="GPT-OSS-20B"
DISPLAY_NAMES["qwen3-coder:30b-a3b-q4_K_M"]="Qwen3-Coder"
DISPLAY_NAMES["gemma3:27b-it-q4_K_M"]="Gemma-3-27B"
DISPLAY_NAMES["glm-4.7-flash:q4_K_M"]="GLM-4.7-Flash"
DISPLAY_NAMES["qwen3.5:27b"]="Qwen3.5-27B"

# 총 실험 수 계산
TOTAL=$(( ${#MODELS[@]} * ${#LABS[@]} ))
CURRENT=0
SKIPPED=0
COMPLETED=0
FAILED=0

echo "============================================================"
echo "  NetConfigQA2.0 전체 실험 실행"
echo "  모델: ${#MODELS[@]}개 × Lab: ${#LABS[@]}개 = ${TOTAL}회"
echo "  시작: $(date '+%Y-%m-%d %H:%M:%S')"
echo "============================================================"
echo ""

START_TIME=$(date +%s)

for MODEL in "${MODELS[@]}"; do
    DISPLAY="${DISPLAY_NAMES[$MODEL]}"

    for LAB in "${LABS[@]}"; do
        CURRENT=$((CURRENT + 1))

        # 이미 결과가 있는지 확인
        RESULT_CHECK="${RESULT_DIR}/${DISPLAY}/Lab${LAB}"
        if [[ -d "$RESULT_CHECK" ]] && ls "${RESULT_CHECK}"/results_raw_*.json 1>/dev/null 2>&1; then
            echo "[${CURRENT}/${TOTAL}] ${DISPLAY} × Lab-${LAB} — 이미 완료, 건너뜀"
            SKIPPED=$((SKIPPED + 1))
            continue
        fi

        echo ""
        echo "============================================================"
        echo "[${CURRENT}/${TOTAL}] ${DISPLAY} × Lab-${LAB}"
        echo "  시작: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "============================================================"

        if "${PYTHON}" "${EVAL_SCRIPT}" --model "${MODEL}" --lab "${LAB}" 2>&1; then
            COMPLETED=$((COMPLETED + 1))
            echo "[OK] ${DISPLAY} × Lab-${LAB} 완료"
        else
            FAILED=$((FAILED + 1))
            echo "[FAIL] ${DISPLAY} × Lab-${LAB} 실패"
        fi

        # 모델 전환 시 Ollama가 이전 모델을 언로드할 시간
        echo "  모델 전환 대기 (10초)..."
        sleep 10
    done
done

END_TIME=$(date +%s)
DURATION=$(( (END_TIME - START_TIME) / 60 ))

echo ""
echo "============================================================"
echo "  전체 실험 완료"
echo "  완료: ${COMPLETED} / 실패: ${FAILED} / 건너뜀: ${SKIPPED}"
echo "  총 소요: ${DURATION}분"
echo "  종료: $(date '+%Y-%m-%d %H:%M:%S')"
echo "============================================================"
echo ""
echo "다음 단계:"
echo "  1. 채점: python analyze_results.py results/*/Lab*/results_raw_*.json"
echo "  2. GPT-4o-mini 별도 실행: python run_eval.py --model gpt-4o-mini --lab all --backend openai"
