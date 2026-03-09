#!/bin/bash
# 전체 결과 채점 스크립트
# 모든 results_raw_*.json을 찾아서 analyze_results.py 실행

set -euo pipefail
export PYTHONUTF8=1

ROOT_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [[ -x "${ROOT_DIR}/.venv/Scripts/python.exe" ]]; then
    PYTHON="${ROOT_DIR}/.venv/Scripts/python.exe"
elif [[ -x "${ROOT_DIR}/.venv/bin/python" ]]; then
    PYTHON="${ROOT_DIR}/.venv/bin/python"
else
    PYTHON="python3"
fi

echo "=== 전체 결과 채점 ==="
echo ""

TOTAL=0
SUCCESS=0

for raw_file in "${SCRIPT_DIR}"/results/*/Lab*/results_raw_*.json; do
    # 이미 채점된 결과가 있으면 건너뜀
    dir=$(dirname "$raw_file")
    if ls "${dir}"/results_analyzed_*.json 1>/dev/null 2>&1; then
        echo "[SKIP] $(basename $(dirname $(dirname "$raw_file")))/$(basename $(dirname "$raw_file")) — 이미 채점됨"
        continue
    fi

    TOTAL=$((TOTAL + 1))
    model_lab="$(basename $(dirname $(dirname "$raw_file")))/$(basename $(dirname "$raw_file"))"
    echo "[${TOTAL}] 채점: ${model_lab}"

    if "${PYTHON}" "${SCRIPT_DIR}/analyze_results.py" "$raw_file" 2>&1 | tail -15; then
        SUCCESS=$((SUCCESS + 1))
    else
        echo "  [FAIL] 채점 실패"
    fi
    echo ""
done

echo "=== 채점 완료: ${SUCCESS}/${TOTAL} ==="
