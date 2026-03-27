#!/bin/bash
# 전체 결과 채점 스크립트
# 모든 results_raw_*.json을 찾아서 analyze_results.py 실행

set -euo pipefail
shopt -s nullglob
export PYTHONUTF8=1

ROOT_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LANGUAGE_FILTER="all"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --language)
            if [[ $# -lt 2 ]]; then
                echo "Usage: $0 [--language en|ko|all]"
                exit 1
            fi
            LANGUAGE_FILTER="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--language en|ko|all]"
            exit 1
            ;;
    esac
done

if [[ "${LANGUAGE_FILTER}" != "all" && "${LANGUAGE_FILTER}" != "en" && "${LANGUAGE_FILTER}" != "ko" ]]; then
    echo "Invalid --language value: ${LANGUAGE_FILTER}"
    echo "Usage: $0 [--language en|ko|all]"
    exit 1
fi

if [[ -x "${ROOT_DIR}/NetAlly/.venv/Scripts/python.exe" ]]; then
    PYTHON="${ROOT_DIR}/NetAlly/.venv/Scripts/python.exe"
elif [[ -x "${ROOT_DIR}/NetAlly/.venv/bin/python" ]]; then
    PYTHON="${ROOT_DIR}/NetAlly/.venv/bin/python"
elif [[ -x "${ROOT_DIR}/.venv/Scripts/python.exe" ]]; then
    PYTHON="${ROOT_DIR}/.venv/Scripts/python.exe"
elif [[ -x "${ROOT_DIR}/.venv/bin/python" ]]; then
    PYTHON="${ROOT_DIR}/.venv/bin/python"
else
    PYTHON="python3"
fi

echo "=== 전체 결과 채점 ==="
echo "Language filter: ${LANGUAGE_FILTER}"
echo ""

TOTAL=0
SUCCESS=0

for raw_file in "${SCRIPT_DIR}"/results_2/*/Lab*/results_raw_*.json; do
    if [[ "${LANGUAGE_FILTER}" == "en" && "$(basename "$raw_file")" != *"_en_"* ]]; then
        continue
    fi
    if [[ "${LANGUAGE_FILTER}" == "ko" && "$(basename "$raw_file")" != *"_ko_"* ]]; then
        continue
    fi

    # 이미 채점된 결과가 있으면 건너뜀
    dir=$(dirname "$raw_file")
    analyzed_file="${raw_file/results_raw_/results_analyzed_}"
    if [[ -f "${analyzed_file}" ]]; then
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
