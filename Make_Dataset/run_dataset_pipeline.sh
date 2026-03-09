#!/usr/bin/env bash
set -euo pipefail
export PYTHONUTF8=1
export PYTHONIOENCODING=utf-8

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB_PATH="${ROOT_DIR}/Data/Pnetlab/LabA_Research_Institute_DC_10nodes"
POLICIES_PATH="${ROOT_DIR}/Make_Dataset/policies.json"
BATFISH_HOST="192.168.146.129"
OUT_DIR=""
MIN_PER_CAT="50"
INCLUDE_L6="0"
QUESTION_LANG="ko"
SEED="42"

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Options:
  --lab-path <path>       Lab path (default: ${LAB_PATH})
  --policies <path>       policies.json path (default: ${POLICIES_PATH})
  --batfish-host <host>   Batfish host (default: ${BATFISH_HOST})
  --out-dir <path>        Dataset output directory (default: <lab-path>/Dataset)
  --min-per-cat <int>     Minimum per category target (default: ${MIN_PER_CAT})
  --seed <int>            Deterministic seed for question instantiation (default: ${SEED})
  --question-lang <lang>  Question language: ko | en | both (default: ${QUESTION_LANG}, IEEE제출=ko)
  --include-l6            Include L6 generation (default: disabled)
  -h, --help              Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --lab-path)
      LAB_PATH="$2"
      shift 2
      ;;
    --policies)
      POLICIES_PATH="$2"
      shift 2
      ;;
    --batfish-host)
      BATFISH_HOST="$2"
      shift 2
      ;;
    --out-dir)
      OUT_DIR="$2"
      shift 2
      ;;
    --min-per-cat)
      MIN_PER_CAT="$2"
      shift 2
      ;;
    --seed)
      SEED="$2"
      shift 2
      ;;
    --question-lang)
      QUESTION_LANG="$2"
      shift 2
      ;;
    --include-l6)
      INCLUDE_L6="1"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[ERROR] Unknown option: $1"
      usage
      exit 1
      ;;
  esac
done

case "${QUESTION_LANG}" in
  ko|en|both) ;;
  *)
    echo "[ERROR] Invalid --question-lang: ${QUESTION_LANG} (expected: ko|en|both)"
    exit 1
    ;;
esac

if [[ ! -d "${LAB_PATH}" ]]; then
  echo "[ERROR] Lab path not found: ${LAB_PATH}"
  exit 1
fi

if [[ ! -f "${POLICIES_PATH}" ]]; then
  echo "[ERROR] Policies file not found: ${POLICIES_PATH}"
  exit 1
fi

# Windows(.venv/Scripts/python.exe) / Linux(.venv/bin/python) 자동 감지
if [[ -x "${ROOT_DIR}/.venv/Scripts/python.exe" ]]; then
  PYTHON_BIN="${ROOT_DIR}/.venv/Scripts/python.exe"
elif [[ -x "${ROOT_DIR}/.venv/bin/python" ]]; then
  PYTHON_BIN="${ROOT_DIR}/.venv/bin/python"
else
  PYTHON_BIN="python3"
fi

if [[ -n "${OUT_DIR}" ]]; then
  DATASET_DIR="${OUT_DIR}"
else
  DATASET_DIR="${LAB_PATH}/Dataset"
fi
mkdir -p "${DATASET_DIR}"

echo "[INFO] ROOT_DIR=${ROOT_DIR}"
echo "[INFO] PYTHON_BIN=${PYTHON_BIN}"
echo "[INFO] LAB_PATH=${LAB_PATH}"
echo "[INFO] DATASET_DIR=${DATASET_DIR}"
echo "[INFO] POLICIES_PATH=${POLICIES_PATH}"
echo "[INFO] BATFISH_HOST=${BATFISH_HOST}"
echo "[INFO] MIN_PER_CAT=${MIN_PER_CAT}"
echo "[INFO] INCLUDE_L6=${INCLUDE_L6}"
echo "[INFO] QUESTION_LANG=${QUESTION_LANG}"
echo "[INFO] SEED=${SEED}"

echo "[STEP 1/4] Validate policies"
validate_cmd=(
  "${PYTHON_BIN}" "${ROOT_DIR}/Make_Dataset/src/validate_policies.py"
  --policies "${POLICIES_PATH}"
)
if [[ "${QUESTION_LANG}" != "ko" ]]; then
  validate_cmd+=(--require-template-en --strict-template-en)
fi
"${validate_cmd[@]}"

RESULT_JSONS=()
RESULT_CSVS=()
RESULT_QUALITY_JSONS=()
RESULT_QUALITY_MDS=()
RESULT_SUMMARIES=()

run_for_lang() {
  local lang="$1"
  echo "[STEP 2/4] Generate dataset (${lang})"
  gen_cmd=(
    "${PYTHON_BIN}" "${ROOT_DIR}/Make_Dataset/src/main_batfish.py"
    --lab-path "${LAB_PATH}"
    --policies "${POLICIES_PATH}"
    --batfish-host "${BATFISH_HOST}"
    --min-per-cat "${MIN_PER_CAT}"
    --seed "${SEED}"
    --question-lang "${lang}"
  )

  if [[ -n "${OUT_DIR}" ]]; then
    gen_cmd+=(--out-dir "${OUT_DIR}")
  fi
  if [[ "${INCLUDE_L6}" == "1" ]]; then
    gen_cmd+=(--include-l6)
  fi

  "${gen_cmd[@]}"

  local dataset_json
  dataset_json="$(find "${DATASET_DIR}" -maxdepth 2 -type f -name "*_dataset_batfish_*_${lang}.json" -printf '%T@ %p\n' | sort -nr | head -n 1 | cut -d' ' -f2-)"
  if [[ -z "${dataset_json}" ]]; then
    echo "[ERROR] Could not locate generated dataset JSON for lang=${lang} in ${DATASET_DIR}"
    exit 1
  fi
  echo "[INFO] Generated dataset JSON (${lang}): ${dataset_json}"

  echo "[STEP 3/4] Validate dataset quality + write reports (${lang})"
  "${PYTHON_BIN}" "${ROOT_DIR}/Make_Dataset/src/validate_dataset_quality.py" --dataset "${dataset_json}"

  local quality_json quality_md dataset_csv summary_md
  quality_json="${dataset_json%.json}_quality_report.json"
  quality_md="${dataset_json%.json}_quality_report.md"
  dataset_csv="${dataset_json%.json}.csv"
  summary_md="${dataset_json%.json}_statistics.md"

  echo "[STEP 4/4] Generate statistics markdown summary (${lang})"
  "${PYTHON_BIN}" "${ROOT_DIR}/Make_Dataset/Make_summary.py" "${dataset_csv}" --output "${summary_md}"

  RESULT_JSONS+=("${dataset_json}")
  RESULT_CSVS+=("${dataset_csv}")
  RESULT_QUALITY_JSONS+=("${quality_json}")
  RESULT_QUALITY_MDS+=("${quality_md}")
  RESULT_SUMMARIES+=("${summary_md}")
}

if [[ "${QUESTION_LANG}" == "both" ]]; then
  run_for_lang "ko"
  run_for_lang "en"
else
  run_for_lang "${QUESTION_LANG}"
fi

echo "[DONE] Pipeline completed"
for i in "${!RESULT_JSONS[@]}"; do
  echo "[RESULT] Dataset JSON : ${RESULT_JSONS[$i]}"
  echo "[RESULT] Dataset CSV  : ${RESULT_CSVS[$i]}"
  echo "[RESULT] Quality JSON : ${RESULT_QUALITY_JSONS[$i]}"
  echo "[RESULT] Quality MD   : ${RESULT_QUALITY_MDS[$i]}"
  echo "[RESULT] Summary MD   : ${RESULT_SUMMARIES[$i]}"
done
