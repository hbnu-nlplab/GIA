#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB_PATH="${ROOT_DIR}/Data/Pnetlab/Research_Institute_Internal_DC"
POLICIES_PATH="${ROOT_DIR}/Make_Dataset/policies.json"
BATFISH_HOST="localhost"
OUT_DIR=""
MIN_PER_CAT="50"
INCLUDE_L6="0"

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Options:
  --lab-path <path>       Lab path (default: ${LAB_PATH})
  --policies <path>       policies.json path (default: ${POLICIES_PATH})
  --batfish-host <host>   Batfish host (default: ${BATFISH_HOST})
  --out-dir <path>        Dataset output directory (default: <lab-path>/Dataset)
  --min-per-cat <int>     Minimum per category target (default: ${MIN_PER_CAT})
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

if [[ ! -d "${LAB_PATH}" ]]; then
  echo "[ERROR] Lab path not found: ${LAB_PATH}"
  exit 1
fi

if [[ ! -f "${POLICIES_PATH}" ]]; then
  echo "[ERROR] Policies file not found: ${POLICIES_PATH}"
  exit 1
fi

if [[ -x "${ROOT_DIR}/.venv/bin/python" ]]; then
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

echo "[STEP 1/4] Validate policies"
"${PYTHON_BIN}" "${ROOT_DIR}/Make_Dataset/src/validate_policies.py" --policies "${POLICIES_PATH}"

before_list="$(mktemp)"
after_list="$(mktemp)"
trap 'rm -f "${before_list}" "${after_list}"' EXIT

find "${DATASET_DIR}" -maxdepth 2 -type f -name '*_dataset_batfish_*.json' | sort > "${before_list}"

echo "[STEP 2/4] Generate dataset"
gen_cmd=(
  "${PYTHON_BIN}" "${ROOT_DIR}/Make_Dataset/src/main_batfish.py"
  --lab-path "${LAB_PATH}"
  --policies "${POLICIES_PATH}"
  --batfish-host "${BATFISH_HOST}"
  --min-per-cat "${MIN_PER_CAT}"
)

if [[ -n "${OUT_DIR}" ]]; then
  gen_cmd+=(--out-dir "${OUT_DIR}")
fi
if [[ "${INCLUDE_L6}" == "1" ]]; then
  gen_cmd+=(--include-l6)
fi

"${gen_cmd[@]}"

find "${DATASET_DIR}" -maxdepth 2 -type f -name '*_dataset_batfish_*.json' | sort > "${after_list}"
NEW_DATASET_JSON="$(comm -13 "${before_list}" "${after_list}" | tail -n 1 || true)"

if [[ -z "${NEW_DATASET_JSON}" ]]; then
  NEW_DATASET_JSON="$(find "${DATASET_DIR}" -maxdepth 2 -type f -name '*_dataset_batfish_*.json' -printf '%T@ %p\n' | sort -nr | head -n 1 | awk '{print $2}')"
fi

if [[ -z "${NEW_DATASET_JSON}" ]]; then
  echo "[ERROR] Could not locate generated dataset JSON in ${DATASET_DIR}"
  exit 1
fi

echo "[INFO] Generated dataset JSON: ${NEW_DATASET_JSON}"

echo "[STEP 3/5] Validate dataset quality + write reports"
"${PYTHON_BIN}" "${ROOT_DIR}/Make_Dataset/src/validate_dataset_quality.py" --dataset "${NEW_DATASET_JSON}"

QUALITY_JSON="${NEW_DATASET_JSON%.json}_quality_report.json"
QUALITY_MD="${NEW_DATASET_JSON%.json}_quality_report.md"
DATASET_CSV="${NEW_DATASET_JSON%.json}.csv"
SUMMARY_MD="${NEW_DATASET_JSON%.json}_statistics.md"

echo "[STEP 4/5] Generate statistics markdown summary"
"${PYTHON_BIN}" "${ROOT_DIR}/Make_Dataset/Make_summary.py" "${DATASET_CSV}" --output "${SUMMARY_MD}"

echo "[STEP 5/5] Done"
echo "[RESULT] Dataset JSON : ${NEW_DATASET_JSON}"
echo "[RESULT] Dataset CSV  : ${DATASET_CSV}"
echo "[RESULT] Quality JSON : ${QUALITY_JSON}"
echo "[RESULT] Quality MD   : ${QUALITY_MD}"
echo "[RESULT] Summary MD   : ${SUMMARY_MD}"
