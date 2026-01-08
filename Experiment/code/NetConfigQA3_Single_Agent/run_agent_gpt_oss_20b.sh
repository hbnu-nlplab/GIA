#!/bin/bash

# Run NetConfigQA Agent with GPT-OSS-20B (local vLLM)
# This script assumes vLLM server is already running

set -e

# Always run from this script's directory (so relative paths work)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Path setup
BASE_DIR="/home/kilab_pyj/codespace"
FACTS_FILE="$BASE_DIR/GIA/Data/Pnetlab/Research_Institute_Internal_DC/Dataset/Research_Institute_Internal_DC_batfish_facts_20251230_125613.json"
QUESTIONS_FILE="$BASE_DIR/GIA/Data/Pnetlab/Research_Institute_Internal_DC/Dataset/Research_Institute_Internal_DC_dataset_batfish_20251230_125613.json"
STRATIFIED_QUESTIONS_FILE="$BASE_DIR/GIA/Experiment/code/NetConfigQA3_Single_Agent/stratified_200.json"
if [ -f "$STRATIFIED_QUESTIONS_FILE" ]; then
    QUESTIONS_FILE="$STRATIFIED_QUESTIONS_FILE"
fi

VLLM_URL="http://localhost:8000/v1"
MODEL_NAME="GPT-OSS-20B"
SAMPLE_SIZE=${1:-}  # If empty: use all questions in file. If set: take first N.
PHASE=${2:-3}       # Phase: 3 (evidence-only, default) or 5 (analysis tools)

echo "========================================"
echo "NetConfigQA Agent - GPT-OSS-20B"
echo "========================================"
echo "vLLM Server: $VLLM_URL"
echo "Model: $MODEL_NAME"
echo "Questions: $QUESTIONS_FILE"
echo "Phase: $PHASE (3=Evidence-only, 5=Analysis)"
if [ -n "$SAMPLE_SIZE" ]; then
    echo "Sample Size: $SAMPLE_SIZE"
else
    echo "Sample Size: ALL (use all questions in file)"
fi
echo "========================================"
echo ""

# Check if vLLM server is running
echo "Checking vLLM server..."
curl -s $VLLM_URL/models > /dev/null 2>&1 || {
    echo "❌ Error: vLLM server not running at $VLLM_URL"
    echo ""
    echo "Start the server first:"
    echo "  ./start_vllm_server.sh"
    exit 1
}

echo "✅ vLLM server is running"
echo ""

# Run agent evaluation
echo "Running Agent evaluation..."
if [ -n "$SAMPLE_SIZE" ]; then
    python3 "$SCRIPT_DIR/run_netconfigqa_eval_agent.py" \
        --facts "$FACTS_FILE" \
        --questions "$QUESTIONS_FILE" \
        --backend vllm_server \
        --model "$MODEL_NAME" \
        --base_url "$VLLM_URL" \
        --phase "$PHASE" \
        --sample "$SAMPLE_SIZE"
else
    python3 "$SCRIPT_DIR/run_netconfigqa_eval_agent.py" \
        --facts "$FACTS_FILE" \
        --questions "$QUESTIONS_FILE" \
        --backend vllm_server \
        --model "$MODEL_NAME" \
        --base_url "$VLLM_URL" \
        --phase "$PHASE"
fi

echo ""
echo "========================================"
echo "✅ Evaluation completed!"
echo "========================================"
echo ""