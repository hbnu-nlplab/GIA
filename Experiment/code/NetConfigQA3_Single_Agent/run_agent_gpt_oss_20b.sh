#!/bin/bash

# Run NetConfigQA Agent with GPT-OSS-20B (local vLLM)
# This script assumes vLLM server is already running

set -e

# Path setup
BASE_DIR="/home/kilab_pyj/codespace"
FACTS_FILE="$BASE_DIR/GIA/Data/Pnetlab/Research_Institute_Internal_DC/Dataset/Research_Institute_Internal_DC_batfish_facts_20251230_125613.json"
QUESTIONS_FILE="$BASE_DIR/GIA/Data/Pnetlab/Research_Institute_Internal_DC/Dataset/Research_Institute_Internal_DC_dataset_batfish_20251230_125613.json"

VLLM_URL="http://localhost:8000/v1"
MODEL_NAME="GPT-OSS-20B"
SAMPLE_SIZE=${1:-10}  # Default 10 samples, or pass as argument

echo "========================================"
echo "NetConfigQA Agent - GPT-OSS-20B"
echo "========================================"
echo "vLLM Server: $VLLM_URL"
echo "Model: $MODEL_NAME"
echo "Sample Size: $SAMPLE_SIZE"
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
python3 run_netconfigqa_eval_agent.py \
    --facts "$FACTS_FILE" \
    --questions "$QUESTIONS_FILE" \
    --backend vllm_server \
    --model "$MODEL_NAME" \
    --base_url "$VLLM_URL" \
    --sample "$SAMPLE_SIZE"

echo ""
echo "========================================"
echo "✅ Evaluation completed!"
echo "========================================"
echo ""
