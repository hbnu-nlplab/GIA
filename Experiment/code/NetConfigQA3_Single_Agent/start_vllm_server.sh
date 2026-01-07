#!/bin/bash

# Start vLLM Server for GPT-OSS-20B with OpenAI Compatible API
# This script starts a vLLM server that can be used with LangChain

set -e

MODEL_NAME="openai/gpt-oss-20b"
PORT=8000
GPU_MEMORY_UTIL=0.9

echo "========================================"
echo "Starting vLLM Server"
echo "========================================"
echo "Model: $MODEL_NAME"
echo "Port: $PORT"
echo "GPU Memory Utilization: $GPU_MEMORY_UTIL"
echo "========================================"
echo ""

# Check if vLLM is installed
python3 -c "import vllm" 2>/dev/null || {
    echo "❌ Error: vLLM not installed"
    echo "Install with: pip install vllm"
    exit 1
}

echo "✅ vLLM installed"
echo ""

# Start vLLM server with OpenAI compatible API
echo "Starting vLLM server..."
echo "Access at: http://localhost:$PORT/v1"
echo ""
echo "To test:"
echo "  curl http://localhost:$PORT/v1/models"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

python3 -m vllm.entrypoints.openai.api_server \
    --model $MODEL_NAME \
    --port $PORT \
    --tensor-parallel-size $(nvidia-smi -L | wc -l) \
    --gpu-memory-utilization $GPU_MEMORY_UTIL \
    --max-model-len 16384 \
    --trust-remote-code \
    --served-model-name GPT-OSS-20B

