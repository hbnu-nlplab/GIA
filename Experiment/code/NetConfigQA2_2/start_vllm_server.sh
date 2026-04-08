#!/bin/bash
# NetConfigQA2.0 — vLLM OpenAI-compatible API Server Launcher
#
# Usage:
#   bash start_vllm_server.sh <model_alias>
#
# Aliases: gpt-oss | qwen3-coder | qwen3.5 | qwen3.5-4b | fdtn-sec

set -e

if [ -z "$1" ]; then
    echo "Usage: bash start_vllm_server.sh <model_alias>"
    echo ""
    echo "Available aliases:"
    echo "  gpt-oss      → openai/gpt-oss-20b"
    echo "  qwen3-coder  → stelterlab/Qwen3-Coder-30B-A3B-Instruct-AWQ"
    echo "  qwen3.5      → cyankiwi/Qwen3.5-9B-AWQ-4bit"
    echo "  qwen3.5-4b   → cyankiwi/Qwen3.5-4B-AWQ-4bit"
    echo "  fdtn-sec     → fdtn-ai/Foundation-Sec-1.1-8B-Instruct"
    exit 1
fi

ALIAS="$1"
PORT=8000
GPU_MEMORY_UTIL=0.90
MAX_MODEL_LEN=42000
EXTRA_FLAGS=""
EXTRA_ENV=""

case "$ALIAS" in
    gpt-oss)
        HF_PATH="openai/gpt-oss-20b"
        SERVED_NAME="GPT-OSS-20B"
        ;;
    qwen3-coder)
        HF_PATH="stelterlab/Qwen3-Coder-30B-A3B-Instruct-AWQ"
        SERVED_NAME="Qwen3-Coder"
        ;;
    qwen3.5)
        HF_PATH="cyankiwi/Qwen3.5-9B-AWQ-4bit"
        SERVED_NAME="Qwen3.5-9B"
        EXTRA_FLAGS="--reasoning-parser qwen3"
        ;;
    qwen3.5-4b)
        HF_PATH="cyankiwi/Qwen3.5-4B-AWQ-4bit"
        SERVED_NAME="Qwen3.5-4B"
        MAX_MODEL_LEN=32768
        GPU_MEMORY_UTIL=0.82
        EXTRA_ENV="PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True"
        EXTRA_FLAGS="--reasoning-parser qwen3"
        ;;
    fdtn-sec)
        HF_PATH="fdtn-ai/Foundation-Sec-1.1-8B-Instruct"
        SERVED_NAME="Foundation-Sec-8B"
        ;;
    *)
        echo "Unknown alias: $ALIAS"
        echo "Available: gpt-oss | qwen3-coder | qwen3.5 | qwen3.5-4b | fdtn-sec"
        exit 1
        ;;
esac

TP_SIZE=$(nvidia-smi -L 2>/dev/null | wc -l)
if [ "$TP_SIZE" -eq 0 ]; then
    TP_SIZE=1
fi

echo "========================================"
echo "  vLLM Server — NetConfigQA2.0"
echo "========================================"
echo "  Alias:       $ALIAS"
echo "  Model:       $HF_PATH"
echo "  Served as:   $SERVED_NAME"
echo "  Port:        $PORT"
echo "  TP size:     $TP_SIZE"
echo "  Max len:     $MAX_MODEL_LEN"
echo "  GPU util:    $GPU_MEMORY_UTIL"
echo "  Extra flags: ${EXTRA_FLAGS:-none}"
echo "  Extra env:   ${EXTRA_ENV:-none}"
echo "========================================"
echo ""
echo "  Access: http://0.0.0.0:$PORT/v1"
echo "  Test:   curl http://localhost:$PORT/v1/models"
echo ""
echo "  Press Ctrl+C to stop"
echo ""

# Set model-specific environment variables
if [ -n "$EXTRA_ENV" ]; then
    export $EXTRA_ENV
fi

exec python3 -m vllm.entrypoints.openai.api_server \
    --model "$HF_PATH" \
    --served-model-name "$SERVED_NAME" \
    --host 0.0.0.0 \
    --port "$PORT" \
    --tensor-parallel-size "$TP_SIZE" \
    --gpu-memory-utilization "$GPU_MEMORY_UTIL" \
    --max-model-len "$MAX_MODEL_LEN" \
    --trust-remote-code \
    --enable-prefix-caching \
    $EXTRA_FLAGS
