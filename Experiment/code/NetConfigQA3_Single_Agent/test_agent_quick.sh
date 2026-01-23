#!/bin/bash

# NetConfigQA Agent Quick Test Script
# 빠르게 10개 샘플로 테스트하고 메트릭 확인

set -e

echo "========================================"
echo "NetConfigQA Agent Quick Test"
echo "========================================"

# Check OpenAI API Key
if [ -z "$OPENAI_API_KEY" ]; then
    echo "❌ Error: OPENAI_API_KEY not set"
    echo "Please set it: export OPENAI_API_KEY='your-key'"
    exit 1
fi

echo "✅ OpenAI API Key found"
echo ""

# Check dependencies
echo "Checking dependencies..."
python3 -c "import langchain" 2>/dev/null || {
    echo "❌ langchain not installed"
    echo "Installing dependencies..."
    pip install -r requirements_agent.txt
}

echo "✅ Dependencies OK"
echo ""

# Run evaluation with 10 samples
echo "Running evaluation (10 samples)..."
python3 run_netconfigqa_eval_agent.py \
    --model gpt-4o-mini \
    --sample 10

echo ""
echo "========================================"
echo "✅ Test completed!"
echo "========================================"
echo ""
echo "Check results in: results/gpt-4o-mini_agent/"
echo ""
echo "Next steps:"
echo "  1. View metrics: cat results/gpt-4o-mini_agent/metrics_agent_*.csv"
echo "  2. Analyze results: python reanalyze_results.py \"results/gpt-4o-mini_agent/results_agent_*.json\""
echo ""

