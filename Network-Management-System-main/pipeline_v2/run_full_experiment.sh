#!/bin/bash
# 전체 실험 자동 실행 스크립트
# Usage: ./run_full_experiment.sh [max_questions]

set -e  # 오류 시 중단

# 컬러 출력 함수
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
}

# 파라미터 처리
MAX_QUESTIONS=${1:-""}
TIMESTAMP=$(date +'%Y%m%d_%H%M%S')
EXPERIMENT_DIR="Network-Management-System-main/pipeline_v2/experiment_results/experiment_${TIMESTAMP}"
EXPERIMENT_NAME="experiment_${TIMESTAMP}"

# .env 파일 로드 (프로젝트 루트에서)
# 스크립트가 어디서 실행되든 절대 경로로 .env 파일 찾기
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ENV_FILE="$PROJECT_ROOT/.env"

if [ -f "$ENV_FILE" ]; then
    log "📁 .env 파일 로드 중: $ENV_FILE"
    set -a  # 자동으로 환경변수로 export
    source "$ENV_FILE"
    set +a
    log "✅ .env 파일 로드 완료"
else
    warn ".env 파일을 찾을 수 없습니다: $ENV_FILE"
fi

# API 키 확인 (다중 키 지원)
API_KEY_FOUND=false

# OPENAI_API_KEY_1~5 확인
for i in {1..5}; do
    key_var="OPENAI_API_KEY_$i"
    if [ -n "${!key_var}" ]; then
        export OPENAI_API_KEY="${!key_var}"
        API_KEY_FOUND=true
        log "✅ $key_var 사용 중"
        break
    fi
done

# 기존 OPENAI_API_KEY 확인
if [ "$API_KEY_FOUND" = false ] && [ -n "$OPENAI_API_KEY" ]; then
    API_KEY_FOUND=true
    log "✅ OPENAI_API_KEY 사용 중"
fi

if [ "$API_KEY_FOUND" = false ]; then
    error "OPENAI_API_KEY 또는 OPENAI_API_KEY_1~5 환경변수가 설정되지 않았습니다."
    echo "다음 중 하나의 방법으로 설정하세요:"
    echo "1) export OPENAI_API_KEY='your-api-key-here'"
    echo "2) .env 파일에 OPENAI_API_KEY_1='your-api-key-here' 추가"
    exit 1
fi

log "🚀 전체 실험 시작: $EXPERIMENT_NAME"
if [ -n "$MAX_QUESTIONS" ]; then
    log "📊 최대 질문 수: $MAX_QUESTIONS"
else
    log "📊 모든 질문 처리"
fi

# 실험 디렉토리 생성
mkdir -p "$EXPERIMENT_DIR"

# Non-RAG 실험
log "🔹 Non-RAG 실험 시작..."
NON_RAG_CMD="python Network-Management-System-main/pipeline_v2/non_rag_pipeline.py --output-dir ${EXPERIMENT_DIR}/non_rag"
if [ -n "$MAX_QUESTIONS" ]; then
    NON_RAG_CMD="$NON_RAG_CMD --max-questions $MAX_QUESTIONS"
fi

if $NON_RAG_CMD; then
    log "✅ Non-RAG 실험 완료"
else
    error "❌ Non-RAG 실험 실패"
    exit 1
fi

# RAG 실험
log "🔹 RAG 실험 시작..."
RAG_CMD="python Network-Management-System-main/pipeline_v2/rag_pipeline.py --output-dir ${EXPERIMENT_DIR}/rag"
if [ -n "$MAX_QUESTIONS" ]; then
    RAG_CMD="$RAG_CMD --max-questions $MAX_QUESTIONS"
fi

if $RAG_CMD; then
    log "✅ RAG 실험 완료"
else
    error "❌ RAG 실험 실패"
    exit 1
fi

# 결과 통합
log "🔹 결과 통합 분석 시작..."
COMPARISON_FILE="${EXPERIMENT_DIR}/comparison_report.md"
LATEX_FILE="${EXPERIMENT_DIR}/paper_table.tex"

if python Network-Management-System-main/pipeline_v2/compare_results.py \
    --non-rag "${EXPERIMENT_DIR}/non_rag" \
    --rag "${EXPERIMENT_DIR}/rag" \
    --output "$COMPARISON_FILE" \
    --latex-output "$LATEX_FILE"; then
    log "✅ 결과 통합 완료"
else
    error "❌ 결과 통합 실패"
    exit 1
fi

# 최종 요약
log "🎉 모든 실험이 성공적으로 완료되었습니다!"
echo ""
echo "📂 실험 결과 구조:"
echo "  $EXPERIMENT_DIR/"
echo "  ├── non_rag/               # Non-RAG 결과"
echo "  ├── rag/                   # RAG 결과"  
echo "  ├── comparison_report.md   # 통합 비교 리포트"
echo "  └── paper_table.tex        # 논문용 LaTeX 표"
echo ""
echo "📊 주요 결과 파일:"
echo "  - 통합 리포트: $COMPARISON_FILE"
echo "  - LaTeX 표: $LATEX_FILE"
echo "  - Non-RAG 상세: ${EXPERIMENT_DIR}/non_rag/"
echo "  - RAG 상세: ${EXPERIMENT_DIR}/rag/"
echo ""
echo "📊 결과 확인:"
echo "  cat $COMPARISON_FILE"
echo ""

# 성능 요약 미리보기 (결과 파일이 있다면)
if [ -f "$COMPARISON_FILE" ]; then
    log "📈 성능 요약 미리보기:"
    echo "----------------------------------------"
    # Markdown 표 부분만 추출해서 보여주기
    awk '/\| Method/,/^$/' "$COMPARISON_FILE" | head -10
    echo "----------------------------------------"
    echo "전체 리포트는 $COMPARISON_FILE 에서 확인하세요."
fi

log "🎯 실험 완료 시각: $(date +'%Y-%m-%d %H:%M:%S')"
