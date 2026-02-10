# =============================================================================
# NetAlly Docker Image
# Multi-stage build: Frontend (Node.js) + Backend (Python)
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Frontend Build (React + Vite)
# -----------------------------------------------------------------------------
FROM node:20-alpine AS frontend-builder

WORKDIR /app/frontend

# 패키지 설치 (캐시 활용)
#
# NOTE: This Dockerfile expects the *repo root* as build context.
# Build command:
#   docker build -f NetAlly/Dockerfile -t netally:latest .
#
COPY NetAlly/frontend/package*.json ./
RUN npm ci --silent

# 소스 복사 및 빌드
COPY NetAlly/frontend/ ./
RUN npm run build


# -----------------------------------------------------------------------------
# Stage 2: Python Backend
# -----------------------------------------------------------------------------
FROM python:3.12-slim

WORKDIR /app

# 시스템 의존성
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 애플리케이션 코드 복사
COPY NetAlly/pyproject.toml ./
COPY NetAlly/agent/ ./agent/
COPY NetAlly/eval/ ./eval/
COPY NetAlly/skills/ ./skills/
COPY NetAlly/main.py ./
COPY Make_Dataset/src ./Make_Dataset/src

# Python 의존성 설치
RUN pip install --no-cache-dir -e .

# 프론트엔드 빌드 결과물 복사
COPY --from=frontend-builder /app/frontend/dist ./static

# 환경변수 (런타임에 오버라이드 가능)
ENV PYTHONUNBUFFERED=1
ENV PORT=8000

# 포트 노출
EXPOSE 8000

# 헬스체크
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

# 실행
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
