# Python 3.12 slim 이미지 사용
FROM python:3.12-slim

# 메타데이터 추가
LABEL maintainer="NIST Security Analysis Team"
LABEL description="FastAPI application for NIST Cybersecurity Framework analysis"
LABEL version="1.0.0"

# 작업 디렉토리 설정
WORKDIR /app

# 시스템 패키지 업데이트 및 필요한 패키지 설치
RUN apt-get update && apt-get install -y \
    curl \
    gcc \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# requirements.txt 먼저 복사하여 Docker 레이어 캐싱 최적화
COPY requirements.txt .

# Python 의존성 설치
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# 애플리케이션 소스 코드 복사
COPY app.py .
COPY models.py .
COPY workflow.py .

# 비root 사용자 생성 및 전환 (보안 강화)
RUN useradd --create-home --shell /bin/bash --uid 1000 appuser && \
    chown -R appuser:appuser /app
USER appuser

# 포트 8000 노출
EXPOSE 8000

# 헬스체크 추가 (ECS에서 오버라이드될 예정)
HEALTHCHECK --interval=60s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# FastAPI 애플리케이션 실행
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--access-log"]
