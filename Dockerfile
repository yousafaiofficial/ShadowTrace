# ShadowTrace Dockerfile
# Security Exposure Intelligence & Analysis Platform
# https://github.com/yousafaiofficial/ShadowTrace.git
#
# Usage:
#   docker build -t shadowtrace .
#   docker run -p 5001:5001 shadowtrace

FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for OSINT modules & build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    git \
    curl \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Copy ShadowTrace codebase
COPY . .

# Expose ShadowTrace Web UI port
EXPOSE 5001

# Default execution: Launch ShadowTrace Web UI on port 5001
ENTRYPOINT ["python3"]
CMD ["sf.py", "-l", "0.0.0.0:5001"]
