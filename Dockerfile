# ── Stage 1: grab Docker CLI binary (avoids apt repo setup entirely) ──────────
FROM docker:27-cli AS docker-cli

# ── Stage 2: main application image ──────────────────────────────────────────
FROM python:3.12-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# ── JADX env vars ─────────────────────────────────────────────────────────────
ENV JADX_BIN=/opt/jadx/bin/jadx
ENV JADX_CACHE_DIR=/tmp/jadx_cache
ENV JADX_VERSION=1.5.0

# ── Copy Docker CLI binary from Stage 1 ──────────────────────────────────────
COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker

# ── uv (fast, non-backtracking resolver) ─────────────────────────────────────
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# ── System dependencies ───────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y \
    build-essential \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libcairo2 \
    libffi-dev \
    libglib2.0-0 \
    libmagic1 \
    default-jre-headless \
    curl \
    unzip \
    aapt \
    apktool \
    apksigner \
    tshark \
    adb \
    && rm -rf /var/lib/apt/lists/*

# ── Set work directory ────────────────────────────────────────────────────────
WORKDIR /app

COPY requirements.txt .
RUN uv pip install --system --no-cache -r requirements.txt

# ── Pre-download HuggingFace MalBERT model ───────────────────────────────────
RUN python -c "from transformers import pipeline; pipeline('zero-shot-classification', model='facebook/bart-large-mnli')"

# ── JADX CLI (full distribution incl. lib/*.jar) ─────────────────────────────
RUN curl -fsSL \
    "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" \
    -o /tmp/jadx.zip \
    && unzip -q /tmp/jadx.zip -d /opt/jadx \
    && chmod +x /opt/jadx/bin/jadx \
    && ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx \
    && rm -f /tmp/jadx.zip

# ── Copy project source ───────────────────────────────────────────────────────
COPY . .

RUN mkdir -p uploads ${JADX_CACHE_DIR}

EXPOSE 8000 8080

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]