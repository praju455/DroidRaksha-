# DroidRaksha APK Sandbox
# Lightweight image: apktool + frida-tools + Python 3.11
# Runs offline Frida analysis on decompiled APK smali bytecode

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# ── System deps ────────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-21-jre-headless \
    wget \
    curl \
    unzip \
    file \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# ── APKTool 2.9.3 ─────────────────────────────────────────────────────────────
RUN wget -q \
    https://github.com/iBotPeaches/Apktool/releases/download/v2.9.3/apktool_2.9.3.jar \
    -O /opt/apktool.jar && \
    # Write a simple wrapper — avoids the complex path-concat bug in the official script
    printf '#!/bin/bash\nexec java -Xmx1024M -Dfile.encoding=utf-8 -jar /opt/apktool.jar "$@"\n' \
    > /usr/local/bin/apktool && \
    chmod +x /usr/local/bin/apktool

# ── Python packages ────────────────────────────────────────────────────────────
RUN pip install --no-cache-dir \
    frida-tools==12.4.3 \
    python-magic==0.4.27 \
    loguru==0.7.3

# ── Sandbox scripts ────────────────────────────────────────────────────────────
WORKDIR /sandbox
COPY analyze.py .
COPY frida_hooks/ ./frida_hooks/

# Input/output mount points
RUN mkdir -p /input /output /work

ENTRYPOINT ["python", "analyze.py"]
