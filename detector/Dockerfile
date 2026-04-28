# Stage 1: Builder
FROM python:3.11-slim as builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Stage 2: Runtime
FROM python:3.11-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    iptables \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Create necessary directories
RUN mkdir -p /app /var/log/detector /var/log/nginx

WORKDIR /app

# Copy Python packages from builder
COPY --from=builder /root/.local /root/.local

# Copy application files
COPY *.py .
RUN if [ -f __init__.py ]; then echo "Package init exists"; else echo "# Package init" > __init__.py; fi
COPY templates/ ./templates/
COPY config.yaml .

# Create non-root user
RUN groupadd -r detector && \
    useradd -r -g detector -d /app -s /bin/bash detector && \
    chown -R detector:detector /app /var/log/detector

# Make sure PATH includes local user packages
ENV PATH=/root/.local/bin:$PATH

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import socket; s=socket.socket(); s.connect(('localhost',8080)); s.close()" || exit 1

# Entrypoint script
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

USER detector

EXPOSE 8080

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["python", "-u", "main.py"]