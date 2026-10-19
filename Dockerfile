FROM python:3.12-slim AS builder
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
WORKDIR /build
COPY requirements.txt .
RUN python -m venv /venv && /venv/bin/pip install --upgrade pip && /venv/bin/pip install -r requirements.txt

FROM python:3.12-slim AS runtime
ENV PATH=/venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 SOCIFY_ENV=production SOCIFY_DATABASE=/data/socify.db SOCIFY_HOST=0.0.0.0 SOCIFY_PORT=5000
RUN groupadd --gid 10001 socify && useradd --uid 10001 --gid socify --no-create-home --shell /usr/sbin/nologin socify && mkdir -p /app /data && chown -R socify:socify /app /data
COPY --from=builder /venv /venv
WORKDIR /app
COPY --chown=socify:socify . .
USER socify
EXPOSE 5000
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health/ready', timeout=3).read()"]
CMD ["gunicorn", "--config", "gunicorn.conf.py", "app:app"]
