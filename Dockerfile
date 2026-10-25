FROM python:3.12-slim AS builder
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
WORKDIR /build
COPY requirements.txt .
RUN --mount=type=secret,id=build_ca if [ -f /run/secrets/build_ca ]; then export PIP_CERT=/run/secrets/build_ca; fi; python -m venv /venv && /venv/bin/pip install --upgrade pip && /venv/bin/pip install -r requirements.txt

FROM python:3.12-slim AS runtime
RUN --mount=type=secret,id=build_ca,mode=0444 build_ca_path=/etc/ssl/certs/ca-certificates.crt; if [ -f /run/secrets/build_ca ]; then build_ca_path=/run/secrets/build_ca; fi; sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources && apt-get -o Acquire::https::CaInfo="$build_ca_path" update && apt-get -o Acquire::https::CaInfo="$build_ca_path" install --yes --no-install-recommends libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0 && rm -rf /var/lib/apt/lists/*
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

FROM runtime AS ingress
USER root
RUN --mount=type=secret,id=build_ca,mode=0444 build_ca_path=/etc/ssl/certs/ca-certificates.crt; if [ -f /run/secrets/build_ca ]; then build_ca_path=/run/secrets/build_ca; fi; apt-get -o Acquire::https::CaInfo="$build_ca_path" update && apt-get -o Acquire::https::CaInfo="$build_ca_path" install --yes --no-install-recommends nginx && rm -rf /var/lib/apt/lists/*
USER socify
CMD ["nginx", "-c", "/app/deploy/nginx.conf", "-g", "daemon off;"]
