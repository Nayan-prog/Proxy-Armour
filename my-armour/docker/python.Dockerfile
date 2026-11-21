# One image for the Python services: scanner (FastAPI), proxy (mitmdump) and mock-llm.
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    # container hostnames (scanner, mock-llm) on top of config.yaml
    ARMOUR_CONFIG_OVERLAY=/app/docker/config.overlay.yaml

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
# non-root at runtime; /certs is where mitmproxy writes its CA (bind-mounted to ./certs)
RUN useradd --create-home --uid 10001 armour && mkdir -p /certs && chown armour:armour /certs
USER armour
