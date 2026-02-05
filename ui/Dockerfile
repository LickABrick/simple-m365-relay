FROM alpine:3.20

RUN apk add --no-cache \
    python3 py3-pip \
    ca-certificates \
    curl \
  && python3 -m venv /opt/venv \
  && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
  && /opt/venv/bin/pip install --no-cache-dir fastapi uvicorn jinja2 python-multipart pyyaml itsdangerous argon2-cffi

ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /opt/ms365-relay
COPY app/ /opt/ms365-relay/app/
COPY ui/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8000
VOLUME ["/data"]

ENTRYPOINT ["/entrypoint.sh"]
