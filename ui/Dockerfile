FROM alpine:3.20

RUN apk add --no-cache \
    python3 py3-pip \
    ca-certificates \
    curl \
    nodejs npm \
    su-exec \
  && python3 -m venv /opt/venv \
  && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
  && /opt/venv/bin/pip install --no-cache-dir fastapi uvicorn jinja2 python-multipart pyyaml itsdangerous argon2-cffi

ENV PATH="/opt/venv/bin:$PATH"

RUN addgroup -S app && adduser -S -G app -h /home/app app

WORKDIR /opt/ms365-relay
COPY app/ /opt/ms365-relay/app/
COPY tailwind.config.js /opt/ms365-relay/tailwind.config.js

# Build tailwind CSS locally (no CDN). We compile against templates.
RUN npm install --no-audit --no-fund --silent tailwindcss@3.4.10 \
  && npx tailwindcss \
      -c /opt/ms365-relay/tailwind.config.js \
      -i /opt/ms365-relay/app/static/tailwind.input.css \
      -o /opt/ms365-relay/app/static/tailwind.css \
      --minify \
  && rm -rf /root/.npm /root/.cache /opt/ms365-relay/node_modules \
  && chown -R app:app /opt/ms365-relay

COPY ui/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8000
VOLUME ["/data"]

ENTRYPOINT ["/entrypoint.sh"]
