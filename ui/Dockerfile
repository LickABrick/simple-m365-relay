FROM alpine:3.23

ARG APP_VERSION=dev
ARG APP_GITHUB_REPO=LickABrick/simple-m365-relay

ENV APP_VERSION="$APP_VERSION"
ENV APP_GITHUB_REPO="$APP_GITHUB_REPO"

RUN apk add --no-cache \
    python3 py3-pip \
    ca-certificates \
    curl \
    nodejs npm \
  && python3 -m venv /opt/venv \
  && /opt/venv/bin/pip install --no-cache-dir --upgrade pip

ENV PATH="/opt/venv/bin:$PATH"

RUN addgroup -S -g 10001 app && adduser -S -D -u 10001 -G app -h /home/app app

WORKDIR /opt/ms365-relay
COPY requirements-ui.txt /opt/ms365-relay/requirements-ui.txt
RUN /opt/venv/bin/pip install --no-cache-dir --requirement /opt/ms365-relay/requirements-ui.txt
COPY app/ /opt/ms365-relay/app/
COPY tailwind.config.js /opt/ms365-relay/tailwind.config.js

# Build tailwind CSS locally (no CDN). We compile against templates.
RUN npm install --no-audit --no-fund --silent tailwindcss@3.4.19 \
  && npx tailwindcss \
      -c /opt/ms365-relay/tailwind.config.js \
      -i /opt/ms365-relay/app/static/tailwind.input.css \
      -o /opt/ms365-relay/app/static/tailwind.css \
      --minify \
  && rm -rf /root/.npm /root/.cache /opt/ms365-relay/node_modules \
  && chown -R app:app /opt/ms365-relay

COPY ui/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER 10001:10001
EXPOSE 8000
VOLUME ["/data"]

ENTRYPOINT ["/entrypoint.sh"]
