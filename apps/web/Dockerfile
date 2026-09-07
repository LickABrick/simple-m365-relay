FROM node:24.18.0-bookworm-slim AS build

WORKDIR /opt/ms365-relay
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ && rm -rf /var/lib/apt/lists/*
COPY package.json package-lock.json ./
COPY apps/web/package.json ./apps/web/package.json
RUN npm ci --workspace @simple-m365-relay/web --include-workspace-root --no-audit --no-fund
COPY apps/web/ ./apps/web/
RUN npm run build --workspace @simple-m365-relay/web

FROM node:24.18.0-bookworm-slim

ARG APP_VERSION=2.0.2
ARG APP_GITHUB_REPO=LickABrick/simple-m365-relay
ENV APP_VERSION="$APP_VERSION" \
    APP_GITHUB_REPO="$APP_GITHUB_REPO" \
    NODE_ENV=production \
    HOST=0.0.0.0 \
    HOST_HEADER=host \
    PORT=8000

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl gosu \
  && rm -rf /var/lib/apt/lists/* \
  && groupadd --gid 10001 app \
  && useradd --uid 10001 --gid app --create-home --home-dir /home/app app

WORKDIR /opt/ms365-relay
COPY --from=build --chown=app:app /opt/ms365-relay/apps/web/build ./build
COPY --from=build --chown=app:app /opt/ms365-relay/node_modules ./node_modules
COPY --from=build --chown=app:app /opt/ms365-relay/apps/web/node_modules ./node_modules
COPY --from=build --chown=app:app /opt/ms365-relay/apps/web/drizzle ./drizzle
COPY --from=build --chown=app:app /opt/ms365-relay/apps/web/package.json ./package.json
COPY --chown=app:app apps/web/docker-entrypoint.sh /entrypoint.sh
COPY --chown=app:app apps/web/scripts/admin-cli.mjs /opt/ms365-relay/admin-cli.mjs
RUN chmod 0555 /entrypoint.sh

EXPOSE 8000
VOLUME ["/data"]
ENTRYPOINT ["/entrypoint.sh"]
