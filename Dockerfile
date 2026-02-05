# syntax=docker/dockerfile:1

############################
# Builder: compile sasl-xoauth2 + build Python venv
############################
FROM debian:12 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl wget \
    build-essential cmake debhelper pkg-config pandoc \
    libcurl4-openssl-dev libjsoncpp-dev libsasl2-dev \
    python3 python3-venv python3-pip python3-msal \
  && rm -rf /var/lib/apt/lists/*

# Build and install sasl-xoauth2 (client-side XOAUTH2 for Postfix -> M365)
ARG SASL_XOAUTH2_VERSION=0.25
RUN set -eux; \
  wget -O /tmp/sasl-xoauth2.tar.gz "https://github.com/tarickb/sasl-xoauth2/archive/refs/tags/release-${SASL_XOAUTH2_VERSION}.tar.gz"; \
  tar -xzf /tmp/sasl-xoauth2.tar.gz -C /tmp; \
  cd "/tmp/sasl-xoauth2-release-${SASL_XOAUTH2_VERSION}"; \
  mkdir -p build; cd build; \
  cmake .. -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_INSTALL_SYSCONFDIR=/etc; \
  make -j"$(nproc)"; \
  make install; \
  cd /; rm -rf /tmp/sasl-xoauth2*

# Python UI deps in a venv (avoid PEP 668 externally-managed-environment)
RUN python3 -m venv /opt/venv \
  && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
  && /opt/venv/bin/pip install --no-cache-dir fastapi uvicorn jinja2 python-multipart pyyaml

############################
# Runtime: slim image
############################
FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/opt/venv/bin:$PATH"

# Runtime deps only
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    postfix libsasl2-modules sasl2-bin \
    rsyslog supervisor \
    openssl \
    python3 \
    libcurl4 libjsoncpp25 \
  && rm -rf /var/lib/apt/lists/*

# Copy sasl-xoauth2 plugin + tool from builder
COPY --from=builder /usr/lib/sasl2/ /usr/lib/sasl2/
COPY --from=builder /usr/bin/sasl-xoauth2-tool /usr/bin/sasl-xoauth2-tool
COPY --from=builder /etc/sasl-xoauth2.conf /etc/sasl-xoauth2.conf

# Copy Python venv
COPY --from=builder /opt/venv /opt/venv

# App + config templates
WORKDIR /opt/ms365-relay
COPY postfix/ /opt/ms365-relay/postfix/
COPY app/ /opt/ms365-relay/app/
COPY supervisord.conf /etc/supervisor/conf.d/ms365-relay.conf
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

EXPOSE 25 587 8000

VOLUME ["/data"]

ENTRYPOINT ["/entrypoint.sh"]
