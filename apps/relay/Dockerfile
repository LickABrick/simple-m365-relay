# syntax=docker/dockerfile:1

############################
# Builder: build sasl-xoauth2 (Debian/glibc)
############################
FROM debian:13-slim AS builder

ARG SASL_XOAUTH2_VERSION=0.25

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl wget tar \
    build-essential cmake pkg-config \
    libjsoncpp-dev libsasl2-dev libcurl4-openssl-dev \
    pandoc \
    git \
  && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
  wget -O /tmp/sasl-xoauth2.tar.gz "https://github.com/tarickb/sasl-xoauth2/archive/refs/tags/release-${SASL_XOAUTH2_VERSION}.tar.gz"; \
  tar -xzf /tmp/sasl-xoauth2.tar.gz -C /tmp; \
  cd "/tmp/sasl-xoauth2-release-${SASL_XOAUTH2_VERSION}"; \
  mkdir -p build; cd build; \
  cmake .. -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_INSTALL_SYSCONFDIR=/etc; \
  make -j"$(nproc)"; \
  make install

############################
# Runtime: postfix relay (Debian 12)
############################
FROM debian:13-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    postfix \
    postfix-lmdb \
    libsasl2-modules \
    libsasl2-modules-db \
    sasl2-bin \
    dovecot-core \
    openssl \
    libcurl4 \
    libjsoncpp26 \
    busybox \
    busybox-syslogd \
    python3 \
    python3-pip \
  && python3 -m pip install --no-cache-dir --break-system-packages msal \
  && mkdir -p /data \
  && rm -rf /var/lib/apt/lists/*

# XOAUTH2 plugin + tool (Debian installs into /usr/lib/x86_64-linux-gnu)
COPY --from=builder /usr/lib/x86_64-linux-gnu/sasl2/ /usr/lib/x86_64-linux-gnu/sasl2/
COPY --from=builder /usr/bin/sasl-xoauth2-tool /usr/bin/sasl-xoauth2-tool
COPY --from=builder /usr/lib/x86_64-linux-gnu/sasl-xoauth2/ /usr/lib/x86_64-linux-gnu/sasl-xoauth2/
COPY --from=builder /etc/sasl-xoauth2.conf /etc/sasl-xoauth2.conf

WORKDIR /opt/ms365-relay
COPY apps/relay/render.py /opt/ms365-relay/relay/render.py
COPY apps/relay/backup.py /opt/ms365-relay/relay/backup.py
COPY apps/relay/control.py /opt/ms365-relay/relay/control.py
COPY apps/relay/entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

EXPOSE 25 587 18080
VOLUME ["/data"]

ENTRYPOINT ["/entrypoint.sh"]
