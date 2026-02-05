# syntax=docker/dockerfile:1

############################
# Builder: build sasl-xoauth2
############################
FROM alpine:3.20 AS builder

ARG SASL_XOAUTH2_VERSION=0.25

RUN apk add --no-cache \
    ca-certificates curl wget tar \
    build-base cmake pkgconf \
    jsoncpp-dev cyrus-sasl-dev curl-dev \
    pandoc \
    git

RUN set -eux; \
  wget -O /tmp/sasl-xoauth2.tar.gz "https://github.com/tarickb/sasl-xoauth2/archive/refs/tags/release-${SASL_XOAUTH2_VERSION}.tar.gz"; \
  tar -xzf /tmp/sasl-xoauth2.tar.gz -C /tmp; \
  cd "/tmp/sasl-xoauth2-release-${SASL_XOAUTH2_VERSION}"; \
  # Alpine/musl: ensure basename() is declared for test_config build
  if ! grep -q "libgen.h" src/test_config.cc; then sed -i '1i#include <libgen.h>' src/test_config.cc; fi; \
  mkdir -p build; cd build; \
  cmake .. -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_INSTALL_SYSCONFDIR=/etc; \
  make -j"$(nproc)"; \
  make install

############################
# Runtime: postfix relay
############################
FROM alpine:3.20

RUN apk add --no-cache \
    postfix \
    cyrus-sasl \
    openssl \
    python3 \
    busybox-suid \
    libcurl \
    jsoncpp \
  && mkdir -p /data

# XOAUTH2 plugin + tool
COPY --from=builder /usr/lib/sasl2/ /usr/lib/sasl2/
COPY --from=builder /usr/bin/sasl-xoauth2-tool /usr/bin/sasl-xoauth2-tool

WORKDIR /opt/ms365-relay
COPY postfix/render.py /opt/ms365-relay/postfix/render.py
COPY postfix/control.py /opt/ms365-relay/postfix/control.py
COPY postfix/entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

EXPOSE 25 587 18080
VOLUME ["/data"]

ENTRYPOINT ["/entrypoint.sh"]
