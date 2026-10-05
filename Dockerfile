FROM python:3.12-slim

ARG SCW_VERSION=2.63.0
ARG TARGETARCH=amd64

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl; \
    bin="scaleway-cli_${SCW_VERSION}_linux_${TARGETARCH}"; \
    curl -fsSL -o "/tmp/${bin}" \
      "https://github.com/scaleway/scaleway-cli/releases/download/v${SCW_VERSION}/${bin}"; \
    curl -fsSL -o /tmp/SHA256SUMS \
      "https://github.com/scaleway/scaleway-cli/releases/download/v${SCW_VERSION}/SHA256SUMS"; \
    (cd /tmp && grep " ${bin}\$" SHA256SUMS | sha256sum -c -); \
    install -m 0755 "/tmp/${bin}" /usr/local/bin/scw; \
    rm -rf /tmp/*; \
    apt-get purge -y curl; \
    apt-get autoremove -y; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY app.py .

RUN useradd --no-create-home --shell /usr/sbin/nologin appuser \
    && mkdir -p /data && chown appuser:appuser /data
USER appuser

ENV SCW_BIN=/usr/local/bin/scw
ENV CREATED_RULES_LOG=/data/created_rules.log

EXPOSE 8080
CMD ["python3", "app.py"]
