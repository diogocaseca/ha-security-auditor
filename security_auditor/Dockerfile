ARG BUILD_FROM=ghcr.io/home-assistant/amd64-base-python:3.12-alpine3.22
FROM ${BUILD_FROM}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Trivy (scanner de imagens) em versão fixa, com SHA-256 conferido.
ARG BUILD_ARCH=amd64
ARG TRIVY_VERSION=0.76.1
RUN set -eu; \
    case "${BUILD_ARCH}" in \
      amd64)   T=Linux-64bit; S=c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0 ;; \
      aarch64) T=Linux-ARM64; S=e174dff2a6dba5e3ae41f8d0537a6324405bd08132497340304c6b20e0f16a1f ;; \
      *) echo "Arquitetura não suportada: ${BUILD_ARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/trivy.tgz \
      "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${T}.tar.gz"; \
    echo "${S}  /tmp/trivy.tgz" | sha256sum -c -; \
    tar -xzf /tmp/trivy.tgz -C /usr/local/bin trivy; \
    rm /tmp/trivy.tgz; \
    trivy --version

# Dependências Python fixadas por versão e hash; só wheels prontas
# (nada de compilar código-fonte de terceiros durante o build).
COPY app/requirements.txt /app/requirements.txt
RUN pip install --require-hashes --only-binary=:all: -r /app/requirements.txt

COPY app/auditor /app/auditor
COPY app/rules /app/rules
COPY rootfs/ /

RUN chmod 0755 /run.sh

WORKDIR /app

# Sem s6-overlay: o processo principal é o run.sh, sob o tini do Docker
# (init: true no config.yaml). Isso mantém o perfil AppArmor enxuto.
ENTRYPOINT []
CMD ["/run.sh"]
