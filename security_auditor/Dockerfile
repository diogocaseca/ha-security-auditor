ARG BUILD_FROM=ghcr.io/home-assistant/amd64-base-python:3.12-alpine3.22
FROM ${BUILD_FROM}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

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
