#!/usr/bin/env bashio
# Ponto de entrada do add-on HA Security Auditor.
set -euo pipefail

bashio::log.info "Iniciando HA Security Auditor"

if ! bashio::fs.directory_exists "/config"; then
    bashio::log.fatal "/config não está montado; verifique o 'map' do add-on."
    exit 1
fi

mkdir -p /data/reports /data/cache

# exec: o Python assume o processo e recebe os sinais do tini diretamente.
exec python3 -m auditor
