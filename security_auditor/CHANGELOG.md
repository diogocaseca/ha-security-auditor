# Changelog

## 0.4.0

- Fase 3: domínios consultados pelo host do HA via AdGuard Home ou Pi-hole v6 (opcional).
  Achados para serviços de exfiltração, pools de mineração, domínios aleatórios, bloqueados e
  novos; seção "Domínios consultados" no relatório.
- Licença MIT.

## 0.3.1

- Corrige o perfil AppArmor que impedia o add-on de iniciar
  (`env: can't execute 'bashio': Permission denied`). Execução continua proibida em `/data`,
  `/tmp`, `/dev/shm` e `/config`.

## 0.3.0

- Fase 2: auditoria dos outros add-ons: permissões, código-fonte no GitHub (Dockerfile,
  scripts, `map`), imagens com Trivy em modo remoto, histórico de CPU/memória/rede e picos de
  tráfego de saída.
- Novas opções: `addons_scan`, `image_scan`, `image_scan_skip`, `stats_interval_minutes`.

## 0.2.0

- Fase 1: integrações customizadas e `www/`: Semgrep com regras próprias e Bandit,
  pip-audit via OSV, integridade contra a release do GitHub.
- Seletor de tema Sistema / Claro / Escuro.

## 0.1.0

- Base: Ingress, varredura agendada e manual, sensores, relatório HTML/JSON, comparação com a
  varredura anterior, allowlist e mascaramento de segredos.
