# HA Security Auditor

Add-on para Home Assistant OS que audita a segurança da instalação: integrações
customizadas (HACS), arquivos de `www/` e outros add-ons. Gera um relatório com
achados classificados por severidade para **revisão humana**. Ele não decide
sozinho que algo é malicioso.

> **Status:** em desenvolvimento.
> - Fase 0 (base: Ingress, agendamento, sensores, relatório, mascaramento de segredos): concluída.
> - Fase 1 (integrações customizadas e `www/`: Semgrep + Bandit com regras próprias,
>   pip-audit via OSV, integridade contra a release do GitHub): concluída.
> - Fase 2 (outros add-ons: permissões, código-fonte, imagens com Trivy remoto,
>   histórico de CPU/memória/rede e picos de tráfego de saída): concluída.
> - Fase 3 (opcional: domínios consultados pelo host do HA via AdGuard Home ou
>   Pi-hole v6): concluída.

## Instalação

1. Em **Configurações → Add-ons → Loja de add-ons → ⋮ → Repositórios**, adicione
   `https://github.com/diogocaseca/ha-security-auditor`.
2. Instale **HA Security Auditor** e inicie. O relatório aparece na barra lateral.

A documentação completa (opções, permissões e limitações) fica em
[`security_auditor/DOCS.md`](security_auditor/DOCS.md), escrita ao fim das fases.

## Desenvolvimento

```bash
uv venv -p 3.12 .venv && uv pip install -p .venv/bin/python -r requirements-dev.txt
.venv/bin/python -m pytest
docker build -t local/security_auditor:dev security_auditor
```

## Licença

[MIT](LICENSE).
