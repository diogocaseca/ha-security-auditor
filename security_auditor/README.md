# HA Security Auditor

Audita a segurança da sua instalação e mostra um relatório na barra lateral:

- **integrações customizadas e `www/`**: código suspeito (Semgrep + Bandit), dependências
  vulneráveis (OSV) e comparação arquivo a arquivo com a release oficial no GitHub;
- **outros add-ons**: permissões, CVEs e segredos nas imagens (Trivy), Dockerfile e scripts,
  picos de tráfego de saída;
- **DNS (opcional)**: domínios consultados pelo host, via AdGuard Home ou Pi-hole v6.

Os achados vêm classificados por severidade, com explicação em português e sugestão de ação.
O auditor aponta o que merece revisão humana; **ele não decide sozinho que algo é malicioso**.

Roda com `/config` somente leitura, perfil AppArmor próprio sem capacidades, Supervisor só
para leitura e sem enviar dados da instalação para fora. Veja a aba **Documentação** para as
opções, o motivo de cada permissão e as limitações.
