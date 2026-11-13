# HA Security Auditor

*[English version](README.md)*

Audita a segurança da sua instalação e mostra um relatório na barra lateral:

- **integrações customizadas e `www/`**: código suspeito (Semgrep + Bandit), dependências
  vulneráveis (OSV) e comparação arquivo a arquivo com a release oficial no GitHub;
- **outros add-ons**: permissões, CVEs e segredos nas imagens (Trivy), Dockerfile e scripts,
  picos de tráfego de saída;
- **lista negra**: selo e aviso para componentes reportados (lista pessoal e a lista comunitária
  assinada, que inclui as listas do HACS e do Home Assistant);
- **instalações e atualizações**: integração, card ou add-on novo ou atualizado é varrido em
  poucos minutos, e o HA mostra uma notificação quando aparece algo grave (avisa, não bloqueia);
- **DNS (opcional)**: domínios consultados pelo host, via AdGuard Home e/ou Pi-hole v6, verificados
  sozinhos a cada 2 horas (configurável) entre as varreduras completas.

Os achados vêm classificados por severidade, com explicação em inglês ou português e sugestão de ação.
O auditor aponta o que merece revisão humana; **ele não decide sozinho que algo é malicioso**.

Roda com `/config` somente leitura, perfil AppArmor próprio sem capacidades, Supervisor só
para leitura e sem enviar dados da instalação para fora (o botão opcional **Perguntar à IA** da
aba DNS envia só o nome de um domínio, e só quando você clica). Veja a aba **Documentação** para as
opções, o motivo de cada permissão e as limitações.
