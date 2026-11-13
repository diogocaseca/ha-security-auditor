# HA Security Auditor

Add-on para Home Assistant OS que audita a segurança da instalação: integrações customizadas
(HACS), recursos de frontend em `www/`, os outros add-ons e, opcionalmente, os domínios
consultados pelo host. Gera um relatório com achados classificados por severidade, explicados
em português, para **revisão humana**.

> O auditor aponta o que merece atenção. Ele **não decide sozinho que algo é malicioso**.

![Arquiteturas](https://img.shields.io/badge/arch-amd64%20%7C%20aarch64-blue)
![Licença](https://img.shields.io/badge/licen%C3%A7a-MIT-green)

## O que ele verifica

| Área | Como |
|---|---|
| **Código das integrações e do `www/`** | Semgrep com 24 regras próprias (ofuscação, `eval`/`exec`, comandos do sistema, download e execução, leitura de `secrets.yaml` e `.storage/auth`, roubo do token no navegador, destinos suspeitos) + Bandit |
| **Dependências** | pip-audit contra a base OSV, sem instalar nada |
| **Integridade** | Compara cada arquivo com a release oficial no GitHub (SHA-256); arquivo alterado ou extra = Alta |
| **Permissões dos add-ons** | `docker_api`, `full_access`, `host_network`, capacidades, AppArmor, papel no Supervisor, modo de proteção, nota de segurança, atualizações |
| **Imagens dos add-ons** | Trivy em modo remoto (sem Docker): CVEs e segredos embutidos |
| **Código dos add-ons** | Dockerfile e scripts do GitHub: `curl \| sh`, shell reverso, `SUPERVISOR_TOKEN` enviado para fora, `map` com escrita em `/config` |
| **Tráfego** | Histórico de CPU, memória e rede; alerta de picos de envio comparados à média do próprio add-on |
| **Lista negra** | Selo e aviso para componentes reportados (lista pessoal e, em breve, a [comunitária](https://github.com/diogocaseca/ha-security-blocklist)), comparando GitHub, imagem e versão localmente |
| **DNS (opcional)** | AdGuard Home e/ou Pi-hole v6 (os dois juntos, se você tiver): exfiltração, mineração, domínios aleatórios, bloqueados e novos |

O resultado aparece na barra lateral (Ingress), pode ser exportado em JSON, destaca o que é
novo desde a varredura anterior e é publicado como sensores
(`sensor.security_auditor_alertas_altos`, `sensor.security_auditor_ultima_varredura`...).
Falsos positivos revisados podem ser ignorados direto no relatório, sem sumir dele.

## Feito para não virar o maior risco da instalação

- `/config` montado **somente leitura**; perfil **AppArmor próprio**, sem nenhuma capacidade do
  kernel e sem permissão de executar nada de onde o add-on escreve.
- **Sem** `docker_api`, `full_access`, `host_network` ou `privileged`.
- API do Supervisor usada **só para leitura**, garantido no código (só `GET`, numa lista fixa de
  caminhos).
- **Nenhum dado da instalação sai para serviços externos.** Só há downloads do GitHub e dos
  registros de imagens e consultas a bases de vulnerabilidades, conferidos contra uma
  allowlist de hosts a cada requisição e redirecionamento.
- Tokens, senhas e o conteúdo do `secrets.yaml` **nunca** aparecem no log ou no relatório.
- **Não sobrecarrega o HA**: prioridade baixa de CPU e disco, modo leve, espera o sistema
  desocupar antes das etapas pesadas e horário fixo de varredura, combináveis nas opções.

Detalhes, motivo de cada permissão e limitações em [`security_auditor/DOCS.md`](security_auditor/DOCS.md).

## Instalação

[![Adicionar repositório ao Home Assistant](https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg)](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2Fdiogocaseca%2Fha-security-auditor)

Ou manualmente:

1. Em **Configurações → Add-ons → Loja de add-ons → ⋮ → Repositórios**, adicione
   `https://github.com/diogocaseca/ha-security-auditor`.
2. Instale **HA Security Auditor**, inicie e ative **Mostrar na barra lateral**.
3. A primeira varredura começa sozinha; depois use **Varrer agora** quando quiser.

## Limitações importantes

- A análise estática **não vê código baixado em tempo de execução**; ela detecta o padrão
  (download + execução), não o conteúdo.
- Integridade só prova igualdade com a release; uma release oficial comprometida passa.
- Sem tag por versão, o código de add-ons analisado é o do `HEAD`.
- O DNS de todos os add-ons passa pelo HA: **não dá para saber qual add-on fez cada consulta**.

Lista completa em [DOCS.md → Limitações](security_auditor/DOCS.md#limitações).

## Estrutura do repositório

```
repository.yaml                 repositório customizado de add-ons
art/                            fontes SVG do ícone e do logo
security_auditor/
  config.yaml build.yaml        manifesto e build do add-on (amd64, aarch64)
  Dockerfile apparmor.txt       imagem e perfil AppArmor
  icon.png logo.png             ícone e logo exibidos no HA
  rootfs/run.sh                 ponto de entrada
  DOCS.md CHANGELOG.md          documentação e histórico exibidos no HA
  translations/                 rótulos das opções (pt-BR, en)
  app/auditor/                  código Python
    scanners/                   static, deps, integrity, addon_*, traffic, dns
    web/ report/                interface do Ingress e relatório
  app/rules/semgrep/            regras próprias (python, javascript, addon)
tests/                          pytest + fixtures (integrações limpa, ofuscada, adulterada)
```

## Desenvolvimento

Requer Python 3.12 e, para os testes de análise estática, Semgrep e Bandit no ambiente.

```bash
uv venv -p 3.12 .venv && uv pip install -p .venv/bin/python -r requirements-dev.txt
```
```bash
.venv/bin/python -m pytest
```
```bash
docker build -t local/security_auditor:dev security_auditor
```

Para rodar fora do HA (sem Supervisor, só a Fase 1), aponte `/config` para uma pasta e libere o
acesso local:

```bash
docker run --rm --init --network host -e AUDITOR_DEV_ALLOW_LOCAL=1 -v "$PWD/tests/fixtures/config:/config:ro" local/security_auditor:dev
```

e abra `http://127.0.0.1:8099/`. Os testes incluem uma checagem do perfil AppArmor contra os
caminhos reais dos executáveis da imagem.

## Licença

[MIT](LICENSE).
