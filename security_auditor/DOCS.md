# HA Security Auditor

O HA Security Auditor examina a sua instalação do Home Assistant em busca de sinais de risco:
código suspeito em integrações customizadas e no frontend (`www/`), arquivos adulterados,
dependências vulneráveis, add-ons com permissões amplas, imagens com CVEs, picos anormais de
tráfego e domínios suspeitos.

> **O auditor aponta o que merece revisão humana. Ele não decide sozinho que algo é
> malicioso.** Um achado é um convite para olhar o código ou a configuração, não um veredito.
> Muitos achados têm explicações legítimas (um add-on de hardware *precisa* de acesso a
> dispositivos). A explicação de cada achado diz por que ele chamou atenção e o que fazer.

## Índice

- [Instalação](#instalação)
- [Primeiro uso](#primeiro-uso)
- [O que é verificado](#o-que-é-verificado)
- [Opções](#opções)
- [Proteções contra sobrecarga](#proteções-contra-sobrecarga)
- [Lista de ignorados e allowlist](#lista-de-ignorados-e-allowlist)
- [Sensores](#sensores)
- [Severidades e nota de risco](#severidades-e-nota-de-risco)
- [Permissões pedidas e por quê](#permissões-pedidas-e-por-quê)
- [Para onde o auditor se conecta](#para-onde-o-auditor-se-conecta)
- [Segredos](#segredos)
- [Limitações](#limitações)
- [Dados guardados](#dados-guardados)
- [Solução de problemas](#solução-de-problemas)

## Instalação

1. Em **Configurações → Add-ons → Loja de add-ons**, abra o menu **⋮ → Repositórios**.
2. Adicione `https://github.com/diogocaseca/ha-security-auditor` e feche.
3. Procure **HA Security Auditor** na loja, instale e clique em **Iniciar**.
4. Ative **Mostrar na barra lateral** para ter o atalho **Security Auditor** no menu.
5. (Recomendado) Ative **Watchdog**. O Supervisor reinicia o add-on se ele cair ou se a
   verificação de saúde (`/api/status`) parar de responder. Varreduras longas não disparam o
   watchdog: o trabalho pesado roda fora do servidor web.

Arquiteturas suportadas: `amd64` e `aarch64` (Raspberry Pi 4/5 com sistema de 64 bits).

## Primeiro uso

Com a opção `scan_on_start` ligada (padrão), a primeira varredura começa assim que o add-on
inicia. Você também pode clicar em **Varrer agora** no topo da página. Enquanto uma varredura
roda, aparece o botão **Cancelar varredura**: as ferramentas em execução são encerradas e o que
já foi analisado fica salvo no histórico como "Cancelada" (uma varredura cancelada não vira
linha de base para a comparação).

- A **primeira varredura demora mais**: o Trivy baixa a base de vulnerabilidades (algumas
  centenas de MB, guardadas em `/data`) e o código das integrações é baixado do GitHub para
  comparação. As seguintes reaproveitam o cache.
- A primeira varredura é a **linha de base**: nada aparece como "novo". A partir da segunda,
  o relatório destaca o que surgiu e o que foi resolvido.
- Por padrão o auditor roda com **prioridade baixa** e **espera o sistema desocupar** antes das
  etapas pesadas; em Raspberry Pi, considere adicionar `modo_leve` e `horario_fixo` (veja
  [Proteções contra sobrecarga](#proteções-contra-sobrecarga)).
- A detecção de **picos de tráfego** só começa depois de cerca de 1 hora de coleta
  (12 amostras com o intervalo padrão de 5 minutos).

No relatório você encontra:

- cartões com o total por severidade: clique em um ou mais para filtrar os achados **e** a
  tabela de componentes (ficam só os componentes com achados nos níveis escolhidos); clique de
  novo para desmarcar;
- a tabela de componentes com a nota de risco e detalhes (versão, origem, integridade,
  código analisado, tráfego, CVEs);
- os achados de um componente: **clique no nome dele na tabela** para abrir uma tela só com
  os achados dele, com filtros por nível. Use **Voltar para o resumo** (ou o voltar do
  navegador); os níveis que estavam marcados no resumo continuam marcados;
- cada achado com componente, tipo, arquivo e linha, trecho de código (com segredos
  mascarados), por que é suspeito e o que fazer;
- filtros por texto, "só novos" e "mostrar suprimidos";
- o botão **Ignorar…** em cada achado e o quadrado **Ignorados**, que mostra quantos achados
  estão ignorados e abre a [lista de ignorados](#lista-de-ignorados-e-allowlist);
- o histórico de varreduras e o botão **Exportar JSON**;
- o seletor de tema **Sistema / Claro / Escuro**.

## O que é verificado

### Integrações customizadas e frontend (`/config/custom_components` e `/config/www`)

**Análise estática** com o [Semgrep](https://semgrep.dev) (regras próprias) e o
[Bandit](https://bandit.readthedocs.io). A lista de arquivos é montada pelo auditor e passada
explicitamente, então arquivos `*.min.js` e pastas `tests/` (que o Semgrep ignora por padrão)
também são analisados. Quando o Bandit e o Semgrep apontam a mesma linha, fica um achado só.

| Regra | O que procura | Severidade |
|---|---|---|
| `auditor.py.ofuscacao-decodifica-e-executa` | base64/zlib/marshal/hex decodificado e executado | Crítica |
| `auditor.py.download-e-execucao` | conteúdo baixado da rede chegando a `exec`/`eval`/subprocess | Crítica |
| `auditor.py.shell-reverso` | socket redirecionado para um shell | Crítica |
| `auditor.py.acesso-storage-auth` | leitura de `.storage/auth*` (usuários e tokens) | Crítica |
| `auditor.py.eval-dinamico` | `eval`/`exec`/`compile` com dados dinâmicos | Alta |
| `auditor.py.marshal-loads` | carregamento de bytecode | Alta |
| `auditor.py.builtins-indireto` | `getattr(__builtins__, ...)` e afins | Alta |
| `auditor.py.shell-true` | comando executado via shell | Alta |
| `auditor.py.instalacao-de-pacote-em-tempo-de-execucao` | `pip install` feito pela própria integração | Alta |
| `auditor.py.destino-suspeito` | webhooks, pastebins, túneis, `raw.githubusercontent.com` | Alta |
| `auditor.py.acesso-secrets-yaml` | leitura direta do `secrets.yaml` | Alta |
| `auditor.py.acesso-storage` | leitura de outros arquivos de `.storage` | Alta |
| `auditor.py.execucao-de-comandos` | `subprocess`, `os.system`, `os.exec*` | Média |
| `auditor.py.carregamento-dinamico-de-modulo` | módulos carregados de caminhos arbitrários | Média |
| `auditor.py.ip-fixo-publico` | IP público fixo no código | Média |
| `auditor.py.tokens-de-acesso` | criação de usuários/tokens do HA | Média |
| `auditor.py.blob-codificado` | string longa em base64/hex | Média |
| `auditor.py.url-fixa` | URLs fixas (para conferência) | Informativa |
| `auditor.js.ofuscacao-decodifica-e-executa` | `eval(atob(...))` e afins | Crítica |
| `auditor.js.acesso-token-ha` | leitura do token de acesso (`hassTokens`) no navegador | Alta |
| `auditor.js.destino-suspeito` | serviços de exfiltração em scripts | Alta |
| `auditor.js.eval-dinamico` | `eval`/`new Function` com dados dinâmicos | Média |
| `auditor.js.codigo-remoto` | script carregado de endereço externo | Média |
| `auditor.js.ip-fixo-publico` | conexão com IP público fixo | Média |
| `bandit.*` | demais avisos do Bandit (pickle, TLS desativado, hash fraco...) | conforme o Bandit |

**Dependências.** Os `requirements` do `manifest.json` são auditados com o
[pip-audit](https://pypi.org/project/pip-audit/) contra a base [OSV](https://osv.dev). Ele roda
em modo `--no-deps --disable-pip`: só consulta a base e nunca instala nem resolve pacotes, porque
resolver poderia executar `setup.py` de terceiros. Por isso só requisitos com versão exata
(`==`) podem ser auditados; os demais aparecem como informativos. Dependências instaladas de
URL ou repositório git aparecem como Média.

**Integridade.** Para cada integração com repositório identificável (pelo HACS, em
`.storage/hacs.repositories`, ou pelas URLs do `manifest.json`), o auditor baixa do GitHub a
versão instalada e compara arquivo a arquivo por SHA-256:

- tenta a tag com e sem o prefixo `v` e o commit gravado pelo HACS;
- respeita `zip_release`, `content_in_root` e `persistent_directory` do `hacs.json`;
- **arquivo alterado** ou **arquivo extra** = Alta, com o diff (ou o início do arquivo) no
  relatório; arquivo ausente = Baixa;
- sem repositório identificável (instalação manual) = Baixa; versão não encontrada no
  repositório = Informativa.

### Outros add-ons (via API do Supervisor)

O próprio Security Auditor fica de fora (permissões, código, imagem e tráfego): ele se
identifica por `/addons/self/info`. As permissões dele estão explicadas em
[Permissões pedidas e por quê](#permissões-pedidas-e-por-quê).

**Permissões e estado**, lidos de `/addons/<slug>/info`:

| Situação | Severidade |
|---|---|
| `docker_api` | Crítica |
| `full_access`, `host_pid`, módulos de kernel, capacidades como `SYS_ADMIN`/`SYS_MODULE`/`SYS_PTRACE`, AppArmor desativado, modo de proteção desligado, papel `admin` no Supervisor | Alta |
| `host_network`, D-Bus do host, API do Home Assistant, papel `manager`, nota de segurança ≤ 2 | Média |
| `auth_api`, papéis `backup`/`homeassistant`, outras capacidades, nota 3, atualização pendente | Baixa |
| Acesso a dispositivos, perfil AppArmor genérico, add-on local ou de terceiros | Informativa |

O próprio Security Auditor também aparece nessa lista, com as permissões dele.

**Código-fonte.** O auditor procura o código do add-on no GitHub (repositório do campo `url`
e repositório da loja), tentando a tag da versão instalada e, por último, o `HEAD`. Se o código
analisado for de outra versão, o relatório avisa. Ele avalia o `map` do `config.yaml`
(`/config` com escrita = Alta, porque permite instalar uma integração e executar código dentro
do HA Core) e aplica as regras abaixo ao Dockerfile e aos scripts, além das regras Python/JS:

| Regra | O que procura | Severidade |
|---|---|---|
| `auditor.sh.decodifica-e-executa` | comando em base64 decodificado e executado | Crítica |
| `auditor.sh.shell-reverso` | `/dev/tcp`, `nc -e`, `socat exec:` | Crítica |
| `auditor.sh.baixa-e-executa` | `curl ... \| sh` | Alta |
| `auditor.sh.token-supervisor-externo` | `SUPERVISOR_TOKEN` enviado a host que não é o Supervisor | Alta |
| `auditor.sh.acesso-sensivel` | leitura de `secrets.yaml` ou `.storage/auth` | Alta |
| `auditor.sh.destino-suspeito` | serviços de exfiltração | Alta |
| `auditor.sh.tls-desativado` | `curl -k`, `wget --no-check-certificate` | Média |
| `auditor.docker.add-de-url` | `ADD https://...` sem verificação de hash | Baixa |
| `auditor.sh.permissao-777` | `chmod 777` | Baixa |

**Imagens.** O [Trivy](https://trivy.dev) varre a imagem de cada add-on **direto no
registro** (ghcr.io, Docker Hub...), sem daemon Docker, procurando CVEs e segredos embutidos.
As CVEs viram um achado por add-on: Alta se há CVE crítica com correção disponível, Média se há
CVE alta com correção, Baixa se as críticas/altas ainda não têm correção. Segredos embutidos
viram achados Alta separados. Add-ons construídos localmente não têm imagem no registro.

**Tráfego.** Um coletor em segundo plano grava CPU, memória e rede (rx/tx) de cada add-on a cada
`stats_interval_minutes`. Um **pico de envio** é registrado quando a taxa passa, ao mesmo tempo,
de: média + 4 desvios-padrão do próprio add-on nos últimos 7 dias, 3× a média e 50 KiB/s. Os
picos aparecem uma vez, na varredura seguinte (Média; Alta se ≥ 20× a média e ≥ 1 MiB/s).

### DNS (opcional, AdGuard Home e/ou Pi-hole v6)

Com `adguard_url` e/ou `pihole_url` preenchidos, o auditor lê dos seus servidores DNS as
consultas feitas pelo host do HA nas últimas 24 horas e mostra a seção **Domínios
consultados** no relatório.

**Com os dois configurados** (por exemplo, um como DNS primário e o outro como secundário),
as consultas dos dois são somadas e analisadas juntas, e a tabela ganha a coluna **Servidor**
(AdGuard Home, Pi-hole ou ambos). Se um deles estiver fora do ar ou recusar a senha, o outro
continua sendo usado e o relatório avisa qual ficou de fora. Se o HA mandar a mesma consulta
para os dois, ela é contada duas vezes; se um encaminhar para o outro (AdGuard → Pi-hole), o
segundo só vê o primeiro como cliente e essas consultas não entram de novo.

> **Não é possível saber qual add-on ou integração fez cada consulta.** O DNS de todos os
> add-ons e integrações passa pelo DNS do Supervisor, que encaminha para o seu servidor; para o
> AdGuard/Pi-hole, tudo vem do mesmo cliente. O relatório repete esse aviso em cada achado.

| Situação | Severidade |
|---|---|
| Serviços de exfiltração, túneis e pastebins (`webhook.site`, `ngrok`, `pastebin`...) | Alta |
| Pools de mineração de criptomoedas | Alta |
| Domínios com aparência aleatória (exceto CDNs conhecidas e Nabu Casa) | Baixa |
| Domínios bloqueados pelo seu filtro | Baixa |
| Domínios novos desde a varredura anterior | Informativa |

O Pi-hole v5 não é suportado (API antiga).

## Opções

| Opção | Padrão | Descrição |
|---|---|---|
| `scan_interval_hours` | `24` | Intervalo entre varreduras agendadas. `0` desativa o agendamento (só o botão). |
| `scan_on_start` | `true` | Varre logo que o add-on inicia. |
| `modo_execucao` | `prioridade_baixa`, `aguardar_folga` | Proteções contra sobrecarga, combináveis. Veja [Proteções contra sobrecarga](#proteções-contra-sobrecarga). |
| `horario_varredura` | `03:30` | Horário diário (HH:MM, fuso do HA) usado com o modo `horario_fixo`. |
| `memoria_minima_mb` | `500` | Memória livre mínima para o modo `aguardar_folga`. A varredura de imagens exige o valor inteiro; as demais etapas pesadas, a metade. |
| `carga_maxima_por_cpu` | `1.5` | Carga média de 1 minuto por núcleo acima da qual o modo `aguardar_folga` espera. |
| `log_level` | `info` | `debug`, `info`, `warning` ou `error`. |
| `github_token` | vazio | Token do GitHub **sem nenhum escopo**, só para subir o limite da API de 60 para 5000 requisições/hora. Recomendado com muitas integrações que usam `zip_release`. Nunca é registrado em log. |
| `report_retention` | `10` | Quantos relatórios guardar. |
| `addons_scan` | `true` | Audita os outros add-ons (permissões, código, imagens, tráfego). |
| `image_scan` | `true` | Varre as imagens com o Trivy. É a etapa mais demorada; consome banda e espaço em `/data`. |
| `image_scan_skip` | `[]` | Slugs de add-ons cujas imagens não devem ser varridas (ex.: `core_mosquitto`). |
| `stats_interval_minutes` | `5` | Intervalo de coleta de CPU/memória/rede. `0` desativa. |
| `adguard_url` | vazio | Endereço do AdGuard Home. Ex.: `http://192.168.1.2:3000` ou `http://a0d7b954-adguard:3000` (AdGuard como add-on). |
| `adguard_username` / `adguard_password` | vazio | Login do AdGuard Home. A senha nunca é registrada em log. |
| `pihole_url` | vazio | Endereço do Pi-hole v6. Ex.: `http://pi.hole` ou `http://192.168.1.3`. |
| `pihole_password` | vazio | **Senha de app** do Pi-hole v6. Nunca é registrada em log. |
| `dns_client_ips` | `[]` | IPs com que o HA aparece no servidor DNS. Vazio = IPs do host (via Supervisor) + `172.30.32.3` (DNS do Supervisor). |
| `dns_verify_tls` | `true` | Desative só se o AdGuard ou o Pi-hole usar HTTPS com certificado próprio (vale para os dois). |
| `allowlist` | `[]` | Exceções; veja abaixo. |

## Proteções contra sobrecarga

O HA OS não permite limitar a CPU ou a memória de um add-on, então o próprio auditor se
contém. Em **`modo_execucao`** você adiciona quantos modos quiser; eles se combinam. Lista
vazia = sem proteções (a varredura fica mais rápida, mas pode pesar no HA).

| Modo | O que faz | Custo |
|---|---|---|
| `prioridade_baixa` | O auditor e tudo o que ele inicia (Semgrep, Bandit, pip-audit, Trivy) rodam com prioridade mínima de CPU (`nice 19`) e de disco (classe "ociosa": só usa o disco quando ninguém mais está usando). | Nenhum perceptível. |
| `modo_leve` | Semgrep com 1 processo e teto de 768 MB de memória; Trivy com paralelismo 1; pausa de 2 s entre componentes. | Varredura bem mais lenta. Recomendado em Raspberry Pi e máquinas com pouca memória. |
| `aguardar_folga` | Antes de cada etapa pesada (análise estática, código dos add-ons, cada imagem), confere a carga e a memória livre **do host**. Se passar de `carga_maxima_por_cpu` ou ficar abaixo de `memoria_minima_mb`, espera (até 10 min, checando a cada 30 s). Se não desocupar, **adia** a etapa e registra o achado informativo "Etapa adiada"; ela roda na próxima varredura. | A varredura pode ficar incompleta em horários de pico. |
| `horario_fixo` | A varredura agendada passa a rodar **uma vez por dia** em `horario_varredura`, no fuso do HA, em vez de a cada `scan_interval_hours` contados do início do add-on. O botão "Varrer agora" continua funcionando a qualquer hora. | Nenhum. |

Combinações úteis:

- **Padrão** (`prioridade_baixa` + `aguardar_folga`): bom para a maioria das instalações.
- **Raspberry Pi**: os quatro modos, com `horario_varredura` numa hora calma (madrugada).
- **Máquina folgada que você quer varrer rápido**: só `prioridade_baixa`.

O topo do relatório mostra quais proteções estão ativas e, com `horario_fixo`, o horário da
próxima varredura.

Limitações:

- O Docker põe cada container num grupo de CPU próprio. A prioridade baixa vale dentro do
  container e no disco, mas **não garante sozinha** que o HA Core fique com a CPU quando os dois
  disputam; por isso os outros modos existem.
- Com `scan_on_start` ligado, a varredura de inicialização ignora o `horario_fixo`. Desligue
  `scan_on_start` para que as varreduras automáticas rodem só no horário escolhido.
- A carga do host inclui o que o próprio auditor acabou de fazer; com o limite padrão
  (1,5 por núcleo), as etapas do auditor sozinhas não costumam disparar a espera.

## Lista de ignorados e allowlist

Use para silenciar falsos positivos que você já revisou. A lista abre ao clicar no quadrado
**Ignorados**, ao lado dos cartões de nível. **Achados ignorados continuam no
relatório** (marque "Mostrar suprimidos"); eles só deixam de contar nos totais, nos sensores
e na nota de risco. Assim nada some em silêncio. Há dois jeitos de ignorar, e os dois valem
juntos:

**Pela interface (lista de ignorados).** Em cada achado do relatório mais recente, clique em
**Ignorar…**, escolha o alcance e escreva o motivo:

| Alcance | O que deixa de contar |
|---|---|
| Só este achado | Apenas esse achado (identificado pela impressão digital: componente, regra, arquivo e trecho). Se o código mudar, ele volta a aparecer. |
| Esta regra neste arquivo | Todos os achados da regra naquele arquivo. |
| Esta regra em todo o componente | Todos os achados da regra no componente. |
| Esta regra em todos os componentes | A regra inteira, em qualquer componente. |

Também dá para ignorar a partir da **tabela de componentes**:

- **Ignorar…** na linha de um componente ignora os achados dele em todas as regras. Se houver
  níveis marcados nos cartões (por exemplo Baixa e Informativa), eles já vêm selecionados e só
  esses níveis são ignorados; os outros continuam contando. Sem nenhum nível marcado, vale para
  todos.
- Com um ou mais níveis marcados nos cartões, aparece **Ignorar estes níveis…**, que ignora os
  níveis escolhidos **em todos os componentes** (por exemplo, todo o nível Informativa). Pede
  confirmação. Ignorar todos os níveis de uma vez não é aceito.

Itens restritos a níveis mostram os níveis na coluna **Alcance** da lista.

Também dá para incluir manualmente em **Lista de ignorados → Incluir na lista…** (componente,
regra, arquivo e níveis, com curingas) e tirar com **Remover** ou com **Deixar de ignorar** no próprio
achado. A mudança vale **na hora** para o relatório mais recente e para os sensores, sem precisar
varrer de novo, e também para as próximas varreduras. Relatórios antigos do histórico não são
alterados. A lista fica em `/data/auditor.db` e entra no backup do add-on. Por segurança, não é
aceito componente `*` com regra `*` sem arquivo (isso ignoraria tudo).

**Pela configuração (allowlist).** A opção `allowlist` continua funcionando e aparece na lista
de ignorados com a origem "Configurações"; essas entradas só podem ser removidas na aba
**Configuração** do add-on. Cada entrada tem:

- `component`: nome da integração, slug do add-on, `dns` ou `*` (qualquer);
- `rule`: id da regra (o relatório mostra), aceita curingas como `bandit.*` ou `*`;
- `path` (opcional): curinga do arquivo, como aparece no relatório;
- `reason`: por que é aceitável (aparece no relatório).

Exemplo (modo YAML das opções):

```yaml
allowlist:
  - component: ping_customizado
    rule: auditor.py.execucao-de-comandos
    reason: Chama o ping do sistema, revisado em 12/11/2026
  - component: minha_integracao
    rule: auditor.integridade.arquivo-extra
    path: custom_components/minha_integracao/cache/*
    reason: A integração grava cache na própria pasta
  - component: "*"
    rule: auditor.py.url-fixa
    reason: Não quero ver URLs fixas
```

## Sensores

Depois de cada varredura (e a cada 15 minutos, porque estados criados por API não sobrevivem a
um reinício do Core), o add-on publica:

| Entidade | Conteúdo |
|---|---|
| `sensor.security_auditor_alertas_criticos` | achados críticos não suprimidos |
| `sensor.security_auditor_alertas_altos` | achados altos |
| `sensor.security_auditor_alertas_medios` | achados médios |
| `sensor.security_auditor_alertas_baixos` | achados baixos |
| `sensor.security_auditor_novos_achados` | achados novos desde a varredura anterior |
| `sensor.security_auditor_ultima_varredura` | data/hora da última varredura (`timestamp`) |
| `sensor.security_auditor_status` | `ocioso`, `varrendo`, `concluida` ou `falhou` |

Exemplo de automação:

```yaml
automation:
  - alias: Avisar sobre achados novos de segurança
    triggers:
      - trigger: numeric_state
        entity_id: sensor.security_auditor_novos_achados
        above: 0
    actions:
      - action: notify.notify
        data:
          title: Security Auditor
          message: >-
            {{ states('sensor.security_auditor_novos_achados') }} achado(s) novo(s).
            Altos: {{ states('sensor.security_auditor_alertas_altos') }},
            críticos: {{ states('sensor.security_auditor_alertas_criticos') }}.
```

## Severidades e nota de risco

| Severidade | Significado |
|---|---|
| **Crítica** | Padrão típico de código malicioso (ofuscação + execução, roubo de credenciais, shell reverso) ou permissão que dá controle total do host. Revise já. |
| **Alta** | Muito incomum em componentes legítimos, ou arquivo diferente da release oficial. |
| **Média** | Pode ser legítimo, mas amplia muito o estrago se o componente for comprometido. |
| **Baixa** | Vale saber; raramente exige ação. |
| **Informativa** | Contexto (URLs usadas, etapas que não puderam rodar). |

A **nota de risco** de cada componente (0 a 100) soma 40 por crítica, 15 por alta, 5 por média
e 1 por baixa, sem contar suprimidos. Ela só ordena o que revisar primeiro; **não é uma
probabilidade de o componente ser malicioso**.

## Permissões pedidas e por quê

O auditor foi desenhado para não virar o maior risco da sua instalação. Ele pede só o
necessário:

| Permissão | Por quê |
|---|---|
| `map: homeassistant_config` **somente leitura** em `/config` | Ler integrações, `www/`, `.storage/hacs.repositories` e o `secrets.yaml` (este último só para mascarar os valores; veja [Segredos](#segredos)). Não é possível escrever em `/config`. |
| `hassio_api: true` com `hassio_role: manager` | Listar os add-ons e ler permissões, estatísticas, repositórios da loja e IPs do host. O papel `default` só libera endpoints terminados em `/info`; listar os add-ons (`/addons`), ler os repositórios da loja e as estatísticas de **outros** add-ons (`/stats`) exige `manager`. **Esse papel permitiria alterações**, por isso a garantia de leitura está no código: o cliente do Supervisor só faz `GET`, e só numa lista fixa de caminhos (`/addons`, `/addons/<slug>/info`, `/addons/<slug>/stats`, `/store`, `/store/repositories`, `/info`, `/core/info`, `/supervisor/info`, `/network/info`). Qualquer outro caminho é recusado antes de sair do add-on. |
| `homeassistant_api: true` | Publicar os sensores. O cliente só aceita gravar entidades `sensor.security_auditor_*`; não lê nem controla outras entidades. |
| `ingress: true` | Mostrar o relatório na barra lateral, com o login do próprio HA. O servidor web só aceita conexões vindas do Ingress (`172.30.32.2`), usa CSP restritiva e token anti-CSRF no botão "Varrer agora". Nenhuma porta é aberta na rede. |
| `apparmor: true` com perfil próprio | Ver abaixo. |
| `init: true` | O tini do Docker como processo inicial, para repassar sinais e recolher processos das ferramentas. |
| `watchdog` | Endereço de saúde (`/api/status`) que o Supervisor consulta quando a chave Watchdog está ligada. Só devolve o estado do agendador, sem dados da instalação. |

O que o auditor **não** pede: `docker_api`, `full_access`, `host_network`, `privileged`,
`host_pid`, acesso a dispositivos ou papel `admin`.

**Perfil AppArmor** (`apparmor.txt`):

- nenhuma capacidade do kernel: o root do container não tem `dac_override`, `sys_admin`,
  `net_admin` etc.;
- escrita só em `/data`, `/tmp` e `/dev/shm`; `/config` somente leitura (negação explícita);
- **nada pode ser executado** de `/data`, `/tmp`, `/dev/shm` ou `/config`: código baixado ou
  analisado nunca roda;
- execução só nas pastas do sistema (somente leitura no container), sempre herdando o mesmo
  perfil.

As ferramentas externas (Semgrep, Bandit, pip-audit, Trivy) rodam com ambiente mínimo: o
`SUPERVISOR_TOKEN` e as opções do add-on **não** são repassados a elas, o `HOME` é um diretório
temporário isolado e a telemetria e a checagem de versão de cada uma estão desligadas.

## Para onde o auditor se conecta

O auditor **nunca envia dados da sua instalação para serviços externos**. As únicas saídas são
downloads e consultas a bases de vulnerabilidades:

| Destino | Para quê | Quem acessa |
|---|---|---|
| `api.github.com`, `github.com`, `codeload.github.com`, `objects.githubusercontent.com`, `release-assets.githubusercontent.com`, `raw.githubusercontent.com` | Baixar o código das integrações e add-ons para comparação e análise | Auditor (Python) |
| `api.osv.dev` | Consultar vulnerabilidades dos requirements (envia só nome e versão do pacote) | pip-audit |
| Registros das imagens (`ghcr.io`, Docker Hub e o registro que cada add-on usar) | Baixar manifesto e camadas das imagens | Trivy |
| `mirror.gcr.io`, `ghcr.io` | Baixar a base de vulnerabilidades do Trivy | Trivy |
| Os hosts de `adguard_url` e `pihole_url` | Ler o log de consultas dos seus servidores DNS (Fase 3, opcional) | Auditor (Python) |

No código Python, toda conexão passa por um cliente único que exige HTTPS e confere o host de
cada requisição **e de cada redirecionamento** contra a lista acima. O token do GitHub só é
enviado para hosts do próprio GitHub, nunca para as CDNs para onde a API redireciona. Na Fase 3
cada servidor DNS tem um cliente separado, que só fala com o host da própria URL (a senha do
AdGuard nunca vai para o Pi-hole e vice-versa). É o único lugar onde HTTP sem TLS é aceito, por
ser comum na rede local.

O AppArmor não consegue filtrar rede por domínio; por isso o filtro fica no código. As conexões
do Trivy e do pip-audit são limitadas ao que essas ferramentas fazem (registros, bases de
vulnerabilidades) e às flags com que o auditor as chama.

## Segredos

Tokens, senhas e o conteúdo do `secrets.yaml` **nunca** vão para o log nem para o relatório:

- os valores do `secrets.yaml`, o `SUPERVISOR_TOKEN`, o `github_token` e as senhas do AdGuard e do Pi-hole são
  carregados **só em memória** e trocados por `****` onde aparecerem (trechos de código, diffs,
  mensagens de erro, tracebacks);
- formatos conhecidos são mascarados mesmo sem estar no `secrets.yaml`: JWT (inclusive os
  tokens de longa duração do HA), tokens do GitHub, AWS, Slack, Telegram e Google, chaves
  privadas PEM, senhas em URLs (`usuario:senha@host`) e atribuições como `password = "..."`;
- o mesmo filtro é aplicado a toda mensagem de log, de qualquer biblioteca.

O mascaramento distingue código de valores: `token = open(...)` aparece normalmente, para não
esconder a evidência de um achado.

## Limitações

Leia antes de concluir que "está tudo limpo":

- **A análise estática não vê código baixado em tempo de execução.** Se uma integração baixa e
  executa código depois de instalada, o auditor pode detectar o *padrão* (download + execução,
  carregamento dinâmico de módulo), mas não o conteúdo que será executado nem mudanças
  feitas pelo servidor remoto depois.
- **Ofuscação suficientemente criativa escapa das regras.** As regras cobrem as técnicas
  comuns; código feito para enganar ferramentas específicas pode passar. A verificação de
  integridade ajuda: código adulterado depois da instalação aparece como arquivo alterado.
- **Integridade só prova que o arquivo é igual à release.** Se a própria release oficial for
  maliciosa (repositório comprometido), a integridade passa; a análise estática é a outra
  camada. Integrações instaladas manualmente, sem repositório no GitHub, não podem ser
  comparadas. Os cards de `www/community/` passam pela análise estática, mas ainda **não** são
  comparados com a release.
- **Código-fonte de add-ons pode não corresponder à imagem.** Repositórios de add-ons raramente
  têm tag por versão; sem tag, o código analisado é o do `HEAD`. Para add-ons com imagem pronta,
  a imagem pode ter sido construída de um código diferente do publicado; a varredura da imagem
  com o Trivy cobre essa lacuna só em parte (CVEs e segredos, não comportamento).
- **CVEs não são necessariamente exploráveis.** Muitas CVEs de imagem estão em pacotes que o
  add-on nem usa. Use a contagem para identificar imagens desatualizadas.
- **Tráfego de add-ons com `host_network` não é medido**: o Docker não separa o tráfego deles
  do host. Picos legítimos (backups, uploads) também disparam alertas.
- **DNS não identifica o autor da consulta** (veja a seção de DNS). Consultas feitas por IP
  direto, por DNS sobre HTTPS ou por servidores DNS fixos no código não passam pelo seu
  AdGuard/Pi-hole e não aparecem.
- **Arquivos que o root sem capacidades não consegue ler** (por exemplo, `0600` de outro
  usuário em `/config`) ficam fora da análise.

## Dados guardados

Tudo fica em `/data` do add-on (incluído nos backups do add-on):

- `auditor.db` (SQLite): histórico de varreduras, lista de ignorados, estatísticas dos add-ons (30 dias), picos de
  tráfego e domínios DNS já vistos;
- `reports/*.json`: os últimos `report_retention` relatórios, os mesmos do botão Exportar JSON;
- `cache/`: código de referência do GitHub (integridade e add-ons), base do Trivy e cache do
  pip-audit.

Nada disso é enviado para fora. Apagar `cache/` só faz o próximo download demorar mais.

## Solução de problemas

**O add-on não inicia e o log mostra `Permission denied`.** É o AppArmor negando algo. Abra
**Configurações → Sistema → Logs → Host** e procure linhas com `apparmor="DENIED"` e
`profile="security_auditor"`; elas dizem qual arquivo e qual permissão faltou. Abra uma issue
no repositório com essas linhas.

**"Integridade não verificada: limite de requisições do GitHub".** Crie um token em
**GitHub → Settings → Developer settings → Fine-grained tokens** sem nenhuma permissão
(apenas acesso a repositórios públicos) e coloque em `github_token`.

**"Integridade não verificada: nenhuma versão correspondente".** A versão instalada não existe
como tag no repositório. É comum em integrações instaladas de um branch. Se a versão deveria
existir, desconfie: o código pode não ser o que se diz.

**A varredura de imagens demora ou enche o disco.** Desative `image_scan` ou liste os add-ons
mais pesados em `image_scan_skip`. A base do Trivy fica em `/data/cache/trivy`.

**O HA fica lento durante a varredura.** Adicione `modo_leve` (e `horario_fixo` com um horário
de madrugada) em `modo_execucao`; veja [Proteções contra sobrecarga](#proteções-contra-sobrecarga).

**Aparece sempre "Etapa adiada".** O sistema está ocupado no horário da varredura. Use
`horario_fixo` para um horário calmo ou aumente `carga_maxima_por_cpu` / reduza
`memoria_minima_mb` (com cuidado: o Trivy é a etapa que mais consome memória).

**A seção de DNS não aparece ou está vazia.**

- Veja o achado `auditor.dns.falha`, que diz o motivo (URL, senha, versão do Pi-hole).
- No Pi-hole v6, use uma **senha de app** (Configurações → Web interface / API).
- Se a lista vier vazia, descubra no log do AdGuard/Pi-hole com que IP o HA aparece e
  preencha `dns_client_ips`.

**Muitos falsos positivos de uma regra.** Use a [allowlist](#lista-de-ignorados-e-allowlist). Se a regra
erra com frequência em integrações populares, abra uma issue com o trecho de código (sem
segredos) para ajustarmos a regra.
