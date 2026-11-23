# Changelog

## 0.33.0

- **Imagem pronta:** o app agora baixa a imagem publicada em `ghcr.io/diogocaseca/security-auditor`
  (amd64 e aarch64, montada e assinada pelo GitHub Actions) em vez de montar tudo na máquina. A
  instalação e as atualizações ficam bem mais rápidas, principalmente em Raspberry Pi, e todo mundo
  roda exatamente a mesma imagem.
- Depois de publicar uma versão, a imagem leva alguns minutos para ficar pronta no GitHub; atualizar
  antes disso dá erro de download (basta tentar de novo depois).

## 0.32.2

Preparação para distribuir o app com imagens prontas:

- **GitHub Actions** (`.github/workflows/build.yaml`): a cada versão, monta as imagens amd64 e
  aarch64 (em máquinas ARM nativas, sem emulação), assina com Cosign e publica em
  `ghcr.io/diogocaseca/security-auditor`, com manifesto multiarquitetura. Uma versão publicada
  nunca é sobrescrita. Todas as actions são fixadas por commit. Pull requests só montam, sem publicar.
- **Dockerfile no formato novo do Home Assistant:** imagem base multiarquitetura
  (`ghcr.io/home-assistant/base-python:3.12-alpine3.22`) direto no `FROM` e rótulos no próprio
  Dockerfile; o `build.yaml` (formato antigo, que o Supervisor vai deixar de ler) saiu.
- **Estágio experimental:** o app aparece como *experimental* na loja enquanto as regras são
  ajustadas a partir de instalações reais.
- README: instalação com o nome novo do menu (**Apps**) e aviso de projeto experimental.

Por enquanto o HA ainda monta a imagem na própria máquina: o `config.yaml` só passa a apontar para
a imagem pronta depois que a primeira publicação for conferida.

## 0.32.1

Correções a partir da primeira varredura real com o registro do Marketplace e as listas de ameaças:

- **Domínios no código:** só contam nomes numa URL (`https://…`) ou sozinhos entre aspas. Antes,
  chamadas como `console.info(`, `performance.now()` e `subprocess.run` viravam "domínios" (os TLDs
  .info, .now e .run existem, e golpistas registraram esses nomes), o que gerou 195 achados Altos
  falsos. Domínio só entre aspas (pode ser uma chave de tradução) agora é Média.
- **Integridade dos cards:**
  - todos os anexos da release são conferidos (antes, só os 20 primeiros; cards com mais anexos
    tinham arquivos legítimos marcados como "extras");
  - arquivo idêntico ao de outra release do repositório (pelo SHA-256 que o GitHub informa) vira
    "Sobra de uma versão anterior" ou "Arquivo de outra versão", Informativa: o HACS não apaga os
    arquivos antigos ao atualizar;
  - arquivo alterado que não é código (README, imagem) é Baixa;
  - o cache antigo é completado no lugar, sem baixar de novo o código-fonte dos cards.
- **Pastas com maiúsculas diferentes:** só a pasta com o nome exato do repositório fica ligada ao
  registro do HACS (uma instalação antiga em `tradingview-widget-card` herdava o registro de
  `Tradingview-Widget-Card` e era comparada com a versão errada).

## 0.32.0

DNS mais esperto, sem mandar nada da sua casa para fora:

- **Lista de ameaças do HaGeZi:** os domínios consultados são comparados com os *Threat
  Intelligence Feeds* (versão média, ~378 mil domínios de malware, phishing, C2 e golpes), baixados
  do GitHub a cada 12 h e comparados aqui dentro. Domínio da lista vira achado Alto (Médio se o seu
  filtro bloqueou todas as consultas).
- **Domínios do código na lista de ameaças:** todo nome de domínio citado no código das integrações
  e dos cards é comparado com a mesma lista; um domínio da lista vira achado Alto no componente,
  com arquivo e linha, mesmo que nunca tenha sido consultado.
- **Quem usa cada domínio:** os achados e a tabela de domínios dizem em que componente o domínio
  aparece no código ("citado no código de…") e se a primeira consulta veio logo depois de instalar
  ou atualizar algo ("primeira consulta logo depois de…").
- **DNS cifrado (DoH/DoT):** consulta a servidores como `dns.google` ou `cloudflare-dns.com`, que
  contornam o AdGuard/Pi-hole, vira achado Médio (lista *Encrypted DNS Bypass* do HaGeZi, com uma
  lista curta embutida de reserva).
- **Túnel por DNS por volume:** 50+ nomes diferentes ou 20+ consultas TXT sob o mesmo domínio em
  24 h.
- **Ritmo regular ("batimento cardíaco"):** domínio novo, que nenhum componente cita, consultado
  em intervalos quase iguais (sinal fraco, Baixa).
- O tipo da consulta (A, AAAA, TXT…) agora é lido do AdGuard Home e do Pi-hole.

## 0.31.0

- **Mais dados para a IA:** ao clicar em **Perguntar à IA**, o auditor junta dados públicos do host e
  manda como evidência, e eles aparecem no diálogo abaixo da resposta:
  - **DNS** (pelo DNS da sua casa, sem destino novo): IPs, cadeia de CNAME, servidores de nome e se há
    MX, SPF e DMARC (sem o TTL, que no cache da casa engana). Diz quando o AdGuard/Pi-hole bloqueia o domínio. Feito em Python
    (`dnspython`), sem rodar `dig`; o texto dos registros TXT não é enviado;
  - **registro (RDAP)**: data de registro e idade, expiração, registrador e status do domínio; para
    IP, rede, organização e país. O servidor vem da lista oficial da IANA (`data.iana.org/rdap`,
    guardada por uma semana) e só sai o domínio registrado ou o IP.
- **Saídas novas:** `data.iana.org` e os servidores RDAP listados pela IANA, só no clique.
- **Dependência nova:** `dnspython` 2.9.2 (com hash fixo, sem dependências).

## 0.30.8

- **HACS virou Marketplace:** o registro agora fica em `.storage/marketplace.repositories` (antes,
  `.storage/hacs.repositories`), e o auditor só procurava os arquivos `hacs.*`. Com isso, todas as
  integrações e cards apareciam como "manual", sem a integridade dos cards e sem os sinais do GitHub.
  Agora lê os dois nomes, nos dois formatos.
- **Diagnóstico no log:** avisa também quando o registro existe mas nenhum repositório aparece como
  baixado.

## 0.30.7

- **Registro do HACS no formato novo:** o auditor só lia `.storage/hacs.repositories`. Versões novas
  do HACS guardam os repositórios em `.storage/hacs.data` (por categoria), e aí todas as integrações
  e cards apareciam como "manual", sem a verificação de integridade dos cards e sem os sinais do
  GitHub (tag reescrita, repositório transferido). Agora lê os dois formatos.
- **Só os baixados:** repositórios que estão só no catálogo do HACS (nunca instalados) não são mais
  confundidos com um card ou integração de mesmo nome.
- **Diagnóstico no log:** cada varredura informa quantos repositórios baixados vieram do registro
  do HACS, e avisa se houver arquivos do HACS num formato desconhecido.

## 0.30.6

- **`secrets.yaml` em comparações:** `nome == "secrets.yaml"`, `!=` e `in (...)` (quase sempre para
  pular o arquivo) viraram a regra `auditor.py.compara-secrets-yaml`, Baixa, que não conta como
  "lê segredos" nas cadeias. Abrir o arquivo ou colocá-lo numa lista que permite ler continua Alta.
- **Bandit B506 (`yaml.load`):** com o loader do Home Assistant, o `SafeLoader` ou um loader próprio,
  agora é Baixa. Continua Média sem loader ou com `Loader`, `UnsafeLoader` ou `FullLoader`.

## 0.30.5

Falsos positivos vistos numa varredura real:

- **IP público fixo:** versões no User-Agent (`Chrome/124.0.0.0`) não contam mais como IP, e as
  faixas reservadas para documentação (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) ficam
  de fora.
- **Bandit B104** (`"0.0.0.0"`) agora é sempre Baixa: o Bandit marca qualquer texto `"0.0.0.0"`,
  inclusive comparações e listas, e só às vezes é uma porta aberta em todas as interfaces.
- **Download sem verificar o certificado:** `curl -k`/`wget --no-check-certificate` só para
  `127.0.0.1` ou `localhost` (teste do próprio container no `HEALTHCHECK`) não é mais marcado.
- **Typosquatting:** `aiofile` é um pacote legítimo e saiu da suspeita de imitar `aiofiles`.

## 0.30.4

- **"Excluir…" de um componente já apagado do HA:** dava o erro "Este componente não pode ser
  excluído da tabela" quando a pasta já não existia (o relatório ainda não sabia da remoção). Agora
  ele só sai do relatório, sem erro; se for instalado de novo, volta a ser analisado.

## 0.30.3

- **Atualizações sem aviso:** uma varredura completa que rodava com atualizações ainda na fila (por
  exemplo a do início, quando o auditor reinicia junto com outras atualizações, ou uma agendada ou
  manual logo depois de atualizar) analisava essas atualizações mas não notificava nem disparava o
  evento `security_auditor_alerta`. Agora a completa avisa sobre cada componente novo ou atualizado
  desde a última referência.
- **Varredura de instalação com falha:** as mudanças não saem mais da fila sem aviso; o auditor tenta
  de novo nas conferências seguintes (até 3 vezes) e, se continuar falhando, deixa para a próxima
  varredura completa, que analisa e avisa.

## 0.30.2

Mais três falsos positivos, vistos numa varredura real:

- **Destino suspeito:** os domínios (`transfer.sh`, `interact.sh`, `file.io`, `paste.ee`…) agora
  precisam aparecer inteiros. Antes `t('transfer.show')` era marcado como `transfer.sh`.
- **`secrets.yaml`:** só conta o nome ou caminho do arquivo, não um texto que o menciona (docstring,
  mensagem). Listas que protegem o arquivo (`PROTECTED_PATHS`, `DENY_…`, `BLOCKED_…`, `EXCLUDE_…`)
  deixaram de ser marcadas; listas que permitem a leitura continuam.
- **Arquivos de testes** (pasta `tests/`, `test_*.py`, `conftest.py`, `*.test.js`…) continuam com
  achados próprios, mas não entram mais no perfil de capacidades nem nas cadeias: o Home Assistant
  não carrega esses arquivos.

## 0.30.1

Dois falsos positivos que geravam cadeias críticas (vistos na integração sentient):

- **Lista de usuários:** `hass.auth.async_get_users()` saiu de "Criação de usuários ou tokens de
  acesso" e virou a regra informativa `auditor.py.lista-usuarios`, que não conta como "lê segredos"
  nas cadeias. Criar usuários ou tokens continua Média e entra nas cadeias.
- **Linha de código enorme:** uma linha que é quase só texto entre aspas, com palavras separadas por
  espaço (um prompt, uma mensagem), não é mais marcada. Continuam marcados código compactado, texto
  codificado (base64, hex) e qualquer linha que execute o texto com `exec`/`eval`.

## 0.30.0

Ajustes de ruído a partir de um relatório real (1.448 achados visíveis caíram para cerca de 725;
altos e críticos de 274 para cerca de 58):

- **`raw.githubusercontent.com` e gists** saíram de "destino suspeito" (Alta) e viraram a regra
  informativa `auditor.py.conteudo-github`. Pastebins, webhooks, túneis e bots continuam Alta.
- **`.storage`:** a regra genérica caiu para Baixa e não conta mais como "lê segredos" nas cadeias
  (costuma ser a integração usando o próprio arquivo). A regra crítica de autenticação passou a
  cobrir também o `.storage/core.config_entries`, que guarda as credenciais das outras integrações.
- **Bandit B324** (`md5`/`sha1` para gerar identificadores) agora é sempre Baixa.
- **Repetições agrupadas:** a mesma regra no mesmo arquivo vira um achado, com o número de
  ocorrências e as linhas; a análise incompleta vira um achado por componente.
- **Integridade:** quando os arquivos não batem com a versão registrada (inclusive pelo HACS), o
  auditor testa as releases mais novas e o branch principal; se bater, é Informativa ("Arquivos de
  outra versão do repositório oficial"). Arquivo extra que não é código passou a Baixa. As consultas
  de releases e do repositório ficam guardadas por um dia.

## 0.29.1

- **Regra de shell reverso (scripts e Dockerfile dos add-ons):** `/dev/tcp` para `127.0.0.1`,
  `localhost` ou `0.0.0.0` sem shell ligado à conexão deixou de ser marcado. É o teste de porta usado
  em `HEALTHCHECK` (ex.: `bash -c '</dev/tcp/127.0.0.1/1883'` no MQTT). Continuam marcados `/dev/tcp`
  para fora do container e qualquer shell ligado à conexão (`bash -i`, `>&`, `0>&1`), mesmo local.

## 0.29.0

- **Cadeias de comportamento:** combinações perigosas no mesmo componente viram um achado próprio,
  com as peças: lê credenciais e acessa a rede (Crítica), código escondido com capacidade perigosa
  (Crítica), acessa a rede e executa código dinâmico (Alta).
- **Perfil de capacidades:** selos na tabela de componentes (rede, comandos, segredos, código
  dinâmico, pacotes, código escondido).
- **Capacidade nova numa atualização:** quando uma versão nova traz uma capacidade que a anterior
  não tinha, sai um achado Alto (sinal típico de repositório que mudou de mãos).
- **Sinais do GitHub:** tag da versão reescrita (Alta), repositório transferido ou renomeado
  (Média) e repositório arquivado (Informativa). Cada repositório é consultado no máximo uma vez
  por dia.
- **Dependências:** pacotes maliciosos catalogados na OSV (`MAL-…`, Crítica) e nomes de
  typosquatting (Média).
- **Ofuscação e código compilado:** `chr()` em sequência, escapes `\xNN`, nomes ofuscados, linhas
  enormes, dados compactados com `exec`/`eval`, `.pyc` fora de `__pycache__` e binários dentro do
  componente.

## 0.28.0

- **Integridade dos cards do HACS** (`www/community`): cada arquivo é comparado com a release
  oficial (anexos da release, `dist/` ou raiz do repositório) na versão que o HACS registrou, e
  cada `.js.gz` criado pelo HACS é conferido contra o `.js` dele (o HA serve o `.gz` no lugar do
  original). Arquivo alterado, JavaScript extra ou `.gz` diferente = Alta.
- **Pesquisa na web para a IA:** nova opção `ia_pesquisa_web` (padrão `false`). Com ela, a IA
  pesquisa o host antes de responder (busca do próprio provedor); a resposta guardada mostra
  "+ web" no modelo. Cada consulta custa mais.
- **Testes do JavaScript da interface** (desenvolvimento): o `app.js` roda em jsdom sobre páginas
  geradas pelo template real e é testado em busca, realce, seleção, filtros, janelas e chamadas à
  API.

## 0.27.0

- **Seleção para ignorar** na tabela de domínios do DNS e na lista de achados: caixa de seleção em
  cada linha/achado, caixa para selecionar todos os visíveis (respeita a busca e os filtros) e o
  botão **Ignorar selecionados (n)…**, com um motivo só.
- Os achados selecionados viram um único item da lista de ignorados; cada um funciona como "Só
  este achado" (achados iguais continuam escondidos e os novos aparecem).

## 0.26.0

- **Integridade com manifest desatualizado:** quando o HACS não informa a versão instalada e os
  arquivos não batem com a versão do `manifest.json`, o auditor testa as 5 releases mais recentes
  do repositório. Se alguma for idêntica arquivo a arquivo, os alertas "Arquivo diferente da
  release oficial" dão lugar a um achado informativo "Versão do manifest desatualizada" (caso do
  `gensyn/ssh_docker`, que declara 1.2.0 em todas as versões até a v1.3.2). Se nenhuma bater,
  ficam os alertas de sempre.

## 0.25.1

- **DNS:** com "Mostrar domínios ignorados" marcado, os botões **Ignorar todos…** e **Perguntar à
  IA sobre todos…** ficam escondidos (eles valem para a tabela de domínios consultados).

## 0.25.0

- **Perguntar à IA nos achados:** quando o trecho de código de um achado tem uma URL ou um IP, ele
  ganha o botão **Perguntar à IA sobre <host>** (um por host, até 5). A resposta usa a mesma
  janela e o mesmo cache da aba DNS e aparece como selo "IA: …" no achado.
- Só o host sai do add-on: da URL, caminho, query (onde ficam tokens) e usuário/senha ficam de
  fora. IPs da rede local, nomes locais e endereços de documentação não são oferecidos. A API só
  aceita domínios vistos no DNS ou hosts dos achados do relatório mais recente.

## 0.24.0

- **Perguntar à IA sobre todos…:** novo botão no topo da tabela de domínios do DNS (com a IA
  configurada). Pergunta pelos domínios visíveis que ainda não têm resposta guardada, um por vez,
  depois de mostrar quantos são e pedir confirmação. Dá para parar clicando de novo; para no
  primeiro erro (chave recusada, limite de uso etc.).

## 0.23.3

- **Busca e realce da linha** também na lista de ignorados, na tabela de domínios do DNS e na lista
  de domínios ignorados. A caixa "Filtrar…" mostra só as linhas com o texto digitado (em qualquer
  coluna); clicar numa linha realça ela.

## 0.23.2

- **Realce da linha clicada** nas tabelas de componentes e de domínios do DNS. Clicar em outra
  linha move o realce; clicar de novo na mesma tira. Botões e links da linha funcionam como antes.

## 0.23.1

- **Ignorar achados por nível…:** botão único no topo da lista de achados (tela de um componente).
  Abre a escolha de níveis e ignora os achados atuais do componente nesses níveis; achados novos
  continuam aparecendo. Os níveis marcados nos chips já vêm selecionados.

## 0.23.0

- **Componentes ignorados saem da tabela de componentes.** Quem foi ignorado com **Ignorar…**
  (fora da varredura) aparece só na lista de ignorados. Para voltar a analisar, remova o item da
  lista: o componente volta para a tabela na hora, com um aviso, e é analisado na próxima
  varredura.
- O botão **Voltar a analisar** (0.22.1) saiu, porque a lista de ignorados já faz isso.
- Com o quadro **Ignorados** aberto, clicar num quadro de nível fecha a lista de ignorados e mostra
  o resumo filtrado por aquele nível.

## 0.22.2

- **Correção:** o botão da linha do componente (**Ignorar…** ou **Voltar a analisar**) agora segue
  a lista de ignorados atual, e não o relatório da última varredura. Antes, um componente que já
  tinha saído da lista ainda mostrava **Voltar a analisar**, e o botão dava "Este componente não
  está ignorado". Enquanto a próxima varredura não roda, a linha avisa que a mudança está pendente.

## 0.22.1

- **Voltar a analisar:** componentes ignorados (fora da varredura) mostram este botão na linha, no
  lugar de **Ignorar…**. Ele remove o item da lista de ignorados e o componente volta a ser
  analisado na próxima varredura. Se o componente estiver ignorado por um curinga (ex.: `meu_*`),
  o auditor explica e pede para remover pela lista, porque o item vale para outros componentes.

## 0.22.0

- **Ignorar achados…:** novo botão em cada linha da tabela de componentes (com achados). Ignora os
  achados atuais do componente nos níveis escolhidos (um, vários ou todos). Achados iguais
  continuam escondidos, achados novos aparecem, e o componente continua sendo analisado.
- **Ignorar estes níveis…** agora tem a opção **Todos os níveis** (todos os achados atuais, em
  todos os componentes; os novos continuam aparecendo).

## 0.21.0

- **Ignorar estes níveis…** agora ignora só os achados que existem no momento, num único item da
  lista ("N achados atuais"). Achados iguais a eles continuam escondidos; achados novos nesses
  níveis aparecem normalmente. Itens de nível antigos continuam valendo como regra.
- **Ignorar…** na linha do componente volta a tirar o componente da varredura (como até a
  0.19.x), agora sem escolha de níveis e para qualquer componente. O botão **Não analisar…** da
  0.20.0 saiu, porque fazia a mesma coisa. Itens antigos de componente inteiro (regra `*`, todos
  os níveis) voltam a tirar o componente da varredura.
- **Busca por nome** na tabela de componentes: a caixa "Filtrar por nome…" mostra só os componentes
  cujo nome contém o texto, inclusive os sem achados.

## 0.20.0

- **Ignorar não tira mais o componente da varredura.** Ignorar todas as regras em todos os níveis
  só esconde os achados; o componente continua sendo analisado. Itens antigos que pulavam o
  componente passam a só esconder os achados.
- **Não analisar…:** novo botão na tabela de componentes para tirar um componente da varredura de
  propósito (fica na lista de ignorados, marcado "não é analisado").
- **Excluir…:** novo botão na tabela de componentes para componentes removidos do HA cujos
  arquivos ficaram no disco. O componente sai da tabela e da varredura e volta sozinho se for
  reinstalado ou atualizado; se os arquivos sumirem, a exclusão é apagada. A lista de excluídos
  fica abaixo da tabela, com **Restaurar**. O auditor não apaga arquivos.
- **Correção:** incluir algo na lista de ignorados apagava a data de descoberta dos componentes
  (e a ordem "mais novos no topo") até a próxima varredura.

## 0.19.3

- **Quadro "Ignorados":** o texto agora é só "Ignorados", com a quantidade de itens da lista no
  número.

## 0.19.2

- **Correção:** o link "Abrir o Security Auditor" dos avisos no HA abria o dashboard principal.
  Ele usava `/hassio/ingress/<slug>`, endereço que o HA não tem mais. Agora abre o painel do
  auditor na barra lateral (`/<slug>`) ou, com "Mostrar na barra lateral" desligado, a página do
  add-on (`/config/app/<slug>/info`). Avisos já criados continuam com o link antigo.

## 0.19.1

- **Quadro "Ignorados":** o número grande agora é a quantidade de itens na lista de ignorados (o
  que o quadro abre), e embaixo aparece quantos achados eles escondem nesta varredura. Antes o
  número era o de achados escondidos, e mostrava "0" com itens na lista quando eles pulam
  componentes inteiros ou não batem com nenhum achado do relatório atual.

## 0.19.0

- **Perguntar à IA (aba DNS):** novo botão em cada linha da tabela de domínios que pergunta ao
  Gemini ou ao Claude se o domínio é conhecido como malicioso, suspeito ou provavelmente seguro,
  com uma explicação curta. A resposta fica guardada e aparece como selo "IA: …" na linha;
  **Perguntar de novo** consulta outra vez.
- Novas opções `ia_provedor` (`desligado`, `gemini` ou `claude`; padrão `desligado`),
  `ia_chave_api` e `ia_modelo` (vazio = `gemini-3.5-flash-lite` ou `claude-opus-5-5`).
- É a única saída de dados do add-on, e é opcional: só o nome do domínio é enviado, só quando o
  usuário clica, só para domínios que o auditor viu, e o cliente HTTP só aceita o host do provedor
  escolhido. A chave é mascarada nos logs. A resposta é a opinião de um modelo e não gera achados.

## 0.18.0

- **Verificação de DNS separada:** a cada `intervalo_dns_minutos` (0 a 1440, padrão 120) o auditor
  relê o log do AdGuard/Pi-hole e atualiza só a parte de DNS do relatório, sem varrer os
  componentes de novo. Verificações de DNS seguidas viram uma entrada só no histórico ("Verificação
  de DNS"), para não empurrar as varreduras completas para fora da retenção. Com `0`, o DNS roda só
  junto com a varredura completa, como antes.
- **Aviso de DNS no HA:** achado de DNS novo a partir de `aviso_nivel_minimo` cria a notificação
  `security_auditor_rede_dns` e dispara o evento `security_auditor_alerta` (`componente: dns`,
  `mudanca: verificacao_dns`).
- **Correção:** achados de DNS não aparecem mais como "novos" só porque mudou o horário da última
  consulta ou a contagem; a identidade deles agora é só o domínio (ou a lista de domínios). Na
  primeira varredura depois de atualizar, os achados de DNS existentes aparecem como novos uma vez.

## 0.17.2

- Nova opção `intervalo_verificacao_minutos` (1 a 60, padrão 2), logo abaixo de
  `verificar_instalacoes`: define de quanto em quanto tempo o auditor confere o que está
  instalado.

## 0.17.1

- **DNS:** "Mostrar domínios ignorados" agora troca a tabela de domínios consultados pela lista de
  domínios ignorados (e volta ao desmarcar); a escolha continua depois de editar ou remover um
  item. O botão **Ignorar domínio…** foi para o topo da tabela, ao lado de **Ignorar todos…**.

## 0.17.0

- **Verificação de instalações e atualizações:** a cada 2 minutos o auditor confere o que está
  instalado (arquivos de `custom_components/` e `www/community/`, sem ler o conteúdo, e versão dos
  add-ons). Quando algo é instalado, atualizado ou removido, espera a instalação terminar e varre
  **só aquele componente** (segundos); o resto do relatório vem da última varredura completa. No
  histórico aparece como "Instalação/atualização: nome (novo)". Opção `verificar_instalacoes`.
- **Avisos no HA:** notificação persistente quando o componente verificado tem achados a partir
  de `aviso_nivel_minimo` (padrão: alta) ou está na lista negra, e o evento
  `security_auditor_alerta` sempre, para automações (ex.: aviso no celular). O auditor avisa, não
  bloqueia.
- **DNS:** botão **Ignorar todos…** na tabela de domínios, que ignora de uma vez todos os domínios
  da tabela que ainda não estão ignorados.

## 0.16.0

- **Mais novos no topo:** a tabela de componentes e a lista de achados de cada componente são
  ordenadas pela data de descoberta (a primeira varredura em que apareceram), da mais nova para a
  mais antiga; a data aparece na linha do componente ("descoberto em") e em cada achado. Na
  primeira varredura depois da atualização, as datas são recuperadas dos relatórios guardados.
- A lista de ignorados e a lista negra pessoal também mostram os itens mais novos primeiro.
- **Domínios ignorados no DNS:** botão **Ignorar…** em cada linha da tabela de domínios e
  **Ignorar domínio…** abaixo dela, com motivo editável e curingas (`*.exemplo.com` vale para o
  domínio e todos os subdomínios). Os domínios ignorados saem dos achados de DNS (aleatórios,
  bloqueados, novos e suspeitos) a partir da próxima varredura e ficam escondidos na tabela
  ("Mostrar domínios ignorados" para vê-los).
- **Tabela de domínios:** os descobertos por último ficam no topo (data da primeira consulta, na
  nova coluna "Descoberto em"), com os mais consultados como desempate.
- **Celular:** a barra do topo não fica mais presa ao rolar a tela.

## 0.15.0

- **Tradução completa da interface para o inglês:** detalhes dos componentes (integridade,
  tráfego, "não verificado"), categorias e fontes dos achados, trechos explicativos (linhas do
  DNS, quadro da lista negra, picos de tráfego), título e aviso da tabela de domínios, motivos
  do teste de conexão DNS, status da varredura (nome da etapa), mensagens de erro da API e o
  sufixo do motivo de itens ignorados.
- **Sensores:** os nomes exibidos no HA seguem o idioma escolhido; entity_id, valores de estado e
  unidade não mudam (automações e estatísticas continuam funcionando).
- **Documentação em inglês** (DOCS.md e README.md, exibidos no HA); as versões em português ficam
  em DOCS.pt-BR.md e README.pt-BR.md.
- Os logs continuam em português.

## 0.14.0

- **Achados em inglês:** título, explicação e recomendação de todos os achados (33 regras do
  Semgrep, Bandit, integridade, dependências, permissões, código e imagem dos add-ons, tráfego,
  DNS, lista negra e avisos do auditor) são gerados nas duas línguas e exibidos no idioma
  escolhido. O mascaramento de segredos também vale para o texto em inglês.
- Relatórios gerados antes desta versão continuam em português até a próxima varredura.
- Ainda em português: detalhes dos componentes na tabela, título e aviso da tabela de domínios,
  mensagens de erro da API, sensores e documentação.

## 0.13.2

- A aba **DNS** fica logo depois de **Componentes**.

## 0.13.1

- Nova aba **DNS** (aparece com AdGuard/Pi-hole configurado): situação dos servidores com
  "Testar conexão", resumo dos achados de DNS com "Ver achados" e a tabela de domínios. O
  item Rede/DNS saiu da tabela de componentes. "Voltar" na lista de achados retorna à aba de
  origem.
- A aba "Início" passou a se chamar **Componentes**.

## 0.13.0

- **Interface em inglês e português**, com o seletor **EN | PT** no topo. O padrão é inglês; a
  escolha fica guardada no add-on e vale em qualquer navegador (inclusive no app do HA).
- Datas no formato de cada idioma.
- Ainda em português: o texto dos achados (título, explicação e recomendação), os detalhes
  gerados na varredura e as mensagens de erro da API.

## 0.12.1

- Filtro **Só lista negra** na tabela de componentes: mostra só os componentes com o selo
  (inclusive "possível correspondência"). Aparece quando há algum marcado e fica na URL.

## 0.12.0

- Nova aba **Lista negra**: mostra a situação da lista comunitária e permite adicionar, editar e
  remover itens da lista pessoal pela tela (formulário com a mesma validação do arquivo).
- Na tela de um componente, **Adicionar à lista negra…** abre o formulário já preenchido com o
  tipo, o GitHub, o nome e (add-ons) a imagem.
- Os itens ficam no banco do add-on (o `/config` continua somente leitura).
- **A lista pessoal por arquivo (`/config/security_auditor/lista_negra.json`) foi removida:** o
  arquivo não é mais lido. Se você o usava, recrie os itens na aba Lista negra e apague o arquivo
  (o log avisa enquanto ele existir).

## 0.11.0

- **Lista negra (fase 4):** a lista comunitária passa a incluir a lista de removidos do HACS e a
  de integrações bloqueadas pelo Home Assistant. Novas categorias `removido` e `incompativel`;
  o achado mostra a fonte de cada item. Itens do HA casam pelo domínio da integração (é como o
  próprio HA bloqueia), com a severidade cheia.
- Compatibilidade: itens com categoria, tipo ou fonte de uma versão mais nova do formato são
  ignorados (com aviso no log) em vez de virar erro.

## 0.10.0

- **Lista negra comunitária (fase 2):** baixada do repositório `diogocaseca/ha-security-blocklist`
  a cada varredura (no máximo a cada 6 horas) e somada à lista pessoal.
  - Só é usada com **assinatura Ed25519 válida** (chave pública embutida no add-on); listas com
    assinatura inválida, chave desconhecida, formato errado ou mais antigas que a cópia local
    são recusadas, mantendo a cópia anterior.
  - Avisos no relatório quando a lista nunca pôde ser baixada ou quando a cópia passa de 7 dias.
  - Nova opção `lista_comunitaria` (ligada por padrão). Logs de cada verificação.

## 0.9.0

- **Lista negra (fase 1):** componentes reportados ganham o selo **Lista negra** na tabela e um
  achado com motivo, versões afetadas e links de evidência. Compara pelo repositório do GitHub,
  pela imagem do add-on (forte) ou só pelo nome ("possível correspondência", um nível abaixo),
  respeitando a faixa de versões. A lista só acrescenta avisos e a comparação é toda local.
- Lista pessoal em `/config/security_auditor/lista_negra.json`. A lista comunitária
  (`diogocaseca/ha-security-blocklist`) já é lida do cache; o download automático vem na fase 2.

## 0.8.2

- Espaço entre a linha "Servidores DNS" e o aviso de revisão humana na tela inicial.

## 0.8.1

- **Teste de conexão com o AdGuard Home e o Pi-hole** ao iniciar o add-on: faz login e lê a
  versão de cada servidor. O resultado aparece no topo da tela inicial (✓ conectado com a
  versão, ou ✗ com o motivo: senha recusada, endereço/porta, certificado, tempo esgotado…) e no
  log, com o tempo de resposta. O botão **Testar conexão** repete o teste a qualquer hora.
- Filtro de **tipo** na tabela de componentes (integração, frontend, add-on…), guardado na URL
  como os níveis.

## 0.8.0

- **Componentes ignorados por inteiro não são mais varridos.** Um item da lista de ignorados
  (ou da `allowlist`) com o nome do componente, regra `*`, todos os níveis e sem arquivo ou
  achado específico faz o componente ser pulado: nenhuma ferramenta roda nele (Semgrep,
  Bandit, pip-audit, integridade, permissões, código, Trivy). Ele aparece na tabela como "não
  verificado" e a lista de ignorados marca esses itens com "não é verificado". O diálogo de
  ignorar avisa antes de confirmar. Itens com só alguns níveis ou só uma regra continuam sendo
  verificados normalmente. Um curinga sozinho (`*`) nunca pula nada.

## 0.7.9

- Lista de ignorados: botão **Editar** para mudar o motivo de um item (Enter salva, Esc
  cancela). O motivo novo aparece na hora nos achados ignorados do relatório.

## 0.7.8

- Diálogo de ignorar: opção **Todos os níveis**, que marca ou desmarca todos de uma vez.
  Não aparece em "Ignorar estes níveis…", em que todos os níveis em todos os componentes
  ignorariam tudo.

## 0.7.7

- Opção **Esconder componentes sem achados** na tabela de componentes, marcada por padrão e
  lembrada no navegador. Componentes cujos achados foram todos ignorados também somem.

## 0.7.6

- Histórico de verificações com paginação (10 por página) e o total de verificações guardadas.

## 0.7.5

- Duas abas no topo: **Início** (o resumo) e **Histórico de verificações**, que agora fica só
  na sua aba, fora da tela inicial.
- O histórico ganhou a coluna **Duração** de cada verificação.

## 0.7.4

- O quadrado **Ignorados** abre uma aba própria com a lista de ignorados: a tabela de
  componentes, o histórico e o resto do resumo ficam escondidos. Volta pelo próprio quadrado,
  por "Voltar para o resumo" ou pelo voltar do navegador.
- Removido o quadrado "Novos desde a anterior". Os achados novos continuam marcados com
  "Novo", há o filtro "Só novos" e o sensor `sensor.security_auditor_novos_achados`.

## 0.7.3

- Clicar num componente abre uma **tela só com os achados dele** (com filtros por nível,
  contagem por nível e botão "Voltar para o resumo"), em vez de rolar a página. O voltar do
  navegador também funciona, e os níveis marcados no resumo continuam marcados ao voltar
  (ficam na URL, então recarregar a página também os mantém).
- Quadrado **Ignorados** junto dos cartões de nível: mostra quantos achados estão ignorados e
  abre ou fecha a lista de ignorados (que agora fica escondida até ser aberta).

## 0.7.2

- Removidas as opções antigas de DNS (`dns_provider`, `dns_url`, `dns_username`,
  `dns_password`). Use `adguard_*` e `pihole_*`. Se você ainda usava as antigas, copie os
  valores para os campos novos antes ou depois de atualizar.

## 0.7.1

- Ícone e logo do add-on (casa com escudo), exibidos na loja e na lista de add-ons do HA.

## 0.7.0

- O auditor não audita mais a si mesmo: o próprio add-on sai das análises de permissões,
  código, imagem e tráfego.
- DNS: **AdGuard Home e Pi-hole juntos**. Novas opções `adguard_url`, `adguard_username`,
  `adguard_password`, `pihole_url` e `pihole_password`; com os dois preenchidos, as consultas
  são somadas e a tabela mostra em qual servidor cada domínio apareceu. Se um falhar, o outro
  continua sendo usado.
- As opções antigas `dns_provider`, `dns_url`, `dns_username` e `dns_password` continuam
  aceitas.
- Lista de ignorados: botão **Ignorar…** em cada linha da tabela de componentes (respeita os
  níveis marcados nos cartões) e **Ignorar estes níveis…** para ignorar um nível inteiro em todos
  os componentes. Itens da lista podem ser restritos por nível.

## 0.6.0

- Botão **Cancelar varredura**: encerra as ferramentas em execução e salva o parcial como
  "Cancelada" (mascarado, fora da comparação). O agendamento continua normalmente.
- **Lista de ignorados** na interface: botão "Ignorar…" em cada achado (só o achado, a regra no
  arquivo, no componente ou em todos), inclusão manual e remoção. Vale na hora para o relatório
  mais recente e os sensores. As entradas da `allowlist` aparecem na lista como "Configurações".
- Os cartões de severidade agora filtram também a **tabela de componentes**; dá para marcar mais
  de um nível ao mesmo tempo.

## 0.5.0

- Proteções contra sobrecarga do HA, combináveis na nova opção `modo_execucao`:
  - `prioridade_baixa`: CPU `nice 19` e disco na classe ociosa para o auditor e as ferramentas;
  - `modo_leve`: Semgrep com 1 processo e teto de memória, Trivy com paralelismo 1, pausas;
  - `aguardar_folga`: espera a carga e a memória do host antes das etapas pesadas e adia a
    etapa (achado "Etapa adiada") se o sistema não desocupar;
  - `horario_fixo`: varredura diária em `horario_varredura`, no fuso do HA.
- Padrão: `prioridade_baixa` + `aguardar_folga`.
- Novas opções: `horario_varredura`, `memoria_minima_mb`, `carga_maxima_por_cpu`.
- O topo do relatório mostra as proteções ativas.

## 0.4.2

- Segurança: varreduras canceladas (por exemplo, ao atualizar ou parar o add-on) ou que
  falhavam no meio salvavam o relatório parcial sem mascarar segredos nos trechos de código.
  Agora o mascaramento é aplicado sempre antes de salvar. Recomenda-se atualizar.

## 0.4.1

- Verificação de saúde para o Watchdog (`/api/status`): com a chave Watchdog ligada, o
  Supervisor reinicia o add-on também se ele travar sem cair.
- Documentação completa (DOCS.md).

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
