# Changelog

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
