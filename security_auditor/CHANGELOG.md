# Changelog

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
