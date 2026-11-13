# Changelog

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
