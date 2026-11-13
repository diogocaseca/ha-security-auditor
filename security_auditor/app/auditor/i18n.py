"""Idiomas da interface (inglês e português).

A chave de cada texto é o próprio texto em português; ``EN`` traz a versão em inglês.
Em português a chave volta como está. Um teste confere que todo texto marcado no template
e no JavaScript tem tradução.

Textos com variáveis usam ``{nome}`` (``str.format``).
"""

from __future__ import annotations

from typing import Any

from markupsafe import Markup, escape

LANGS = ("en", "pt")
DEFAULT_LANG = "en"
HTML_LANG = {"en": "en", "pt": "pt-BR"}


class Bi(str):
    """Texto em português (o próprio valor) que carrega a versão em inglês em ``en``."""

    en: str

    def __new__(cls, pt: str, en: str | None = None) -> Bi:
        obj = super().__new__(cls, pt)
        obj.en = en if en is not None else pt
        return obj


def english(text: Any) -> str:
    """Versão em inglês de um texto (``Bi``) ou o próprio texto."""
    return getattr(text, "en", None) or str(text)


_SUPPRESSION_EN = (
    ("(lista de ignorados)", "(ignore list)"),
    ("(allowlist das configurações)", "(configuration allowlist)"),
    ("sem motivo informado", "no reason given"),
)

# Nome interno de cada etapa da varredura -> rótulo em português (o inglês fica em EN)
STEP_LABELS: dict[str, str] = {
    "lista_negra": "lista negra",
    "analise_estatica": "análise estática",
    "dependencias": "dependências",
    "integridade": "integridade",
    "permissoes_addons": "permissões dos add-ons",
    "codigo_addons": "código dos add-ons",
    "trafego_addons": "tráfego dos add-ons",
    "dns": "DNS",
    "imagens_addons": "imagens dos add-ons",
}

# Categoria interna do achado -> (rótulo em português, em inglês)
CATEGORY_LABELS: dict[str, tuple[str, str]] = {
    "acesso_sensivel": ("acesso a dados sensíveis", "sensitive data access"),
    "analise_incompleta": ("análise incompleta", "incomplete analysis"),
    "arquivo_temporario": ("arquivo temporário", "temporary file"),
    "atualizacao": ("atualização", "update"),
    "bandit": ("bandit", "bandit"),
    "configuracao": ("configuração", "configuration"),
    "criptografia_fraca": ("criptografia fraca", "weak cryptography"),
    "cve": ("CVE", "CVE"),
    "dependencia": ("dependência", "dependency"),
    "dependencia_vulneravel": ("dependência vulnerável", "vulnerable dependency"),
    "desserializacao": ("desserialização", "deserialization"),
    "destino_suspeito": ("destino suspeito", "suspicious destination"),
    "dns_anormal": ("DNS anormal", "abnormal DNS"),
    "dns_bloqueado": ("DNS bloqueado", "blocked DNS"),
    "dns_novo": ("DNS novo", "new DNS"),
    "download_execucao": ("download e execução", "download and execution"),
    "execucao_de_comandos": ("execução de comandos", "command execution"),
    "execucao_dinamica": ("execução dinâmica", "dynamic execution"),
    "integridade": ("integridade", "integrity"),
    "link_simbolico": ("link simbólico", "symbolic link"),
    "lista_negra": ("lista negra", "blocklist"),
    "mineracao": ("mineração", "mining"),
    "ofuscacao": ("ofuscação", "obfuscation"),
    "origem": ("origem", "origin"),
    "permissao": ("permissão", "permission"),
    "rede": ("rede", "network"),
    "segredo_embutido": ("segredo embutido", "embedded secret"),
    "semgrep": ("semgrep", "semgrep"),
    "tls": ("TLS", "TLS"),
    "trafego_anormal": ("tráfego anormal", "abnormal traffic"),
    "url_ip_fixo": ("URL/IP fixo", "hard-coded URL/IP"),
}


# Ferramenta/fonte que gerou o achado -> nome em inglês (as que já são nomes próprios ficam iguais)
SOURCE_EN: dict[str, str] = {
    "integridade": "integrity",
    "codigo-fonte": "source code",
    "estatisticas": "statistics",
    "lista_negra": "blocklist",
}


def normalize(lang: Any) -> str:
    value = str(lang or "").strip().lower()[:5]
    return value if value in LANGS else DEFAULT_LANG


class Translator:
    """``t(texto, **vars)`` devolve texto puro; ``h(...)`` devolve HTML confiável (só textos nossos)."""

    def __init__(self, lang: str) -> None:
        self.lang = normalize(lang)

    def _raw(self, text: str) -> str:
        if self.lang == "pt":
            return text
        return EN.get(text, text)

    def t(self, text: str, **kw: Any) -> str:
        out = self._raw(text)
        return out.format(**kw) if kw else out

    def h(self, text: str, **kw: Any) -> Markup:
        # O texto vem do catálogo (confiável); as variáveis são escapadas pelo Markup.format.
        out = Markup(self._raw(text))  # noqa: S704 - texto estático do próprio add-on
        return out.format(**{k: escape(v) for k, v in kw.items()}) if kw else out

    def category(self, key: str) -> str:
        labels = CATEGORY_LABELS.get(key)
        return (labels[1] if self.lang == "en" else labels[0]) if labels else key

    def source(self, key: str) -> str:
        return SOURCE_EN.get(key, key) if self.lang == "en" else key

    def meta(self, meta: dict, key: str) -> Any:
        """Valor de metadado no idioma: ``chave_en`` em inglês, quando existir."""
        if self.lang == "en" and meta.get(f"{key}_en") not in (None, ""):
            return meta[f"{key}_en"]
        return meta.get(key)

    def suppression(self, text: str | None) -> str:
        """Motivo de supressão ("motivo (origem)") com a origem no idioma."""
        out = text or ""
        if self.lang == "en":
            for pt, en in _SUPPRESSION_EN:
                out = out.replace(pt, en)
        return out

    def steps(self) -> dict[str, str]:
        """Rótulos das etapas no idioma (usados no status da varredura)."""
        return {k: self.t(v) for k, v in STEP_LABELS.items()}

    def js_catalog(self) -> dict[str, str]:
        """Traduções usadas pelo JavaScript (vazio em português)."""
        return {} if self.lang == "pt" else {k: EN[k] for k in JS_KEYS if k in EN}


# Textos usados pelo app.js (passados para a página como JSON).
JS_KEYS = (
    "Varrendo", "Varrendo…", "Varrer agora", "Cancelando…", "Cancelar varredura",
    "Não foi possível iniciar a varredura.", "Não foi possível cancelar a varredura.",
    "Cancelar a varredura em andamento? O que já foi analisado fica salvo como relatório cancelado.",
    "({a} de {b})", "Com achados de nível: {niveis}",
    "Ignorar achado", "Ignorar achados do componente", "Ignorar níveis inteiros", "Incluir na lista de ignorados",
    "Componente {nome}: todas as regras, nos níveis marcados abaixo.",
    "Todos os componentes e regras. Os achados continuam visíveis com \"Mostrar suprimidos\".",
    "Use * como curinga (ex.: semgrep.* ou */vendor/*).",
    "Níveis a ignorar em todos os componentes", "Só estes níveis (nenhum marcado = todos)",
    "Marque pelo menos um nível.",
    "Ignorar todos os achados de nível {niveis} em todos os componentes?",
    "Não foi possível incluir (HTTP {status}).", "Não foi possível incluir.",
    "Remover da lista de ignorados? Os achados voltam a contar nos totais.",
    "Não foi possível remover da lista.",
    "Remover da lista de domínios ignorados? Ele volta aos achados na próxima varredura.",
    "Ignorar todos os domínios",
    "Ignorar domínio",
    "Todos os {n} domínios da tabela que ainda não estão ignorados: {lista}",
    "Salvar", "Cancelar", "Motivo",
    "Não foi possível salvar (HTTP {status}).", "Não foi possível salvar.",
    "Testando…", "Editar item {id}", "Adicionar à lista negra pessoal",
    "Remover o item {id} da lista negra pessoal?", "Não foi possível remover o item.",
)

EN: dict[str, str] = {
    # --- Cabeçalho e geral ---
    "Varredura de {data}": "Scan of {data}",
    "visualizando relatório antigo": "viewing an old report",
    "ir para o mais recente": "go to the latest",
    "Nenhuma varredura concluída ainda": "No scan completed yet",
    "Tema": "Theme",
    "Idioma": "Language",
    "Seguir o tema do sistema": "Follow the system theme",
    "Sistema": "System",
    "Claro": "Light",
    "Escuro": "Dark",
    "Varrendo": "Scanning",
    "Varrendo…": "Scanning…",
    "Próxima: {data}": "Next: {data}",
    " (todo dia às {hora})": " (daily at {hora})",
    "Agendamento desativado": "Scheduling disabled",
    "Exportar JSON": "Export JSON",
    "Varrer agora": "Scan now",
    "Cancelando…": "Cancelling…",
    "Cancelar varredura": "Cancel scan",
    "Seções": "Sections",
    "Histórico de verificações": "Scan history",
    "Lista negra": "Blocklist",
    "Lista negra?": "Blocklist?",
    "Proteções contra sobrecarga:": "Overload protection:",
    "prioridade baixa": "low priority",
    "modo leve": "light mode",
    "aguarda o sistema desocupar": "waits for the system to be idle",
    "horário fixo": "fixed time",
    "nenhuma": "none",
    "Servidores DNS:": "DNS servers:",
    "testando a conexão…": "testing the connection…",
    "verificado em {data}": "checked at {data}",
    "Testar conexão": "Test connection",
    "Testando…": "Testing…",
    "Este relatório aponta o que <strong>merece revisão humana</strong>. Um achado não significa que "
    "o componente seja malicioso; leia a explicação e decida.":
        "This report points out what <strong>deserves human review</strong>. A finding does not mean the "
        "component is malicious; read the explanation and decide.",
    "Ainda não há relatório": "No report yet",
    "Clique em <strong>Varrer agora</strong> para executar a primeira varredura. Ela vira a linha de base "
    "para destacar o que for novo nas próximas.":
        "Click <strong>Scan now</strong> to run the first scan. It becomes the baseline used to highlight "
        "what is new in the next ones.",
    # --- Severidades e tipos ---
    "Crítica": "Critical",
    "Alta": "High",
    "Média": "Medium",
    "Baixa": "Low",
    "Informativa": "Info",
    "Aviso": "Notice",
    "Integração": "Integration",
    "Frontend (www)": "Frontend (www)",
    "Frontend": "Frontend",
    "Add-on": "Add-on",
    "Rede/DNS": "Network/DNS",
    # --- Cartões e erros ---
    "Resumo por severidade": "Summary by severity",
    "Mostrar ou esconder a lista de ignorados": "Show or hide the ignore list",
    "Ignorados · {n} item na lista": "Ignored · {n} item in the list",
    "Ignorados · {n} itens na lista": "Ignored · {n} items in the list",
    "Etapas com erro": "Steps with errors",
    "Estas etapas não terminaram; o relatório pode estar incompleto.":
        "These steps did not finish; the report may be incomplete.",
    # --- Componentes ---
    "Componentes": "Components",
    "Tipo": "Type",
    "Filtrar componentes por tipo": "Filter components by type",
    "Todos": "All",
    "Só lista negra": "Blocklist only",
    "Esconder componentes sem achados": "Hide components without findings",
    "Ignora os achados dos níveis selecionados em todos os componentes":
        "Ignores the findings of the selected levels in every component",
    "Ignorar estes níveis…": "Ignore these levels…",
    "Componente": "Component",
    "Nota de risco": "Risk score",
    "Item {id} da lista {origem} · {categoria}": "Item {id} from the {origem} list · {categoria}",
    " · {n} itens": " · {n} items",
    "Ignorar…": "Ignore…",
    "Nenhum componente para mostrar com os filtros atuais.": "No components to show with the current filters.",
    "pessoal": "personal",
    "comunitária": "community",
    # Detalhes dos componentes (rótulos)
    "versão": "version",
    "origem": "source",
    "integridade": "integrity",
    "código": "code",
    "envio médio": "average upload",
    "pico de envio": "peak upload",
    "tráfego": "traffic",
    "CVEs: {c} críticas, {a} altas": "CVEs: {c} critical, {a} high",
    # --- Tela do componente ---
    "← Voltar para o resumo": "← Back to summary",
    "← Voltar": "← Back",
    "Adicionar à lista negra…": "Add to blocklist…",
    "Achados de": "Findings for",
    "Filtrar por nível": "Filter by level",
    "Filtrar por texto, arquivo, regra…": "Filter by text, file, rule…",
    "Filtrar": "Filter",
    "Só novos": "New only",
    "Mostrar suprimidos": "Show suppressed",
    "Limpar filtros": "Clear filters",
    "Novo": "New",
    "Suprimido": "Suppressed",
    "Deixar de ignorar": "Stop ignoring",
    "Arquivo": "File",
    "Regra": "Rule",
    "Por que é suspeito:": "Why it is suspicious:",
    "O que fazer:": "What to do:",
    "Evidências:": "Evidence:",
    "Ignorado: {motivo}": "Ignored: {motivo}",
    "Nenhum achado deste componente corresponde aos filtros.": "No finding of this component matches the filters.",
    "Este componente não tem achados nesta varredura.": "This component has no findings in this scan.",
    # --- Ignorados ---
    "Lista de ignorados": "Ignore list",
    "Incluir na lista…": "Add to the list…",
    "Achados ignorados continuam no relatório (marque \"Mostrar suprimidos\"), mas não contam nos totais, "
    "nas notas nem nos sensores. A mudança vale na hora para o relatório mais recente e nas próximas varreduras.":
        "Ignored findings stay in the report (tick \"Show suppressed\"), but do not count in the totals, scores "
        "or sensors. Changes apply immediately to the latest report and to the next scans.",
    "Alcance": "Scope",
    "Motivo": "Reason",
    "Origem": "Source",
    "só o achado “{titulo}”": "only the finding “{titulo}”",
    "específico": "specific",
    "arquivos": "files",
    "todos os achados": "all findings",
    "todos os achados da regra": "all findings of the rule",
    "níveis: {niveis}": "levels: {niveis}",
    "não é verificado": "not scanned",
    "Interface · {data}": "Interface · {data}",
    "Editar": "Edit",
    "Remover": "Remove",
    "Configurações": "Configuration",
    "remova na aba Configuração": "remove it in the Configuration tab",
    "Nada está sendo ignorado.": "Nothing is being ignored.",
    # --- DNS e resolvidos ---
    "Domínios consultados": "Queried domains",
    "Clientes considerados: {clientes}.": "Clients considered: {clientes}.",
    "Mostrando os {n} mais recentes de {total}.": "Showing the {n} most recent out of {total}.",
    "*.exemplo.com vale para exemplo.com e todos os subdomínios.": "*.example.com covers example.com and all its subdomains.",
    "Domínios ignorados": "Ignored domains",
    "Domínios que você reconhece saem dos achados de DNS (aleatórios, bloqueados, novos e suspeitos) a partir da <strong>próxima varredura</strong> e não aparecem na tabela de domínios consultados.":
        "Domains you recognise are left out of the DNS findings (random, blocked, new and suspicious) from the <strong>next scan</strong> on and do not show in the queried domains table.",
    "Nenhum domínio ignorado.": "No ignored domains.",
    "Ignorar domínio": "Ignore domain",
    "Ignorar domínio…": "Ignore domain…",
    "Incluído em": "Added",
    "Mostrar domínios ignorados ({n})": "Show ignored domains ({n})",
    "ex.: api.exemplo.com ou *.exemplo.com": "e.g. api.example.com or *.example.com",
    "Remover da lista de domínios ignorados? Ele volta aos achados na próxima varredura.":
        "Remove it from the ignored domains? It comes back to the findings on the next scan.",
    "Domínio": "Domain",
    "Servidor": "Server",
    "Consultas": "Queries",
    "Bloqueadas": "Blocked",
    "Última": "Last",
    "ambos": "both",
    "Resolvidos desde a varredura anterior": "Resolved since the previous scan",
    # Etapas da varredura
    "lista negra": "blocklist",
    "análise estática": "static analysis",
    "dependências": "dependencies",
    "permissões dos add-ons": "add-on permissions",
    "código dos add-ons": "add-on code",
    "tráfego dos add-ons": "add-on traffic",
    "imagens dos add-ons": "add-on images",
    "Achados de DNS: {n}": "DNS findings: {n}",
    "Ver achados": "View findings",
    "Nenhum achado de DNS nesta varredura.": "No DNS findings in this scan.",
    "Os domínios consultados aparecem aqui depois da próxima varredura.":
        "Queried domains appear here after the next scan.",
    # --- Lista negra ---
    "Malicioso": "Malicious",
    "Comprometido": "Compromised",
    "Vulnerável": "Vulnerable",
    "Abandonado": "Abandoned",
    "Telemetria": "Telemetry",
    "Removido de loja": "Removed from store",
    "Incompatível": "Incompatible",
    "Componentes reportados ganham o selo <strong>Lista negra</strong> na tabela de componentes. A comparação "
    "é local; as mudanças valem na <strong>próxima varredura</strong>.":
        "Reported components get the <strong>Blocklist</strong> badge in the components table. The comparison "
        "is local; changes apply on the <strong>next scan</strong>.",
    "Lista comunitária": "Community list",
    "Desligada nas opções (<code>lista_comunitaria</code>).": "Turned off in the options (<code>lista_comunitaria</code>).",
    "<strong>{itens}</strong> itens · lista de {data} · última busca {busca} · assinatura conferida (chave {chave}).":
        "<strong>{itens}</strong> items · list from {data} · last fetch {busca} · signature verified (key {chave}).",
    "Ver no GitHub": "View on GitHub",
    "· inclui relatos da comunidade e as listas do HACS e do Home Assistant.":
        "· includes community reports and the HACS and Home Assistant lists.",
    "Ainda não baixada. Ela é buscada na próxima varredura (no máximo a cada 6 horas).":
        "Not downloaded yet. It is fetched on the next scan (at most every 6 hours).",
    "Lista pessoal": "Personal list",
    "Adicionar item…": "Add item…",
    "Vale só nesta instalação. Os itens ficam guardados no add-on (entram no backup dele) e não precisam de "
    "assinatura nem de evidência.":
        "Applies only to this installation. Items are stored in the add-on (included in its backup) and need no "
        "signature or evidence.",
    "Nível": "Level",
    "Versões": "Versions",
    "Categoria": "Category",
    "Criado em": "Created",
    "Descoberto em": "Discovered",
    "Instalação/atualização:": "Install/update:",
    "Ignorar todos…": "Ignore all…",
    "Domínios ignorados deixam de gerar achados, inclusive de mineração e exfiltração. Confira a lista antes de confirmar.":
        "Ignored domains no longer create findings, including mining and exfiltration ones. Check the list before confirming.",
    "Ignorar todos os domínios": "Ignore all domains",
    "Todos os {n} domínios da tabela que ainda não estão ignorados: {lista}":
        "All {n} domains in the table that are not ignored yet: {lista}",
    "novo": "new",
    "atualizado": "updated",
    "removido": "removed",
    "verificação de instalação/atualização": "install/update check",
    "verificação de DNS": "DNS check",
    "Verificação de DNS (só a parte de DNS foi atualizada)": "DNS check (only the DNS part was updated)",
    "descoberto em {data}": "discovered {data}",
    "qualquer tipo": "any type",
    "todas": "all",
    "Nenhum item. Use <strong>Adicionar item…</strong> ou, na tela de um componente, "
    "<strong>Adicionar à lista negra…</strong>.":
        "No items. Use <strong>Add item…</strong> or, on a component's page, <strong>Add to blocklist…</strong>.",
    # --- Histórico ---
    "Clique na data para abrir o relatório daquela verificação.": "Click the date to open that scan's report.",
    "{n} verificação guardada": "{n} scan stored",
    "{n} verificações guardadas": "{n} scans stored",
    "(o limite é a opção <code>report_retention</code>).": "(the limit is the <code>report_retention</code> option).",
    "Varredura": "Scan",
    "Status": "Status",
    "Duração": "Duration",
    "Novos": "New",
    "Concluída": "Completed",
    "Falhou": "Failed",
    "Cancelada": "Cancelled",
    "Em andamento": "Running",
    "Páginas do histórico": "History pages",
    "← Anterior": "← Previous",
    "Próxima →": "Next →",
    "Nenhuma verificação ainda.": "No scans yet.",
    # --- Diálogo da lista negra ---
    "Informe pelo menos o repositório do GitHub, o nome ou a imagem. O GitHub (ou a imagem) dá correspondência "
    "forte; só o nome gera \"possível correspondência\".":
        "Provide at least the GitHub repository, the name or the image. GitHub (or the image) gives a strong match; "
        "the name alone produces a \"possible match\".",
    "Qualquer": "Any",
    "Versões afetadas": "Affected versions",
    "ex.: <1.4.2 (vazio = todas)": "e.g. <1.4.2 (empty = all)",
    "Repositório do GitHub": "GitHub repository",
    "dono/repositorio": "owner/repository",
    "Nome": "Name",
    "domínio, pasta do card ou slug": "domain, card folder or slug",
    "Imagem do add-on": "Add-on image",
    "O que acontece, em uma ou duas frases": "What happens, in one or two sentences",
    "Evidências (opcional, um link https:// por linha)": "Evidence (optional, one https:// link per line)",
    "Cancelar": "Cancel",
    "Salvar": "Save",
    # --- Diálogo de ignorar ---
    "Ignorar achado": "Ignore finding",
    "O que ignorar": "What to ignore",
    "Só este achado": "Only this finding",
    "Esta regra neste arquivo": "This rule in this file",
    "Esta regra em todo o componente": "This rule in the whole component",
    "Esta regra em todos os componentes": "This rule in every component",
    "Níveis": "Levels",
    "Todos os níveis": "All levels",
    "ex.: minha_integracao ou *": "e.g. my_integration or *",
    "ex.: auditor.semgrep.eval ou semgrep.*": "e.g. auditor.semgrep.eval or semgrep.*",
    "Arquivo (opcional)": "File (optional)",
    "ex.: */vendor/*": "e.g. */vendor/*",
    "Por que isto pode ser ignorado?": "Why can this be ignored?",
    "Com todos os níveis, este componente <strong>deixa de ser verificado</strong> nas próximas varreduras "
    "(nenhuma ferramenta roda nele). Remova da lista para voltar a verificá-lo.":
        "With all levels, this component <strong>is no longer scanned</strong> in the next scans (no tool runs on "
        "it). Remove it from the list to scan it again.",
    "Ignorar": "Ignore",
    # --- JavaScript ---
    "Não foi possível iniciar a varredura.": "Could not start the scan.",
    "Não foi possível cancelar a varredura.": "Could not cancel the scan.",
    "Cancelar a varredura em andamento? O que já foi analisado fica salvo como relatório cancelado.":
        "Cancel the running scan? What has been analysed so far is saved as a cancelled report.",
    "({a} de {b})": "({a} of {b})",
    "Com achados de nível: {niveis}": "With findings of level: {niveis}",
    "Ignorar achados do componente": "Ignore the component's findings",
    "Ignorar níveis inteiros": "Ignore whole levels",
    "Incluir na lista de ignorados": "Add to the ignore list",
    "Componente {nome}: todas as regras, nos níveis marcados abaixo.":
        "Component {nome}: all rules, at the levels ticked below.",
    "Todos os componentes e regras. Os achados continuam visíveis com \"Mostrar suprimidos\".":
        "All components and rules. The findings stay visible with \"Show suppressed\".",
    "Use * como curinga (ex.: semgrep.* ou */vendor/*).": "Use * as a wildcard (e.g. semgrep.* or */vendor/*).",
    "Níveis a ignorar em todos os componentes": "Levels to ignore in every component",
    "Só estes níveis (nenhum marcado = todos)": "Only these levels (none ticked = all)",
    "Marque pelo menos um nível.": "Tick at least one level.",
    "Ignorar todos os achados de nível {niveis} em todos os componentes?":
        "Ignore every finding of level {niveis} in every component?",
    "Não foi possível incluir (HTTP {status}).": "Could not add (HTTP {status}).",
    "Não foi possível incluir.": "Could not add.",
    "Remover da lista de ignorados? Os achados voltam a contar nos totais.":
        "Remove from the ignore list? The findings count in the totals again.",
    "Não foi possível remover da lista.": "Could not remove it from the list.",
    "Não foi possível salvar (HTTP {status}).": "Could not save (HTTP {status}).",
    "Não foi possível salvar.": "Could not save.",
    "Editar item {id}": "Edit item {id}",
    "Adicionar à lista negra pessoal": "Add to the personal blocklist",
    "Remover o item {id} da lista negra pessoal?": "Remove item {id} from the personal blocklist?",
    "Não foi possível remover o item.": "Could not remove the item.",
}
