"""Perfil de capacidades de cada componente, cadeias de comportamento e capacidade nova em atualização.

Cada achado das regras indica uma capacidade do componente (acessa a rede, executa comandos, lê
segredos, executa código dinâmico, instala pacotes, tem código escondido). Sozinhas, muitas são
normais; algumas combinações são o padrão de ataque clássico e viram um achado próprio (cadeia):

- lê segredos/tokens **e** acessa a rede (roubo de credenciais);
- tem código escondido (ofuscação, compilado sem fonte) **e** alguma capacidade perigosa;
- acessa a rede **e** executa código dinâmico (baixa e executa).

O perfil também é guardado por versão: quando uma atualização acrescenta uma capacidade que o
componente não tinha, sai o achado "capacidade nova nesta atualização" (o ataque mais comum de
cadeia de suprimentos: o repositório muda de mãos e uma versão nova passa a mandar dados para fora).
"""

from __future__ import annotations

from typing import Any

from .models import Finding, Severity, en_text

# Capacidade -> (rótulo em português, em inglês, ícone)
LABELS = {
    "rede": ("acessa a rede", "network access", "🌐"),
    "shell": ("executa comandos", "runs commands", "🖥️"),
    "segredos": ("lê segredos ou tokens", "reads secrets or tokens", "🔑"),
    "execucao": ("executa código dinâmico", "runs dynamic code", "⚙️"),
    "pacotes": ("instala pacotes", "installs packages", "📦"),
    "escondido": ("tem código escondido", "has hidden code", "🕶️"),
}

RULES: dict[str, set[str]] = {
    "rede": {
        "auditor.py.url-fixa", "auditor.py.ip-fixo-publico", "auditor.py.destino-suspeito", "auditor.py.conteudo-github",
        "auditor.py.download-e-execucao", "auditor.js.destino-suspeito", "auditor.js.ip-fixo-publico",
        "auditor.js.codigo-remoto", "auditor.sh.baixa-e-executa", "auditor.sh.destino-suspeito",
        "auditor.docker.add-de-url", "bandit.B310", "bandit.B113",
    },
    "shell": {
        "auditor.py.execucao-de-comandos", "auditor.py.shell-true", "auditor.py.shell-reverso",
        "auditor.sh.shell-reverso", "bandit.B602", "bandit.B604", "bandit.B605", "bandit.B606", "bandit.B607",
    },
    "segredos": {
        # acesso-storage (pasta .storage em geral) e lista-usuarios (só nomes/permissões) não entram: costumam
        # ser a integração usando o próprio arquivo ou mostrando quem fez o quê.
        "auditor.py.acesso-secrets-yaml", "auditor.py.acesso-storage-auth", "auditor.py.tokens-de-acesso", "auditor.js.acesso-token-ha", "auditor.sh.token-supervisor-externo",
        "auditor.sh.acesso-sensivel",
    },
    "execucao": {
        "auditor.py.eval-dinamico", "auditor.py.marshal-loads", "auditor.py.builtins-indireto",
        "auditor.py.carregamento-dinamico-de-modulo", "auditor.py.ofuscacao-decodifica-e-executa",
        "auditor.py.download-e-execucao", "auditor.js.eval-dinamico", "auditor.js.ofuscacao-decodifica-e-executa",
        "auditor.js.codigo-remoto", "auditor.sh.decodifica-e-executa", "auditor.sh.baixa-e-executa",
        "auditor.ofuscacao.descompacta-e-executa", "bandit.B102", "bandit.B307", "bandit.B301", "bandit.B302",
    },
    "pacotes": {"auditor.py.instalacao-de-pacote-em-tempo-de-execucao"},
    "escondido": {
        "auditor.py.blob-codificado", "auditor.py.ofuscacao-decodifica-e-executa",
        "auditor.js.ofuscacao-decodifica-e-executa",
    },
}
_PREFIXES = {"auditor.ofuscacao.": "escondido", "auditor.compilado.": "escondido"}
DERIVED = {"cadeia"}  # categorias calculadas aqui (não contam como capacidade)
CHANGE_RULE = "auditor.capacidade-nova"
_MAX_PIECES = 6


def capabilities_of(finding: Finding) -> set[str]:
    caps = {cap for cap, rules in RULES.items() if finding.rule_id in rules}
    caps |= {cap for prefix, cap in _PREFIXES.items() if finding.rule_id.startswith(prefix)}
    return caps


def profile(findings: list[Finding]) -> dict[tuple[str, str], dict[str, list[Finding]]]:
    """(tipo, componente) -> capacidade -> achados que a mostram. Inclui achados ignorados: são fatos."""
    out: dict[tuple[str, str], dict[str, list[Finding]]] = {}
    for f in findings:
        if f.category in DERIVED or f.rule_id == CHANGE_RULE:
            continue
        for cap in capabilities_of(f):
            out.setdefault((str(f.component_type), f.component), {}).setdefault(cap, []).append(f)
    return out


def _pieces(caps: dict[str, list[Finding]], wanted: list[str], en: bool = False) -> str:
    lines = []
    for cap in wanted:
        label = LABELS[cap][1 if en else 0]
        for f in caps.get(cap, [])[:_MAX_PIECES]:
            title = ((f.en or {}).get("title") if en else None) or f.title
            where = f"{f.file}:{f.line}" if f.file and f.line else (f.file or "")
            lines.append(f"[{label}] {title}" + (f" — {where}" if where else ""))
    return "\n".join(lines)


_CHAINS = [
    # (id, capacidades exigidas (todas), alternativas (pelo menos uma), severidade, textos)
    ("segredos-e-rede", ["segredos", "rede"], [], Severity.CRITICAL,
     "Lê credenciais e acessa a rede",
     ("O mesmo componente lê segredos ou tokens do Home Assistant e também se comunica pela rede. Cada parte "
     "pode ser legítima sozinha, mas juntas são o padrão clássico de roubo de credenciais."),
     "Reads credentials and accesses the network",
     ("The same component reads Home Assistant secrets or tokens and also talks over the network. Each part may be "
     "legitimate on its own, but together they are the classic credential-theft pattern.")),
    ("escondido-e-perigoso", ["escondido"], ["rede", "segredos", "shell", "execucao", "pacotes"], Severity.CRITICAL,
     "Código escondido junto com capacidade perigosa",
     ("O componente tem código ofuscado ou compilado sem fonte e também faz algo sensível (rede, segredos, "
     "comandos ou código dinâmico). Código legítimo raramente precisa se esconder."),
     "Hidden code together with a dangerous capability",
     ("The component has obfuscated code or compiled code without source and also does something sensitive "
     "(network, secrets, commands or dynamic code). Legitimate code rarely needs to hide.")),
    ("rede-e-execucao", ["rede", "execucao"], [], Severity.HIGH,
     "Acessa a rede e executa código dinâmico",
     ("O componente se comunica pela rede e executa código montado em tempo de execução (eval, exec, "
     "carregamento dinâmico). É o caminho para baixar e rodar código que não está no componente."),
     "Accesses the network and runs dynamic code",
     ("The component talks over the network and runs code built at runtime (eval, exec, dynamic loading). It is "
     "the path to download and run code that is not in the component.")),
]
_CHAIN_TODO = (("Veja as peças abaixo juntas: de onde vêm os dados lidos e para onde vão as conexões. Se não houver "
               "explicação clara, desative o componente e troque as credenciais."),
               ("Look at the pieces below together: where the data read comes from and where the connections go. "
               "If there is no clear explanation, disable the component and change the credentials."))


def build_chains(findings: list[Finding]) -> list[Finding]:
    out: list[Finding] = []
    for (ctype, comp), caps in sorted(profile(findings).items()):
        for chain_id, required, any_of, sev, title, why, title_en, why_en in _CHAINS:
            if not all(c in caps for c in required) or (any_of and not any(c in caps for c in any_of)):
                continue
            used = required + [c for c in any_of if c in caps]
            out.append(Finding(
                component=comp, component_type=ctype, category="cadeia", rule_id=f"auditor.cadeia.{chain_id}",
                severity=sev, title=title, explanation=why, recommendation=_CHAIN_TODO[0],
                en=en_text(title_en, why_en, _CHAIN_TODO[1], _pieces(caps, used, en=True)),
                snippet=_pieces(caps, used), source="auditor", extra={"fingerprint_key": chain_id},
            ))
    return out


def capability_changes(findings: list[Finding], components: list[Any], storage: Any, now: str) -> list[Finding]:
    """Atualiza o perfil guardado e devolve os achados de capacidade nova trazida por atualização.

    Só compara quando a versão muda: novas regras do próprio auditor não viram alerta.
    """
    prof = profile(findings)
    out: list[Finding] = []
    for comp in components:
        if comp.component_type not in ("integracao", "frontend", "addon"):
            continue
        key = (str(comp.component_type), comp.name)
        caps = prof.get(key, {})
        now_caps = set(caps)
        version = str(comp.metadata.get("versao") or "")
        row = storage.capability_row(*key)
        if row is None:
            storage.save_capabilities(*key, version, now_caps, set(), None, now)
            continue
        if version and version != row["version"]:
            added = now_caps - set(row["caps"])
            previous = row["version"]
        else:
            added = set(row["added"]) & now_caps
            previous = row["previous"]
        storage.save_capabilities(*key, version or row["version"], now_caps, added, previous, now)
        if added and previous is not None:
            out.append(_change_finding(comp, sorted(added), previous, version, caps))
    return out


def _change_finding(comp: Any, added: list[str], previous: str, version: str,
                    caps: dict[str, list[Finding]]) -> Finding:
    names = ", ".join(LABELS[c][0] for c in added)
    names_en = ", ".join(LABELS[c][1] for c in added)
    old = previous or "?"
    return Finding(
        component=comp.name, component_type=comp.component_type, category="capacidade",
        rule_id=CHANGE_RULE, severity=Severity.HIGH,
        title=f"Atualização trouxe capacidade nova: {names}",
        explanation=(f"Na versão {old} o componente não fazia isto; a versão {version} passou a: {names}. Mudança "
                     "assim numa atualização é o sinal típico de repositório que mudou de mãos ou foi invadido."),
        recommendation=("Leia o changelog da versão e as peças abaixo. Se a mudança não for explicada pelo autor, "
                        "volte para a versão anterior e avise o autor."),
        en=en_text(f"Update added a new capability: {names_en}",
                   f"In version {old} the component did not do this; version {version} now: {names_en}. A change "
                   "like this in an update is the typical sign of a repository that changed hands or was hacked.",
                   "Read the release notes and the pieces below. If the author does not explain the change, go back "
                   "to the previous version and let the author know.", _pieces(caps, added, en=True)),
        snippet=_pieces(caps, added), source="auditor",
        extra={"fingerprint_key": f"{old}>{version}:{','.join(added)}"},
    )

