"""Avaliação das permissões e do estado de cada add-on instalado.

Permissões amplas não provam má intenção (add-ons de hardware precisam delas),
mas definem o tamanho do estrago se o add-on for comprometido.
"""

from __future__ import annotations

from typing import Any

from ..addons import AddonInfo
from ..models import ComponentType, Finding, Severity
from .base import ScanContext

# Capacidades Linux que, sozinhas, praticamente equivalem a root no host.
DANGEROUS_CAPS = frozenset({"SYS_ADMIN", "SYS_MODULE", "SYS_RAWIO", "SYS_PTRACE", "DAC_READ_SEARCH", "SYS_BOOT"})

# (campo, severidade, título, explicação, recomendação)
_BOOL_PERMS: list[tuple[str, Severity, str, str, str]] = [
    ("docker_api", Severity.CRITICAL, "Acesso à API do Docker",
     "Com a API do Docker o add-on pode criar containers privilegiados e montar o disco do host: "
     "na prática, controle total do sistema. Só é concedida com o modo de proteção desativado.",
     "Mantenha apenas se for indispensável (ex.: Portainer) e de autor muito confiável."),
    ("full_access", Severity.HIGH, "Acesso total ao hardware (full_access)",
     "O add-on enxerga todos os dispositivos do host e roda praticamente sem isolamento.",
     "Confirme se o add-on realmente precisa disso; prefira alternativas com acesso a dispositivos específicos."),
    ("host_pid", Severity.HIGH, "Compartilha os processos do host (host_pid)",
     "O add-on vê e pode interagir com todos os processos do sistema, incluindo os de outros add-ons.",
     "Verifique a necessidade; é raro um add-on precisar disso."),
    ("host_network", Severity.MEDIUM, "Usa a rede do host (host_network)",
     "O add-on fica fora da rede isolada do Supervisor: pode escutar e abrir conexões em qualquer "
     "interface do host, e o tráfego dele não aparece separado nas estatísticas.",
     "Normal para descoberta de dispositivos (mDNS, DLNA); estranho para serviços web comuns."),
    ("host_dbus", Severity.MEDIUM, "Acesso ao D-Bus do host",
     "Pelo D-Bus é possível controlar serviços do sistema operacional (rede, Bluetooth, systemd).",
     "Confirme para que o add-on usa o D-Bus."),
    ("host_ipc", Severity.LOW, "Compartilha IPC do host", "O add-on compartilha memória/IPC com o host.",
     "Verifique a necessidade."),
    ("host_uts", Severity.LOW, "Compartilha o hostname do host", "O add-on pode alterar o nome do host.",
     "Normalmente inofensivo."),
    ("homeassistant_api", Severity.MEDIUM, "Acesso à API do Home Assistant",
     "O add-on pode ler e controlar todas as entidades e serviços do Home Assistant.",
     "Esperado em add-ons que integram com o HA; confira se faz sentido neste."),
    ("auth_api", Severity.LOW, "Validação de usuário e senha do HA (auth_api)",
     "O add-on recebe usuário e senha do Home Assistant para validá-los, ou seja, vê as senhas digitadas nele.",
     "Use apenas com add-ons confiáveis; prefira login via Ingress quando possível."),
    ("kernel_modules", Severity.HIGH, "Carrega módulos do kernel",
     "Módulos de kernel rodam com privilégio máximo no host.",
     "Mantenha apenas se o add-on for de hardware e de autor confiável."),
]

_ROLE_SEVERITY = {
    "admin": (Severity.HIGH, "Pode administrar o Supervisor, inclusive instalar e configurar outros add-ons."),
    "manager": (Severity.MEDIUM, "Pode ler e alterar add-ons e a configuração do Supervisor."),
    "backup": (Severity.LOW, "Pode criar e restaurar backups (que contêm todas as senhas)."),
    "homeassistant": (Severity.LOW, "Pode controlar o Home Assistant Core (reiniciar, atualizar)."),
}


class AddonPermissionsScanner:
    name = "permissoes_addons"

    async def scan(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for addon in await ctx.addons():
            findings.extend(evaluate(addon))
        return findings


def evaluate(addon: AddonInfo) -> list[Finding]:
    i = addon.info
    out: list[Finding] = []

    def add(rule: str, sev: Severity, title: str, why: str, todo: str, snippet: str | None = None,
            category: str = "permissao") -> None:
        out.append(Finding(
            component=addon.slug, component_type=ComponentType.ADDON, category=category,
            rule_id=f"auditor.addon.{rule}", severity=sev, title=title, explanation=why,
            recommendation=todo, snippet=snippet, source="supervisor",
        ))

    if i.get("protected") is False:
        add("protecao-desativada", Severity.HIGH, "Modo de proteção desativado",
            "Com o modo de proteção desligado o add-on pode receber permissões perigosas (como acesso ao "
            "Docker e ao hardware) que normalmente seriam bloqueadas.",
            "Reative o modo de proteção na página do add-on, a menos que ele exija o contrário.",
            "protected: false")

    for key, sev, title, why, todo in _BOOL_PERMS:
        if i.get(key):
            add(key.replace("_", "-"), sev, title, why, todo, f"{key}: true")

    caps = [str(c).upper() for c in (i.get("privileged") or [])]
    if caps:
        dangerous = sorted(set(caps) & DANGEROUS_CAPS)
        add("capacidades", Severity.HIGH if dangerous else Severity.LOW,
            "Capacidades Linux extras (privileged)",
            ("O add-on recebe capacidades extras do kernel. "
             + (f"{', '.join(dangerous)} permitem escapar do container ou ler qualquer arquivo do host."
                if dangerous else "Nenhuma delas dá controle total do host isoladamente.")),
            "Confira se cada capacidade é necessária para a função do add-on.",
            "privileged: " + ", ".join(caps))

    apparmor = i.get("apparmor")
    if apparmor == "disable":
        add("apparmor-desativado", Severity.HIGH, "AppArmor desativado",
            "Sem AppArmor o add-on não tem a camada extra que limita arquivos e capacidades acessíveis.",
            "Pergunte ao autor por que o AppArmor precisa ficar desligado.", "apparmor: disable")
    elif apparmor == "default":
        add("apparmor-padrao", Severity.INFO, "AppArmor com perfil genérico",
            "O add-on usa o perfil padrão do Docker, não um perfil próprio feito para ele.",
            "Nenhuma ação necessária; um perfil próprio seria mais restritivo.", "apparmor: default")

    role = str(i.get("hassio_role") or "default")
    if i.get("hassio_api") and role in _ROLE_SEVERITY:
        sev, why = _ROLE_SEVERITY[role]
        add(f"role-{role}", sev, f"Acesso à API do Supervisor com papel '{role}'", why,
            "Confirme se o add-on precisa desse nível de acesso.", f"hassio_role: {role}")

    devices = i.get("devices") or []
    hw = [k for k in ("usb", "uart", "gpio", "video", "audio", "udev", "devicetree") if i.get(k)]
    if devices or hw:
        add("hardware", Severity.INFO, "Acesso a dispositivos",
            "O add-on acessa dispositivos do host. É o esperado em add-ons de rádio, câmera ou serial.",
            "Confira se os dispositivos combinam com a função do add-on.",
            "; ".join(filter(None, [("devices: " + ", ".join(map(str, devices))) if devices else "",
                                    ("hardware: " + ", ".join(hw)) if hw else ""])))

    rating = i.get("rating")
    if isinstance(rating, int) and rating <= 3:
        add("nota-seguranca", Severity.MEDIUM if rating <= 2 else Severity.LOW,
            f"Nota de segurança baixa ({rating}/6)",
            "O Supervisor calcula essa nota a partir das permissões pedidas; quanto menor, mais "
            "privilégios o add-on tem.",
            "Revise as permissões listadas para este add-on.", f"rating: {rating}")

    if i.get("update_available") and addon.version_latest:
        add("atualizacao-pendente", Severity.LOW, "Atualização pendente",
            f"Instalado: {addon.version}; disponível: {addon.version_latest}. Atualizações costumam "
            "trazer correções de segurança.",
            "Leia o changelog e atualize.", f"{addon.version} → {addon.version_latest}",
            category="atualizacao")

    if i.get("detached"):
        add("sem-repositorio", Severity.MEDIUM, "Add-on órfão (removido do repositório)",
            "O add-on não existe mais no repositório de origem: não recebe atualizações nem correções.",
            "Procure uma alternativa mantida.", category="origem")

    if addon.repository == "local":
        add("local", Severity.INFO, "Add-on local",
            "Construído a partir da pasta /addons do próprio host; não há origem externa para comparar.",
            "Nenhuma ação, se foi você quem o colocou lá.", category="origem")
    elif addon.repository != "core" and addon.repository_source:
        add("terceiro", Severity.INFO, "Add-on de repositório de terceiros",
            f"Origem: {addon.repository_source}.",
            "Confira se o repositório é o oficial do projeto e tem manutenção ativa.",
            addon.repository_source, category="origem")
    return out


def summarize_permissions(info: dict[str, Any]) -> list[str]:
    """Lista curta das permissões relevantes (usada nos metadados do relatório)."""
    names = [k for k, *_ in _BOOL_PERMS if info.get(k)]
    if info.get("privileged"):
        names.append("privileged")
    if info.get("hassio_api"):
        names.append(f"hassio_role={info.get('hassio_role') or 'default'}")
    return names
