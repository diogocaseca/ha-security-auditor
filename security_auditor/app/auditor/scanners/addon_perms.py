"""Avaliação das permissões e do estado de cada add-on instalado.

Permissões amplas não provam má intenção (add-ons de hardware precisam delas),
mas definem o tamanho do estrago se o add-on for comprometido.

Cada mensagem tem a versão em português e em inglês (título, explicação, recomendação).
"""

from __future__ import annotations

from ..addons import AddonInfo
from ..models import ComponentType, Finding, Severity, en_text
from .base import ScanContext

# Capacidades Linux que, sozinhas, praticamente equivalem a root no host.
DANGEROUS_CAPS = frozenset({"SYS_ADMIN", "SYS_MODULE", "SYS_RAWIO", "SYS_PTRACE", "DAC_READ_SEARCH", "SYS_BOOT"})

Text = tuple[str, str, str]  # (título, explicação, recomendação)

# campo -> (severidade, português, inglês)
_BOOL_PERMS: list[tuple[str, Severity, Text, Text]] = [
    ("docker_api", Severity.CRITICAL,
     ("Acesso à API do Docker",
      "Com a API do Docker o add-on pode criar containers privilegiados e montar o disco do host: "
      "na prática, controle total do sistema. Só é concedida com o modo de proteção desativado.",
      "Mantenha apenas se for indispensável (ex.: Portainer) e de autor muito confiável."),
     ("Access to the Docker API",
      "With the Docker API the add-on can create privileged containers and mount the host disk: in practice, "
      "full control of the system. It is only granted with protection mode disabled.",
      "Keep it only if it is essential (e.g. Portainer) and from a very trusted author.")),
    ("full_access", Severity.HIGH,
     ("Acesso total ao hardware (full_access)",
      "O add-on enxerga todos os dispositivos do host e roda praticamente sem isolamento.",
      "Confirme se o add-on realmente precisa disso; prefira alternativas com acesso a dispositivos específicos."),
     ("Full hardware access (full_access)",
      "The add-on sees every host device and runs with almost no isolation.",
      "Confirm the add-on really needs this; prefer alternatives with access to specific devices.")),
    ("host_pid", Severity.HIGH,
     ("Compartilha os processos do host (host_pid)",
      "O add-on vê e pode interagir com todos os processos do sistema, incluindo os de outros add-ons.",
      "Verifique a necessidade; é raro um add-on precisar disso."),
     ("Shares the host processes (host_pid)",
      "The add-on sees and can interact with every process on the system, including other add-ons'.",
      "Check whether it is needed; add-ons rarely need this.")),
    ("host_network", Severity.MEDIUM,
     ("Usa a rede do host (host_network)",
      "O add-on fica fora da rede isolada do Supervisor: pode escutar e abrir conexões em qualquer "
      "interface do host, e o tráfego dele não aparece separado nas estatísticas.",
      "Normal para descoberta de dispositivos (mDNS, DLNA); estranho para serviços web comuns."),
     ("Uses the host network (host_network)",
      "The add-on is outside the Supervisor's isolated network: it can listen and open connections on any host "
      "interface, and its traffic does not show up separately in the statistics.",
      "Normal for device discovery (mDNS, DLNA); odd for regular web services.")),
    ("host_dbus", Severity.MEDIUM,
     ("Acesso ao D-Bus do host",
      "Pelo D-Bus é possível controlar serviços do sistema operacional (rede, Bluetooth, systemd).",
      "Confirme para que o add-on usa o D-Bus."),
     ("Access to the host D-Bus",
      "Through D-Bus it is possible to control operating system services (network, Bluetooth, systemd).",
      "Confirm what the add-on uses D-Bus for.")),
    ("host_ipc", Severity.LOW,
     ("Compartilha IPC do host", "O add-on compartilha memória/IPC com o host.", "Verifique a necessidade."),
     ("Shares the host IPC", "The add-on shares memory/IPC with the host.", "Check whether it is needed.")),
    ("host_uts", Severity.LOW,
     ("Compartilha o hostname do host", "O add-on pode alterar o nome do host.", "Normalmente inofensivo."),
     ("Shares the host hostname", "The add-on can change the host name.", "Usually harmless.")),
    ("homeassistant_api", Severity.MEDIUM,
     ("Acesso à API do Home Assistant",
      "O add-on pode ler e controlar todas as entidades e serviços do Home Assistant.",
      "Esperado em add-ons que integram com o HA; confira se faz sentido neste."),
     ("Access to the Home Assistant API",
      "The add-on can read and control every Home Assistant entity and service.",
      "Expected in add-ons that integrate with HA; check that it makes sense for this one.")),
    ("auth_api", Severity.LOW,
     ("Validação de usuário e senha do HA (auth_api)",
      "O add-on recebe usuário e senha do Home Assistant para validá-los, ou seja, vê as senhas digitadas nele.",
      "Use apenas com add-ons confiáveis; prefira login via Ingress quando possível."),
     ("HA username and password validation (auth_api)",
      "The add-on receives Home Assistant usernames and passwords to validate them, so it sees the passwords "
      "typed into it.",
      "Use it only with trusted add-ons; prefer logging in through Ingress when possible.")),
    ("kernel_modules", Severity.HIGH,
     ("Carrega módulos do kernel",
      "Módulos de kernel rodam com privilégio máximo no host.",
      "Mantenha apenas se o add-on for de hardware e de autor confiável."),
     ("Loads kernel modules",
      "Kernel modules run with the highest privilege on the host.",
      "Keep it only if it is a hardware add-on from a trusted author.")),
]

# papel -> (severidade, explicação em português, explicação em inglês)
_ROLE_SEVERITY = {
    "admin": (Severity.HIGH, "Pode administrar o Supervisor, inclusive instalar e configurar outros add-ons.",
              "It can administer the Supervisor, including installing and configuring other add-ons."),
    "manager": (Severity.MEDIUM, "Pode ler e alterar add-ons e a configuração do Supervisor.",
                "It can read and change add-ons and the Supervisor configuration."),
    "backup": (Severity.LOW, "Pode criar e restaurar backups (que contêm todas as senhas).",
               "It can create and restore backups (which contain every password)."),
    "homeassistant": (Severity.LOW, "Pode controlar o Home Assistant Core (reiniciar, atualizar).",
                      "It can control Home Assistant Core (restart, update)."),
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

    def add(rule: str, sev: Severity, pt: Text, en: Text, snippet: str | None = None,
            category: str = "permissao") -> None:
        out.append(Finding(
            component=addon.slug, component_type=ComponentType.ADDON, category=category,
            rule_id=f"auditor.addon.{rule}", severity=sev, title=pt[0], explanation=pt[1],
            recommendation=pt[2], en=en_text(*en), snippet=snippet, source="supervisor",
        ))

    if i.get("protected") is False:
        add("protecao-desativada", Severity.HIGH,
            ("Modo de proteção desativado",
             "Com o modo de proteção desligado o add-on pode receber permissões perigosas (como acesso ao "
             "Docker e ao hardware) que normalmente seriam bloqueadas.",
             "Reative o modo de proteção na página do add-on, a menos que ele exija o contrário."),
            ("Protection mode disabled",
             "With protection mode off the add-on can receive dangerous permissions (such as access to Docker and "
             "to the hardware) that would normally be blocked.",
             "Turn protection mode back on in the add-on page, unless it requires otherwise."),
            "protected: false")

    for key, sev, pt, en in _BOOL_PERMS:
        if i.get(key):
            add(key.replace("_", "-"), sev, pt, en, f"{key}: true")

    caps = [str(c).upper() for c in (i.get("privileged") or [])]
    if caps:
        dangerous = sorted(set(caps) & DANGEROUS_CAPS)
        add("capacidades", Severity.HIGH if dangerous else Severity.LOW,
            ("Capacidades Linux extras (privileged)",
             "O add-on recebe capacidades extras do kernel. "
             + (f"{', '.join(dangerous)} permitem escapar do container ou ler qualquer arquivo do host."
                if dangerous else "Nenhuma delas dá controle total do host isoladamente."),
             "Confira se cada capacidade é necessária para a função do add-on."),
            ("Extra Linux capabilities (privileged)",
             "The add-on receives extra kernel capabilities. "
             + (f"{', '.join(dangerous)} allow escaping the container or reading any host file."
                if dangerous else "None of them gives full control of the host on its own."),
             "Check that each capability is needed for what the add-on does."),
            "privileged: " + ", ".join(caps))

    apparmor = i.get("apparmor")
    if apparmor == "disable":
        add("apparmor-desativado", Severity.HIGH,
            ("AppArmor desativado",
             "Sem AppArmor o add-on não tem a camada extra que limita arquivos e capacidades acessíveis.",
             "Pergunte ao autor por que o AppArmor precisa ficar desligado."),
            ("AppArmor disabled",
             "Without AppArmor the add-on lacks the extra layer that limits accessible files and capabilities.",
             "Ask the author why AppArmor has to be turned off."),
            "apparmor: disable")
    elif apparmor == "default":
        add("apparmor-padrao", Severity.INFO,
            ("AppArmor com perfil genérico",
             "O add-on usa o perfil padrão do Docker, não um perfil próprio feito para ele.",
             "Nenhuma ação necessária; um perfil próprio seria mais restritivo."),
            ("AppArmor with a generic profile",
             "The add-on uses Docker's default profile, not a profile made for it.",
             "No action needed; a dedicated profile would be more restrictive."),
            "apparmor: default")

    role = str(i.get("hassio_role") or "default")
    if i.get("hassio_api") and role in _ROLE_SEVERITY:
        sev, why, why_en = _ROLE_SEVERITY[role]
        add(f"role-{role}", sev,
            (f"Acesso à API do Supervisor com papel '{role}'", why,
             "Confirme se o add-on precisa desse nível de acesso."),
            (f"Supervisor API access with role '{role}'", why_en,
             "Confirm the add-on needs this level of access."),
            f"hassio_role: {role}")

    devices = i.get("devices") or []
    hw = [k for k in ("usb", "uart", "gpio", "video", "audio", "udev", "devicetree") if i.get(k)]
    if devices or hw:
        add("hardware", Severity.INFO,
            ("Acesso a dispositivos",
             "O add-on acessa dispositivos do host. É o esperado em add-ons de rádio, câmera ou serial.",
             "Confira se os dispositivos combinam com a função do add-on."),
            ("Device access",
             "The add-on accesses host devices. This is expected in radio, camera or serial add-ons.",
             "Check that the devices match what the add-on does."),
            "; ".join(filter(None, [("devices: " + ", ".join(map(str, devices))) if devices else "",
                                    ("hardware: " + ", ".join(hw)) if hw else ""])))

    rating = i.get("rating")
    if isinstance(rating, int) and rating <= 3:
        add("nota-seguranca", Severity.MEDIUM if rating <= 2 else Severity.LOW,
            (f"Nota de segurança baixa ({rating}/6)",
             "O Supervisor calcula essa nota a partir das permissões pedidas; quanto menor, mais "
             "privilégios o add-on tem.",
             "Revise as permissões listadas para este add-on."),
            (f"Low security rating ({rating}/6)",
             "The Supervisor computes this rating from the requested permissions; the lower it is, the more "
             "privileges the add-on has.",
             "Review the permissions listed for this add-on."),
            f"rating: {rating}")

    if i.get("update_available") and addon.version_latest:
        add("atualizacao-pendente", Severity.LOW,
            ("Atualização pendente",
             f"Instalado: {addon.version}; disponível: {addon.version_latest}. Atualizações costumam "
             "trazer correções de segurança.",
             "Leia o changelog e atualize."),
            ("Update available",
             f"Installed: {addon.version}; available: {addon.version_latest}. Updates often bring security fixes.",
             "Read the changelog and update."),
            f"{addon.version} → {addon.version_latest}", category="atualizacao")

    if i.get("detached"):
        add("sem-repositorio", Severity.MEDIUM,
            ("Add-on órfão (removido do repositório)",
             "O add-on não existe mais no repositório de origem: não recebe atualizações nem correções.",
             "Procure uma alternativa mantida."),
            ("Orphaned add-on (removed from its repository)",
             "The add-on no longer exists in its source repository: it receives no updates or fixes.",
             "Look for a maintained alternative."),
            category="origem")

    if addon.repository == "local":
        add("local", Severity.INFO,
            ("Add-on local",
             "Construído a partir da pasta /addons do próprio host; não há origem externa para comparar.",
             "Nenhuma ação, se foi você quem o colocou lá."),
            ("Local add-on",
             "Built from the host's own /addons folder; there is no external source to compare with.",
             "No action, if you are the one who put it there."),
            category="origem")
    elif addon.repository != "core" and addon.repository_source:
        add("terceiro", Severity.INFO,
            ("Add-on de repositório de terceiros",
             f"Origem: {addon.repository_source}.",
             "Confira se o repositório é o oficial do projeto e tem manutenção ativa."),
            ("Add-on from a third-party repository",
             f"Source: {addon.repository_source}.",
             "Check that the repository is the project's official one and is actively maintained."),
            addon.repository_source, category="origem")
    return out
