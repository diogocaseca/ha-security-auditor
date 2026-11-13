# HA Security Auditor

*[Versão em português](README.pt-BR.md)*

Home Assistant OS add-on that audits the security of your installation: custom integrations (HACS),
frontend resources in `www/`, the other add-ons and, optionally, the domains queried by the host. It
produces a report with findings ranked by severity, explained in English or Portuguese (EN | PT
selector in the interface), for **human review**.

> The auditor points out what deserves attention. It **does not decide on its own that something
> is malicious**.

![Architectures](https://img.shields.io/badge/arch-amd64%20%7C%20aarch64-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## What it checks

| Area | How |
|---|---|
| **Integration and `www/` code** | Semgrep with 24 custom rules (obfuscation, `eval`/`exec`, system commands, download and execution, reading `secrets.yaml` and `.storage/auth`, token theft in the browser, suspicious destinations) + Bandit |
| **Dependencies** | pip-audit against the OSV database, without installing anything |
| **Integrity** | Compares each file with the official GitHub release (SHA-256); modified or extra file = High |
| **Add-on permissions** | `docker_api`, `full_access`, `host_network`, capabilities, AppArmor, Supervisor role, protection mode, security rating, updates |
| **Add-on images** | Trivy in remote mode (no Docker): CVEs and embedded secrets |
| **Add-on code** | Dockerfile and scripts from GitHub: `curl \| sh`, reverse shell, `SUPERVISOR_TOKEN` sent elsewhere, `map` with write access to `/config` |
| **Traffic** | CPU, memory and network history; alert on upload spikes compared with the add-on's own average |
| **Blocklist** | Badge and warning for reported components (personal list and the signed [community list](https://github.com/diogocaseca/ha-security-blocklist)), matching GitHub, image and version locally |
| **Installs and updates** | Every few minutes (configurable), notices a new or updated integration, card or add-on, scans only that component and warns in HA (notification and event) when there are serious findings or a blocklist match |
| **DNS (optional)** | AdGuard Home and/or Pi-hole v6 (both together, if you have them): exfiltration, mining, random, blocked and new domains; checked on its own every 2 hours (configurable), with a warning in HA when something new shows up |

The result shows in the sidebar (Ingress), can be exported as JSON, highlights what is new since the
previous scan and is published as sensors (`sensor.security_auditor_alertas_altos`,
`sensor.security_auditor_ultima_varredura`...). Reviewed false positives can be ignored right in the
report, without disappearing from it.

## Built not to become the biggest risk in the installation

- `/config` mounted **read-only**; **its own AppArmor profile**, with no kernel capabilities and no
  permission to execute anything from where the add-on writes.
- **No** `docker_api`, `full_access`, `host_network` or `privileged`.
- Supervisor API used **read-only**, enforced in the code (only `GET`, on a fixed list of paths).
- **No installation data goes to external services.** There are only downloads from GitHub and the
  image registries and queries to vulnerability databases, checked against a host allowlist on
  every request and redirect.
- Tokens, passwords and the contents of `secrets.yaml` **never** show up in the log or the report.
- **Does not overload HA**: low CPU and disk priority, light mode, waits for the system to be idle
  before the heavy steps and a fixed scan time, combinable in the options.

Details, the reason for each permission and limitations in
[`security_auditor/DOCS.md`](security_auditor/DOCS.md).

## Installation

[![Add repository to Home Assistant](https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg)](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2Fdiogocaseca%2Fha-security-auditor)

Or manually:

1. In **Settings → Add-ons → Add-on store → ⋮ → Repositories**, add
   `https://github.com/diogocaseca/ha-security-auditor`.
2. Install **HA Security Auditor**, start it and turn on **Show in sidebar**.
3. The first scan starts on its own; afterwards use **Scan now** whenever you want.

## Important limitations

- Static analysis **does not see code downloaded at runtime**; it detects the pattern (download +
  execution), not the content.
- Integrity only proves equality with the release; a compromised official release passes.
- Without per-version tags, the analysed add-on code is `HEAD`.
- DNS for every add-on goes through HA: **it is not possible to tell which add-on made each
  query**.

Full list in [DOCS.md → Limitations](security_auditor/DOCS.md#limitations).

## Repository layout

```
repository.yaml                 custom add-on repository
art/                            SVG sources of the icon and logo
security_auditor/
  config.yaml build.yaml        add-on manifest and build (amd64, aarch64)
  Dockerfile apparmor.txt       image and AppArmor profile
  icon.png logo.png             icon and logo shown in HA
  rootfs/run.sh                 entry point
  DOCS.md DOCS.pt-BR.md         documentation (English, shown in HA, and Portuguese)
  CHANGELOG.md                  version history (in Portuguese)
  translations/                 option labels (pt-BR, en)
  app/auditor/                  Python code (comments and logs in Portuguese)
    i18n.py                     interface languages (English and Portuguese)
    scanners/                   static, deps, integrity, addon_*, traffic, dns, blocklist
    web/ report/                Ingress interface and report
  app/rules/semgrep/            custom rules (python, javascript, addon), texts in both languages
tests/                          pytest + fixtures (clean, obfuscated and tampered integrations)
```

## Development

Requires Python 3.12 and, for the static analysis tests, Semgrep and Bandit in the environment.

```bash
uv venv -p 3.12 .venv && uv pip install -p .venv/bin/python -r requirements-dev.txt
```
```bash
.venv/bin/python -m pytest
```
```bash
docker build -t local/security_auditor:dev security_auditor
```

To run outside HA (no Supervisor, integrations only), point `/config` to a folder and allow local
access:

```bash
docker run --rm --init --network host -e AUDITOR_DEV_ALLOW_LOCAL=1 -v "$PWD/tests/fixtures/config:/config:ro" local/security_auditor:dev
```

and open `http://127.0.0.1:8099/`. The tests include a check of the AppArmor profile against the
real paths of the image's executables. New interface texts must be added to `i18n.py` (a test
fails otherwise), and every finding must carry its English text (`en=`).

## License

[MIT](LICENSE).
