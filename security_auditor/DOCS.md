# HA Security Auditor

*[Versão em português](DOCS.pt-BR.md)*

HA Security Auditor examines your Home Assistant installation for signs of risk: suspicious code
in custom integrations and in the frontend (`www/`), tampered files, vulnerable dependencies,
add-ons with broad permissions, images with CVEs, abnormal traffic spikes and suspicious domains.

> **The auditor points out what deserves human review. It does not decide on its own that
> something is malicious.** A finding is an invitation to look at the code or the configuration,
> not a verdict. Many findings have legitimate explanations (a hardware add-on *needs* device
> access). Each finding explains why it caught attention and what to do.

## Contents

- [Installation](#installation)
- [First use](#first-use)
- [What is checked](#what-is-checked)
- [Options](#options)
- [Overload protection](#overload-protection)
- [Installs and updates](#installs-and-updates)
- [Ignore list and allowlist](#ignore-list-and-allowlist)
- [Blocklist](#blocklist)
- [Sensors](#sensors)
- [Severities and risk score](#severities-and-risk-score)
- [Requested permissions and why](#requested-permissions-and-why)
- [Where the auditor connects to](#where-the-auditor-connects-to)
- [Secrets](#secrets)
- [Limitations](#limitations)
- [Stored data](#stored-data)
- [Troubleshooting](#troubleshooting)

## Installation

1. In **Settings → Add-ons → Add-on store**, open the **⋮ → Repositories** menu.
2. Add `https://github.com/diogocaseca/ha-security-auditor` and close.
3. Find **HA Security Auditor** in the store, install it and click **Start**.
4. Turn on **Show in sidebar** to get the **Security Auditor** shortcut in the menu.
5. (Recommended) Turn on **Watchdog**. The Supervisor restarts the add-on if it crashes or if the
   health check (`/api/status`) stops answering. Long scans do not trigger the watchdog: the heavy
   work runs outside the web server.

Supported architectures: `amd64` and `aarch64` (Raspberry Pi 4/5 with a 64-bit system).

## First use

With the `scan_on_start` option on (default), the first scan starts as soon as the add-on starts.
You can also click **Scan now** at the top of the page. While a scan runs, a **Cancel scan** button
appears: running tools are stopped and what was already analysed is saved in the history as
"Cancelled" (a cancelled scan does not become the comparison baseline).

- The **first scan takes longer**: Trivy downloads its vulnerability database (a few hundred MB,
  kept in `/data`) and the integrations' code is downloaded from GitHub for comparison. Later scans
  reuse the cache.
- The first scan is the **baseline**: nothing shows as "new". From the second one on, the report
  highlights what appeared and what was resolved.
- By default the auditor runs with **low priority** and **waits for the system to be idle** before
  the heavy steps; on a Raspberry Pi, consider adding `modo_leve` and `horario_fixo` (see
  [Overload protection](#overload-protection)).
- **Traffic spike** detection only starts after about 1 hour of collection (12 samples with the
  default 5-minute interval).

The page has the tabs **Components**, **DNS** (when AdGuard Home or Pi-hole is configured),
**Scan history** and **Blocklist**. In the report you find:

- cards with the total per severity: click one or more to filter the components table (only
  components with findings at the chosen levels remain); click again to clear;
- the components table with the risk score and details (version, source, integrity, analysed
  code, traffic, CVEs). **Hide components without findings** is ticked by default; untick it to see
  clean components too. The **Type** selector shows only integrations, frontend, add-ons, etc., and
  **Blocklist only** (shown when some component is flagged) shows only blocklisted components.
  The **newest components come first**: the table is ordered by discovery date (the first scan in
  which the auditor saw the component, shown as "discovered"), with the risk score as tie-breaker;
- a component's findings: **click its name in the table** to open a page with only its findings,
  with level filters. Use **← Back** (or the browser's back); the levels that were ticked stay
  ticked;
- each finding with component, type, discovery date (findings are ordered newest first too),
  file and line, code snippet (with secrets masked), why it is
  suspicious and what to do;
- filters by text, "New only" and "Show suppressed";
- the **Ignore…** button on each finding and the **Ignored** card, which shows how many findings are
  ignored and opens the [ignore list](#ignore-list-and-allowlist) in its own view;
- the **Scan history** tab, with status, duration and totals of each scan, 10 per page (click the
  date to open that report). The last `report_retention` scans are kept (default 10, up to 100);
- the **Export JSON** button;
- the **System / Light / Dark** theme selector;
- the **EN | PT** language selector (English is the default). The choice is stored in the add-on
  and applies to any browser, including the HA mobile app. Findings also show in the chosen
  language (reports created before version 0.14.0 stay in Portuguese until the next scan).

## What is checked

### Custom integrations and frontend (`/config/custom_components` and `/config/www`)

**Static analysis** with [Semgrep](https://semgrep.dev) (custom rules) and
[Bandit](https://bandit.readthedocs.io). The auditor builds the file list and passes it
explicitly, so `*.min.js` files and `tests/` folders (which Semgrep skips by default) are analysed
too. When Bandit and Semgrep flag the same line, only one finding is kept.

| Rule | What it looks for | Severity |
|---|---|---|
| `auditor.py.ofuscacao-decodifica-e-executa` | base64/zlib/marshal/hex decoded and executed | Critical |
| `auditor.py.download-e-execucao` | content downloaded from the network reaching `exec`/`eval`/subprocess | Critical |
| `auditor.py.shell-reverso` | socket redirected to a shell | Critical |
| `auditor.py.acesso-storage-auth` | reading `.storage/auth*` (users and tokens) | Critical |
| `auditor.py.eval-dinamico` | `eval`/`exec`/`compile` with dynamic data | High |
| `auditor.py.marshal-loads` | bytecode loading | High |
| `auditor.py.builtins-indireto` | `getattr(__builtins__, ...)` and similar | High |
| `auditor.py.shell-true` | command run through a shell | High |
| `auditor.py.instalacao-de-pacote-em-tempo-de-execucao` | `pip install` done by the integration itself | High |
| `auditor.py.destino-suspeito` | webhooks, pastebins, tunnels, `raw.githubusercontent.com` | High |
| `auditor.py.acesso-secrets-yaml` | direct read of `secrets.yaml` | High |
| `auditor.py.acesso-storage` | reading other `.storage` files | High |
| `auditor.py.execucao-de-comandos` | `subprocess`, `os.system`, `os.exec*` | Medium |
| `auditor.py.carregamento-dinamico-de-modulo` | modules loaded from arbitrary paths | Medium |
| `auditor.py.ip-fixo-publico` | hard-coded public IP in the code | Medium |
| `auditor.py.tokens-de-acesso` | creation of HA users/tokens | Medium |
| `auditor.py.blob-codificado` | long base64/hex string | Medium |
| `auditor.py.url-fixa` | hard-coded URLs (for review) | Info |
| `auditor.js.ofuscacao-decodifica-e-executa` | `eval(atob(...))` and similar | Critical |
| `auditor.js.acesso-token-ha` | reading the access token (`hassTokens`) in the browser | High |
| `auditor.js.destino-suspeito` | exfiltration services in scripts | High |
| `auditor.js.eval-dinamico` | `eval`/`new Function` with dynamic data | Medium |
| `auditor.js.codigo-remoto` | script loaded from an external address | Medium |
| `auditor.js.ip-fixo-publico` | connection to a hard-coded public IP | Medium |
| `bandit.*` | other Bandit warnings (pickle, disabled TLS, weak hash...) | as reported by Bandit |

**Dependencies.** The `requirements` in `manifest.json` are audited with
[pip-audit](https://pypi.org/project/pip-audit/) against the [OSV](https://osv.dev) database. It
runs in `--no-deps --disable-pip` mode: it only queries the database and never installs or resolves
packages, because resolving could run third-party `setup.py` files. That is why only requirements
with an exact version (`==`) can be audited; the others show up as informational. Dependencies
installed from a URL or git repository show up as Medium.

**Integrity.** For each integration with an identifiable repository (through HACS, in
`.storage/hacs.repositories`, or through the URLs in `manifest.json`), the auditor downloads the
installed version from GitHub and compares it file by file with SHA-256:

- it tries the tag with and without the `v` prefix and the commit recorded by HACS;
- it honours `zip_release`, `content_in_root` and `persistent_directory` from `hacs.json`;
- **modified file** or **extra file** = High, with the diff (or the start of the file) in the
  report; missing file = Low;
- no identifiable repository (manual install) = Low; version not found in the repository = Info.

### Other add-ons (through the Supervisor API)

The Security Auditor itself is left out (permissions, code, image and traffic): it identifies itself
through `/addons/self/info`. Its permissions are explained in
[Requested permissions and why](#requested-permissions-and-why).

**Permissions and state**, read from `/addons/<slug>/info`:

| Situation | Severity |
|---|---|
| `docker_api` | Critical |
| `full_access`, `host_pid`, kernel modules, capabilities such as `SYS_ADMIN`/`SYS_MODULE`/`SYS_PTRACE`, AppArmor disabled, protection mode off, `admin` role in the Supervisor | High |
| `host_network`, host D-Bus, Home Assistant API, `manager` role, security rating ≤ 2 | Medium |
| `auth_api`, `backup`/`homeassistant` roles, other capabilities, rating 3, pending update | Low |
| Device access, generic AppArmor profile, local or third-party add-on | Info |

**Source code.** The auditor looks for the add-on's code on GitHub (the repository in the `url`
field and the store repository), trying the tag of the installed version and, as a last resort,
`HEAD`. If the analysed code is from another version, the report says so. It evaluates the `map` in
`config.yaml` (`/config` with write access = High, because it allows installing an integration and
running code inside HA Core) and applies the rules below to the Dockerfile and scripts, in addition
to the Python/JS rules:

| Rule | What it looks for | Severity |
|---|---|---|
| `auditor.sh.decodifica-e-executa` | base64 command decoded and executed | Critical |
| `auditor.sh.shell-reverso` | `/dev/tcp`, `nc -e`, `socat exec:` | Critical |
| `auditor.sh.baixa-e-executa` | `curl ... \| sh` | High |
| `auditor.sh.token-supervisor-externo` | `SUPERVISOR_TOKEN` sent to a host other than the Supervisor | High |
| `auditor.sh.acesso-sensivel` | reading `secrets.yaml` or `.storage/auth` | High |
| `auditor.sh.destino-suspeito` | exfiltration services | High |
| `auditor.sh.tls-desativado` | `curl -k`, `wget --no-check-certificate` | Medium |
| `auditor.docker.add-de-url` | `ADD https://...` without hash verification | Low |
| `auditor.sh.permissao-777` | `chmod 777` | Low |

**Images.** [Trivy](https://trivy.dev) scans each add-on's image **directly in the registry**
(ghcr.io, Docker Hub...), without a Docker daemon, looking for CVEs and embedded secrets. CVEs
become one finding per add-on: High if there is a critical CVE with a fix available, Medium if
there is a high CVE with a fix, Low if the critical/high ones have no fix yet. Embedded secrets
become separate High findings. Locally built add-ons have no image in a registry.

**Traffic.** A background collector records CPU, memory and network (rx/tx) of each add-on every
`stats_interval_minutes`. An **upload spike** is recorded when the rate exceeds, at the same time:
the add-on's own average + 4 standard deviations over the last 7 days, 3× the average and 50 KiB/s.
Spikes show up once, on the next scan (Medium; High if ≥ 20× the average and ≥ 1 MiB/s).

### DNS (optional, AdGuard Home and/or Pi-hole v6)

With `adguard_url` and/or `pihole_url` set, the auditor reads from your DNS servers the queries made
by the HA host in the last 24 hours and shows everything in the **DNS** tab: the servers' status,
the DNS findings (**View findings** button) and the table of queried domains. DNS does not show up
in the components table.

**With both configured** (for example, one as primary DNS and the other as secondary), the queries
from both are added up and analysed together, and the table gets a **Server** column (AdGuard
Home, Pi-hole or both). If one of them is down or rejects the password, the other is still used and
the report says which one was left out. If HA sends the same query to both, it is counted twice; if
one forwards to the other (AdGuard → Pi-hole), the second only sees the first as the client and
those queries are not counted again.

> **It is not possible to tell which add-on or integration made each query.** DNS for every add-on
> and integration goes through the Supervisor DNS, which forwards to your server; for
> AdGuard/Pi-hole, everything comes from the same client. The report repeats this notice on every
> finding.

| Situation | Severity |
|---|---|
| Exfiltration services, tunnels and pastebins (`webhook.site`, `ngrok`, `pastebin`...) | High |
| Cryptocurrency mining pools | High |
| Random-looking domains (except known CDNs and Nabu Casa) | Low |
| Domains blocked by your filter | Low |
| New domains since the previous scan | Info |

With **Ignore all…** (next to the table title) every domain in the table that is not ignored yet
goes to the list at once, with a single reason. Check the list first: ignored domains no longer
create findings, including mining and exfiltration ones.

The domain table shows the **most recently discovered domains first** (date of the first query the
auditor saw), with the most queried as tie-breaker, up to 150 domains.

**Ignored domains.** Domains you recognise (a CDN, your cloud provider) can be ignored: click
**Ignore…** on the domain's row, or **Ignore domain…** at the top of the table, and write the
reason. Use `*.example.com` to cover `example.com` and all its subdomains (`*` and `?` are
wildcards; wildcards alone are not accepted). Ignored domains are left out of the DNS findings
(random, blocked, new and suspicious) **from the next scan on** and no longer show in the queried
domains table. Tick **Show ignored domains** to swap that table for the list of ignored domains,
where the reason can be edited and items removed; untick it to go back. The list is stored in the
add-on. It is separate from the [ignore list](#ignore-list-and-allowlist), because one DNS finding
groups many domains.

On start, the add-on **tests the connection** to each configured server (login and version read)
and shows the result in the **DNS** tab and in the log:

```
INFO  DNS AdGuard Home (192.168.1.2:3000): conexão OK, versão v0.107.57 (35 ms)
WARNING DNS Pi-hole (192.168.1.3): falha na conexão: o Pi-hole recusou a senha (...) (120 ms)
```

Use **Test connection** in the **DNS** tab to run the test again after fixing something (a new
configuration only applies after restarting the add-on). The add-on log is in Portuguese.

Pi-hole v5 is not supported (old API).

## Options

The option names are in Portuguese; the Configuration tab in Home Assistant shows them in your
language.

| Option | Default | Description |
|---|---|---|
| `scan_interval_hours` | `24` | Interval between scheduled scans. `0` turns scheduling off (button only). |
| `scan_on_start` | `true` | Scan as soon as the add-on starts. |
| `modo_execucao` | `prioridade_baixa`, `aguardar_folga` | Overload protections, combinable. See [Overload protection](#overload-protection). |
| `horario_varredura` | `03:30` | Daily time (HH:MM, HA time zone) used with the `horario_fixo` mode. |
| `memoria_minima_mb` | `500` | Minimum free memory for the `aguardar_folga` mode. The image scan needs the full value; the other heavy steps, half of it. |
| `carga_maxima_por_cpu` | `1.5` | 1-minute load average per core above which the `aguardar_folga` mode waits. |
| `log_level` | `info` | `debug`, `info`, `warning` or `error`. |
| `github_token` | empty | GitHub token **with no scopes at all**, only to raise the API limit from 60 to 5000 requests/hour. Recommended with many integrations that use `zip_release`. Never logged. |
| `report_retention` | `10` | How many reports to keep. |
| `addons_scan` | `true` | Audit the other add-ons (permissions, code, images, traffic). |
| `image_scan` | `true` | Scan the images with Trivy. It is the slowest step; it uses bandwidth and space in `/data`. |
| `image_scan_skip` | `[]` | Slugs of add-ons whose images must not be scanned (e.g. `core_mosquitto`). |
| `stats_interval_minutes` | `5` | CPU/memory/network collection interval. `0` turns it off. |
| `adguard_url` | empty | AdGuard Home address. E.g. `http://192.168.1.2:3000` or `http://a0d7b954-adguard:3000` (AdGuard as an add-on). |
| `adguard_username` / `adguard_password` | empty | AdGuard Home login. The password is never logged. |
| `pihole_url` | empty | Pi-hole v6 address. E.g. `http://pi.hole` or `http://192.168.1.3`. |
| `pihole_password` | empty | Pi-hole v6 **app password**. Never logged. |
| `dns_client_ips` | `[]` | IPs HA shows up with on the DNS server. Empty = host IPs (through the Supervisor) + `172.30.32.3` (Supervisor DNS). |
| `lista_comunitaria` | `true` | Download and use the signed [community blocklist](#blocklist). |
| `verificar_instalacoes` | `true` | Check installs and updates right away. See [Installs and updates](#installs-and-updates). |
| `intervalo_verificacao_minutos` | `2` | How often (1 to 60 minutes) the auditor looks at what is installed. It is a light check; it only scans when something changed. |
| `aviso_nivel_minimo` | `alta` | Minimum level that creates a notification after an install or update: `critica`, `alta`, `media`, `baixa` or `desligado` (no notification). |
| `dns_verify_tls` | `true` | Turn off only if AdGuard or Pi-hole uses HTTPS with a self-signed certificate (applies to both). |
| `allowlist` | `[]` | Exceptions; see below. |

## Overload protection

HA OS does not allow limiting an add-on's CPU or memory, so the auditor restrains itself. In
**`modo_execucao`** you add as many modes as you want; they combine. Empty list = no protection (the
scan is faster, but may weigh on HA).

| Mode | What it does | Cost |
|---|---|---|
| `prioridade_baixa` | The auditor and everything it starts (Semgrep, Bandit, pip-audit, Trivy) run with minimum CPU priority (`nice 19`) and disk priority ("idle" class: it only uses the disk when nothing else does). | Nothing noticeable. |
| `modo_leve` | Semgrep with 1 process and a 768 MB memory cap; Trivy with parallelism 1; a 2 s pause between components. | Much slower scan. Recommended on a Raspberry Pi and machines with little memory. |
| `aguardar_folga` | Before each heavy step (static analysis, add-on code, each image), it checks the **host's** load and free memory. If it exceeds `carga_maxima_por_cpu` or falls below `memoria_minima_mb`, it waits (up to 10 min, checking every 30 s). If it does not calm down, it **postpones** the step and records the informational finding "Step postponed"; it runs on the next scan. | The scan may be incomplete at peak times. |
| `horario_fixo` | The scheduled scan runs **once a day** at `horario_varredura`, in the HA time zone, instead of every `scan_interval_hours` counted from the add-on start. The "Scan now" button still works at any time. | None. |

Useful combinations:

- **Default** (`prioridade_baixa` + `aguardar_folga`): good for most installations.
- **Raspberry Pi**: all four modes, with `horario_varredura` at a quiet hour (night).
- **A roomy machine you want to scan quickly**: only `prioridade_baixa`.

The top of the report shows which protections are active and, with `horario_fixo`, the time of the
next scan.

Limitations:

- Docker puts each container in its own CPU group. Low priority applies inside the container and
  on the disk, but **does not guarantee on its own** that HA Core keeps the CPU when both compete;
  that is why the other modes exist.
- With `scan_on_start` on, the start-up scan ignores `horario_fixo`. Turn `scan_on_start` off so
  that automatic scans only run at the chosen time.
- The host load includes what the auditor itself just did; with the default limit (1.5 per core),
  the auditor's steps alone do not usually trigger the wait.

## Installs and updates

With `verificar_instalacoes` on (default), every `intervalo_verificacao_minutos` (default 2) the
auditor takes a light snapshot of what is installed: the name, size and date of each file in
`custom_components/<name>` and `www/community/<name>` (without reading their contents) and the
version of each add-on (`GET /addons`). When something is **installed, updated or removed**, it
waits until the snapshot stops changing (HACS writes the files little by little, so the scan starts
on the following check) and runs a **scan of only that component**, which takes seconds. The rest of
the report comes from the latest full scan. The scan shows up in the history as "Install/update:
name (new)".

Then it **warns you in HA**:

- a **notification** (the bell) when the component has findings from `aviso_nivel_minimo` up
  (default: high and critical) or matches the blocklist, with the main findings and a link to the
  report. Each component has its own notification, replaced on the next update;
- the **`security_auditor_alerta` event**, always, for every component checked, so you can build
  your own automations (for example, a push notification to your phone):

```yaml
automation:
  - alias: Warn about suspicious installs
    triggers:
      - trigger: event
        event_type: security_auditor_alerta
        event_data:
          alerta: true
    actions:
      - action: notify.mobile_app_my_phone
        data:
          title: Security Auditor
          message: >-
            {{ trigger.event.data.componente }} {{ trigger.event.data.versao or '' }}
            ({{ trigger.event.data.mudanca }}): {{ trigger.event.data.achados.critical }} critical,
            {{ trigger.event.data.achados.high }} high
            {{- ', on the blocklist' if trigger.event.data.lista_negra else '' }}.
```

Event data: `tipo` (`integracao`, `frontend`, `addon`), `componente`, `mudanca` (`novo` or
`atualizado`), `versao`, `achados` (count per level: `critical`, `high`, `medium`, `low`, `info`),
`lista_negra`, `alerta` (whether it reached the notification level) and `scan_id`.

What to know:

- The auditor **warns, it does not block**: when it scans, the files are already on disk. If HA is
  restarted in that interval, the integration's code runs before the check. Blocking would require
  writing to `/config` or intercepting HACS, against the principle that the auditor must never
  become the biggest risk in the installation.
- Only the steps that look at the component itself run (blocklist, static analysis, dependencies,
  integrity, add-on permissions, code and image). DNS and traffic spikes stay for the full scan.
- Files in `www/` outside `community/` are not watched (they change often, e.g. camera snapshots);
  the full scan still checks them.
- Components fully ignored in the [ignore list](#ignore-list-and-allowlist) are not scanned or
  notified.
- If a scan is already running, the check waits for it to finish. Without a previous full report,
  the first check becomes a full scan.

## Ignore list and allowlist

Use them to silence false positives you have already reviewed. The list opens in its own view when
you click the **Ignored** card, next to the level cards. **Ignored findings stay in the report**
(tick "Show suppressed"); they just stop counting in the totals, sensors and risk score. That way
nothing disappears silently. There are two ways to ignore, and both apply together:

**Through the interface (ignore list).** On each finding of the latest report, click **Ignore…**,
choose the scope and write the reason:

| Scope | What stops counting |
|---|---|
| Only this finding | Only that finding (identified by its fingerprint: component, rule, file and snippet). If the code changes, it shows up again. |
| This rule in this file | Every finding of the rule in that file. |
| This rule in the whole component | Every finding of the rule in the component. |
| This rule in every component | The whole rule, in any component. |

You can also ignore from the **components table**:

- **Ignore…** on a component's row ignores its findings for every rule. If levels are ticked on the
  cards (for example Low and Info), they come pre-selected and only those levels are ignored; the
  others keep counting. **All levels** ticks them all at once (the same as ticking none).
- With one or more levels ticked on the cards, **Ignore these levels…** appears; it ignores the
  chosen levels **in every component** (for example, the whole Info level). It asks for
  confirmation. Ignoring every level at once is not accepted.

Items restricted to levels show the levels in the list's **Scope** column.

**Fully ignoring skips the scan.** When an item covers a whole component (component name or a
wildcard such as `my_*`, rule `*`, every level, no file or specific finding), the component **is no
longer scanned**: no tool runs on it, it shows in the table as "not scanned" and the list marks the
item with "not scanned". Use it for your own apps and the ones you consider trustworthy; it is at
your own risk. To scan it again, remove the item from the list. A wildcard alone (`*`) never skips
anything.

In the other cases (only some levels, only one rule, a file or a finding) **the component is still
analysed** on every scan; the auditor only stops counting what was ignored. If a finding ignored
with "Only this finding" changes (the code snippet is edited, for example), it becomes another
finding and counts again.

The reason of each interface item can be changed with **Edit** in the list.

You can also add items manually with **Ignore list → Add to the list…** (component, rule, file and
levels, with wildcards) and remove them with **Remove** or with **Stop ignoring** on the finding.
The change applies **immediately** to the latest report and to the sensors, without a new scan, and
also to the next scans. Old reports in the history are not changed. The list is stored in
`/data/auditor.db` and is included in the add-on backup. For safety, component `*` with rule `*`
without a file is not accepted (it would ignore everything).

**Through the configuration (allowlist).** The `allowlist` option still works and shows up in the
ignore list with the source "Configuration"; those entries can only be removed in the add-on's
**Configuration** tab. Each entry has:

- `component`: integration name, add-on slug, `dns` or `*` (any);
- `rule`: rule id (shown in the report), accepts wildcards such as `bandit.*` or `*`;
- `path` (optional): file wildcard, as shown in the report;
- `reason`: why it is acceptable (shown in the report).

Example (YAML mode of the options):

```yaml
allowlist:
  - component: custom_ping
    rule: auditor.py.execucao-de-comandos
    reason: Calls the system ping, reviewed on 2026-11-12
  - component: my_integration
    rule: auditor.integridade.arquivo-extra
    path: custom_components/my_integration/cache/*
    reason: The integration writes a cache into its own folder
  - component: "*"
    rule: auditor.py.url-fixa
    reason: I do not want to see hard-coded URLs
```

## Blocklist

Components **reported** as malicious, compromised, vulnerable, abandoned or with undisclosed
telemetry get the **Blocklist** badge in the components table and a finding with the reason, the
affected versions and the evidence links. It is a report, not a verdict: check the evidence before
deciding. Everything lives in the **Blocklist** tab.

### Personal list

To flag whatever you want yourself, with no signature or evidence:

1. Open the **Blocklist → Add item…** tab, or, on a component's page, click **Add to blocklist…**
   (pre-filled with the type, GitHub, name and, for add-ons, the image).
2. Choose the level and the category, write the reason and save.
3. Click **Scan now**: badges are computed during the scan.

In the same tab you can **Edit** and **Remove** items. They are stored in the add-on database
(`/data`, included in its backup); there is no need to create folders or files in `/config`.

Form fields:

| Field | What for |
|---|---|
| Type | Integration, Frontend, Add-on or any |
| GitHub repository | `owner/repo`; strong match (prefer this) |
| Name | Integration domain, card folder or add-on slug; accepts `*`. On its own it gives a "possible match" |
| Add-on image | E.g. `ghcr.io/owner/{arch}-addon-x` (`{arch}` matches any architecture); strong match |
| Affected versions | Range in pip format, e.g. `<1.4.2` or `>=1.0,<1.2`; empty = all |
| Level | Critical, High, Medium or Notice |
| Category | Malicious, Compromised, Vulnerable, Abandoned, Telemetry, Removed from store, Incompatible |
| Reason and evidence | What happens and, optionally, `https://` links (one per line) |

You must provide the GitHub repository, the name or the image. To find a component's GitHub
repository or name, look at its row in the components table (`repositorio: owner/repo`).

### Community list

Maintained at [diogocaseca/ha-security-blocklist](https://github.com/diogocaseca/ha-security-blocklist).
Besides community reports, it includes the **HACS removed list** (repositories taken out of the
default list: critical, blacklist, removed, abandoned) and the **Home Assistant blocked list**
(integration versions HA itself refuses to load). The finding shows the source of each item. It is
downloaded on every scan (at most every 6 hours) and added to the personal list; the
`lista_comunitaria` option (on by default) turns it off. The **Blocklist** tab shows how many items
it has, the list date, the last fetch and the signing key.

It is only used if it is **signed** by the maintainer (Ed25519; the public key is embedded in the
add-on). A list with an invalid signature, an unknown key, a wrong format or older than the local
copy is rejected, and the auditor keeps the previous copy. The whole file is downloaded, without
sending anything about the installation. In the log (in Portuguese):

```
INFO  Lista negra comunitária atualizada: 560 item(ns), lista de 2026-11-13, assinatura OK (chave 539f9e99d82adfd9)
WARNING Lista negra comunitária: lista recusada: assinatura inválida (...); mantendo a cópia anterior
```

If the list could never be downloaded, the report shows "Community blocklist unavailable"
(informational); if the local copy gets older than 7 days because updates are failing, "Community
blocklist out of date".

**To suggest an item for everyone**, open a *Relatar um componente* issue or a Pull Request in the
[list repository](https://github.com/diogocaseca/ha-security-blocklist#how-to-add-an-item),
which has the full step by step.

### How matching works

| Match | Badge | Severity |
|---|---|---|
| Same GitHub repository (HACS, manifest or add-on store) or same image | **Blocklist** (red) | the item's |
| Domain of an integration blocked by Home Assistant | **Blocklist** (red) | the item's |
| Name only | **Blocklist?** (yellow), "possible match" | one level lower |
| Same name, but the component has another repository | none (it is another project) | — |
| Installed version outside the version range | none (already fixed) | — |

To see only flagged components, use **Blocklist only** in the components table header (shown when
there is at least one).

Items with errors are ignored and produce the "Blocklist with errors" finding, saying which item and
why; the rest of the list still applies. The list only **adds** warnings: it never allows or hides
anything, and the comparison is entirely local.

## Sensors

After each scan (and every 15 minutes, because states created through the API do not survive a
Core restart), the add-on publishes:

| Entity | Content |
|---|---|
| `sensor.security_auditor_alertas_criticos` | non-suppressed critical findings |
| `sensor.security_auditor_alertas_altos` | high findings |
| `sensor.security_auditor_alertas_medios` | medium findings |
| `sensor.security_auditor_alertas_baixos` | low findings |
| `sensor.security_auditor_novos_achados` | new findings since the previous scan |
| `sensor.security_auditor_ultima_varredura` | date/time of the last scan (`timestamp`) |
| `sensor.security_auditor_status` | `ocioso`, `varrendo`, `concluida`, `cancelada` or `falhou` |

The sensor names shown in HA follow the language chosen in the interface; the entity ids, the state
values and the unit (`achados`) do not change, so automations and statistics keep working.

Automation example:

```yaml
automation:
  - alias: Notify about new security findings
    triggers:
      - trigger: numeric_state
        entity_id: sensor.security_auditor_novos_achados
        above: 0
    actions:
      - action: notify.notify
        data:
          title: Security Auditor
          message: >-
            {{ states('sensor.security_auditor_novos_achados') }} new finding(s).
            High: {{ states('sensor.security_auditor_alertas_altos') }},
            critical: {{ states('sensor.security_auditor_alertas_criticos') }}.
```

## Severities and risk score

| Severity | Meaning |
|---|---|
| **Critical** | Typical malicious code pattern (obfuscation + execution, credential theft, reverse shell) or a permission that gives full control of the host. Review now. |
| **High** | Very unusual in legitimate components, or a file different from the official release. |
| **Medium** | May be legitimate, but greatly widens the damage if the component is compromised. |
| **Low** | Worth knowing; rarely requires action. |
| **Info** | Context (URLs used, steps that could not run). |

Each component's **risk score** (0 to 100) adds 40 per critical, 15 per high, 5 per medium and 1
per low, not counting suppressed ones. It only orders what to review first; **it is not a
probability that the component is malicious**.

## Requested permissions and why

The auditor was designed not to become the biggest risk in your installation. It asks only for what
it needs:

| Permission | Why |
|---|---|
| `map: homeassistant_config` **read-only** at `/config` | Read integrations, `www/`, `.storage/hacs.repositories` and `secrets.yaml` (the latter only to mask its values; see [Secrets](#secrets)). Writing to `/config` is not possible. |
| `hassio_api: true` with `hassio_role: manager` | List add-ons and read permissions, statistics, store repositories and host IPs. The `default` role only allows endpoints ending in `/info`; listing add-ons (`/addons`), reading store repositories and **other** add-ons' statistics (`/stats`) requires `manager`. **That role would allow changes**, so the read-only guarantee is in the code: the Supervisor client only does `GET`, and only on a fixed list of paths (`/addons`, `/addons/<slug>/info`, `/addons/<slug>/stats`, `/store`, `/store/repositories`, `/info`, `/core/info`, `/supervisor/info`, `/network/info`). Any other path is refused before leaving the add-on. |
| `homeassistant_api: true` | Publish the sensors and warn about installs. The client only accepts writing `sensor.security_auditor_*` entities, creating notifications whose id starts with `security_auditor_` and firing the `security_auditor_alerta` event; it does not read or control other entities. |
| `ingress: true` | Show the report in the sidebar, with HA's own login. The web server only accepts connections from Ingress (`172.30.32.2`), uses a strict CSP and an anti-CSRF token on every action. No port is opened on the network. |
| `apparmor: true` with its own profile | See below. |
| `init: true` | Docker's tini as the init process, to forward signals and reap the tools' processes. |
| `watchdog` | Health address (`/api/status`) the Supervisor queries when the Watchdog switch is on. It only returns the scheduler state, no installation data. |

What the auditor does **not** ask for: `docker_api`, `full_access`, `host_network`, `privileged`,
`host_pid`, device access or the `admin` role.

**AppArmor profile** (`apparmor.txt`):

- no kernel capabilities: the container's root has no `dac_override`, `sys_admin`, `net_admin`,
  etc.;
- writing only to `/data`, `/tmp` and `/dev/shm`; `/config` read-only (explicit deny);
- **nothing can be executed** from `/data`, `/tmp`, `/dev/shm` or `/config`: downloaded or analysed
  code never runs;
- execution only from the system folders (read-only in the container), always inheriting the same
  profile.

External tools (Semgrep, Bandit, pip-audit, Trivy) run with a minimal environment: the
`SUPERVISOR_TOKEN` and the add-on options are **not** passed to them, `HOME` is an isolated
temporary folder, and each tool's telemetry and version check are turned off.

## Where the auditor connects to

The auditor **never sends data from your installation to external services**. The only outbound
connections are downloads and queries to vulnerability databases:

| Destination | What for | Who connects |
|---|---|---|
| `api.github.com`, `github.com`, `codeload.github.com`, `objects.githubusercontent.com`, `release-assets.githubusercontent.com`, `raw.githubusercontent.com` | Download the integrations' and add-ons' code for comparison and analysis | Auditor (Python) |
| `raw.githubusercontent.com` (`diogocaseca/ha-security-blocklist`) | Download the community blocklist and its signature (whole file; nothing is sent) | Auditor (Python) |
| `api.osv.dev` | Query vulnerabilities of the requirements (sends only package name and version) | pip-audit |
| Image registries (`ghcr.io`, Docker Hub and whichever registry each add-on uses) | Download image manifests and layers | Trivy |
| `mirror.gcr.io`, `ghcr.io` | Download Trivy's vulnerability database | Trivy |
| The `adguard_url` and `pihole_url` hosts | Read your DNS servers' query log (optional) | Auditor (Python) |

In the Python code, every connection goes through a single client that requires HTTPS and checks
the host of every request **and every redirect** against the list above. The GitHub token is only
sent to GitHub's own hosts, never to the CDNs the API redirects to. For DNS, each server has its own
client, which only talks to the host of its own URL (the AdGuard password never goes to Pi-hole and
vice versa). It is the only place where HTTP without TLS is accepted, since it is common on a local
network.

AppArmor cannot filter the network by domain, so the filter lives in the code. Trivy's and
pip-audit's connections are limited to what those tools do (registries, vulnerability databases)
and to the flags the auditor calls them with.

## Secrets

Tokens, passwords and the contents of `secrets.yaml` **never** go to the log or the report:

- the values in `secrets.yaml`, the `SUPERVISOR_TOKEN`, the `github_token` and the AdGuard and
  Pi-hole passwords are loaded **only in memory** and replaced by `****` wherever they appear (code
  snippets, diffs, error messages, tracebacks), in both report languages;
- known formats are masked even when they are not in `secrets.yaml`: JWT (including HA long-lived
  tokens), GitHub, AWS, Slack, Telegram and Google tokens, PEM private keys, passwords in URLs
  (`user:password@host`) and assignments such as `password = "..."`;
- the same filter is applied to every log message, from any library.

Masking tells code apart from values: `token = open(...)` shows normally, so the evidence of a
finding is not hidden.

## Limitations

Read this before concluding that "everything is clean":

- **Static analysis does not see code downloaded at runtime.** If an integration downloads and runs
  code after being installed, the auditor can detect the *pattern* (download + execution, dynamic
  module loading), but not the content that will run nor later changes made by the remote server.
- **Sufficiently creative obfuscation escapes the rules.** The rules cover common techniques; code
  built to fool specific tools may pass. The integrity check helps: code tampered with after
  installation shows up as a modified file.
- **Integrity only proves the file is the same as the release.** If the official release itself is
  malicious (compromised repository), integrity passes; static analysis is the other layer.
  Manually installed integrations, with no GitHub repository, cannot be compared. Cards in
  `www/community/` go through static analysis, but are **not** compared with the release yet.
- **Add-on source code may not match the image.** Add-on repositories rarely have per-version tags;
  without a tag, the analysed code is `HEAD`. For add-ons with a prebuilt image, the image may have
  been built from different code than what is published; the Trivy image scan only partly covers
  this gap (CVEs and secrets, not behaviour).
- **CVEs are not necessarily exploitable.** Many image CVEs are in packages the add-on does not even
  use. Use the count to identify outdated images.
- **Traffic of add-ons with `host_network` is not measured**: Docker does not separate their
  traffic from the host's. Legitimate spikes (backups, uploads) also trigger alerts.
- **DNS does not identify who made the query** (see the DNS section). Queries made by direct IP,
  DNS over HTTPS or DNS servers hard-coded in the code do not go through your AdGuard/Pi-hole and do
  not show up.
- **Files that root without capabilities cannot read** (for example, `0600` files of another user
  in `/config`) are left out of the analysis.
- **The add-on log is in Portuguese.**

## Stored data

Everything lives in the add-on's `/data` (included in the add-on backups):

- `auditor.db` (SQLite): scan history, ignore list, personal blocklist, interface preferences
  (language), add-on statistics (30 days), traffic spikes, DNS domains already seen, ignored DNS
  domains and the discovery date of each component and finding;
- `reports/*.json`: the last `report_retention` reports, the same as the Export JSON button;
- `cache/`: reference code from GitHub (integrity and add-ons), Trivy's database, pip-audit's cache
  and the community blocklist (`lista_comunitaria.json`).

None of this is sent anywhere. Deleting `cache/` only makes the next download take longer.

## Troubleshooting

**The add-on does not start and the log shows `Permission denied`.** It is AppArmor denying
something. Open **Settings → System → Logs → Host** and look for lines with `apparmor="DENIED"` and
`profile="security_auditor"`; they tell which file and permission were missing. Open an issue in
the repository with those lines.

**"Integrity not verified: GitHub rate limit reached".** Create a token in
**GitHub → Settings → Developer settings → Fine-grained tokens** with no permissions (public
repositories only) and put it in `github_token`.

**"Integrity not verified: no matching version".** The installed version does not exist as a tag
in the repository. It is common for integrations installed from a branch. If the version should
exist, be suspicious: the code may not be what it claims to be.

**The image scan takes long or fills the disk.** Turn off `image_scan` or list the heaviest add-ons
in `image_scan_skip`. Trivy's database lives in `/data/cache/trivy`.

**HA gets slow during the scan.** Add `modo_leve` (and `horario_fixo` with a night-time hour) to
`modo_execucao`; see [Overload protection](#overload-protection).

**"Step postponed" shows up every time.** The system is busy at scan time. Use `horario_fixo` for a
quiet time or raise `carga_maxima_por_cpu` / lower `memoria_minima_mb` (carefully: Trivy is the step
that uses the most memory).

**The DNS tab does not show up or is empty.**

- Check the `auditor.dns.falha` finding, which tells the reason (URL, password, Pi-hole version).
- On Pi-hole v6, use an **app password** (Settings → Web interface / API).
- If the list is empty, find out in the AdGuard/Pi-hole log which IP HA shows up with and fill in
  `dns_client_ips`.

**Many false positives from one rule.** Use the [ignore list](#ignore-list-and-allowlist). If the
rule is often wrong for popular integrations, open an issue with the code snippet (no secrets) so
the rule can be adjusted.
