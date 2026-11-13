# HA Security Auditor

*[Versão em português](README.pt-BR.md)*

Audits the security of your installation and shows a report in the sidebar:

- **custom integrations and `www/`**: suspicious code (Semgrep + Bandit), vulnerable dependencies
  (OSV) and a file-by-file comparison with the official release on GitHub;
- **other add-ons**: permissions, CVEs and secrets in the images (Trivy), Dockerfile and scripts,
  outbound traffic spikes;
- **blocklist**: badge and warning for reported components (personal list and the signed community
  list, which includes the HACS and Home Assistant lists);
- **installs and updates**: a new or updated integration, card or add-on is scanned within minutes,
  and HA shows a notification when something serious turns up (it warns, it does not block);
- **DNS (optional)**: domains queried by the host, through AdGuard Home and/or Pi-hole v6, checked
  on its own every 2 hours (configurable) between full scans.

Findings are ranked by severity, with an explanation (in English or Portuguese) and a suggested
action. The auditor points out what deserves human review; **it does not decide on its own that
something is malicious**.

It runs with `/config` read-only, its own AppArmor profile with no capabilities, the Supervisor
read-only and without sending installation data anywhere. See the **Documentation** tab for the
options, the reason for each permission and the limitations.
