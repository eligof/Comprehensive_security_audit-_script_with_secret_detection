# server_audit.py

A production-ready, **read-only** server audit collection script for security audits and upgrade planning. Run it on any Linux or Windows server to get a comprehensive inventory of the system, its services, network exposure, security posture, and more — output as JSON, Markdown, and HTML reports.

**Single file. Zero dependencies. No installs. No changes to your system.**

```
sudo python3 server_audit.py --output-dir /tmp/audit
```

```
============================================================
Audit complete — 4.8s — status: ok
  → /tmp/audit/audit_web-prod-01_20260216_143022.json
  → /tmp/audit/audit_web-prod-01_20260216_143022.md
  → /tmp/audit/audit_web-prod-01_20260216_143022.html
============================================================
```

---

## Features

- **Cross-platform** — Linux (Debian/Ubuntu, RHEL/Rocky/Alma/CentOS, SUSE, Arch) and Windows Server (2016/2019/2022)
- **12 collection categories** — system identity, OS/patch state, installed software, services, network, users, scheduled tasks, storage, certificates, logs, containers, and security posture
- **3 output formats** — machine-readable JSON with a deterministic schema, human-readable Markdown, and a styled self-contained HTML report
- **Automatic secret detection** — scans configs and env vars for passwords, API keys, tokens, and private keys; redacts values and logs locations with `WORNING SECRET FOUND!` warnings
- **Risk flags** — auto-generated, evidence-backed findings (EOL OS, exposed database ports, weak SSH config, expiring TLS certs, missing EDR, disabled firewall, found secrets)
- **Upgrade planning** — lists discovered component versions with upgrade recommendations
- **Graceful degradation** — runs without root/admin; records `permission_missing` and continues
- **Offline** — no internet required, no package installs, Python 3 standard library only

---

## Quick Start

### Prerequisites

- **Python 3.6+** (standard library only — no `pip install` needed)
- Works best with root/admin for full collection, but runs fine without it

### Linux

```bash
# Full audit (recommended — run as root for complete data):
sudo python3 server_audit.py --output-dir /tmp/audit

# Deep profile with verbose logging:
sudo python3 server_audit.py --output-dir /tmp/audit --profile deep --verbose

# Non-root (collects what it can, flags permission gaps):
python3 server_audit.py --output-dir ~/audit

# Safe mode (minimal, conservative collection):
python3 server_audit.py --output-dir /tmp/audit --safe-mode

# JSON only:
python3 server_audit.py --output-dir /tmp/audit --formats json
```

### Windows

```powershell
# Run from an elevated PowerShell prompt:
python server_audit.py --output-dir C:\audit

# Deep collection:
python server_audit.py --output-dir C:\audit --profile deep --verbose
```

---

## CLI Reference

```
usage: server_audit.py [-h] --output-dir OUTPUT_DIR [--verbose] [--safe-mode]
                       [--profile {minimal,standard,deep}] [--formats FORMATS]
                       [--version]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--output-dir` | *(required)* | Directory to write report files (created if missing) |
| `--profile` | `standard` | Collection depth: `minimal`, `standard`, or `deep` |
| `--formats` | `json,md,html` | Comma-separated list: any combination of `json`, `md`, `html` |
| `--verbose` | off | Debug-level logging + secret count summary at the end |
| `--safe-mode` | off | Forces `minimal` profile for extra-conservative collection |
| `--version` | — | Print version and exit |

### Profiles

| Profile | What it collects | Typical runtime |
|---------|-----------------|-----------------|
| `minimal` | System identity, OS version, basic network, basic security posture | ~2s |
| `standard` | Everything in minimal + full package lists, service configs, user/group details, SSH keys, firewall rules, certificates, log summaries, containers | ~5s |
| `deep` | Everything in standard + upgradeable package lists, deeper log analysis | ~10s |

---

## Output Files

Every run produces up to three files with a shared base name:

```
audit_<hostname>_<YYYYMMDD_HHMMSS>.json
audit_<hostname>_<YYYYMMDD_HHMMSS>.md
audit_<hostname>_<YYYYMMDD_HHMMSS>.html
```

### JSON Schema (v2.0.0)

The JSON report follows a deterministic schema. Every collection section has the same structure:

```json
{
  "status": "ok | partial | fail",
  "evidence": { },
  "errors": [ ]
}
```

Top-level structure:

```
schema_version
collection_meta
├── hostname, fqdn, os, kernel, collection_time, timezone
├── script_version, user, privilege_level, profile
├── runtime_seconds, checks_executed[]
system_identity        → hostname, CPU, RAM, disk, virtualization, boot mode
os_version             → distro, version, kernel, patches, uptime
software_inventory     → packages, language runtimes, OpenSSL, SSH
services               → systemd/Windows services, config fingerprints
network                → interfaces, IPs, routes, DNS, listeners, firewall
users                  → local users/groups, sudo, SSH authorized keys, admins
scheduled_tasks        → cron, systemd timers, Windows tasks, startup items
storage                → mounts, disk usage, backup agents, LVM
certificates           → CA bundle, service certs (issuer, expiry, SANs)
logs                   → logging stack, retention, event summaries
containers             → Docker/Podman version, running containers, images
security_posture       → EDR, disk encryption, SELinux/AppArmor, SSH hardening
environment_variables  → all env vars (secrets redacted)
risk_flags[]           → auto-generated findings with severity + evidence
upgrade_planning[]     → component versions + recommendations
secrets_findings[]     → detected secret locations (values never stored)
data_minimization      → confirmation of what was excluded
```

### Example JSON (abridged)

```json
{
  "schema_version": "2.0.0",
  "collection_meta": {
    "hostname": "web-prod-01",
    "fqdn": "web-prod-01.example.com",
    "os": "Linux",
    "kernel": "5.15.0-91-generic",
    "collection_time": "2026-02-16T14:30:22.123456+00:00",
    "script_version": "2.0.0",
    "user": "root",
    "privilege_level": "root",
    "profile": "standard",
    "runtime_seconds": 4.82,
    "checks_executed": [
      "system_identity", "os_version", "software_inventory",
      "services", "network", "users", "scheduled_tasks",
      "storage", "certificates", "logs", "containers",
      "security_posture"
    ]
  },
  "system_identity": {
    "status": "ok",
    "evidence": {
      "hostname": "web-prod-01",
      "fqdn": "web-prod-01.example.com",
      "virtualization": "kvm",
      "cpu_count": 4,
      "cpu_model": "Intel Xeon E5-2680 v4",
      "ram_gb": 16.0,
      "boot_mode": "UEFI"
    },
    "errors": []
  },
  "network": {
    "status": "ok",
    "evidence": {
      "dns_servers": ["10.0.0.2", "10.0.0.3"],
      "listening_ports": [
        { "proto": "tcp", "local_addr": "0.0.0.0:22",       "process": "sshd" },
        { "proto": "tcp", "local_addr": "0.0.0.0:443",      "process": "nginx" },
        { "proto": "tcp", "local_addr": "127.0.0.1:5432",   "process": "postgres" }
      ],
      "firewall_ufw": "Status: active ..."
    },
    "errors": []
  },
  "risk_flags": [
    {
      "category": "ssh",
      "severity": "medium",
      "summary": "SSH PasswordAuthentication is enabled",
      "confidence": "high",
      "evidence": "sshd_config"
    },
    {
      "category": "certificate",
      "severity": "high",
      "summary": "TLS cert expires in 12 days (/etc/ssl/certs/web.pem)",
      "confidence": "high",
      "evidence": "notAfter=Mar 01 00:00:00 2026 GMT"
    }
  ],
  "secrets_findings": [
    {
      "location": "/etc/myapp/config.yml:L14",
      "secret_type": "api_key_or_token",
      "confidence": "medium",
      "evidence_hint": "key name: 'api_secret_key'",
      "timestamp": "2026-02-16T15:31:10.123456+00:00"
    }
  ],
  "upgrade_planning": [
    {
      "component": "Operating System",
      "current_version": "Ubuntu 20.04.6 LTS",
      "recommendation": "Review against vendor support lifecycle",
      "type": "recommendation"
    }
  ],
  "data_minimization": {
    "secrets_redacted": true,
    "secret_values_never_stored": true,
    "full_config_files_excluded": true,
    "password_hashes_excluded": true,
    "private_keys_excluded": true,
    "only_safe_metadata_collected": true
  }
}
```

---

## What It Collects

| Category | Key data points |
|----------|----------------|
| **System Identity** | Hostname, FQDN, domain, cloud/VM hints, CPU, RAM, disks, filesystems, time sync, UEFI/BIOS |
| **OS & Patches** | Distro, version, build, kernel, installed packages + versions, uptime, last reboot |
| **Software Inventory** | Installed packages, language runtimes (Python, Java, .NET, Node, PHP, Go, Ruby), OpenSSL, SSH |
| **Services** | systemd units / Windows services (name, status, start mode, user, path); config fingerprints for SSH, Nginx, Apache, MySQL, Redis, Docker with safe parsed fields |
| **Network** | Interfaces, IPs, routes, DNS, listening ports + owning processes, firewall rules (iptables/nftables/ufw/firewalld/Windows Firewall), RDP/WinRM status |
| **Users & Identity** | Local users/groups (no password hashes), sudo/admin membership, SSH authorized key fingerprints, domain join status |
| **Scheduled Tasks** | Cron, systemd timers, at jobs, Windows Scheduled Tasks, startup/Run key persistence |
| **Storage & Backups** | NFS/SMB mounts, disk usage, backup agent detection (Veeam, Rubrik, Bacula, Borg, etc.), LVM snapshots |
| **Certificates** | CA bundle metadata, service certs with subject/issuer/SANs/expiry/key size, TLS config hints |
| **Logs** | Logging stack detection (syslog, journald, Filebeat, Fluentd, etc.), retention info, 7-day security event summary (counts only) |
| **Containers** | Docker/Podman version, running containers, images, exposed ports; Kubernetes node signals |
| **Security Posture** | EDR/AV presence, disk encryption (LUKS/BitLocker), SELinux/AppArmor, SSH hardening, password policy hints, EOL detection |

---

## Secret Handling

The script **never stores or prints secret values**. Here's how it works:

1. **Pattern matching** — regex patterns detect private keys, AWS keys, API tokens, passwords in config files, bearer tokens, GitHub PATs, and more
2. **Env var scanning** — a hardcoded list of ~30 secret-bearing environment variable names (e.g., `AWS_SECRET_ACCESS_KEY`, `DATABASE_URL`, `API_KEY`) are always redacted
3. **Redaction** — matched values are replaced with `[REDACTED]` in all three output formats
4. **Location logging** — each finding is printed to stderr as:
   ```
   WORNING SECRET FOUND! location=/etc/myapp/config.yml:L14 type=api_key_or_token confidence=medium
   ```
5. **Structured recording** — findings go into `secrets_findings[]` in the JSON with safe metadata only (location, type, confidence, evidence hint like the key name — never the value)

When running with `--verbose`, a summary line is printed at the end:
```
Total suspected secrets found: 3 (see secrets_findings in JSON)
```

---

## Risk Flags

The script auto-generates evidence-backed risk findings:

| Category | What it checks |
|----------|---------------|
| **EOL** | OS version against a built-in EOL mapping table (Debian, Ubuntu, RHEL, CentOS, Rocky, Alma, SLES, Windows Server) |
| **Network exposure** | Database ports (MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch, Memcached, RabbitMQ) listening on `0.0.0.0` |
| **SSH** | `PermitRootLogin` enabled, `PasswordAuthentication` enabled |
| **Firewall** | Windows Firewall profiles disabled |
| **Endpoint protection** | No EDR/AV agent detected |
| **Certificates** | Expired or expiring within 30 days |
| **Secrets** | Any suspected secrets found on the system |
| **Disk encryption** | No LUKS detected; BitLocker protection off |

Each flag includes `category`, `severity` (critical/high/medium/info), `summary`, `confidence`, and `evidence`.

---

## Read-Only Guarantee

The script is designed to be provably read-only:

- **Filesystem reads only** — uses `open(..., "r")`, `os.stat()`, `os.path.exists()`, `os.listdir()`, `os.walk()`. The only writes are the report files in your `--output-dir`.
- **No installs** — never runs `apt install`, `pip install`, `yum install`, or any equivalent.
- **No config changes** — never edits, moves, or deletes any file outside the output directory.
- **No network calls** — works fully offline; never phones home or contacts any external service.
- **Subprocess safety** — all subprocess calls are read-only commands (`cat`, `lscpu`, `ss`, `systemctl list-*`, `Get-CimInstance`, etc.). No `systemctl start/stop/restart`, no `iptables -A`, nothing that mutates state.

---

## Privileges

The script works at any privilege level. Here's what requires elevation:

| Data point | Requires root/admin? | Behavior without |
|-----------|---------------------|------------------|
| Firewall rules (iptables/nft) | Usually | Section status → `partial`, error logged |
| Some service configs (e.g., `/etc/ssh/sshd_config`) | Sometimes | `permission_denied` in file meta |
| Sudoers file contents | Yes | Only metadata (path, perms, hash) |
| BitLocker / LUKS details | Yes | Detection may fail silently |
| Windows Scheduled Tasks (full list) | Recommended | Partial results |
| Certificate private key detection | Yes | Skipped |
| Detailed security event logs | Recommended | Reduced event summary |
| Docker socket access | Yes (or docker group) | Container section empty |

The script never fails entirely due to missing privileges. It collects what it can and marks incomplete sections with `"status": "partial"` and descriptive error messages.

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | All collectors succeeded |
| `1` | One or more collectors failed entirely |
| `2` | Unsupported platform |
| `3` | Partial collection (some collectors had permission or command issues) |

---

## Extending

The script is organized as a collection of independent collector functions. To add a new collection category:

1. Write a `collect_<name>_linux(profile)` and/or `collect_<name>_windows(profile)` function
2. Return `section_result(status, evidence_dict, errors_list)`
3. Add it to the `collectors` list in `main()`
4. Use `gate(profile, "standard")` to skip expensive checks in `minimal` mode
5. Use `secrets.check_text(value, location)` to scan any extracted text for secrets

---

## License

[MIT](LICENSE)
