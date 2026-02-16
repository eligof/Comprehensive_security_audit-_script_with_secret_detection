#!/usr/bin/env python3
"""
server_audit.py — Production-ready, read-only server audit collection script.

Collects full details about a server and its apps/services for security audit
and upgrade planning. Outputs JSON, Markdown, and HTML reports.

Safety guarantees:
  • READ-ONLY: never writes outside the output directory, never modifies
    system state, never installs packages, never edits configs.
  • SECRET REDACTION: secret values are replaced with [REDACTED]; only
    the *location* and type are recorded.
  • Works offline, works as non-root (degrades gracefully).

Usage:
  Linux:   sudo python3 server_audit.py --output-dir /tmp/audit
  Windows: python server_audit.py --output-dir C:\audit

Schema version: 2.0.0
Script version: 2.0.0

Author: Security Engineering — generated for manual audit runs.
License: Internal / proprietary.
"""

from __future__ import annotations

__version__ = "2.0.0"
SCHEMA_VERSION = "2.0.0"

import argparse
import datetime
import getpass
import hashlib
import json
import html as html_mod
import logging
import os
import platform
import re
import socket
import subprocess
import sys
import textwrap
import time
import traceback
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
REDACTED = "[REDACTED]"
SECRET_WARNING_PREFIX = "WARNING SECRET FOUND!"

# Patterns that strongly suggest a secret value
SECRET_PATTERNS: List[Tuple[re.Pattern, str, str]] = [
    (re.compile(r"-----BEGIN\s+(RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", re.I), "private_key", "high"),
    (re.compile(r"AKIA[0-9A-Z]{16}", re.I), "aws_access_key", "high"),
    (re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*\S+"), "password_assignment", "medium"),
    (re.compile(r"(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*\S+"), "api_key_or_token", "medium"),
    (re.compile(r"(?i)(connection[_-]?string|conn[_-]?str)\s*[:=]\s*\S+"), "connection_string", "medium"),
    (re.compile(r"(?i)(private[_-]?key|client[_-]?secret)\s*[:=]\s*\S+"), "credential", "medium"),
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*", re.I), "bearer_token", "medium"),
    (re.compile(r"ghp_[A-Za-z0-9]{36,}"), "github_pat", "high"),
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "openai_key_like", "medium"),
]

# Environment variable names that are typically secrets
SECRET_ENV_NAMES: set = {
    "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AZURE_CLIENT_SECRET",
    "GCP_SERVICE_ACCOUNT_KEY", "DATABASE_URL", "DB_PASSWORD", "DB_PASS",
    "MYSQL_ROOT_PASSWORD", "POSTGRES_PASSWORD", "REDIS_PASSWORD",
    "API_KEY", "API_SECRET", "SECRET_KEY", "PRIVATE_KEY",
    "SMTP_PASSWORD", "MAIL_PASSWORD", "AUTH_TOKEN", "ACCESS_TOKEN",
    "GITHUB_TOKEN", "GITLAB_TOKEN", "NPM_TOKEN", "DOCKER_PASSWORD",
    "VAULT_TOKEN", "ENCRYPTION_KEY", "JWT_SECRET", "SESSION_SECRET",
    "SLACK_TOKEN", "SLACK_WEBHOOK", "TWILIO_AUTH_TOKEN",
    "SENDGRID_API_KEY", "STRIPE_SECRET_KEY", "PAYPAL_SECRET",
}

# EOL mapping (conservative built-in table)
EOL_MAP: Dict[str, Dict[str, str]] = {
    # Debian
    "debian_8":  {"eol": "2020-06-30", "name": "Debian 8 Jessie"},
    "debian_9":  {"eol": "2022-06-30", "name": "Debian 9 Stretch"},
    "debian_10": {"eol": "2024-06-30", "name": "Debian 10 Buster"},
    "debian_11": {"eol": "2026-06-30", "name": "Debian 11 Bullseye"},
    "debian_12": {"eol": "2028-06-30", "name": "Debian 12 Bookworm"},
    # Ubuntu
    "ubuntu_14.04": {"eol": "2019-04-25", "name": "Ubuntu 14.04 Trusty"},
    "ubuntu_16.04": {"eol": "2021-04-30", "name": "Ubuntu 16.04 Xenial"},
    "ubuntu_18.04": {"eol": "2023-05-31", "name": "Ubuntu 18.04 Bionic"},
    "ubuntu_20.04": {"eol": "2025-04-02", "name": "Ubuntu 20.04 Focal"},
    "ubuntu_22.04": {"eol": "2027-04-01", "name": "Ubuntu 22.04 Jammy"},
    "ubuntu_24.04": {"eol": "2029-04-01", "name": "Ubuntu 24.04 Noble"},
    # RHEL / CentOS / Rocky / Alma
    "rhel_6":  {"eol": "2020-11-30", "name": "RHEL/CentOS 6"},
    "rhel_7":  {"eol": "2024-06-30", "name": "RHEL/CentOS 7"},
    "rhel_8":  {"eol": "2029-05-31", "name": "RHEL 8 / Rocky 8 / Alma 8"},
    "rhel_9":  {"eol": "2032-05-31", "name": "RHEL 9 / Rocky 9 / Alma 9"},
    "centos_6": {"eol": "2020-11-30", "name": "CentOS 6"},
    "centos_7": {"eol": "2024-06-30", "name": "CentOS 7"},
    "centos_8": {"eol": "2021-12-31", "name": "CentOS 8 (non-Stream)"},
    # SUSE
    "sles_12": {"eol": "2024-10-31", "name": "SLES 12"},
    "sles_15": {"eol": "2031-07-31", "name": "SLES 15"},
    # Windows Server
    "windows_server_2012":   {"eol": "2023-10-10", "name": "Windows Server 2012"},
    "windows_server_2012r2": {"eol": "2023-10-10", "name": "Windows Server 2012 R2"},
    "windows_server_2016":   {"eol": "2027-01-12", "name": "Windows Server 2016"},
    "windows_server_2019":   {"eol": "2029-01-09", "name": "Windows Server 2019"},
    "windows_server_2022":   {"eol": "2031-10-14", "name": "Windows Server 2022"},
}

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
log = logging.getLogger("server_audit")

def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    log.setLevel(level)
    log.addHandler(handler)

# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------
IS_WINDOWS = platform.system().lower() == "windows"
IS_LINUX = platform.system().lower() == "linux"

def run_cmd(
    cmd: list | str,
    timeout: int = 30,
    shell: bool = False,
    env: dict | None = None,
) -> Tuple[int, str, str]:
    """Run a command, return (returncode, stdout, stderr). Never raises."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=shell,
            env=env,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except FileNotFoundError:
        return -1, "", f"command not found: {cmd if isinstance(cmd, str) else cmd[0]}"
    except subprocess.TimeoutExpired:
        return -2, "", f"timeout ({timeout}s) running: {cmd}"
    except Exception as exc:
        return -3, "", str(exc)


def run_ps(script: str, timeout: int = 30) -> Tuple[int, str, str]:
    """Run a PowerShell snippet on Windows."""
    return run_cmd(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        timeout=timeout,
    )


def sha256_file(path: str) -> str:
    """Return SHA-256 hex digest of a file, or error string."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except PermissionError:
        return "permission_denied"
    except Exception as exc:
        return f"error: {exc}"


def file_meta(path: str) -> Dict[str, Any]:
    """Gather metadata about a file without reading its full content."""
    result: Dict[str, Any] = {"path": path, "exists": False}
    try:
        p = Path(path)
        if not p.exists():
            return result
        result["exists"] = True
        stat = p.stat()
        result["size_bytes"] = stat.st_size
        result["last_modified"] = datetime.datetime.fromtimestamp(
            stat.st_mtime, tz=datetime.timezone.utc
        ).isoformat()
        if IS_LINUX:
            import pwd, grp
            try:
                result["owner"] = pwd.getpwuid(stat.st_uid).pw_name
            except KeyError:
                result["owner"] = str(stat.st_uid)
            try:
                result["group"] = grp.getgrgid(stat.st_gid).gr_name
            except KeyError:
                result["group"] = str(stat.st_gid)
            result["permissions"] = oct(stat.st_mode)[-4:]
        result["sha256"] = sha256_file(path)
    except PermissionError:
        result["error"] = "permission_denied"
    except Exception as exc:
        result["error"] = str(exc)
    return result


def first_existing(*paths: str) -> Optional[str]:
    """Return the first path that exists, or None."""
    for p in paths:
        if os.path.exists(p):
            return p
    return None


def safe_read_lines(path: str, max_lines: int = 500) -> List[str]:
    """Read up to max_lines from a text file. Never raises."""
    try:
        with open(path, "r", errors="replace") as fh:
            lines = []
            for i, line in enumerate(fh):
                if i >= max_lines:
                    break
                lines.append(line.rstrip("\n\r"))
            return lines
    except PermissionError:
        return ["[permission_denied]"]
    except Exception:
        return []


def now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def section_result(status: str = "ok", evidence: Any = None, errors: list | None = None) -> Dict[str, Any]:
    """Standard section wrapper."""
    return {
        "status": status,
        "evidence": evidence if evidence is not None else {},
        "errors": errors or [],
    }


def merge_status(current: str, new: str) -> str:
    rank = {"ok": 0, "partial": 1, "fail": 2}
    return new if rank.get(new, 0) > rank.get(current, 0) else current


# ---------------------------------------------------------------------------
# Secret detection engine
# ---------------------------------------------------------------------------
class SecretFinder:
    """Detects and records suspected secrets. Never stores actual values."""

    def __init__(self):
        self.findings: List[Dict[str, Any]] = []

    def check_text(self, text: str, location: str) -> str:
        """Scan text, record findings, return redacted text."""
        redacted = text
        for pat, stype, confidence in SECRET_PATTERNS:
            for m in pat.finditer(text):
                self._record(location, stype, confidence, self._safe_hint(m, stype))
                # Redact the matched value
                redacted = redacted.replace(m.group(0), REDACTED)
        return redacted

    def check_env_var(self, name: str, value: str) -> str:
        """Check an environment variable name/value pair."""
        upper = name.upper()
        if upper in SECRET_ENV_NAMES or any(
            kw in upper for kw in ("SECRET", "TOKEN", "PASSWORD", "CREDENTIAL", "PRIVATE_KEY", "API_KEY")
        ):
            self._record(
                f"env:{name}", "env_secret", "high",
                f"environment variable name '{name}' matches secret pattern",
            )
            return REDACTED
        # Also scan the value itself
        for pat, stype, confidence in SECRET_PATTERNS:
            if pat.search(value):
                self._record(f"env:{name}", stype, confidence, f"value of env var '{name}' matched pattern")
                return REDACTED
        return value

    def check_file_content(self, path: str, lines: List[str], max_scan: int = 200) -> List[str]:
        """Scan file lines for secrets, return redacted lines."""
        out = []
        for i, line in enumerate(lines[:max_scan]):
            redacted = line
            for pat, stype, confidence in SECRET_PATTERNS:
                if pat.search(line):
                    self._record(
                        f"{path}:L{i+1}", stype, confidence,
                        self._safe_hint_line(line, stype),
                    )
                    redacted = pat.sub(REDACTED, redacted)
            out.append(redacted)
        return out

    def _record(self, location: str, secret_type: str, confidence: str, evidence_hint: str):
        finding = {
            "location": location,
            "secret_type": secret_type,
            "confidence": confidence,
            "evidence_hint": evidence_hint,
            "timestamp": now_iso(),
        }
        self.findings.append(finding)
        # Print the loud warning
        print(f"{SECRET_WARNING_PREFIX} location={location} type={secret_type} confidence={confidence}",
              file=sys.stderr)

    @staticmethod
    def _safe_hint(match: re.Match, stype: str) -> str:
        g = match.group(0)
        if "PRIVATE KEY" in g.upper():
            return "BEGIN PRIVATE KEY marker"
        if stype == "aws_access_key":
            return f"AWS access key ID prefix AKIA..."
        return f"pattern match for {stype}"

    @staticmethod
    def _safe_hint_line(line: str, stype: str) -> str:
        # Extract the key name but not the value
        for sep in ("=", ":", " "):
            if sep in line:
                key_part = line.split(sep, 1)[0].strip().strip('"').strip("'")
                if len(key_part) < 80:
                    return f"key name: '{key_part}'"
        return f"pattern match for {stype}"


# ---------------------------------------------------------------------------
# Global secret finder instance (set in main)
# ---------------------------------------------------------------------------
secrets: SecretFinder = SecretFinder()

# ---------------------------------------------------------------------------
# Profile gating
# ---------------------------------------------------------------------------
PROFILE_LEVELS = {"minimal": 0, "standard": 1, "deep": 2}

def gate(profile: str, minimum: str = "standard") -> bool:
    """Return True if current profile meets minimum level."""
    return PROFILE_LEVELS.get(profile, 1) >= PROFILE_LEVELS.get(minimum, 1)


# ---------------------------------------------------------------------------
# COLLECTORS — Linux
# ---------------------------------------------------------------------------

def collect_system_identity_linux(profile: str) -> Dict[str, Any]:
    """A) System identity + platform on Linux."""
    ev: Dict[str, Any] = {}
    errors: List[str] = []
    status = "ok"

    ev["hostname"] = socket.gethostname()
    try:
        ev["fqdn"] = socket.getfqdn()
    except Exception:
        ev["fqdn"] = ev["hostname"]

    # Domain / workgroup
    rc, out, _ = run_cmd(["hostname", "-d"])
    ev["domain"] = out if rc == 0 and out else None

    # Virtualization hints
    rc, out, _ = run_cmd(["systemd-detect-virt"])
    ev["virtualization"] = out if rc == 0 else None
    if ev["virtualization"] is None:
        rc, out, _ = run_cmd(["cat", "/sys/class/dmi/id/sys_vendor"])
        if rc == 0:
            ev["virtualization_hint_vendor"] = out

    # Hardware model
    for f in ["/sys/class/dmi/id/product_name", "/sys/class/dmi/id/sys_vendor"]:
        rc, out, _ = run_cmd(["cat", f])
        if rc == 0:
            ev[f.split("/")[-1]] = out

    # CPU
    rc, out, _ = run_cmd(["nproc"])
    ev["cpu_count"] = int(out) if rc == 0 and out.isdigit() else None
    rc, out, _ = run_cmd(["lscpu"])
    if rc == 0:
        for line in out.splitlines():
            if line.startswith("Model name:"):
                ev["cpu_model"] = line.split(":", 1)[1].strip()
            if line.startswith("Architecture:"):
                ev["cpu_arch"] = line.split(":", 1)[1].strip()

    # RAM
    rc, out, _ = run_cmd(["cat", "/proc/meminfo"])
    if rc == 0:
        for line in out.splitlines():
            if line.startswith("MemTotal:"):
                ev["ram_kb"] = int(line.split()[1])
                ev["ram_gb"] = round(ev["ram_kb"] / 1048576, 1)
                break

    # Disk layout (lsblk)
    rc, out, _ = run_cmd(["lsblk", "-J", "-o", "NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE"])
    if rc == 0:
        try:
            ev["block_devices"] = json.loads(out)
        except json.JSONDecodeError:
            ev["block_devices_raw"] = out[:2000]

    # Filesystems + mount options
    rc, out, _ = run_cmd(["findmnt", "-J"])
    if rc == 0:
        try:
            ev["filesystems"] = json.loads(out)
        except json.JSONDecodeError:
            pass

    # Time sync source
    for cmd in [["timedatectl", "show"], ["chronyc", "sources"], ["ntpq", "-p"]]:
        rc, out, _ = run_cmd(cmd)
        if rc == 0 and out:
            ev["time_sync"] = {"command": " ".join(cmd), "output": out[:1000]}
            break

    # Boot mode
    ev["boot_mode"] = "UEFI" if os.path.isdir("/sys/firmware/efi") else "BIOS"

    if not ev.get("hostname"):
        status = "partial"
        errors.append("Could not determine hostname")

    return section_result(status, ev, errors)


def collect_os_version_linux(profile: str) -> Dict[str, Any]:
    """B) OS versioning + patch state on Linux."""
    ev: Dict[str, Any] = {}
    errors: List[str] = []
    status = "ok"

    # OS release
    rc, out, _ = run_cmd(["cat", "/etc/os-release"])
    if rc == 0:
        parsed = {}
        for line in out.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                parsed[k.strip()] = v.strip().strip('"')
        ev["os_release"] = parsed
    else:
        errors.append("Could not read /etc/os-release")
        status = "partial"

    ev["kernel"] = platform.release()
    ev["kernel_version"] = platform.version()

    # Uptime
    rc, out, _ = run_cmd(["cat", "/proc/uptime"])
    if rc == 0:
        try:
            ev["uptime_seconds"] = float(out.split()[0])
        except (ValueError, IndexError):
            pass

    # Last reboot
    rc, out, _ = run_cmd(["who", "-b"])
    if rc == 0:
        ev["last_reboot"] = out.strip()

    # Installed packages (versions)
    if gate(profile, "standard"):
        # dpkg
        rc, out, _ = run_cmd(["dpkg-query", "-W", "-f", "${Package} ${Version}\n"], timeout=60)
        if rc == 0 and out:
            pkgs = {}
            for line in out.splitlines():
                parts = line.split(None, 1)
                if len(parts) == 2:
                    pkgs[parts[0]] = parts[1]
            ev["installed_packages_dpkg"] = pkgs
            ev["installed_package_count_dpkg"] = len(pkgs)
        # rpm
        rc, out, _ = run_cmd(["rpm", "-qa", "--queryformat", "%{NAME} %{VERSION}-%{RELEASE}\n"], timeout=60)
        if rc == 0 and out:
            pkgs = {}
            for line in out.splitlines():
                parts = line.split(None, 1)
                if len(parts) == 2:
                    pkgs[parts[0]] = parts[1]
            ev["installed_packages_rpm"] = pkgs
            ev["installed_package_count_rpm"] = len(pkgs)

    # Upgradeable (best-effort, offline only — just reads cache)
    if gate(profile, "deep"):
        rc, out, _ = run_cmd(["apt", "list", "--upgradable"], timeout=30)
        if rc == 0 and out:
            ev["upgradeable_apt"] = [l for l in out.splitlines() if "/" in l][:200]
        rc, out, _ = run_cmd(["yum", "check-update", "--quiet"], timeout=30)
        if rc in (0, 100) and out:
            ev["upgradeable_yum"] = out.splitlines()[:200]

    return section_result(status, ev, errors)


def collect_software_inventory_linux(profile: str) -> Dict[str, Any]:
    """C) Installed software inventory on Linux."""
    ev: Dict[str, Any] = {}
    errors: List[str] = []
    status = "ok"

    # Language runtimes
    runtimes = {}
    checks = [
        ("python3", ["python3", "--version"]),
        ("python2", ["python2", "--version"]),
        ("java", ["java", "-version"]),
        ("node", ["node", "--version"]),
        ("php", ["php", "--version"]),
        ("go", ["go", "version"]),
        ("ruby", ["ruby", "--version"]),
        ("dotnet", ["dotnet", "--version"]),
        ("perl", ["perl", "-v"]),
    ]
    for name, cmd in checks:
        rc, out, err = run_cmd(cmd, timeout=10)
        text = out or err
        if rc == 0 and text:
            runtimes[name] = {"version": text.splitlines()[0][:200]}
            # Find path
            rc2, path, _ = run_cmd(["which", cmd[0]])
            if rc2 == 0:
                runtimes[name]["path"] = path

    ev["language_runtimes"] = runtimes

    # Critical libs
    rc, out, _ = run_cmd(["openssl", "version"])
    if rc == 0:
        ev["openssl_version"] = out

    rc, out, _ = run_cmd(["ssh", "-V"])
    if rc == 0 or out:
        ev["ssh_version"] = (out or "").strip()
    # ssh -V prints to stderr
    if not ev.get("ssh_version"):
        rc, _, err = run_cmd(["ssh", "-V"])
        if err:
            ev["ssh_version"] = err.strip()

    return section_result(status, ev, errors)


def collect_services_linux(profile: str) -> Dict[str, Any]:
    """D) Running services and config fingerprints on Linux."""
    ev: Dict[str, Any] = {}
    errors: List[str] = []
    status = "ok"

    # Systemd services
    rc, out, _ = run_cmd(
        ["systemctl", "list-units", "--type=service", "--all", "--no-pager", "--plain"],
        timeout=30,
    )
    if rc == 0:
        services = []
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0].endswith(".service"):
                services.append({
                    "name": parts[0],
                    "load": parts[1],
                    "active": parts[2],
                    "sub": parts[3],
                    "description": " ".join(parts[4:]) if len(parts) > 4 else "",
                })
        ev["systemd_services"] = services
        ev["systemd_service_count"] = len(services)
    else:
        errors.append("systemctl not available or failed")
        status = "partial"

    # Common service config fingerprints
    service_configs = {}

    config_map = {
        "sshd": ["/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d"],
        "nginx": ["/etc/nginx/nginx.conf"],
        "apache2": ["/etc/apache2/apache2.conf", "/etc/httpd/conf/httpd.conf"],
        "mysql": ["/etc/mysql/my.cnf", "/etc/my.cnf"],
        "postgresql": [],  # handled separately
        "redis": ["/etc/redis/redis.conf", "/etc/redis.conf"],
        "docker": ["/etc/docker/daemon.json"],
    }

    safe_fields_map = {
        "sshd": ["Port", "ListenAddress", "PermitRootLogin", "PasswordAuthentication",
                  "PubkeyAuthentication", "Protocol", "MaxAuthTries", "X11Forwarding",
                  "AllowUsers", "AllowGroups", "UsePAM", "ChallengeResponseAuthentication"],
        "nginx": ["listen", "server_name", "ssl_certificate", "ssl_protocols",
                   "error_log", "access_log", "worker_processes"],
        "apache2": ["Listen", "ServerName", "SSLEngine", "SSLProtocol",
                     "ErrorLog", "CustomLog", "ServerRoot"],
        "mysql": ["port", "bind-address", "socket", "datadir", "log_error", "ssl"],
        "redis": ["port", "bind", "requirepass", "logfile", "dir"],
    }

    if gate(profile, "standard"):
        for svc, paths in config_map.items():
            for p in paths:
                if os.path.exists(p):
                    meta = file_meta(p)
                    # Parse safe fields
                    lines = safe_read_lines(p, 300)
                    safe_keys = safe_fields_map.get(svc, [])
                    parsed = {}
                    for line in lines:
                        stripped = line.strip()
                        if stripped.startswith("#") or not stripped:
                            continue
                        for key in safe_keys:
                            if stripped.lower().startswith(key.lower()):
                                val = stripped.split(None, 1)[1] if len(stripped.split(None, 1)) > 1 else stripped
                                # Redact if looks secret
                                val = secrets.check_text(val, f"{p}:{key}")
                                parsed[key] = val
                    meta["safe_parsed_fields"] = parsed
                    service_configs[svc] = meta

    ev["service_configs"] = service_configs
    return section_result(status, ev, errors)


def collect_network_linux(profile: str) -> Dict[str, Any]:
    """E) Network exposure on Linux."""
    ev: Dict[str, Any] = {}
    errors: List[str] = []
    status = "ok"

    # Interfaces and IPs
    rc, out, _ = run_cmd(["ip", "-j", "addr"])
    if rc == 0:
        try:
            ev["interfaces"] = json.loads(out)
        except json.JSONDecodeError:
            ev["interfaces_raw"] = out[:3000]
    else:
        rc, out, _ = run_cmd(["ip", "addr"])
        if rc == 0:
            ev["interfaces_raw"] = out[:3000]

    # Routes
    rc, out, _ = run_cmd(["ip", "-j", "route"])
    if rc == 0:
        try:
            ev["routes"] = json.loads(out)
        except json.JSONDecodeError:
            ev["routes_raw"] = out[:2000]

    # DNS
    if os.path.exists("/etc/resolv.conf"):
        lines = safe_read_lines("/etc/resolv.conf", 50)
        ev["dns_servers"] = [l.split()[1] for l in lines if l.strip().startswith("nameserver")]

    # Listening ports
    rc, out, _ = run_cmd(["ss", "-tulnp"])
    if rc == 0:
        ev["listening_ports_raw"] = out[:5000]
        # Parse
        listeners = []
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 6:
                listeners.append({
                    "proto": parts[0],
                    "local_addr": parts[4],
                    "process": parts[-1] if "users:" in parts[-1] else "",
                })
        ev["listening_ports"] = listeners
    else:
        rc, out, _ = run_cmd(["netstat", "-tulnp"])
        if rc == 0:
            ev["listening_ports_raw"] = out[:5000]

    # Firewall rules
    if gate(profile, "standard"):
        for fw_cmd, key in [
            (["iptables", "-L", "-n", "--line-numbers"], "iptables"),
            (["nft", "list", "ruleset"], "nftables"),
            (["firewall-cmd", "--list-all"], "firewalld"),
            (["ufw", "status", "verbose"], "ufw"),
        ]:
            rc, out, err = run_cmd(fw_cmd)
            if rc == 0 and out:
                ev[f"firewall_{key}"] = out[:5000]

    return section_result(status, ev, errors)


def collect_users_linux(profile: str) -> Dict[str, Any]:
    """F) Users, groups, and identity controls on Linux."""
    ev: Dict[str, Any] = {}
    errors: List[str] = []
    status = "ok"

    # Local users (no password hashes)
    users = []
    try:
        with open("/etc/passwd", "r") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 7:
                    users.append({
                        "username": parts[0],
                        "uid": int(parts[2]),
                        "gid": int(parts[3]),
                        "home": parts[5],
                        "shell": parts[6],
                    })
    except PermissionError:
        errors.append("Cannot read /etc/passwd")
        status = "partial"
    ev["local_users"] = users
    ev["local_user_count"] = len(users)

    # Groups
    groups = []
    try:
        with open("/etc/group", "r") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 4:
                    groups.append({
                        "name": parts[0],
                        "gid": int(parts[2]),
                        "members": parts[3].split(",") if parts[3] else [],
                    })
    except PermissionError:
        errors.append("Cannot read /etc/group")
        status = merge_status(status, "partial")
    ev["local_groups"] = groups

    # Sudoers membership
    sudo_group_members = []
    for g in groups:
        if g["name"] in ("sudo", "wheel", "admin"):
            sudo_group_members.extend(g["members"])
    ev["sudo_group_members"] = sudo_group_members

    # Sudoers file (safe excerpts only)
    if gate(profile, "standard"):
        sudoers_path = "/etc/sudoers"
        if os.path.exists(sudoers_path):
            ev["sudoers_meta"] = file_meta(sudoers_path)
            lines = safe_read_lines(sudoers_path, 200)
            safe_lines = [l for l in lines if l.strip() and not l.strip().startswith("#")]
            ev["sudoers_effective_lines"] = secrets.check_file_content(sudoers_path, safe_lines)

    # SSH authorized keys inventory
    if gate(profile, "standard"):
        auth_keys = []
        for user in users:
            ak_path = os.path.join(user["home"], ".ssh", "authorized_keys")
            if os.path.exists(ak_path):
                meta = file_meta(ak_path)
                # Count keys and fingerprints
                lines = safe_read_lines(ak_path, 100)
                key_count = sum(1 for l in lines if l.strip() and not l.strip().startswith("#"))
                # Get fingerprints via ssh-keygen if available
                rc, fp_out, _ = run_cmd(["ssh-keygen", "-lf", ak_path])
                fingerprints = fp_out.splitlines() if rc == 0 else []
                auth_keys.append({
                    "user": user["username"],
                    "path": ak_path,
                    "meta": meta,
                    "key_count": key_count,
                    "fingerprints": fingerprints[:50],
                })
        ev["ssh_authorized_keys"] = auth_keys

    return section_result(status, ev, errors)


def collect_scheduled_tasks_linux(profile: str) -> Dict[str, Any]:
    """G) Scheduled tasks / persistence on Linux."""
    ev: Dict[str, Any] = {}
    errors: List[str] = []
    status = "ok"

    # System crontabs
    crontabs = {}
    for path in ["/etc/crontab", "/etc/cron.d"]:
        if os.path.isfile(path):
            lines = safe_read_lines(path, 100)
            crontabs[path] = secrets.check_file_content(path, [l for l in lines if l.strip() and not l.strip().startswith("#")])
        elif os.path.isdir(path):
            try:
                for f in os.listdir(path):
                    fp = os.path.join(path, f)
                    if os.path.isfile(fp):
                        lines = safe_read_lines(fp, 50)
                        crontabs[fp] = secrets.check_file_content(fp, [l for l in lines if l.strip() and not l.strip().startswith("#")])
            except PermissionError:
                errors.append(f"Cannot list {path}")
                status = "partial"
    ev["system_crontabs"] = crontabs

    # User crontabs
    rc, out, _ = run_cmd(["ls", "/var/spool/cron/crontabs/"])
    if rc == 0 and out:
        ev["user_crontab_files"] = out.splitlines()
    else:
        rc, out, _ = run_cmd(["ls", "/var/spool/cron/"])
        if rc == 0 and out:
            ev["user_crontab_files"] = out.splitlines()

    # Systemd timers
    rc, out, _ = run_cmd(["systemctl", "list-timers", "--all", "--no-pager"])
    if rc == 0:
        ev["systemd_timers"] = out[:3000]

    # At jobs
    rc, out, _ = run_cmd(["atq"])
    if rc == 0:
        ev["at_jobs"] = out[:1000] if out else "none"

    # Enabled services (startup/persistence)
    rc, out, _ = run_cmd(["systemctl", "list-unit-files", "--type=service", "--state=enabled", "--no-pager"])
    if rc == 0:
        ev["enabled_services"] = out[:5000]

    return section_result(status, ev, errors)


def collect_storage_linux(profile: str) -> Dict[str, Any]:
    """H) Storage + backups signals on Linux."""
    ev: Dict[str, Any] = {}
    errors: List[str] = []
    status = "ok"

    # Mounted shares
    rc, out, _ = run_cmd(["mount", "-t", "nfs,nfs4,cifs,smbfs"])
    if rc == 0:
        ev["network_mounts"] = out if out else "none"

    rc, out, _ = run_cmd(["df", "-hT"])
    if rc == 0:
        ev["disk_usage"] = out[:3000]

    # Backup agents
    backup_hints = []
    backup_services = ["veeamservice", "veeamtransport", "rubrik-agent", "bacula-fd",
                       "bareos-fd", "restic", "duplicity", "borg", "acronis_mms",
                       "commvault", "tsm", "dsmcad"]
    for svc in backup_services:
        rc, out, _ = run_cmd(["systemctl", "is-active", f"{svc}.service"])
        if rc == 0 and "active" in out:
            backup_hints.append({"service": svc, "status": "active"})
        # Also check if binary exists
        rc2, path, _ = run_cmd(["which", svc])
        if rc2 == 0:
            backup_hints.append({"binary": svc, "path": path})
    ev["backup_agents"] = backup_hints

    # LVM snapshots
    rc, out, _ = run_cmd(["lvs", "--noheadings", "-o", "lv_name,lv_attr,lv_size,origin"])
    if rc == 0 and out:
        ev["lvm_volumes"] = out[:2000]

    return section_result(status, ev, errors)


def collect_certificates_linux(profile: str) -> Dict[str, Any]:
    """I) Certificates / TLS posture on Linux."""
    ev: Dict[str, Any] = {}
    errors: List[str] = []
    status = "ok"

    # System CA bundle info
    ca_paths = ["/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt",
                "/etc/ssl/ca-bundle.pem"]
    for p in ca_paths:
        if os.path.exists(p):
            ev["system_ca_bundle"] = file_meta(p)
            break

    # Find .pem/.crt/.key files in common locations
    if gate(profile, "standard"):
        cert_files = []
        search_dirs = ["/etc/ssl", "/etc/pki", "/etc/nginx/ssl", "/etc/apache2/ssl",
                       "/etc/letsencrypt/live"]
        for d in search_dirs:
            if not os.path.isdir(d):
                continue
            try:
                for root, dirs, files in os.walk(d):
                    # Limit depth
                    depth = root.replace(d, "").count(os.sep)
                    if depth > 3:
                        continue
                    for f in files:
                        if f.endswith((".pem", ".crt", ".cer")):
                            fp = os.path.join(root, f)
                            meta = file_meta(fp)
                            # Parse cert info with openssl
                            rc, out, _ = run_cmd(
                                ["openssl", "x509", "-in", fp, "-noout",
                                 "-subject", "-issuer", "-dates", "-ext", "subjectAltName",
                                 "-serial", "-fingerprint"],
                                timeout=10,
                            )
                            if rc == 0:
                                meta["x509_info"] = out
                            cert_files.append(meta)
                            if len(cert_files) >= 50:
                                break
            except PermissionError:
                errors.append(f"Cannot walk {d}")
                status = merge_status(status, "partial")
        ev["certificate_files"] = cert_files

    return section_result(status, ev, errors)


def collect_logs_linux(profile: str) -> Dict[str, Any]:
    """J) Logs and audit evidence on Linux."""
    ev: Dict[str, Any] = {}
    errors: List[str] = []
    status = "ok"

    # Logging stack detection
    logging_stack = []
    for svc in ["rsyslog", "syslog-ng", "journald", "fluentd", "fluent-bit",
                "filebeat", "logstash", "vector", "promtail"]:
        rc, out, _ = run_cmd(["systemctl", "is-active", f"{svc}.service"])
        if rc == 0 and "active" in out:
            logging_stack.append(svc)
    # Also check for plain syslog
    if os.path.exists("/var/log/syslog") or os.path.exists("/var/log/messages"):
        logging_stack.append("syslog_files_present")
    ev["logging_stack"] = logging_stack

    # Journal disk usage
    rc, out, _ = run_cmd(["journalctl", "--disk-usage"])
    if rc == 0:
        ev["journal_disk_usage"] = out

    # Recent security events summary (counts only, not contents)
    if gate(profile, "standard"):
        rc, out, _ = run_cmd(
            ["journalctl", "-p", "warning", "--since", "7 days ago", "--no-pager",
             "-o", "json", "--output-fields=PRIORITY,_SYSTEMD_UNIT"],
            timeout=30,
        )
        if rc == 0 and out:
            # Count by unit
            counts: Dict[str, int] = {}
            for line in out.splitlines():
                try:
                    entry = json.loads(line)
                    unit = entry.get("_SYSTEMD_UNIT", "unknown")
                    counts[unit] = counts.get(unit, 0) + 1
                except json.JSONDecodeError:
                    continue
            ev["recent_warnings_by_unit_7d"] = dict(sorted(counts.items(), key=lambda x: -x[1])[:30])

        # Auth log summary
        auth_log = first_existing("/var/log/auth.log", "/var/log/secure")
        if auth_log:
            ev["auth_log_meta"] = file_meta(auth_log)
            rc, out, _ = run_cmd(["wc", "-l", auth_log])
            if rc == 0:
                ev["auth_log_lines"] = out.split()[0]

    return section_result(status, ev, errors)


def collect_containers_linux(profile: str) -> Dict[str, Any]:
    """K) Containers and orchestration on Linux."""
    ev: Dict[str, Any] = {}
    errors: List[str] = []
    status = "ok"

    # Docker
    for engine in ["docker", "podman"]:
        rc, out, _ = run_cmd([engine, "version", "--format", "json"])
        if rc == 0:
            try:
                ev[f"{engine}_version"] = json.loads(out)
            except json.JSONDecodeError:
                ev[f"{engine}_version_raw"] = out[:500]

            # Running containers
            rc, out, _ = run_cmd(
                [engine, "ps", "--format", "{{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}\t{{.Names}}"],
                timeout=15,
            )
            if rc == 0:
                containers = []
                for line in out.splitlines():
                    parts = line.split("\t")
                    if len(parts) >= 5:
                        containers.append({
                            "id": parts[0], "image": parts[1],
                            "status": parts[2], "ports": parts[3], "name": parts[4],
                        })
                ev[f"{engine}_containers"] = containers

            # Images
            rc, out, _ = run_cmd([engine, "images", "--format", "{{.Repository}}:{{.Tag}}\t{{.Size}}\t{{.ID}}"])
            if rc == 0:
                images = []
                for line in out.splitlines():
                    parts = line.split("\t")
                    if parts:
                        images.append({"image": parts[0], "size": parts[1] if len(parts) > 1 else "",
                                       "id": parts[2] if len(parts) > 2 else ""})
                ev[f"{engine}_images"] = images

    # Kubernetes signals
    for k in ["kubelet", "k3s-agent", "k3s"]:
        rc, _, _ = run_cmd(["systemctl", "is-active", f"{k}.service"])
        if rc == 0:
            ev["kubernetes_hint"] = f"{k} service active"
            break
    rc, out, _ = run_cmd(["kubectl", "version", "--client", "--output=json"])
    if rc == 0:
        ev["kubectl_version"] = out[:500]

    return section_result(status, ev, errors)


def collect_security_posture_linux(profile: str) -> Dict[str, Any]:
    """L) Security posture quick checks on Linux."""
    ev: Dict[str, Any] = {}
    errors: List[str] = []
    status = "ok"

    # AV/EDR presence
    edr_signals = []
    edr_checks = [
        ("crowdstrike-falcon-sensor", "CrowdStrike Falcon"),
        ("falcon-sensor", "CrowdStrike Falcon"),
        ("SentinelAgent", "SentinelOne"),
        ("sentinelone", "SentinelOne"),
        ("wazuh-agent", "Wazuh"),
        ("ossec-agent", "OSSEC"),
        ("clamd", "ClamAV"),
        ("sophos-av", "Sophos"),
    ]
    for svc, name in edr_checks:
        rc, out, _ = run_cmd(["systemctl", "is-active", f"{svc}.service"])
        if rc == 0 and "active" in out:
            edr_signals.append({"product": name, "service": svc, "status": "active"})
    ev["edr_signals"] = edr_signals

    # Disk encryption (LUKS)
    rc, out, _ = run_cmd(["lsblk", "-o", "NAME,FSTYPE,TYPE"])
    if rc == 0:
        luks_found = "crypto_LUKS" in out
        ev["disk_encryption"] = {"luks_detected": luks_found, "raw": out[:1000]}

    # SELinux / AppArmor
    rc, out, _ = run_cmd(["getenforce"])
    if rc == 0:
        ev["selinux"] = out
    rc, out, _ = run_cmd(["aa-status"])
    if rc == 0:
        ev["apparmor_status"] = out[:1000]
    elif os.path.exists("/sys/module/apparmor"):
        ev["apparmor_loaded"] = True

    # SSH hardening highlights
    sshd_config = first_existing("/etc/ssh/sshd_config")
    if sshd_config:
        lines = safe_read_lines(sshd_config, 300)
        ssh_settings = {}
        for line in lines:
            s = line.strip()
            if s.startswith("#") or not s:
                continue
            for key in ["PermitRootLogin", "PasswordAuthentication", "PubkeyAuthentication",
                        "X11Forwarding", "MaxAuthTries", "Protocol", "ChallengeResponseAuthentication",
                        "UsePAM", "AllowUsers", "AllowGroups"]:
                if s.lower().startswith(key.lower()):
                    ssh_settings[key] = s.split(None, 1)[1] if len(s.split(None, 1)) > 1 else ""
        ev["ssh_hardening"] = ssh_settings

    # Password policy (PAM hints)
    pam_paths = ["/etc/pam.d/common-password", "/etc/pam.d/system-auth",
                 "/etc/security/pwquality.conf"]
    pam_hints = {}
    for p in pam_paths:
        if os.path.exists(p):
            lines = safe_read_lines(p, 50)
            pam_hints[p] = [l for l in lines if l.strip() and not l.strip().startswith("#")][:20]
    ev["password_policy_hints"] = pam_hints

    return section_result(status, ev, errors)


# ---------------------------------------------------------------------------
# COLLECTORS — Windows
# ---------------------------------------------------------------------------

def collect_system_identity_windows(profile: str) -> Dict[str, Any]:
    ev: Dict[str, Any] = {}
    errors: List[str] = []
    status = "ok"

    ev["hostname"] = socket.gethostname()
    try:
        ev["fqdn"] = socket.getfqdn()
    except Exception:
        ev["fqdn"] = ev["hostname"]

    # Computer system info
    rc, out, _ = run_ps(
        "Get-CimInstance Win32_ComputerSystem | Select-Object Name,Domain,Manufacturer,"
        "Model,TotalPhysicalMemory,DomainRole | ConvertTo-Json"
    )
    if rc == 0 and out:
        try:
            ev["computer_system"] = json.loads(out)
        except json.JSONDecodeError:
            ev["computer_system_raw"] = out[:2000]

    # CPU
    rc, out, _ = run_ps(
        "Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores,"
        "NumberOfLogicalProcessors,MaxClockSpeed | ConvertTo-Json"
    )
    if rc == 0 and out:
        try:
            ev["cpu"] = json.loads(out)
        except json.JSONDecodeError:
            pass

    # Disk layout
    rc, out, _ = run_ps(
        "Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID,DriveType,"
        "FileSystem,Size,FreeSpace,VolumeName | ConvertTo-Json"
    )
    if rc == 0 and out:
        try:
            ev["disks"] = json.loads(out)
        except json.JSONDecodeError:
            pass

    # Boot mode
    rc, out, _ = run_ps("bcdedit /enum firmware 2>$null; if($?){ 'UEFI' } else { 'BIOS_or_unknown' }")
    ev["boot_mode_hint"] = out.strip().splitlines()[-1] if out else "unknown"

    # Virtualization hints
    rc, out, _ = run_ps("(Get-CimInstance Win32_ComputerSystem).Model")
    if rc == 0:
        ev["hw_model"] = out.strip()
        low = out.lower()
        if "virtual" in low or "vmware" in low or "kvm" in low or "hyper-v" in low:
            ev["virtualization_hint"] = out.strip()

    # Time sync
    rc, out, _ = run_cmd(["w32tm", "/query", "/status"])
    if rc == 0:
        ev["time_sync"] = out[:1000]

    return section_result(status, ev, errors)


def collect_os_version_windows(profile: str) -> Dict[str, Any]:
    ev: Dict[str, Any] = {}
    errors: List[str] = []
    status = "ok"

    rc, out, _ = run_ps(
        "Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,"
        "BuildNumber,OSArchitecture,LastBootUpTime,InstallDate | ConvertTo-Json"
    )
    if rc == 0 and out:
        try:
            ev["os_info"] = json.loads(out)
        except json.JSONDecodeError:
            ev["os_info_raw"] = out[:2000]

    ev["kernel"] = platform.version()
    ev["platform_release"] = platform.release()

    # Installed KBs
    if gate(profile, "standard"):
        rc, out, _ = run_ps(
            "Get-HotFix | Select-Object HotFixID,Description,InstalledOn | ConvertTo-Json",
            timeout=60,
        )
        if rc == 0 and out:
            try:
                ev["installed_kbs"] = json.loads(out)
            except json.JSONDecodeError:
                ev["installed_kbs_raw"] = out[:5000]

    return section_result(status, ev, errors)


def collect_software_inventory_windows(profile: str) -> Dict[str, Any]:
    ev: Dict[str, Any] = {}
    errors: List[str] = []
    status = "ok"

    # Installed programs
    if gate(profile, "standard"):
        rc, out, _ = run_ps(
            "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,"
            "HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* "
            "| Select-Object DisplayName,DisplayVersion,Publisher,InstallDate "
            "| Where-Object { $_.DisplayName } | ConvertTo-Json",
            timeout=60,
        )
        if rc == 0 and out:
            try:
                ev["installed_programs"] = json.loads(out)
            except json.JSONDecodeError:
                ev["installed_programs_raw"] = out[:10000]

    # Language runtimes
    runtimes = {}
    checks = [
        ("python", "python --version 2>&1"),
        ("java", "java -version 2>&1"),
        ("node", "node --version 2>&1"),
        ("dotnet", "dotnet --version 2>&1"),
        ("php", "php --version 2>&1"),
        ("go", "go version 2>&1"),
        ("ruby", "ruby --version 2>&1"),
    ]
    for name, cmd in checks:
        rc, out, err = run_cmd(cmd, shell=True, timeout=10)
        text = out or err
        if text and "not recognized" not in text.lower() and "not found" not in text.lower():
            runtimes[name] = {"version": text.splitlines()[0][:200]}
    ev["language_runtimes"] = runtimes

    return section_result(status, ev, errors)


def collect_services_windows(profile: str) -> Dict[str, Any]:
    ev: Dict[str, Any] = {}
    errors: List[str] = []
    status = "ok"

    rc, out, _ = run_ps(
        "Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,"
        "StartMode,StartName,PathName | ConvertTo-Json",
        timeout=60,
    )
    if rc == 0 and out:
        try:
            services = json.loads(out)
            # Redact any secrets in command lines
            if isinstance(services, list):
                for svc in services:
                    if svc.get("PathName"):
                        svc["PathName"] = secrets.check_text(svc["PathName"], f"service:{svc.get('Name','?')}")
            ev["services"] = services
            ev["service_count"] = len(services) if isinstance(services, list) else 0
        except json.JSONDecodeError:
            ev["services_raw"] = out[:10000]

    # IIS
    rc, out, _ = run_ps(
        "Import-Module WebAdministration -ErrorAction SilentlyContinue; "
        "Get-Website | Select-Object Name,State,PhysicalPath,Bindings | ConvertTo-Json 2>$null"
    )
    if rc == 0 and out and "ConvertTo-Json" not in out:
        try:
            ev["iis_sites"] = json.loads(out)
        except json.JSONDecodeError:
            pass

    return section_result(status, ev, errors)


def collect_network_windows(profile: str) -> Dict[str, Any]:
    ev: Dict[str, Any] = {}
    errors: List[str] = []
    status = "ok"

    # Interfaces
    rc, out, _ = run_ps(
        "Get-NetIPAddress | Select-Object InterfaceAlias,IPAddress,PrefixLength,"
        "AddressFamily | ConvertTo-Json"
    )
    if rc == 0 and out:
        try:
            ev["interfaces"] = json.loads(out)
        except json.JSONDecodeError:
            pass

    # Routes
    rc, out, _ = run_ps("Get-NetRoute | Select-Object DestinationPrefix,NextHop,InterfaceAlias | ConvertTo-Json")
    if rc == 0 and out:
        try:
            ev["routes"] = json.loads(out)
        except json.JSONDecodeError:
            pass

    # DNS
    rc, out, _ = run_ps(
        "Get-DnsClientServerAddress | Select-Object InterfaceAlias,ServerAddresses | ConvertTo-Json"
    )
    if rc == 0 and out:
        try:
            ev["dns_servers"] = json.loads(out)
        except json.JSONDecodeError:
            pass

    # Listening ports
    rc, out, _ = run_ps(
        "Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,"
        "OwningProcess | ConvertTo-Json"
    )
    if rc == 0 and out:
        try:
            ev["listening_tcp"] = json.loads(out)
        except json.JSONDecodeError:
            pass

    # Firewall
    if gate(profile, "standard"):
        rc, out, _ = run_ps(
            "Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,"
            "DefaultOutboundAction | ConvertTo-Json"
        )
        if rc == 0 and out:
            try:
                ev["firewall_profiles"] = json.loads(out)
            except json.JSONDecodeError:
                pass

        # RDP settings
        rc, out, _ = run_ps(
            "(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server').fDenyTSConnections"
        )
        if rc == 0:
            ev["rdp_enabled"] = out.strip() == "0"

        # WinRM
        rc, out, _ = run_ps("Get-Service WinRM | Select-Object Status | ConvertTo-Json")
        if rc == 0 and out:
            try:
                ev["winrm"] = json.loads(out)
            except json.JSONDecodeError:
                pass

    return section_result(status, ev, errors)


def collect_users_windows(profile: str) -> Dict[str, Any]:
    ev: Dict[str, Any] = {}
    errors: List[str] = []
    status = "ok"

    # Local users
    rc, out, _ = run_ps(
        "Get-LocalUser | Select-Object Name,Enabled,LastLogon,PasswordRequired,"
        "PasswordLastSet | ConvertTo-Json"
    )
    if rc == 0 and out:
        try:
            ev["local_users"] = json.loads(out)
        except json.JSONDecodeError:
            pass

    # Local groups
    rc, out, _ = run_ps("Get-LocalGroup | Select-Object Name,Description | ConvertTo-Json")
    if rc == 0 and out:
        try:
            ev["local_groups"] = json.loads(out)
        except json.JSONDecodeError:
            pass

    # Admin group members
    rc, out, _ = run_ps(
        "Get-LocalGroupMember -Group 'Administrators' | Select-Object Name,ObjectClass,"
        "PrincipalSource | ConvertTo-Json"
    )
    if rc == 0 and out:
        try:
            ev["admin_group_members"] = json.loads(out)
        except json.JSONDecodeError:
            pass

    # Domain join
    rc, out, _ = run_ps("(Get-CimInstance Win32_ComputerSystem).PartOfDomain")
    if rc == 0:
        ev["domain_joined"] = out.strip().lower() == "true"

    return section_result(status, ev, errors)


def collect_scheduled_tasks_windows(profile: str) -> Dict[str, Any]:
    ev: Dict[str, Any] = {}
    errors: List[str] = []
    status = "ok"

    rc, out, _ = run_ps(
        "Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } "
        "| Select-Object TaskName,TaskPath,State,Author "
        "| ConvertTo-Json",
        timeout=60,
    )
    if rc == 0 and out:
        try:
            tasks = json.loads(out)
            # Redact secrets in task names/paths
            if isinstance(tasks, list):
                for t in tasks:
                    for k in ("TaskName", "TaskPath", "Author"):
                        if t.get(k):
                            t[k] = secrets.check_text(str(t[k]), f"scheduled_task:{t.get('TaskName','?')}")
            ev["scheduled_tasks"] = tasks
        except json.JSONDecodeError:
            ev["scheduled_tasks_raw"] = out[:5000]

    # Startup (Run keys)
    for key_path in [
        r"HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    ]:
        rc, out, _ = run_ps(f"Get-ItemProperty '{key_path}' 2>$null | ConvertTo-Json")
        if rc == 0 and out:
            try:
                parsed = json.loads(out)
                # Redact
                for k, v in list(parsed.items()):
                    if isinstance(v, str):
                        parsed[k] = secrets.check_text(v, f"registry:{key_path}\\{k}")
                ev[f"run_key_{key_path.split(chr(92))[-1]}"] = parsed
            except json.JSONDecodeError:
                pass

    return section_result(status, ev, errors)


def collect_storage_windows(profile: str) -> Dict[str, Any]:
    ev: Dict[str, Any] = {}
    errors: List[str] = []
    status = "ok"

    # Mapped drives / shares
    rc, out, _ = run_ps("Get-SmbMapping 2>$null | Select-Object LocalPath,RemotePath,Status | ConvertTo-Json")
    if rc == 0 and out:
        try:
            ev["smb_mappings"] = json.loads(out)
        except json.JSONDecodeError:
            pass

    rc, out, _ = run_ps("Get-SmbShare 2>$null | Select-Object Name,Path,Description | ConvertTo-Json")
    if rc == 0 and out:
        try:
            ev["smb_shares"] = json.loads(out)
        except json.JSONDecodeError:
            pass

    # Backup agents
    backup_svcs = ["VeeamBackupSvc", "VeeamTransportSvc", "Rubrik Backup Service",
                   "wbengine", "SQLWriter", "YOURBACKUPAGENT"]
    rc, out, _ = run_ps(
        "Get-Service | Where-Object { " +
        " -or ".join(f"$_.Name -like '*{s}*'" for s in backup_svcs) +
        " } | Select-Object Name,Status | ConvertTo-Json"
    )
    if rc == 0 and out:
        try:
            ev["backup_services"] = json.loads(out)
        except json.JSONDecodeError:
            pass

    return section_result(status, ev, errors)


def collect_certificates_windows(profile: str) -> Dict[str, Any]:
    ev: Dict[str, Any] = {}
    errors: List[str] = []
    status = "ok"

    rc, out, _ = run_ps(
        "Get-ChildItem Cert:\\LocalMachine\\My 2>$null | "
        "Select-Object Subject,Issuer,NotBefore,NotAfter,Thumbprint,"
        "HasPrivateKey,SignatureAlgorithm | ConvertTo-Json",
        timeout=30,
    )
    if rc == 0 and out:
        try:
            ev["machine_certs"] = json.loads(out)
        except json.JSONDecodeError:
            pass

    # Root CA count
    rc, out, _ = run_ps("(Get-ChildItem Cert:\\LocalMachine\\Root).Count")
    if rc == 0:
        ev["root_ca_count"] = out.strip()

    return section_result(status, ev, errors)


def collect_logs_windows(profile: str) -> Dict[str, Any]:
    ev: Dict[str, Any] = {}
    errors: List[str] = []
    status = "ok"

    # Event log sizes
    rc, out, _ = run_ps(
        "Get-WinEvent -ListLog Security,Application,System 2>$null | "
        "Select-Object LogName,RecordCount,MaximumSizeInBytes,IsEnabled | ConvertTo-Json"
    )
    if rc == 0 and out:
        try:
            ev["event_logs"] = json.loads(out)
        except json.JSONDecodeError:
            pass

    # Recent security events summary (counts by ID)
    if gate(profile, "standard"):
        rc, out, _ = run_ps(
            "$events = Get-WinEvent -FilterHashtable @{LogName='Security';StartTime=(Get-Date).AddDays(-7)} "
            "-MaxEvents 5000 -ErrorAction SilentlyContinue | Group-Object Id | "
            "Select-Object Name,Count | Sort-Object Count -Descending | Select-Object -First 20 | ConvertTo-Json",
            timeout=60,
        )
        if rc == 0 and out:
            try:
                ev["security_event_summary_7d"] = json.loads(out)
            except json.JSONDecodeError:
                pass

    return section_result(status, ev, errors)


def collect_containers_windows(profile: str) -> Dict[str, Any]:
    ev: Dict[str, Any] = {}
    errors: List[str] = []
    status = "ok"

    rc, out, _ = run_cmd(["docker", "version", "--format", "json"])
    if rc == 0 and out:
        try:
            ev["docker_version"] = json.loads(out)
        except json.JSONDecodeError:
            ev["docker_version_raw"] = out[:500]

        rc, out, _ = run_cmd(
            ["docker", "ps", "--format", "{{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}\t{{.Names}}"]
        )
        if rc == 0:
            containers = []
            for line in out.splitlines():
                parts = line.split("\t")
                if len(parts) >= 5:
                    containers.append({
                        "id": parts[0], "image": parts[1],
                        "status": parts[2], "ports": parts[3], "name": parts[4],
                    })
            ev["docker_containers"] = containers

    return section_result(status, ev, errors)


def collect_security_posture_windows(profile: str) -> Dict[str, Any]:
    ev: Dict[str, Any] = {}
    errors: List[str] = []
    status = "ok"

    # Windows Defender
    rc, out, _ = run_ps(
        "Get-MpComputerStatus 2>$null | Select-Object AntivirusEnabled,"
        "RealTimeProtectionEnabled,AntivirusSignatureLastUpdated,"
        "QuickScanEndTime | ConvertTo-Json"
    )
    if rc == 0 and out and "ConvertTo-Json" not in out:
        try:
            ev["windows_defender"] = json.loads(out)
        except json.JSONDecodeError:
            pass

    # EDR signals
    edr_svcs = ["CrowdStrike", "CSFalcon", "SentinelAgent", "SentinelOne",
                "CarbonBlack", "CbDefense", "Cylance", "Tanium"]
    rc, out, _ = run_ps(
        "Get-Service | Where-Object { " +
        " -or ".join(f"$_.Name -like '*{s}*'" for s in edr_svcs) +
        " } | Select-Object Name,Status | ConvertTo-Json"
    )
    if rc == 0 and out:
        try:
            ev["edr_services"] = json.loads(out)
        except json.JSONDecodeError:
            pass

    # BitLocker
    rc, out, _ = run_ps(
        "Get-BitLockerVolume 2>$null | Select-Object MountPoint,VolumeStatus,"
        "ProtectionStatus,EncryptionMethod | ConvertTo-Json"
    )
    if rc == 0 and out:
        try:
            ev["bitlocker"] = json.loads(out)
        except json.JSONDecodeError:
            pass

    # Password policy
    rc, out, _ = run_cmd(["net", "accounts"])
    if rc == 0:
        ev["password_policy"] = out[:1000]

    # RDP NLA
    rc, out, _ = run_ps(
        "(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp').UserAuthentication"
    )
    if rc == 0:
        ev["rdp_nla_enabled"] = out.strip() == "1"

    return section_result(status, ev, errors)


# ---------------------------------------------------------------------------
# Environment variable scanning (both platforms)
# ---------------------------------------------------------------------------
def collect_env_secrets() -> Dict[str, Any]:
    """Scan environment variables for secrets."""
    ev: Dict[str, str] = {}
    for name, value in os.environ.items():
        ev[name] = secrets.check_env_var(name, value)
    return ev


# ---------------------------------------------------------------------------
# Risk flags and upgrade planning generators
# ---------------------------------------------------------------------------

def generate_risk_flags(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Produce evidence-backed risk findings from the collected data."""
    flags: List[Dict[str, Any]] = []

    # --- EOL check ---
    os_info = report.get("os_version", {}).get("evidence", {})
    os_rel = os_info.get("os_release", {})
    os_id = os_rel.get("ID", "").lower()
    os_ver = os_rel.get("VERSION_ID", "")
    # Windows
    win_info = os_info.get("os_info", {})
    if isinstance(win_info, dict):
        caption = win_info.get("Caption", "").lower()
    else:
        caption = ""

    eol_key = None
    if os_id and os_ver:
        major = os_ver.split(".")[0]
        eol_key = f"{os_id}_{os_ver}"
        if eol_key not in EOL_MAP:
            eol_key = f"{os_id}_{major}"
    elif "2016" in caption:
        eol_key = "windows_server_2016"
    elif "2019" in caption:
        eol_key = "windows_server_2019"
    elif "2022" in caption:
        eol_key = "windows_server_2022"
    elif "2012 r2" in caption:
        eol_key = "windows_server_2012r2"
    elif "2012" in caption:
        eol_key = "windows_server_2012"

    if eol_key and eol_key in EOL_MAP:
        entry = EOL_MAP[eol_key]
        try:
            eol_date = datetime.datetime.strptime(entry["eol"], "%Y-%m-%d").date()
            if eol_date < datetime.date.today():
                flags.append({
                    "category": "eol",
                    "severity": "high",
                    "summary": f"OS appears end-of-life: {entry['name']} (EOL {entry['eol']})",
                    "confidence": "medium",
                    "evidence": f"Matched {eol_key} in built-in EOL table",
                })
            elif (eol_date - datetime.date.today()).days < 180:
                flags.append({
                    "category": "eol",
                    "severity": "medium",
                    "summary": f"OS approaching end-of-life: {entry['name']} (EOL {entry['eol']})",
                    "confidence": "medium",
                    "evidence": f"Matched {eol_key}, EOL in {(eol_date - datetime.date.today()).days} days",
                })
        except ValueError:
            pass
    elif eol_key:
        flags.append({
            "category": "eol",
            "severity": "info",
            "summary": f"OS EOL status unknown for {eol_key}",
            "confidence": "low",
            "evidence": "Not in built-in EOL mapping table",
        })

    # --- Listening on 0.0.0.0 / :: with common dangerous ports ---
    network = report.get("network", {}).get("evidence", {})
    listeners = network.get("listening_ports", [])
    risky_ports = {3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
                   9200: "Elasticsearch", 11211: "Memcached", 5672: "RabbitMQ"}
    for l in listeners:
        addr = l.get("local_addr", "")
        for port, svc_name in risky_ports.items():
            if f":{port}" in addr and ("0.0.0.0" in addr or ":::" in addr or "*:" in addr):
                flags.append({
                    "category": "network_exposure",
                    "severity": "high",
                    "summary": f"{svc_name} listening on all interfaces (port {port})",
                    "confidence": "high",
                    "evidence": f"Listener: {addr}",
                })

    # --- SSH hardening ---
    sec = report.get("security_posture", {}).get("evidence", {})
    ssh = sec.get("ssh_hardening", {})
    if ssh.get("PermitRootLogin", "").lower() in ("yes", "without-password"):
        flags.append({
            "category": "ssh",
            "severity": "high",
            "summary": f"SSH PermitRootLogin is '{ssh['PermitRootLogin']}'",
            "confidence": "high",
            "evidence": "sshd_config",
        })
    if ssh.get("PasswordAuthentication", "").lower() == "yes":
        flags.append({
            "category": "ssh",
            "severity": "medium",
            "summary": "SSH PasswordAuthentication is enabled",
            "confidence": "high",
            "evidence": "sshd_config",
        })

    # --- Firewall disabled ---
    fw_profiles = network.get("firewall_profiles", [])
    if isinstance(fw_profiles, list):
        for fp in fw_profiles:
            if isinstance(fp, dict) and fp.get("Enabled") is False:
                flags.append({
                    "category": "firewall",
                    "severity": "high",
                    "summary": f"Windows Firewall profile '{fp.get('Name', '?')}' is disabled",
                    "confidence": "high",
                    "evidence": "Get-NetFirewallProfile",
                })

    # --- No EDR ---
    edr = sec.get("edr_signals", sec.get("edr_services"))
    if not edr:
        flags.append({
            "category": "endpoint_protection",
            "severity": "medium",
            "summary": "No EDR/AV agent detected",
            "confidence": "low",
            "evidence": "No known EDR services found running",
        })

    # --- Certificate expiry ---
    certs = report.get("certificates", {}).get("evidence", {})
    for cf in certs.get("certificate_files", []):
        x509 = cf.get("x509_info", "")
        if "notAfter" in x509:
            for line in x509.splitlines():
                if "notAfter" in line:
                    try:
                        date_str = line.split("=", 1)[1].strip()
                        exp = datetime.datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
                        days_left = (exp.replace(tzinfo=datetime.timezone.utc) - datetime.datetime.now(datetime.timezone.utc)).days
                        if days_left < 0:
                            flags.append({
                                "category": "certificate",
                                "severity": "critical",
                                "summary": f"TLS cert EXPIRED ({cf.get('path', '?')})",
                                "confidence": "high",
                                "evidence": f"Expired {abs(days_left)} days ago",
                            })
                        elif days_left < 30:
                            flags.append({
                                "category": "certificate",
                                "severity": "high",
                                "summary": f"TLS cert expires in {days_left} days ({cf.get('path', '?')})",
                                "confidence": "high",
                                "evidence": f"notAfter={date_str}",
                            })
                    except (ValueError, IndexError):
                        pass

    # Windows certs
    for mc in certs.get("machine_certs", []) if isinstance(certs.get("machine_certs"), list) else []:
        not_after = mc.get("NotAfter")
        if not_after:
            # PowerShell date string: varies
            pass  # Could parse, but fragile. Skip for safety.

    # --- Secrets found ---
    if secrets.findings:
        flags.append({
            "category": "secrets",
            "severity": "high",
            "summary": f"{len(secrets.findings)} suspected secret(s) found on this system",
            "confidence": "varies",
            "evidence": "See secrets_findings section",
        })

    # --- Disk encryption ---
    de = sec.get("disk_encryption", {})
    if isinstance(de, dict) and de.get("luks_detected") is False:
        flags.append({
            "category": "disk_encryption",
            "severity": "info",
            "summary": "No LUKS disk encryption detected",
            "confidence": "low",
            "evidence": "lsblk output",
        })
    bl = sec.get("bitlocker")
    if isinstance(bl, list):
        for vol in bl:
            if isinstance(vol, dict) and vol.get("ProtectionStatus") == 0:
                flags.append({
                    "category": "disk_encryption",
                    "severity": "medium",
                    "summary": f"BitLocker protection OFF on {vol.get('MountPoint', '?')}",
                    "confidence": "high",
                    "evidence": "Get-BitLockerVolume",
                })

    return flags


def generate_upgrade_planning(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Generate upgrade recommendations (labelled as recommendations)."""
    recs: List[Dict[str, Any]] = []

    # OS version
    os_ev = report.get("os_version", {}).get("evidence", {})
    os_rel = os_ev.get("os_release", {})
    if os_rel:
        recs.append({
            "component": "Operating System",
            "current_version": f"{os_rel.get('NAME', '?')} {os_rel.get('VERSION', '?')}",
            "recommendation": "Review against vendor support lifecycle",
            "type": "recommendation",
        })

    # Kernel
    kernel = os_ev.get("kernel", "")
    if kernel:
        recs.append({
            "component": "Kernel",
            "current_version": kernel,
            "recommendation": "Ensure kernel receives security patches",
            "type": "recommendation",
        })

    # Language runtimes
    sw_ev = report.get("software_inventory", {}).get("evidence", {})
    for name, info in sw_ev.get("language_runtimes", {}).items():
        recs.append({
            "component": f"Runtime: {name}",
            "current_version": info.get("version", "?"),
            "recommendation": "Verify version is within vendor support window",
            "type": "recommendation",
        })

    # OpenSSL
    ossl = sw_ev.get("openssl_version", "")
    if ossl:
        recs.append({
            "component": "OpenSSL",
            "current_version": ossl,
            "recommendation": "Ensure version is patched and supported",
            "type": "recommendation",
        })

    return recs


# ---------------------------------------------------------------------------
# Report generators: Markdown + HTML
# ---------------------------------------------------------------------------

def json_to_markdown(report: Dict[str, Any]) -> str:
    """Convert the JSON report to a human-readable Markdown report."""
    lines: List[str] = []
    meta = report.get("collection_meta", {})

    lines.append(f"# Server Audit Report")
    lines.append(f"")
    lines.append(f"**Host:** {meta.get('hostname', '?')} ({meta.get('fqdn', '?')})")
    lines.append(f"**Generated:** {meta.get('collection_time', '?')}")
    lines.append(f"**Script version:** {meta.get('script_version', '?')} | Schema: {report.get('schema_version', '?')}")
    lines.append(f"**Run as:** {meta.get('user', '?')} | Privilege: {meta.get('privilege_level', '?')}")
    lines.append(f"**Profile:** {meta.get('profile', '?')} | Runtime: {meta.get('runtime_seconds', '?')}s")
    lines.append(f"**OS:** {meta.get('os', '?')} {meta.get('os_version_short', '?')}")
    lines.append("")

    # Risk flags
    flags = report.get("risk_flags", [])
    if flags:
        lines.append("## Risk Flags")
        lines.append("")
        for f in flags:
            sev = f.get("severity", "?").upper()
            lines.append(f"- **[{sev}]** {f.get('summary', '?')} _(confidence: {f.get('confidence', '?')})_")
            lines.append(f"  - Evidence: {f.get('evidence', 'N/A')}")
        lines.append("")

    # Secrets findings
    sf = report.get("secrets_findings", [])
    if sf:
        lines.append("## Suspected Secrets Found")
        lines.append("")
        for s in sf:
            lines.append(f"- **{s.get('secret_type', '?')}** at `{s.get('location', '?')}` "
                         f"(confidence: {s.get('confidence', '?')})")
            lines.append(f"  - Hint: {s.get('evidence_hint', 'N/A')}")
        lines.append("")

    # Sections
    section_order = [
        ("system_identity", "System Identity & Platform"),
        ("os_version", "OS Versioning & Patch State"),
        ("software_inventory", "Installed Software Inventory"),
        ("services", "Running Services & Config"),
        ("network", "Network Exposure"),
        ("users", "Users, Groups & Identity"),
        ("scheduled_tasks", "Scheduled Tasks & Persistence"),
        ("storage", "Storage & Backups"),
        ("certificates", "Certificates & TLS"),
        ("logs", "Logs & Audit Evidence"),
        ("containers", "Containers & Orchestration"),
        ("security_posture", "Security Posture"),
    ]
    for key, title in section_order:
        section = report.get(key, {})
        if not section:
            continue
        st = section.get("status", "?")
        lines.append(f"## {title}")
        lines.append(f"")
        lines.append(f"**Status:** {st}")
        if section.get("errors"):
            lines.append(f"**Errors:** {', '.join(section['errors'])}")
        lines.append("")
        ev = section.get("evidence", {})
        # Render key fields
        for k, v in ev.items():
            if isinstance(v, (dict, list)):
                rendered = json.dumps(v, indent=2, default=str)
                if len(rendered) > 2000:
                    rendered = rendered[:2000] + "\n... (truncated)"
                lines.append(f"### {k}")
                lines.append(f"```json")
                lines.append(rendered)
                lines.append(f"```")
            else:
                val_str = str(v)
                if len(val_str) > 500:
                    val_str = val_str[:500] + "... (truncated)"
                lines.append(f"- **{k}:** {val_str}")
        lines.append("")

    # Upgrade planning
    up = report.get("upgrade_planning", [])
    if up:
        lines.append("## Upgrade Planning (Recommendations)")
        lines.append("")
        for item in up:
            lines.append(f"- **{item.get('component', '?')}**: {item.get('current_version', '?')} → "
                         f"_{item.get('recommendation', '?')}_")
        lines.append("")

    # Data minimization
    dm = report.get("data_minimization", {})
    if dm:
        lines.append("## Data Minimization Note")
        lines.append("")
        for k, v in dm.items():
            lines.append(f"- {k}: {v}")
        lines.append("")

    lines.append("---")
    lines.append("*Report generated by server_audit.py*")
    return "\n".join(lines)


def json_to_html(report: Dict[str, Any]) -> str:
    """Convert the JSON report to a self-contained HTML report."""
    md_content = json_to_markdown(report)
    meta = report.get("collection_meta", {})
    hostname = html_mod.escape(meta.get("hostname", "unknown"))

    # Simple Markdown → HTML conversion (no external deps)
    def md_to_html_simple(md: str) -> str:
        """Very basic Markdown to HTML — handles headers, bold, code blocks, lists."""
        html_lines = []
        in_code = False
        in_list = False
        for line in md.splitlines():
            if line.startswith("```"):
                if in_code:
                    html_lines.append("</pre>")
                    in_code = False
                else:
                    if in_list:
                        html_lines.append("</ul>")
                        in_list = False
                    lang = line[3:].strip()
                    html_lines.append(f'<pre class="code-block">')
                    in_code = True
                continue
            if in_code:
                html_lines.append(html_mod.escape(line))
                continue
            # Headers
            if line.startswith("# "):
                if in_list:
                    html_lines.append("</ul>"); in_list = False
                html_lines.append(f"<h1>{html_mod.escape(line[2:])}</h1>")
            elif line.startswith("## "):
                if in_list:
                    html_lines.append("</ul>"); in_list = False
                html_lines.append(f"<h2>{html_mod.escape(line[3:])}</h2>")
            elif line.startswith("### "):
                if in_list:
                    html_lines.append("</ul>"); in_list = False
                html_lines.append(f"<h3>{html_mod.escape(line[4:])}</h3>")
            elif line.startswith("- "):
                if not in_list:
                    html_lines.append("<ul>"); in_list = True
                content = line[2:]
                # Bold
                content = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', content)
                content = re.sub(r'_(.+?)_', r'<em>\1</em>', content)
                content = re.sub(r'`(.+?)`', r'<code>\1</code>', content)
                html_lines.append(f"<li>{content}</li>")
            elif line.startswith("---"):
                if in_list:
                    html_lines.append("</ul>"); in_list = False
                html_lines.append("<hr>")
            elif line.strip() == "":
                if in_list:
                    html_lines.append("</ul>"); in_list = False
                html_lines.append("<br>")
            else:
                if in_list:
                    html_lines.append("</ul>"); in_list = False
                processed = line
                processed = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', processed)
                processed = re.sub(r'_(.+?)_', r'<em>\1</em>', processed)
                processed = re.sub(r'`(.+?)`', r'<code>\1</code>', processed)
                html_lines.append(f"<p>{processed}</p>")
        if in_code:
            html_lines.append("</pre>")
        if in_list:
            html_lines.append("</ul>")
        return "\n".join(html_lines)

    body = md_to_html_simple(md_content)

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Server Audit — {hostname}</title>
<style>
  :root {{ --bg: #f8f9fa; --card: #fff; --text: #212529; --border: #dee2e6;
           --accent: #0d6efd; --danger: #dc3545; --warn: #ffc107; --ok: #198754; }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
          background: var(--bg); color: var(--text); line-height: 1.6; padding: 2rem; max-width: 1200px; margin: auto; }}
  h1 {{ color: var(--accent); border-bottom: 3px solid var(--accent); padding-bottom: 0.5rem; margin-bottom: 1rem; }}
  h2 {{ color: #495057; border-bottom: 1px solid var(--border); padding-bottom: 0.3rem;
        margin-top: 2rem; margin-bottom: 0.5rem; }}
  h3 {{ color: #6c757d; margin-top: 1rem; margin-bottom: 0.3rem; }}
  p {{ margin-bottom: 0.5rem; }}
  ul {{ padding-left: 1.5rem; margin-bottom: 0.5rem; }}
  li {{ margin-bottom: 0.3rem; }}
  code {{ background: #e9ecef; padding: 0.15rem 0.4rem; border-radius: 3px; font-size: 0.9em; }}
  pre.code-block {{ background: #212529; color: #f8f9fa; padding: 1rem; border-radius: 6px;
                    overflow-x: auto; font-size: 0.85em; margin: 0.5rem 0 1rem 0; white-space: pre-wrap; word-break: break-all; }}
  strong {{ color: #343a40; }}
  hr {{ border: none; border-top: 2px solid var(--border); margin: 2rem 0; }}
  .severity-CRITICAL, .severity-HIGH {{ color: var(--danger); font-weight: bold; }}
  .severity-MEDIUM {{ color: #e67e22; font-weight: bold; }}
  .severity-LOW, .severity-INFO {{ color: #6c757d; }}
  @media print {{ body {{ padding: 0; }} pre.code-block {{ white-space: pre-wrap; }} }}
</style>
</head>
<body>
{body}
</body>
</html>"""
    return html_doc


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

def build_collection_meta(start_time: float, profile: str, checks: List[str]) -> Dict[str, Any]:
    meta: Dict[str, Any] = {}
    meta["hostname"] = socket.gethostname()
    try:
        meta["fqdn"] = socket.getfqdn()
    except Exception:
        meta["fqdn"] = meta["hostname"]
    meta["os"] = platform.system()
    meta["os_version_short"] = platform.platform()
    meta["kernel"] = platform.release()
    meta["collection_time"] = now_iso()
    meta["timezone"] = str(time.tzname)
    meta["script_version"] = __version__
    meta["user"] = getpass.getuser()
    # Privilege level
    if IS_LINUX:
        meta["privilege_level"] = "root" if os.geteuid() == 0 else "unprivileged"
    elif IS_WINDOWS:
        try:
            import ctypes
            meta["privilege_level"] = "admin" if ctypes.windll.shell32.IsUserAnAdmin() else "standard"
        except Exception:
            meta["privilege_level"] = "unknown"
    else:
        meta["privilege_level"] = "unknown"
    meta["profile"] = profile
    meta["runtime_seconds"] = round(time.time() - start_time, 2)
    meta["checks_executed"] = checks
    return meta


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Production-ready, read-only server audit collector.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python3 server_audit.py --output-dir /tmp/audit
              python3 server_audit.py --output-dir /tmp/audit --profile deep --verbose
              python3 server_audit.py --output-dir C:\\audit --formats json,md
              python3 server_audit.py --output-dir /tmp/audit --safe-mode
        """),
    )
    parser.add_argument("--output-dir", required=True, help="Directory to write report files")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--safe-mode", action="store_true", help="Extra conservative data capture")
    parser.add_argument("--profile", choices=["minimal", "standard", "deep"], default="standard",
                        help="Collection depth (default: standard)")
    parser.add_argument("--formats", default="json,md,html",
                        help="Comma-separated output formats: json,md,html (default: json,md,html)")
    parser.add_argument("--version", action="version", version=f"server_audit.py {__version__}")
    args = parser.parse_args()

    setup_logging(args.verbose)
    global secrets
    secrets = SecretFinder()

    start_time = time.time()
    profile = args.profile
    if args.safe_mode:
        profile = "minimal"
        log.info("Safe mode enabled — using minimal profile")

    formats = [f.strip().lower() for f in args.formats.split(",")]
    for fmt in formats:
        if fmt not in ("json", "md", "html"):
            log.error(f"Unknown format: {fmt}")
            return 1

    # Ensure output dir exists
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    report: Dict[str, Any] = {}
    report["schema_version"] = SCHEMA_VERSION
    checks: List[str] = []
    overall_status = "ok"

    # ---- Select collectors based on OS ----
    if IS_LINUX:
        collectors = [
            ("system_identity", collect_system_identity_linux),
            ("os_version", collect_os_version_linux),
            ("software_inventory", collect_software_inventory_linux),
            ("services", collect_services_linux),
            ("network", collect_network_linux),
            ("users", collect_users_linux),
            ("scheduled_tasks", collect_scheduled_tasks_linux),
            ("storage", collect_storage_linux),
            ("certificates", collect_certificates_linux),
            ("logs", collect_logs_linux),
            ("containers", collect_containers_linux),
            ("security_posture", collect_security_posture_linux),
        ]
    elif IS_WINDOWS:
        collectors = [
            ("system_identity", collect_system_identity_windows),
            ("os_version", collect_os_version_windows),
            ("software_inventory", collect_software_inventory_windows),
            ("services", collect_services_windows),
            ("network", collect_network_windows),
            ("users", collect_users_windows),
            ("scheduled_tasks", collect_scheduled_tasks_windows),
            ("storage", collect_storage_windows),
            ("certificates", collect_certificates_windows),
            ("logs", collect_logs_windows),
            ("containers", collect_containers_windows),
            ("security_posture", collect_security_posture_windows),
        ]
    else:
        log.error(f"Unsupported platform: {platform.system()}")
        return 2

    # ---- Run collectors ----
    for name, func in collectors:
        log.info(f"Collecting: {name}")
        try:
            result = func(profile)
            report[name] = result
            checks.append(name)
            if result.get("status") != "ok":
                overall_status = merge_status(overall_status, result["status"])
        except Exception as exc:
            log.error(f"Collector {name} failed: {exc}")
            if args.verbose:
                traceback.print_exc(file=sys.stderr)
            report[name] = section_result("fail", {}, [str(exc)])
            checks.append(f"{name}(FAILED)")
            overall_status = merge_status(overall_status, "fail")

    # ---- Environment secret scan ----
    log.info("Scanning environment variables for secrets")
    report["environment_variables"] = collect_env_secrets()

    # ---- Generate risk flags & upgrade planning ----
    report["risk_flags"] = generate_risk_flags(report)
    report["upgrade_planning"] = generate_upgrade_planning(report)

    # ---- Secret findings ----
    report["secrets_findings"] = secrets.findings

    # ---- Data minimization note ----
    report["data_minimization"] = {
        "secrets_redacted": True,
        "secret_values_never_stored": True,
        "full_config_files_excluded": True,
        "password_hashes_excluded": True,
        "private_keys_excluded": True,
        "only_safe_metadata_collected": True,
    }

    # ---- Collection metadata ----
    report["collection_meta"] = build_collection_meta(start_time, profile, checks)

    # ---- Write outputs ----
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    hostname = socket.gethostname().replace(" ", "_").replace("/", "_")[:50]
    base = f"audit_{hostname}_{timestamp}"

    written_files = []

    if "json" in formats:
        json_path = out_dir / f"{base}.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str, ensure_ascii=False)
        log.info(f"JSON report: {json_path}")
        written_files.append(str(json_path))

    if "md" in formats:
        md_path = out_dir / f"{base}.md"
        md_content = json_to_markdown(report)
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md_content)
        log.info(f"Markdown report: {md_path}")
        written_files.append(str(md_path))

    if "html" in formats:
        html_path = out_dir / f"{base}.html"
        html_content = json_to_html(report)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        log.info(f"HTML report: {html_path}")
        written_files.append(str(html_path))

    # ---- Summary ----
    runtime = round(time.time() - start_time, 2)
    print(f"\n{'='*60}", file=sys.stderr)
    print(f"Audit complete — {runtime}s — status: {overall_status}", file=sys.stderr)
    for wf in written_files:
        print(f"  → {wf}", file=sys.stderr)
    print(f"{'='*60}", file=sys.stderr)

    if args.verbose and secrets.findings:
        print(f"\nTotal suspected secrets found: {len(secrets.findings)} "
              f"(see secrets_findings in JSON)", file=sys.stderr)

    # Exit code
    if overall_status == "ok":
        return 0
    elif overall_status == "partial":
        return 3
    else:
        return 1


if __name__ == "__main__":
    sys.exit(main())
