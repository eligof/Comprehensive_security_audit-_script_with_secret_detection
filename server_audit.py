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
License: MIT
"""

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
from typing import Any, Dict, List, Optional, Tuple, Union

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
REDACTED = "[REDACTED]"
SECRET_WARNING_PREFIX = "WARNING SECRET FOUND!"

# Patterns that strongly suggest a secret value
SECRET_PATTERNS: List[Tuple[Any, str, str]] = [
    (re.compile(r"-----BEGIN\s+(RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", re.I), "private_key", "high"),
    (re.compile(r"AKIA[0-9A-Z]{16}", re.I), "aws_access_key", "high"),
    (re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*\S+"), "password_assignment", "medium"),
    (re.compile(r"(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*\S+"), "api_key_or_token", "medium"),
    (re.compile(r"(?i)(connection[_-]?string|conn[_-]?str)\s*[:=]\s*\S+"), "connection_string", "medium"),
    (re.compile(r"(?i)(private[_-]?key|client[_-]?secret)\s*[:=]\s*\S+"), "credential", "medium"),
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*", re.I), "bearer_token", "medium"),
    (re.compile(r"ghp_[A-Za-z0-9]{36,}"), "github_pat", "high"),
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "openai_key_like", "medium"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+"), "jwt", "high"),
    (re.compile(r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/@]+:[^\s/@]+@"), "url_credentials", "high"),
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

# User / permission audit constants
DISABLED_SHELLS = [
    "/sbin/nologin", "/usr/sbin/nologin",
    "/bin/false", "/usr/bin/false",
    "/bin/sync", "/usr/bin/sync",
]

PRIVILEGED_GROUPS = ["sudo", "wheel", "admin", "root", "docker", "lxd", "adm", "shadow"]

SENSITIVE_FILES = [
    # (path, expected_perms, expected_owner, expected_group)
    ("/etc/shadow",           "0640", "root", "shadow"),
    ("/etc/shadow-",          "0640", "root", "shadow"),
    ("/etc/passwd",           "0644", "root", "root"),
    ("/etc/passwd-",          "0644", "root", "root"),
    ("/etc/group",            "0644", "root", "root"),
    ("/etc/group-",           "0644", "root", "root"),
    ("/etc/gshadow",          "0640", "root", "shadow"),
    ("/etc/gshadow-",         "0640", "root", "shadow"),
    ("/etc/sudoers",          "0440", "root", "root"),
    ("/etc/ssh/sshd_config",  "0600", "root", "root"),
    ("/etc/crontab",          "0644", "root", "root"),
]

SUID_SAFE_LIST = [
    "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd", "/usr/bin/chsh",
    "/usr/bin/chfn", "/usr/bin/newgrp", "/usr/bin/gpasswd", "/usr/bin/mount",
    "/usr/bin/umount", "/usr/bin/fusermount", "/usr/bin/fusermount3",
    "/usr/bin/pkexec", "/usr/bin/crontab", "/usr/bin/at",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/lib/openssh/ssh-keysign",
    "/usr/lib/policykit-1/polkit-agent-helper-1",
    "/usr/libexec/polkit-agent-helper-1",
    "/usr/bin/ssh-agent",
    "/usr/sbin/unix_chkpwd",
    "/usr/sbin/pam_extrausers_chkpwd",
    "/bin/su", "/bin/mount", "/bin/umount", "/bin/ping", "/bin/ping6",
    "/usr/bin/ping", "/usr/bin/traceroute6.iputils",
    "/snap/core/",  # prefix match
]

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
    cmd: Union[List[str], str],
    timeout: int = 30,
    shell: bool = False,
    env: Optional[dict] = None,
) -> Tuple[int, str, str]:
    """Run a command, return (returncode, stdout, stderr). Never raises."""
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
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


def section_result(status: str = "ok", evidence: Any = None, errors: Optional[list] = None) -> Dict[str, Any]:
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
    def _safe_hint(match: Any, stype: str) -> str:
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


def is_suid_safe(path: str) -> bool:
    """Check if a SUID binary is in the known-safe list."""
    for safe in SUID_SAFE_LIST:
        if safe.endswith("/"):
            if path.startswith(safe):
                return True
        elif path == safe:
            return True
    return False


# ---------------------------------------------------------------------------
# User audit helpers
# ---------------------------------------------------------------------------

def _parse_passwd_status(line: str) -> Dict[str, Any]:
    """Parse output of `passwd -S username`."""
    parts = line.split()
    if len(parts) < 2:
        return {"locked": None, "password_status": "unknown", "password_status_raw": line}
    status_code = parts[1]
    locked = status_code in ("L", "LK")
    no_password = status_code in ("NP",)
    result: Dict[str, Any] = {
        "locked": locked,
        "no_password": no_password,
        "password_status": status_code,
        "password_status_raw": line,
    }
    if len(parts) >= 3:
        result["last_password_change"] = parts[2]
    return result


def _parse_chage_output(output: str) -> Dict[str, Any]:
    """Parse output of `chage -l username`."""
    info: Dict[str, Any] = {}
    for line in output.splitlines():
        line = line.strip()
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        key = key.strip().lower()
        val = val.strip()
        if "account expires" in key:
            info["account_expires"] = val
            info["expired"] = False
            if val.lower() not in ("never", ""):
                try:
                    for fmt in ("%b %d, %Y", "%Y-%m-%d", "%B %d, %Y"):
                        try:
                            exp_date = datetime.datetime.strptime(val, fmt)
                            if exp_date < datetime.datetime.now():
                                info["expired"] = True
                            break
                        except ValueError:
                            continue
                except Exception:
                    pass
        elif "password expires" in key:
            info["password_expires"] = val
        elif "last password change" in key:
            info["last_password_change_chage"] = val
    return info


def _get_last_login(username: str) -> Dict[str, Any]:
    """Get last login info for a user."""
    rc, out, _ = run_cmd(["lastlog", "-u", username])
    if rc == 0 and out:
        lines = out.splitlines()
        if len(lines) >= 2:
            data = lines[-1]
            if "**Never logged in**" in data:
                return {"last_login_time": "never", "source": "lastlog"}
            parts = data.split()
            if len(parts) >= 4:
                return {
                    "last_login_from": parts[2] if len(parts) > 2 else "",
                    "last_login_time": " ".join(parts[3:]) if len(parts) > 3 else "unknown",
                    "source": "lastlog",
                }
    # Fallback to last
    rc, out, _ = run_cmd(["last", "-n", "1", "-w", username])
    if rc == 0 and out:
        lines = out.strip().splitlines()
        if lines and not lines[0].startswith("wtmp"):
            parts = lines[0].split()
            if len(parts) >= 4:
                return {
                    "last_login_from": parts[2] if len(parts) > 2 else "",
                    "last_login_time": " ".join(parts[3:7]) if len(parts) > 3 else "unknown",
                    "source": "last",
                }
    return {"last_login_time": "unknown", "source": "none"}


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
    """F) Users, groups, identity controls, sudo, and SSH keys on Linux."""
    ev: Dict[str, Any] = {}
    errors: List[str] = []
    status = "ok"

    # ---- Local users from /etc/passwd ----
    users = []
    try:
        with open("/etc/passwd", "r") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 7:
                    uid = int(parts[2])
                    shell = parts[6]
                    users.append({
                        "username": parts[0],
                        "uid": uid,
                        "gid": int(parts[3]),
                        "gecos": parts[4],
                        "home": parts[5],
                        "shell": shell,
                        "disabled_shell": shell in DISABLED_SHELLS,
                        "user_type": "root" if uid == 0 else ("human" if uid >= 1000 else "system"),
                    })
    except PermissionError:
        errors.append("Cannot read /etc/passwd")
        status = "partial"
    except Exception as exc:
        errors.append(f"Error reading /etc/passwd: {exc}")
        status = "partial"

    # Account status via passwd -S and chage -l
    if gate(profile, "standard"):
        for user in users:
            rc, out, _ = run_cmd(["passwd", "-S", user["username"]])
            if rc == 0 and out:
                user["account_status"] = _parse_passwd_status(out)
            else:
                user["account_status"] = {"locked": None, "password_status": "unknown"}
            rc, out, _ = run_cmd(["chage", "-l", user["username"]])
            if rc == 0 and out:
                user["account_status"].update(_parse_chage_output(out))
            user["last_login"] = _get_last_login(user["username"])

    # Classify users
    human_users = [u["username"] for u in users if u["user_type"] == "human"]
    system_users = [u["username"] for u in users if u["user_type"] == "system"]
    login_shell_users = [u["username"] for u in users if not u["disabled_shell"]]
    locked_users = [u["username"] for u in users
                    if u.get("account_status", {}).get("locked") is True]

    ev["local_users"] = users
    ev["local_user_count"] = len(users)
    ev["human_users"] = human_users
    ev["system_users"] = system_users
    ev["users_with_login_shell"] = login_shell_users
    ev["locked_users"] = locked_users

    # ---- Groups from /etc/group ----
    groups = []
    try:
        with open("/etc/group", "r") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 4:
                    groups.append({
                        "name": parts[0],
                        "gid": int(parts[2]),
                        "members": [m for m in parts[3].split(",") if m],
                    })
    except PermissionError:
        errors.append("Cannot read /etc/group")
        status = merge_status(status, "partial")
    ev["local_groups"] = groups
    ev["group_count"] = len(groups)

    # Privileged group membership
    privileged_groups: Dict[str, List[str]] = {}
    for g in groups:
        if g["name"] in PRIVILEGED_GROUPS:
            privileged_groups[g["name"]] = g["members"]
    ev["privileged_groups"] = privileged_groups

    sudo_group_members = list(set(
        privileged_groups.get("sudo", []) +
        privileged_groups.get("wheel", []) +
        privileged_groups.get("admin", [])
    ))
    ev["sudo_group_members"] = sorted(sudo_group_members)

    # ---- Sudoers (safe excerpts) ----
    if gate(profile, "standard"):
        sudoers_path = "/etc/sudoers"
        if os.path.exists(sudoers_path):
            ev["sudoers_meta"] = file_meta(sudoers_path)
            lines = safe_read_lines(sudoers_path, 200)
            if lines and lines[0] == "[permission_denied]":
                errors.append("Cannot read /etc/sudoers (need root)")
                status = merge_status(status, "partial")
                ev["sudoers_effective_lines"] = ["[permission_denied]"]
            else:
                safe_lines = [l for l in lines if l.strip() and not l.strip().startswith("#")]
                ev["sudoers_effective_lines"] = secrets.check_file_content(sudoers_path, safe_lines)

        # sudoers.d directory
        sudoers_d = "/etc/sudoers.d"
        sudoers_d_entries: Dict[str, List[str]] = {}
        sudoers_d_files: List[str] = []
        if os.path.isdir(sudoers_d):
            try:
                for fname in sorted(os.listdir(sudoers_d)):
                    fpath = os.path.join(sudoers_d, fname)
                    if os.path.isfile(fpath):
                        sudoers_d_files.append(fname)
                        flines = safe_read_lines(fpath, 100)
                        if flines and flines[0] == "[permission_denied]":
                            sudoers_d_entries[fname] = ["[permission_denied]"]
                        else:
                            effective = [l for l in flines if l.strip() and not l.strip().startswith("#")]
                            sudoers_d_entries[fname] = secrets.check_file_content(fpath, effective)
            except PermissionError:
                errors.append("Cannot list /etc/sudoers.d/")
                status = merge_status(status, "partial")
        ev["sudoers_d_files"] = sudoers_d_files
        ev["sudoers_d_entries"] = sudoers_d_entries

        # Detect NOPASSWD users
        nopasswd_users: List[str] = []
        all_sudoers_lines = ev.get("sudoers_effective_lines", [])
        for entries in sudoers_d_entries.values():
            all_sudoers_lines = all_sudoers_lines + entries
        for sline in all_sudoers_lines:
            if "NOPASSWD" in sline.upper():
                sparts = sline.split()
                if sparts and sparts[0] not in ("%", "#", "Defaults", REDACTED, "[permission_denied]"):
                    uname = sparts[0].lstrip("%")
                    if uname:
                        nopasswd_users.append(uname)
        ev["nopasswd_users"] = sorted(set(nopasswd_users))

        # All privileged users
        all_priv = set(sudo_group_members)
        for sline in all_sudoers_lines:
            sparts = sline.split()
            if sparts and "ALL" in sline and sparts[0] not in ("#", "Defaults", REDACTED, "[permission_denied]"):
                uname = sparts[0].lstrip("%")
                if uname:
                    all_priv.add(uname)
        all_priv.add("root")
        ev["all_privileged_users"] = sorted(all_priv)

    # ---- SSH authorized keys inventory ----
    if gate(profile, "standard"):
        auth_keys = []
        for user in users:
            home = user.get("home", "")
            if not home or not os.path.isdir(home):
                continue
            ssh_dir = os.path.join(home, ".ssh")
            for ak_name in ["authorized_keys", "authorized_keys2"]:
                ak_path = os.path.join(ssh_dir, ak_name)
                if not os.path.exists(ak_path):
                    continue
                entry: Dict[str, Any] = {
                    "user": user["username"],
                    "path": ak_path,
                    "file_meta": file_meta(ak_path),
                }
                if os.path.isdir(ssh_dir):
                    ssh_meta = file_meta(ssh_dir)
                    entry["ssh_dir_permissions"] = ssh_meta.get("permissions", "unknown")
                lines = safe_read_lines(ak_path, 100)
                key_lines = [l for l in lines if l.strip() and not l.strip().startswith("#") and l != "[permission_denied]"]
                entry["key_count"] = len(key_lines)
                rc, fp_out, _ = run_cmd(["ssh-keygen", "-lf", ak_path])
                entry["fingerprints"] = fp_out.splitlines()[:50] if rc == 0 and fp_out else []
                auth_keys.append(entry)

        ev["ssh_authorized_keys"] = auth_keys
        ev["users_with_authorized_keys"] = sorted(set(e["user"] for e in auth_keys))
        ev["total_authorized_keys"] = sum(e["key_count"] for e in auth_keys)

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


def collect_file_permissions_linux(profile: str) -> Dict[str, Any]:
    """F2) Sensitive file permission compliance and home directory auditing on Linux."""
    ev: Dict[str, Any] = {}
    errors: List[str] = []
    status = "ok"

    # Sensitive system files
    sensitive_results: List[Dict[str, Any]] = []
    non_compliant = 0
    for path, expected_perms, expected_owner, expected_group in SENSITIVE_FILES:
        meta = file_meta(path)
        if not meta.get("exists"):
            sensitive_results.append({"path": path, "exists": False, "expected_permissions": expected_perms, "compliant": True})
            continue
        actual_perms = meta.get("permissions", "")
        actual_owner = meta.get("owner", "")
        actual_group = meta.get("group", "")
        perms_ok = True
        if actual_perms and expected_perms:
            try:
                actual_int = int(actual_perms, 8)
                expected_int = int(expected_perms, 8)
                perms_ok = (actual_int & ~expected_int) == 0
            except ValueError:
                perms_ok = actual_perms == expected_perms
        owner_ok = actual_owner == expected_owner if actual_owner else True
        group_ok = actual_group == expected_group if actual_group else True
        compliant = perms_ok and owner_ok and group_ok
        if not compliant:
            non_compliant += 1
        sensitive_results.append({
            "path": path, "exists": True,
            "permissions": actual_perms, "owner": actual_owner, "group": actual_group,
            "expected_permissions": expected_perms, "expected_owner": expected_owner, "expected_group": expected_group,
            "compliant": compliant,
        })
    ev["sensitive_files"] = sensitive_results
    ev["non_compliant_count"] = non_compliant

    # Home directory permissions
    if gate(profile, "standard"):
        home_results: List[Dict[str, Any]] = []
        try:
            with open("/etc/passwd", "r") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 7:
                        home = parts[5]
                        if not home or not os.path.isdir(home) or home in ("/", "/nonexistent", "/dev/null"):
                            continue
                        meta = file_meta(home)
                        perms = meta.get("permissions", "")
                        world_writable = False
                        if perms:
                            try:
                                mode = int(perms, 8)
                                world_writable = bool(mode & 0o002)
                            except ValueError:
                                pass
                        home_results.append({
                            "user": parts[0], "path": home,
                            "permissions": perms, "owner": meta.get("owner", ""),
                            "world_writable": world_writable,
                        })
        except Exception:
            pass
        ev["home_directory_permissions"] = home_results

    # World-writable paths
    ww_results: List[Dict[str, Any]] = []
    for ww_path in ["/tmp", "/var/tmp", "/dev/shm"]:
        if not os.path.exists(ww_path):
            continue
        meta = file_meta(ww_path)
        perms = meta.get("permissions", "")
        sticky = False
        if perms:
            try:
                sticky = bool(int(perms, 8) & 0o1000)
            except ValueError:
                pass
        ww_results.append({"path": ww_path, "permissions": perms, "sticky_bit": sticky})
    ev["world_writable_paths"] = ww_results

    return section_result(status, ev, errors)


def collect_suid_sgid_linux(profile: str, suid_timeout: int = 60) -> Dict[str, Any]:
    """F3) Find SUID and SGID binaries on Linux."""
    ev: Dict[str, Any] = {}
    errors: List[str] = []
    status = "ok"

    if not gate(profile, "standard"):
        return section_result("ok", {"skipped": "profile too low"}, [])

    # SUID
    rc, out, err = run_cmd(
        ["find", "/", "-perm", "-4000", "-type", "f",
         "-not", "-path", "/proc/*", "-not", "-path", "/sys/*", "-not", "-path", "/snap/*"],
        timeout=suid_timeout,
    )
    suid_list: List[Dict[str, Any]] = []
    if rc == 0 and out:
        for p in out.splitlines():
            p = p.strip()
            if not p:
                continue
            meta = file_meta(p)
            suid_list.append({
                "path": p, "permissions": meta.get("permissions", ""),
                "owner": meta.get("owner", ""), "group": meta.get("group", ""),
                "known_safe": is_suid_safe(p),
            })
    elif rc == -2:
        errors.append(f"SUID scan timed out after {suid_timeout}s (partial results)")
        status = "partial"
    elif rc != 0 and err:
        errors.append(f"SUID scan issue: {err[:200]}")

    # SGID
    rc2, out2, err2 = run_cmd(
        ["find", "/", "-perm", "-2000", "-type", "f",
         "-not", "-path", "/proc/*", "-not", "-path", "/sys/*", "-not", "-path", "/snap/*"],
        timeout=suid_timeout,
    )
    sgid_list: List[Dict[str, Any]] = []
    if rc2 == 0 and out2:
        for p in out2.splitlines():
            p = p.strip()
            if not p:
                continue
            meta = file_meta(p)
            sgid_list.append({
                "path": p, "permissions": meta.get("permissions", ""),
                "owner": meta.get("owner", ""), "group": meta.get("group", ""),
            })
    elif rc2 == -2:
        errors.append(f"SGID scan timed out after {suid_timeout}s")
        status = merge_status(status, "partial")

    unknown_suid = [s for s in suid_list if not s["known_safe"]]
    ev["suid_binaries"] = suid_list
    ev["sgid_binaries"] = sgid_list
    ev["suid_count"] = len(suid_list)
    ev["sgid_count"] = len(sgid_list)
    ev["unknown_suid_count"] = len(unknown_suid)
    ev["unknown_suid_binaries"] = [s["path"] for s in unknown_suid]

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

    # --- File permission issues ---
    fp = report.get("file_permissions", {}).get("evidence", {})
    nc = fp.get("non_compliant_count", 0)
    if nc > 0:
        flags.append({
            "category": "file_permissions",
            "severity": "high",
            "summary": f"{nc} sensitive file(s) have non-compliant permissions",
            "confidence": "high",
            "evidence": "See file_permissions section",
        })
    for hd in fp.get("home_directory_permissions", []):
        if hd.get("world_writable"):
            flags.append({
                "category": "file_permissions",
                "severity": "high",
                "summary": f"World-writable home directory: {hd.get('path', '?')}",
                "confidence": "high",
                "evidence": f"User: {hd.get('user', '?')}, permissions: {hd.get('permissions', '?')}",
            })

    # --- Unknown SUID binaries ---
    suid = report.get("suid_sgid", {}).get("evidence", {})
    unknown_suid = suid.get("unknown_suid_count", 0)
    if unknown_suid > 0:
        flags.append({
            "category": "suid_sgid",
            "severity": "medium",
            "summary": f"{unknown_suid} unknown SUID binary/binaries found",
            "confidence": "medium",
            "evidence": "See suid_sgid section for paths",
        })

    # --- NOPASSWD sudo ---
    users_ev = report.get("users", {}).get("evidence", {})
    nopasswd = users_ev.get("nopasswd_users", [])
    if nopasswd:
        flags.append({
            "category": "sudo",
            "severity": "medium",
            "summary": f"NOPASSWD sudo access for: {', '.join(nopasswd)}",
            "confidence": "high",
            "evidence": "See users section",
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
        ("file_permissions", "File Permission Compliance"),
        ("suid_sgid", "SUID/SGID Binaries"),
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


# ---------------------------------------------------------------------------
# Multi-server report mode — CSS, loading, merging, HTML generation
# ---------------------------------------------------------------------------

REPORT_CSS_DARK = """\
:root {
  --bg: #0d1117; --surface: #161b22; --surface2: #21262d;
  --text: #c9d1d9; --text-muted: #8b949e; --border: #30363d;
  --critical-bg: #4a0e0e; --critical-fg: #ff6b6b; --critical-border: #da3633;
  --high-bg: #3d1515; --high-fg: #ff4444; --high-border: #f85149;
  --medium-bg: #3d2e00; --medium-fg: #f0c040; --medium-border: #d29922;
  --low-bg: #0d2818; --low-fg: #56d364; --low-border: #238636;
  --info-bg: #0d1d33; --info-fg: #58a6ff; --info-border: #1f6feb;
  --accent: #58a6ff; --accent2: #bc8cff;
  --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
  --mono: "Cascadia Code", "Fira Code", "JetBrains Mono", Consolas, monospace;
}"""

REPORT_CSS_LIGHT = """\
:root {
  --bg: #ffffff; --surface: #f6f8fa; --surface2: #eaeef2;
  --text: #1f2328; --text-muted: #656d76; --border: #d0d7de;
  --critical-bg: #ffebe9; --critical-fg: #cf222e; --critical-border: #cf222e;
  --high-bg: #ffebe9; --high-fg: #d1242f; --high-border: #d1242f;
  --medium-bg: #fff8c5; --medium-fg: #9a6700; --medium-border: #bf8700;
  --low-bg: #dafbe1; --low-fg: #116329; --low-border: #1a7f37;
  --info-bg: #ddf4ff; --info-fg: #0969da; --info-border: #218bff;
  --accent: #0969da; --accent2: #8250df;
  --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
  --mono: "Cascadia Code", "Fira Code", "JetBrains Mono", Consolas, monospace;
}"""

REPORT_CSS_COMMON = """\
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: var(--font); background: var(--bg); color: var(--text);
       line-height: 1.6; padding: 0; margin: 0; }
.container { max-width: 1300px; margin: 0 auto; padding: 2rem; }
.header { background: var(--surface); border-bottom: 1px solid var(--border);
           padding: 1.5rem 2rem; margin-bottom: 2rem; }
.header h1 { font-size: 1.8rem; color: var(--accent); margin-bottom: 0.5rem; }
.header .meta { color: var(--text-muted); font-size: 0.85rem; }
.header .meta span { margin-right: 1.5rem; }
.summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
                 gap: 0.75rem; margin: 1rem 0 1.5rem 0; }
.summary-card { background: var(--surface); border: 1px solid var(--border);
                 border-radius: 8px; padding: 1rem; text-align: center; }
.summary-card .count { font-size: 2rem; font-weight: 700; }
.summary-card .label { font-size: 0.8rem; color: var(--text-muted); text-transform: uppercase;
                        letter-spacing: 0.05em; }
.summary-card.info { border-left: 4px solid var(--info-border); }
.summary-card.info .count { color: var(--info-fg); }
.summary-card.warn { border-left: 4px solid var(--medium-border); }
.summary-card.warn .count { color: var(--medium-fg); }
.summary-card.critical { border-left: 4px solid var(--critical-border); }
.summary-card.critical .count { color: var(--critical-fg); }
.badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px;
         font-size: 0.75rem; font-weight: 600; letter-spacing: 0.03em; }
.badge-high { background: var(--high-bg); color: var(--high-fg); border: 1px solid var(--high-border); }
.badge-medium { background: var(--medium-bg); color: var(--medium-fg); border: 1px solid var(--medium-border); }
.badge-low { background: var(--low-bg); color: var(--low-fg); border: 1px solid var(--low-border); }
.badge-info { background: var(--info-bg); color: var(--info-fg); border: 1px solid var(--info-border); }
details.section-header { background: var(--surface); border: 1px solid var(--border);
                          border-radius: 8px; padding: 0; margin: 1.5rem 0; }
details.section-header summary { padding: 0.75rem 1rem; font-weight: 600; font-size: 1.1rem;
                                  list-style: none; display: flex; align-items: center; gap: 0.5rem;
                                  cursor: pointer; }
details.section-header summary::-webkit-details-marker { display: none; }
details.section-header summary::before { content: "\\25B6"; font-size: 0.7rem; color: var(--text-muted);
                                          transition: transform 0.2s; }
details.section-header[open] summary::before { transform: rotate(90deg); }
.section-body { padding: 0 1rem 1rem 1rem; }
.audit-table { width: 100%; border-collapse: collapse; font-size: 0.85rem; margin: 0.75rem 0; }
.audit-table th { background: var(--surface2); color: var(--text); padding: 0.5rem 0.75rem;
                   text-align: left; border-bottom: 2px solid var(--border); font-weight: 600; }
.audit-table td { padding: 0.4rem 0.75rem; border-bottom: 1px solid var(--border); vertical-align: top; }
.audit-table tr:hover { background: var(--surface); }
.audit-table tr.row-privileged { border-left: 3px solid var(--critical-border); }
.audit-table tr.row-locked { opacity: 0.6; }
.matrix-table { width: 100%; border-collapse: collapse; font-size: 0.8rem; margin: 0.75rem 0; }
.matrix-table th { background: var(--surface2); padding: 0.4rem; text-align: center;
                    border: 1px solid var(--border); font-weight: 600; }
.matrix-table th.rotated { writing-mode: vertical-rl; text-orientation: mixed;
                            transform: rotate(180deg); min-width: 2rem; height: 8rem; }
.matrix-table td { padding: 0.3rem; text-align: center; border: 1px solid var(--border); font-size: 0.85rem; }
.matrix-table td.present { background: var(--low-bg); color: var(--low-fg); }
.matrix-table td.absent { background: transparent; color: var(--text-muted); }
.matrix-table td.user-name { text-align: left; font-weight: 500; white-space: nowrap; padding-left: 0.5rem; }
.matrix-table td.user-name.privileged { color: var(--critical-fg); font-weight: 700; }
.finding-item { background: var(--surface); border: 1px solid var(--border);
                 border-radius: 6px; padding: 0.5rem 0.75rem; margin: 0.3rem 0;
                 font-size: 0.85rem; display: flex; align-items: flex-start; gap: 0.5rem; }
.finding-item .server-tag { font-family: var(--mono); font-size: 0.75rem; color: var(--accent);
                              white-space: nowrap; min-width: 100px; }
.recommendation { background: var(--info-bg); border: 1px solid var(--info-border);
                   border-radius: 6px; padding: 0.5rem 0.75rem; margin: 0.3rem 0; font-size: 0.85rem; }
.footer { text-align: center; color: var(--text-muted); font-size: 0.8rem;
           margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); }
@media print {
  body { background: white; color: black; }
  .container { max-width: 100%; padding: 0; }
  details[open] { break-inside: avoid; }
  .badge { border: 1px solid #666; }
  .audit-table th { background: #eee; }
}
"""


def load_audit_files(input_dir: str) -> List[Dict[str, Any]]:
    """Load all audit JSON files from a directory for multi-server report."""
    audit_dir = Path(input_dir)
    if not audit_dir.is_dir():
        log.error(f"Input directory not found: {input_dir}")
        return []
    # Accept both naming patterns
    files = sorted(set(list(audit_dir.glob("*_users_audit.json")) + list(audit_dir.glob("audit_*.json"))))
    if not files:
        log.error(f"No audit JSON files found in {input_dir}")
        return []
    audits: List[Dict[str, Any]] = []
    for fp in files:
        try:
            with open(fp, "r") as f:
                data = json.load(f)
            data["_source_file"] = fp.name
            audits.append(data)
            log.info(f"Loaded: {fp.name}")
        except json.JSONDecodeError as exc:
            log.warning(f"Skipping invalid JSON: {fp.name} ({exc})")
        except Exception as exc:
            log.warning(f"Skipping {fp.name}: {exc}")
    return audits


def _report_collect_findings(findings: List[Dict[str, Any]], audit: Dict[str, Any], hostname: str) -> None:
    """Extract notable findings from an audit for the multi-server report."""
    # Non-compliant file permissions
    fp_ev = audit.get("file_permissions", {}).get("evidence", {})
    for sf in fp_ev.get("sensitive_files", []):
        if sf.get("exists") and not sf.get("compliant"):
            findings.append({
                "server": hostname, "severity": "high", "category": "file_permissions",
                "detail": f"Non-compliant permissions on {sf['path']}: "
                          f"{sf.get('permissions', '?')} (expected {sf.get('expected_permissions', '?')})",
            })
    for hd in fp_ev.get("home_directory_permissions", []):
        if hd.get("world_writable"):
            findings.append({
                "server": hostname, "severity": "high", "category": "home_permissions",
                "detail": f"World-writable home directory: {hd['path']} ({hd.get('user', '?')})",
            })
    # Unknown SUID binaries
    suid_ev = audit.get("suid_sgid", {}).get("evidence", {})
    for p in suid_ev.get("unknown_suid_binaries", []):
        findings.append({"server": hostname, "severity": "medium", "category": "suid",
                         "detail": f"Unknown SUID binary: {p}"})
    # NOPASSWD sudo
    users_ev = audit.get("users", {}).get("evidence", {})
    for user in users_ev.get("nopasswd_users", []):
        findings.append({"server": hostname, "severity": "medium", "category": "sudo",
                         "detail": f"User '{user}' has NOPASSWD sudo access"})
    # Users with login shell that never logged in
    for user in users_ev.get("local_users", []):
        if (not user.get("disabled_shell") and user.get("user_type") == "human"
                and user.get("last_login", {}).get("last_login_time") == "never"):
            findings.append({"server": hostname, "severity": "low", "category": "unused_account",
                             "detail": f"User '{user['username']}' has login shell but never logged in"})
    # Secrets found
    for sf in audit.get("secrets_findings", []):
        findings.append({"server": hostname, "severity": "high", "category": "secret",
                         "detail": f"Potential secret at {sf.get('location', '?')}: {sf.get('secret_type', '?')}"})
    # Risk flags from individual audit
    for rf in audit.get("risk_flags", []):
        sev = rf.get("severity", "info")
        if sev in ("high", "critical", "medium"):
            findings.append({"server": hostname, "severity": sev, "category": rf.get("category", "risk"),
                             "detail": rf.get("summary", "")})


def merge_server_data(audits: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Merge audit data from multiple servers into a unified structure."""
    merged: Dict[str, Any] = {
        "report_meta": {
            "generated_at": now_iso(), "server_count": len(audits),
            "audit_files": [a.get("_source_file", "unknown") for a in audits],
            "script_version": __version__,
        },
        "servers": {},
        "cross_server": {"all_users": {}, "all_privileged_users": {}, "user_count_by_server": {}},
        "findings": [],
    }
    for audit in audits:
        hostname = audit.get("collection_meta", {}).get("hostname", "unknown")
        merged["servers"][hostname] = audit
        users_ev = audit.get("users", {}).get("evidence", {})
        local_users = users_ev.get("local_users", [])
        merged["cross_server"]["user_count_by_server"][hostname] = len(local_users)
        for user in local_users:
            uname = user["username"]
            merged["cross_server"]["all_users"].setdefault(uname, []).append(hostname)
        for puser in users_ev.get("all_privileged_users", []):
            merged["cross_server"]["all_privileged_users"].setdefault(puser, []).append(hostname)
        _report_collect_findings(merged["findings"], audit, hostname)
    return merged


def _report_generate_recommendations(merged: Dict[str, Any]) -> List[str]:
    """Auto-generate recommendations from merged findings."""
    recs: List[str] = []
    servers = merged["servers"]
    cross = merged["cross_server"]
    server_names = sorted(servers.keys())
    for srv_name in server_names:
        srv = servers[srv_name]
        for user in srv.get("users", {}).get("evidence", {}).get("nopasswd_users", []):
            recs.append(f"[{srv_name}] Review NOPASSWD sudo access for user '{user}'.")
        fp_ev = srv.get("file_permissions", {}).get("evidence", {})
        for sf in fp_ev.get("sensitive_files", []):
            if sf.get("exists") and not sf.get("compliant"):
                recs.append(f"[{srv_name}] Fix permissions on {sf['path']}: "
                            f"current {sf.get('permissions', '?')}, expected {sf.get('expected_permissions', '?')}.")
        for p in srv.get("suid_sgid", {}).get("evidence", {}).get("unknown_suid_binaries", [])[:10]:
            recs.append(f"[{srv_name}] Investigate unknown SUID binary: {p}")
        for user in srv.get("users", {}).get("evidence", {}).get("local_users", []):
            if (not user.get("disabled_shell") and user.get("user_type") == "human"
                    and user.get("last_login", {}).get("last_login_time") == "never"):
                recs.append(f"[{srv_name}] Consider disabling unused account '{user['username']}'.")
        for hd in fp_ev.get("home_directory_permissions", []):
            if hd.get("world_writable"):
                recs.append(f"[{srv_name}] Tighten permissions on {hd['path']} for user '{hd.get('user', '?')}'.")
    if len(server_names) > 1:
        for uname, srvs in cross["all_privileged_users"].items():
            if 0 < len(srvs) < len(server_names):
                present = ", ".join(sorted(srvs))
                missing = ", ".join(sorted(set(server_names) - set(srvs)))
                recs.append(f"Privileged user '{uname}' exists on [{present}] but not [{missing}] -- verify.")
    return recs


def generate_multi_server_html(merged: Dict[str, Any], output_path: str, dark_theme: bool = True) -> None:
    """Generate a self-contained HTML report from merged multi-server data."""
    e = html_mod.escape
    css_vars = REPORT_CSS_DARK if dark_theme else REPORT_CSS_LIGHT
    servers = merged["servers"]
    cross = merged["cross_server"]
    findings = merged["findings"]
    meta = merged["report_meta"]
    server_names = sorted(servers.keys())

    total_users = sum(cross["user_count_by_server"].values())
    human_users_all = set()
    for srv in servers.values():
        for u in srv.get("users", {}).get("evidence", {}).get("human_users", []):
            human_users_all.add(u)
    priv_users = set(cross["all_privileged_users"].keys())
    finding_high = sum(1 for f in findings if f["severity"] in ("high", "critical"))
    finding_med = sum(1 for f in findings if f["severity"] == "medium")
    finding_low = sum(1 for f in findings if f["severity"] == "low")

    # Header
    header = f"""<div class="header">
  <h1>Users &amp; Permissions Audit Report</h1>
  <div class="meta">
    <span>Generated: <strong>{e(meta['generated_at'][:19])}</strong></span>
    <span>Servers: <strong>{meta['server_count']}</strong></span>
    <span>Script: <strong>server_audit.py v{e(__version__)}</strong></span>
  </div>
</div>"""

    # Summary cards
    summary = f"""<h2>Executive Summary</h2>
<div class="summary-grid">
  <div class="summary-card info"><div class="count">{meta['server_count']}</div><div class="label">Servers</div></div>
  <div class="summary-card info"><div class="count">{total_users}</div><div class="label">Total Users</div></div>
  <div class="summary-card info"><div class="count">{len(human_users_all)}</div><div class="label">Human Users</div></div>
  <div class="summary-card warn"><div class="count">{len(priv_users)}</div><div class="label">Privileged</div></div>
  <div class="summary-card critical"><div class="count">{finding_high}</div><div class="label">High Findings</div></div>
  <div class="summary-card warn"><div class="count">{finding_med}</div><div class="label">Medium</div></div>
</div>"""

    # Per-server user tables
    srv_sections: List[str] = []
    for srv_name in server_names:
        srv = servers[srv_name]
        srv_meta = srv.get("collection_meta", {})
        users_ev = srv.get("users", {}).get("evidence", {})
        local_users = users_ev.get("local_users", [])
        all_priv_set = set(users_ev.get("all_privileged_users", []))
        nopasswd_set = set(users_ev.get("nopasswd_users", []))
        groups_ev = users_ev  # groups are inside users evidence now

        # User -> groups map
        user_groups_map: Dict[str, List[str]] = {}
        for g in groups_ev.get("local_groups", []):
            for member in g.get("members", []):
                user_groups_map.setdefault(member, []).append(g["name"])

        # Show root + human users
        display = [u for u in local_users if u.get("user_type") in ("root", "human")]
        display.sort(key=lambda x: (0 if x.get("user_type") == "root" else 1, x["username"]))

        rows: List[str] = []
        for u in display:
            uname = u["username"]
            groups_str = ", ".join(sorted(user_groups_map.get(uname, [])))
            sudo_str = "No"
            if uname in all_priv_set:
                sudo_str = '<span class="badge badge-medium">NOPASSWD</span>' if uname in nopasswd_set else '<span class="badge badge-high">Yes</span>'
            acct = u.get("account_status", {})
            status_parts: List[str] = []
            if acct.get("locked"):
                status_parts.append("Locked")
            if acct.get("expired"):
                status_parts.append("Expired")
            if acct.get("no_password"):
                status_parts.append("No-Pwd")
            if u.get("disabled_shell"):
                status_parts.append("nologin")
            status_str = ", ".join(status_parts) if status_parts else "Active"
            ll = u.get("last_login", {})
            ll_str = e(ll.get("last_login_time", "unknown"))
            row_cls = ' class="row-privileged"' if uname in all_priv_set else (' class="row-locked"' if acct.get("locked") else "")
            rows.append(f"<tr{row_cls}><td><strong>{e(uname)}</strong></td><td>{u.get('uid','?')}</td>"
                        f"<td>{e(groups_str)}</td><td>{sudo_str}</td><td><code>{e(u.get('shell','?'))}</code></td>"
                        f"<td>{ll_str}</td><td>{e(status_str)}</td></tr>")

        human_count = len(users_ev.get("human_users", []))
        total_count = users_ev.get("local_user_count", len(local_users))
        distro = e(srv_meta.get("distro", srv_meta.get("os_version_short", "Unknown")))
        priv_level = e(srv_meta.get("privilege_level", "?"))
        srv_sections.append(f"""<details class="section-header" open>
    <summary>{e(srv_name)} &mdash; {distro}
      <span style="margin-left:auto;font-size:0.8rem;color:var(--text-muted);">{human_count} human / {total_count} total | {priv_level}</span>
    </summary>
    <div class="section-body">
      <table class="audit-table">
        <thead><tr><th>Username</th><th>UID</th><th>Groups</th><th>Sudo</th><th>Shell</th><th>Last Login</th><th>Status</th></tr></thead>
        <tbody>{"".join(rows)}</tbody>
      </table>
    </div>
  </details>""")

    servers_html = f"<h2>Per-Server User Details</h2>{''.join(srv_sections)}"

    # Cross-server matrix
    matrix_users = set()
    for uname, srvs in cross["all_users"].items():
        for sn in srvs:
            if uname in servers.get(sn, {}).get("users", {}).get("evidence", {}).get("human_users", []):
                matrix_users.add(uname)
                break
        if uname in priv_users:
            matrix_users.add(uname)

    matrix_html = ""
    if matrix_users and len(server_names) > 1:
        hdr = '<th style="text-align:left;">User</th>' + "".join(f'<th class="rotated">{e(sn)}</th>' for sn in server_names)
        mrows: List[str] = []
        for uname in sorted(matrix_users):
            is_p = uname in priv_users
            nc = "user-name privileged" if is_p else "user-name"
            cells = f'<td class="{nc}">{e(uname)}</td>'
            for sn in server_names:
                cells += '<td class="present">&#10003;</td>' if sn in cross["all_users"].get(uname, []) else '<td class="absent">&#8212;</td>'
            mrows.append(f"<tr>{cells}</tr>")
        matrix_html = f"""<h2>Cross-Server User Matrix</h2>
<details class="section-header" open>
  <summary>User presence across {len(server_names)} servers
    <span style="margin-left:auto;font-size:0.8rem;color:var(--text-muted);">{len(matrix_users)} users</span>
  </summary>
  <div class="section-body" style="overflow-x:auto;">
    <table class="matrix-table"><thead><tr>{hdr}</tr></thead><tbody>{"".join(mrows)}</tbody></table>
  </div>
</details>"""

    # Findings
    findings_html = ""
    if findings:
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_f = sorted(findings, key=lambda f: (sev_order.get(f["severity"], 5), f["server"]))
        fitems = "".join(
            f'<div class="finding-item"><span class="server-tag">{e(f["server"])}</span>'
            f'<span class="badge badge-{f["severity"]}">{f["severity"].upper()}</span> {e(f["detail"])}</div>'
            for f in sorted_f)
        findings_html = f"""<h2>Findings ({len(findings)})</h2>
<details class="section-header" open>
  <summary>All findings <span style="margin-left:auto;font-size:0.8rem;color:var(--text-muted);">{finding_high} high | {finding_med} medium | {finding_low} low</span></summary>
  <div class="section-body">{fitems}</div>
</details>"""

    # Recommendations
    recs = _report_generate_recommendations(merged)
    recs_html = ""
    if recs:
        rec_items = "".join(f'<div class="recommendation">{e(r)}</div>' for r in recs)
        recs_html = f"""<h2>Recommendations</h2>
<details class="section-header" open>
  <summary>{len(recs)} recommendations</summary>
  <div class="section-body">{rec_items}</div>
</details>"""

    full_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Users &amp; Permissions Audit Report</title>
<style>
{css_vars}
{REPORT_CSS_COMMON}
</style>
</head>
<body>
{header}
<div class="container">
  {summary}
  {servers_html}
  {matrix_html}
  {findings_html}
  {recs_html}
</div>
<div class="footer">Generated by server_audit.py v{__version__}</div>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(full_html)


def run_report(input_dir: str, output: Optional[str], dark_theme: bool, verbose: bool) -> int:
    """Load audit files, merge, and generate HTML report."""
    setup_logging(verbose)
    audits = load_audit_files(input_dir)
    if not audits:
        return 1
    log.info(f"Loaded {len(audits)} audit file(s)")
    merged = merge_server_data(audits)
    if output is None:
        output = os.path.join(input_dir, "users_audit_report.html")
    generate_multi_server_html(merged, output, dark_theme=dark_theme)
    log.info(f"Report generated: {output}")
    log.info(f"Servers: {merged['report_meta']['server_count']} | Findings: {len(merged['findings'])}")
    return 0


def _run_collect(args) -> int:
    """Run the server audit collection (original + enhanced user/permissions)."""
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
            ("file_permissions", collect_file_permissions_linux),
        ]
        if not getattr(args, "skip_suid", False):
            suid_timeout = getattr(args, "suid_timeout", 60)
            collectors.append(("suid_sgid", lambda p, t=suid_timeout: collect_suid_sgid_linux(p, suid_timeout=t)))
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

    if overall_status == "ok":
        return 0
    elif overall_status == "partial":
        return 3
    else:
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="server_audit.py",
        description="Production-ready server audit collector with multi-server reporting.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              # Collect audit data on a server (backward-compatible):
              sudo python3 server_audit.py --output-dir /tmp/audit
              sudo python3 server_audit.py --output-dir /tmp/audit --profile deep --verbose

              # Generate multi-server users & permissions HTML report:
              python3 server_audit.py report --input-dir ./collected_audits -o report.html
        """),
    )
    parser.add_argument("--version", action="version", version=f"server_audit.py {__version__}")

    # Support both subcommand and flat modes for backward compatibility
    sub = parser.add_subparsers(dest="command")

    # -- report subcommand --
    p_report = sub.add_parser("report",
        help="Generate merged multi-server HTML report from collected JSON files",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p_report.add_argument("--input-dir", required=True, help="Directory containing audit JSON files")
    p_report.add_argument("-o", "--output", default=None, help="Output HTML file path")
    p_report.add_argument("--light-theme", action="store_true", help="Use light color scheme (default: dark)")
    p_report.add_argument("--verbose", action="store_true", help="Enable verbose output")

    # -- collect args (flat, backward-compatible) --
    parser.add_argument("--output-dir", default=None, help="Directory to write report files")
    parser.add_argument("--verbose", action="store_true", default=False, help="Enable verbose output")
    parser.add_argument("--safe-mode", action="store_true", help="Extra conservative data capture")
    parser.add_argument("--profile", choices=["minimal", "standard", "deep"], default="standard",
                        help="Collection depth (default: standard)")
    parser.add_argument("--formats", default="json,md,html",
                        help="Comma-separated output formats: json,md,html (default: json,md,html)")
    parser.add_argument("--skip-suid", action="store_true", help="Skip SUID/SGID binary scan")
    parser.add_argument("--suid-timeout", type=int, default=60, help="SUID scan timeout in seconds (default: 60)")

    args = parser.parse_args()

    # Dispatch
    if args.command == "report":
        return run_report(
            input_dir=args.input_dir,
            output=args.output,
            dark_theme=not args.light_theme,
            verbose=args.verbose,
        )

    # Collect mode (default) — requires --output-dir
    if not args.output_dir:
        parser.print_help()
        print("\nError: --output-dir is required for collect mode.", file=sys.stderr)
        return 1

    return _run_collect(args)


if __name__ == "__main__":
    sys.exit(main())
