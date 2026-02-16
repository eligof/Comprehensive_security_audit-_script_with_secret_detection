# Server Audit Report

**Host:** runsc (localhost)
**Generated:** 2026-02-16T15:31:14.621548+00:00
**Script version:** 2.0.0 | Schema: 2.0.0
**Run as:** root | Privilege: root
**Profile:** standard | Runtime: 6.31s
**OS:** Linux Linux-4.4.0-x86_64-with-glibc2.39

## Risk Flags

- **[MEDIUM]** No EDR/AV agent detected _(confidence: low)_
  - Evidence: No known EDR services found running
- **[CRITICAL]** TLS cert EXPIRED (/etc/ssl/certs/Baltimore_CyberTrust_Root.pem) _(confidence: high)_
  - Evidence: Expired 280 days ago

## System Identity & Platform

**Status:** ok

- **hostname:** runsc
- **fqdn:** localhost
- **domain:** None
- **virtualization:** docker
- **product_name:** Google Compute Engine
- **cpu_count:** 4
- **cpu_arch:** x86_64
- **cpu_model:** unknown
- **ram_kb:** 9437184
- **ram_gb:** 9.0
### filesystems
```json
{
  "filesystems": [
    {
      "target": "/",
      "source": "none",
      "fstype": "9p",
      "options": "rw,trans=fd,rfdno=4,wfdno=4,aname=/,dfltuid=4294967294,dfltgid=4294967294,dcache=1000,cache=remote_revalidating,disable_fifo_open,overlayfs_stale_read,directfs",
      "children": [
        {
          "target": "/dev",
          "source": "none",
          "fstype": "dev",
          "options": "rw,mode=0755",
          "children": [
            {
              "target": "/dev/shm",
              "source": "none",
              "fstype": "tmpfs",
              "options": "rw,noexec,nosuid,mode=1777"
            },
            {
              "target": "/dev/pts",
              "source": "none",
              "fstype": "devpts",
              "options": "rw"
            }
          ]
        },
        {
          "target": "/sys",
          "source": "none",
          "fstype": "sysfs",
          "options": "ro,noexec,nosuid,dentry_cache_limit=1000",
          "children": [
            {
              "target": "/sys/fs/cgroup",
              "source": "none",
              "fstype": "tmpfs",
              "options": "rw,noexec,nosuid",
              "children": [
                {
                  "target": "/sys/fs/cgroup/cpu",
                  "source": "none[/container_01FDN3WzZyCryFBPePgt5nZm--wiggle--d07664]",
                  "fstype": "cgroup",
                  "options": "rw,cpu"
                },
                {
                  "target": "/sys/fs/cgroup/cpuacct",
                  "source": "none[/container_01FDN3WzZyCryFBPePgt5nZm--wiggle--d07664]",
                  "fstype": "cgroup",
                  "options": "rw,cpuacct"
                },
                {
                  "target": "/sys/fs/cgroup/cpuset",
                  "source": "none[/container_01FDN3WzZyCryFBPePgt5nZm--wiggle--d07664]",
                  "fstype": "cgroup",
                  "options": "rw,cpuset"
                },
                {
                  "
... (truncated)
```
- **boot_mode:** BIOS

## OS Versioning & Patch State

**Status:** ok

### os_release
```json
{
  "PRETTY_NAME": "Ubuntu 24.04.3 LTS",
  "NAME": "Ubuntu",
  "VERSION_ID": "24.04",
  "VERSION": "24.04.3 LTS (Noble Numbat)",
  "VERSION_CODENAME": "noble",
  "ID": "ubuntu",
  "ID_LIKE": "debian",
  "HOME_URL": "https://www.ubuntu.com/",
  "SUPPORT_URL": "https://help.ubuntu.com/",
  "BUG_REPORT_URL": "https://bugs.launchpad.net/ubuntu/",
  "PRIVACY_POLICY_URL": "https://www.ubuntu.com/legal/terms-and-policies/privacy-policy",
  "UBUNTU_CODENAME": "noble",
  "LOGO": "ubuntu-logo"
}
```
- **kernel:** 4.4.0
- **kernel_version:** #1 SMP Sun Jan 10 15:06:54 PST 2016
- **uptime_seconds:** 11.24
- **last_reboot:** system boot  Feb 16 15:30
### installed_packages_dpkg
```json
{
  "adduser": "3.137ubuntu1",
  "adwaita-icon-theme": "46.0-1",
  "apt": "2.8.3",
  "apt-transport-https": "2.8.3",
  "at-spi2-common": "2.52.0-1build1",
  "base-files": "13ubuntu10.3",
  "base-passwd": "3.6.3build1",
  "bash": "5.2.21-2ubuntu4",
  "bc": "1.07.1-3ubuntu4",
  "binutils": "2.42-4ubuntu2.8",
  "binutils-common": "2.42-4ubuntu2.8",
  "binutils-x86-64-linux-gnu": "2.42-4ubuntu2.8",
  "bsdutils": "1:2.39.3-9ubuntu6.4",
  "build-essential": "12.10ubuntu1",
  "bzip2": "1.0.8-5.1build0.1",
  "ca-certificates": "20240203",
  "ca-certificates-java": "20240118",
  "coreutils": "9.4-3ubuntu6.1",
  "cpp": "4:13.2.0-7ubuntu1",
  "cpp-13": "13.3.0-6ubuntu2~24.04",
  "cpp-13-x86-64-linux-gnu": "13.3.0-6ubuntu2~24.04",
  "cpp-x86-64-linux-gnu": "4:13.2.0-7ubuntu1",
  "curl": "8.5.0-2ubuntu10.6",
  "dash": "0.5.12-6ubuntu5",
  "dbus": "1.14.10-4ubuntu4.1",
  "dbus-bin": "1.14.10-4ubuntu4.1",
  "dbus-daemon": "1.14.10-4ubuntu4.1",
  "dbus-session-bus-common": "1.14.10-4ubuntu4.1",
  "dbus-system-bus-common": "1.14.10-4ubuntu4.1",
  "dbus-user-session": "1.14.10-4ubuntu4.1",
  "dconf-gsettings-backend": "0.40.0-4ubuntu0.1",
  "dconf-service": "0.40.0-4ubuntu0.1",
  "debconf": "1.5.86ubuntu1",
  "debianutils": "5.17build1",
  "default-jre-headless": "2:1.21-75+exp1",
  "dictionaries-common": "1.29.7",
  "diffutils": "1:3.10-1build1",
  "dirmngr": "2.4.4-2ubuntu17.4",
  "distro-info-data": "0.60ubuntu0.5",
  "dpkg": "1.22.6ubuntu6.5",
  "dpkg-dev": "1.22.6ubuntu6.5",
  "e2fsprogs": "1.47.0-2.4~exp1ubuntu4.1",
  "emacsen-common": "3.0.5",
  "ffmpeg": "7:6.1.1-3ubuntu5",
  "file": "1:5.45-3build1",
  "findutils": "4.9.0-5build1",
  "fontconfig": "2.15.0-1.1ubuntu2",
  "fontconfig-config": "2.15.0-1.1ubuntu2",
  "fonts-crosextra-caladea": "20200211-2",
  "fonts-crosextra-carlito": "20230309-2",
  "fonts-dejavu": "2.37-8",
  "fonts-dejavu-core": "2.37-8",
  "fonts-dejavu-extra": "2.37-8",
  "fonts-dejavu-mono": "2.37-8",
  "fonts-freefont-ttf": "20211204+svn4273-2",
  "fonts
... (truncated)
```
- **installed_package_count_dpkg:** 867

## Installed Software Inventory

**Status:** ok

### language_runtimes
```json
{
  "python3": {
    "version": "Python 3.12.3",
    "path": "/usr/bin/python3"
  },
  "java": {
    "version": "openjdk version \"21.0.9\" 2025-10-21",
    "path": "/usr/bin/java"
  },
  "node": {
    "version": "v22.22.0",
    "path": "/usr/bin/node"
  },
  "perl": {
    "version": "This is perl 5, version 38, subversion 2 (v5.38.2) built for x86_64-linux-gnu-thread-multi",
    "path": "/usr/bin/perl"
  }
}
```
- **openssl_version:** OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)
- **ssh_version:** command not found: ssh

## Running Services & Config

**Status:** partial
**Errors:** systemctl not available or failed

### service_configs
```json
{}
```

## Network Exposure

**Status:** ok

### dns_servers
```json
[]
```

## Users, Groups & Identity

**Status:** ok

### local_users
```json
[
  {
    "username": "root",
    "uid": 0,
    "gid": 0,
    "home": "/root",
    "shell": "/bin/bash"
  },
  {
    "username": "daemon",
    "uid": 1,
    "gid": 1,
    "home": "/usr/sbin",
    "shell": "/usr/sbin/nologin"
  },
  {
    "username": "bin",
    "uid": 2,
    "gid": 2,
    "home": "/bin",
    "shell": "/usr/sbin/nologin"
  },
  {
    "username": "sys",
    "uid": 3,
    "gid": 3,
    "home": "/dev",
    "shell": "/usr/sbin/nologin"
  },
  {
    "username": "sync",
    "uid": 4,
    "gid": 65534,
    "home": "/bin",
    "shell": "/bin/sync"
  },
  {
    "username": "games",
    "uid": 5,
    "gid": 60,
    "home": "/usr/games",
    "shell": "/usr/sbin/nologin"
  },
  {
    "username": "man",
    "uid": 6,
    "gid": 12,
    "home": "/var/cache/man",
    "shell": "/usr/sbin/nologin"
  },
  {
    "username": "lp",
    "uid": 7,
    "gid": 7,
    "home": "/var/spool/lpd",
    "shell": "/usr/sbin/nologin"
  },
  {
    "username": "mail",
    "uid": 8,
    "gid": 8,
    "home": "/var/mail",
    "shell": "/usr/sbin/nologin"
  },
  {
    "username": "news",
    "uid": 9,
    "gid": 9,
    "home": "/var/spool/news",
    "shell": "/usr/sbin/nologin"
  },
  {
    "username": "uucp",
    "uid": 10,
    "gid": 10,
    "home": "/var/spool/uucp",
    "shell": "/usr/sbin/nologin"
  },
  {
    "username": "proxy",
    "uid": 13,
    "gid": 13,
    "home": "/bin",
    "shell": "/usr/sbin/nologin"
  },
  {
    "username": "www-data",
    "uid": 33,
    "gid": 33,
    "home": "/var/www",
    "shell": "/usr/sbin/nologin"
  },
  {
    "username": "backup",
    "uid": 34,
    "gid": 34,
    "home": "/var/backups",
    "shell": "/usr/sbin/nologin"
  },
  {
    "username": "list",
    "uid": 38,
    "gid": 38,
    "home": "/var/list",
    "shell": "/usr/sbin/nologin"
  },
  {
    "username": "irc",
    "uid": 39,
    "gid": 39,
    "home": "/run/ircd",
    "shell": "/usr/sbin/nologin"
  },
  {
    "username": "_apt",
    "uid": 42,
    "gid": 65534,
    "home": "/nonexistent"
... (truncated)
```
- **local_user_count:** 22
### local_groups
```json
[
  {
    "name": "root",
    "gid": 0,
    "members": []
  },
  {
    "name": "daemon",
    "gid": 1,
    "members": []
  },
  {
    "name": "bin",
    "gid": 2,
    "members": []
  },
  {
    "name": "sys",
    "gid": 3,
    "members": []
  },
  {
    "name": "adm",
    "gid": 4,
    "members": [
      "ubuntu"
    ]
  },
  {
    "name": "tty",
    "gid": 5,
    "members": []
  },
  {
    "name": "disk",
    "gid": 6,
    "members": []
  },
  {
    "name": "lp",
    "gid": 7,
    "members": []
  },
  {
    "name": "mail",
    "gid": 8,
    "members": []
  },
  {
    "name": "news",
    "gid": 9,
    "members": []
  },
  {
    "name": "uucp",
    "gid": 10,
    "members": []
  },
  {
    "name": "man",
    "gid": 12,
    "members": []
  },
  {
    "name": "proxy",
    "gid": 13,
    "members": []
  },
  {
    "name": "kmem",
    "gid": 15,
    "members": []
  },
  {
    "name": "dialout",
    "gid": 20,
    "members": [
      "ubuntu"
    ]
  },
  {
    "name": "fax",
    "gid": 21,
    "members": []
  },
  {
    "name": "voice",
    "gid": 22,
    "members": []
  },
  {
    "name": "cdrom",
    "gid": 24,
    "members": [
      "ubuntu"
    ]
  },
  {
    "name": "floppy",
    "gid": 25,
    "members": [
      "ubuntu"
    ]
  },
  {
    "name": "tape",
    "gid": 26,
    "members": []
  },
  {
    "name": "sudo",
    "gid": 27,
    "members": [
      "ubuntu"
    ]
  },
  {
    "name": "audio",
    "gid": 29,
    "members": [
      "ubuntu"
    ]
  },
  {
    "name": "dip",
    "gid": 30,
    "members": [
      "ubuntu"
    ]
  },
  {
    "name": "www-data",
    "gid": 33,
    "members": []
  },
  {
    "name": "backup",
    "gid": 34,
    "members": []
  },
  {
    "name": "operator",
    "gid": 37,
    "members": []
  },
  {
    "name": "list",
    "gid": 38,
    "members": []
  },
  {
    "name": "irc",
    "gid": 39,
    "members": []
  },
  {
    "name": "src",
    "gid": 40,
    "members": []
  },
  {
    "name": "shadow",
    "gid": 42,
    "members": []
 
... (truncated)
```
### sudo_group_members
```json
[
  "ubuntu"
]
```
### ssh_authorized_keys
```json
[]
```

## Scheduled Tasks & Persistence

**Status:** ok

### system_crontabs
```json
{
  "/etc/cron.d/e2scrub_all": [
    "30 3 * * 0 root test -e /run/systemd/system || SERVICE_MODE=1 /usr/lib/x86_64-linux-gnu/e2fsprogs/e2scrub_all_cron",
    "10 3 * * * root test -e /run/systemd/system || SERVICE_MODE=1 /sbin/e2scrub_all -A -r"
  ]
}
```
- **enabled_services:** UNIT FILE              STATE   PRESET
e2scrub_reap.service   enabled enabled
getty@.service         enabled enabled
systemd-pstore.service enabled enabled

3 unit files listed.

## Storage & Backups

**Status:** ok

- **network_mounts:** none
- **disk_usage:** Filesystem     Type   Size  Used Avail Use% Mounted on
none           9p     9.9G  2.3M  9.9G   1% /
none           dev    315G     0  315G   0% /dev
none           tmpfs  315G     0  315G   0% /dev/shm
none           tmpfs  315G     0  315G   0% /sys/fs/cgroup
none           9p     1.0P     0  1.0P   0% /mnt/transcripts
none           9p     1.0P     0  1.0P   0% /mnt/skills/public
none           9p     9.9G  2.3M  9.9G   1% /container_info.json
none           9p     1.0P     0  1.0P   0% /mnt/... (truncated)
### backup_agents
```json
[]
```

## Certificates & TLS

**Status:** ok

### system_ca_bundle
```json
{
  "path": "/etc/ssl/certs/ca-certificates.crt",
  "exists": true,
  "size_bytes": 221954,
  "last_modified": "2026-01-21T18:14:01+00:00",
  "owner": "999",
  "group": "ubuntu",
  "permissions": "0644",
  "sha256": "962a77ab3ccf93510b3ed97c5d39a9823aa564fde8c3b4ff553872e20c2f3665"
}
```
### certificate_files
```json
[
  {
    "path": "/etc/ssl/certs/ACCVRAIZ1.pem",
    "exists": true,
    "size_bytes": 2772,
    "last_modified": "2024-02-04T09:41:43+00:00",
    "owner": "999",
    "group": "ubuntu",
    "permissions": "0644",
    "sha256": "04846f73d9d0421c60076fd02bad7f0a81a3f11a028d653b0de53290e41dcead",
    "x509_info": "subject=CN = ACCVRAIZ1, OU = PKIACCV, O = ACCV, C = ES\nissuer=CN = ACCVRAIZ1, OU = PKIACCV, O = ACCV, C = ES\nnotBefore=May  5 09:37:37 2011 GMT\nnotAfter=Dec 31 09:37:37 2030 GMT\nX509v3 Subject Alternative Name: \n    email:accv@accv.es\nserial=5EC3B7A6437FA4E0\nSHA1 Fingerprint=93:05:7A:88:15:C6:4F:CE:88:2F:FA:91:16:52:28:78:BC:53:64:17"
  },
  {
    "path": "/etc/ssl/certs/AC_RAIZ_FNMT-RCM.pem",
    "exists": true,
    "size_bytes": 1972,
    "last_modified": "2024-02-04T09:41:43+00:00",
    "owner": "999",
    "group": "ubuntu",
    "permissions": "0644",
    "sha256": "aa18ea4c9a8441a461bb436a1c90beb994ac841980b8fd62c72de9a62ddf8ae3",
    "x509_info": "subject=C = ES, O = FNMT-RCM, OU = AC RAIZ FNMT-RCM\nissuer=C = ES, O = FNMT-RCM, OU = AC RAIZ FNMT-RCM\nnotBefore=Oct 29 15:59:56 2008 GMT\nnotAfter=Jan  1 00:00:00 2030 GMT\nserial=5D938D306736C8061D1AC754846907\nSHA1 Fingerprint=EC:50:35:07:B2:15:C4:95:62:19:E2:A8:9A:5B:42:99:2C:4C:2C:20"
  },
  {
    "path": "/etc/ssl/certs/AC_RAIZ_FNMT-RCM_SERVIDORES_SEGUROS.pem",
    "exists": true,
    "size_bytes": 904,
    "last_modified": "2024-02-04T09:41:43+00:00",
    "owner": "999",
    "group": "ubuntu",
    "permissions": "0644",
    "sha256": "8e3f237813d3f3e2f5767bc2a694a7557f84bb79fd60ef1adc25afd0c1fc5ef6",
    "x509_info": "subject=C = ES, O = FNMT-RCM, OU = Ceres, organizationIdentifier = VATES-Q2826004J, CN = AC RAIZ FNMT-RCM SERVIDORES SEGUROS\nissuer=C = ES, O = FNMT-RCM, OU = Ceres, organizationIdentifier = VATES-Q2826004J, CN = AC RAIZ FNMT-RCM SERVIDORES SEGUROS\nnotBefore=Dec 20 09:37:33 2018 GMT\nnotAfter=Dec 20 09:37:33 2043 GMT\nserial=62F6326CE5C4E3685C1B62DD9C2E9D95\nSHA1 Fingerprint=62:
... (truncated)
```

## Logs & Audit Evidence

**Status:** ok

### logging_stack
```json
[]
```
- **journal_disk_usage:** Archived and active journals take up 0B in the file system.

## Containers & Orchestration

**Status:** ok


## Security Posture

**Status:** ok

### edr_signals
```json
[]
```
### password_policy_hints
```json
{
  "/etc/pam.d/common-password": [
    "password\t[success=1 default=ignore]\tpam_unix.so obscure yescrypt",
    "password\trequisite\t\t\tpam_deny.so",
    "password\trequired\t\t\tpam_permit.so"
  ]
}
```

## Upgrade Planning (Recommendations)

- **Operating System**: Ubuntu 24.04.3 LTS (Noble Numbat) → _Review against vendor support lifecycle_
- **Kernel**: 4.4.0 → _Ensure kernel receives security patches_
- **Runtime: python3**: Python 3.12.3 → _Verify version is within vendor support window_
- **Runtime: java**: openjdk version "21.0.9" 2025-10-21 → _Verify version is within vendor support window_
- **Runtime: node**: v22.22.0 → _Verify version is within vendor support window_
- **Runtime: perl**: This is perl 5, version 38, subversion 2 (v5.38.2) built for x86_64-linux-gnu-thread-multi → _Verify version is within vendor support window_
- **OpenSSL**: OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024) → _Ensure version is patched and supported_

## Data Minimization Note

- secrets_redacted: True
- secret_values_never_stored: True
- full_config_files_excluded: True
- password_hashes_excluded: True
- private_keys_excluded: True
- only_safe_metadata_collected: True

---
*Report generated by server_audit.py*