# Sarge Control Mapping — NIST 800-53 Rev 5
**Oscar Six Security LLC | Scope: OpenClaw deployments on Ubuntu 22.04/24.04 LTS**

---

## AC — Access Control

### AC-2: Account Management
- **OpenClaw:** Restrict `agents.allowlist` and `channels.*.allowedUsers` to named, authorized users only
- **OS:** Remove unused accounts. No accounts with empty passwords. No non-root UID 0 accounts.
- **Evidence:** `getent passwd`, `awk -F: '($2=="")' /etc/shadow`, `lastlog`

### AC-3: Access Enforcement
- **OpenClaw:** Set `tools.fs.workspaceOnly: true`. Set `agents.defaults.sandbox.mode: "all"`
- **OS:** `~/.openclaw/` must be 700. `~/.openclaw/secrets/` must be 700. Secret files must be 600.
- **Evidence:** `stat ~/.openclaw`, `ls -la ~/.openclaw/secrets/`

### AC-6: Least Privilege
- **OpenClaw:** Set `tools.exec.elevated: false` unless explicitly required
- **OS:** Service account (`oscar`) should not be in sudo group. No passwordless sudo.
- **Evidence:** `sudo -l`, `groups oscar`

### AC-17: Remote Access
- **OpenClaw:** Set `gateway.bind: "lan"`. Use Cloudflare Tunnel for remote access only.
- **OS:** UFW enabled, default deny. Gateway port allowed from LAN subnet only.
- **Evidence:** `ufw status verbose`, `ss -tlnp`

---

## AU — Audit & Accountability

### AU-2: Event Logging
- **OpenClaw:** Set `logging.level: "info"` or higher. Enable `logging.auditActions: true`
- **OS:** auditd installed and running. journald persisting to disk.
- **Evidence:** `systemctl status auditd`, `journalctl --disk-usage`

### AU-3: Content of Audit Records
- **OpenClaw:** Enable `logging.includeTimestamp: true` and `logging.includeUser: true`
- **OS:** Audit records must include: timestamp, user identity, action, outcome
- **Evidence:** `ausearch -m LOGIN`, `last`

### AU-9: Protection of Audit Information
- **OS:** `/var/log/audit/audit.log` owned by root, mode 600. No world-readable audit logs.
- **Evidence:** `stat /var/log/audit/audit.log`

### AU-12: Audit Record Generation
- **OS:** auditd watch rules for `~/.openclaw/secrets/`, `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`
- **Evidence:** `auditctl -l | grep -E 'openclaw|passwd|shadow|sudoers'`

---

## CM — Configuration Management

### CM-2: Baseline Configuration
- **Sarge:** `baseline/openclaw.json.baseline` is the documented baseline
- **OS:** Package list documented. Enabled services documented.
- **Evidence:** `dpkg --get-selections`, `systemctl list-units --state=enabled`

### CM-6: Configuration Settings
- **OpenClaw:** All settings per `openclaw.json.baseline` applied
- **OS:** All Sarge hardening scripts applied. `unattended-upgrades` enabled.
- **Evidence:** Sarge gap analysis report

### CM-7: Least Functionality
- **OpenClaw:** Disable unused plugins and tools
- **OS:** Remove or disable: telnet, rsh, vsftpd, cups, avahi-daemon. SSH: `PermitRootLogin no`
- **Evidence:** `systemctl list-units --state=enabled`, `apt list --installed`

---

## IA — Identification & Authentication

### IA-2: Identification and Authentication
- **OpenClaw:** `channels.*.allowedUsers` restricts access to authenticated users only
- **OS:** PAM faillock: deny=5, unlock_time=1800. Session timeout: TMOUT=900
- **Evidence:** `grep pam_faillock /etc/pam.d/common-auth`, `grep TMOUT /etc/profile.d/`

### IA-5: Authenticator Management
- **OS:** pwquality: minlen=12, dcredit/ucredit/ocredit/lcredit enabled. PASS_MAX_DAYS=90, PASS_MIN_DAYS=1
- **Evidence:** `cat /etc/security/pwquality.conf`, `grep PASS_ /etc/login.defs`

### IA-6: Authentication Feedback
- **OS:** Login failure messages must not reveal username vs. password specificity
- **Evidence:** Test failed login, review PAM configuration

---

## SC — System & Communications Protection (partial)

### SC-8: Transmission Confidentiality and Integrity
- **OpenClaw:** Enable `gateway.tls: true`. Use Cloudflare Tunnel for remote access (TLS enforced)
- **Evidence:** `ss -tlnp`, check Cloudflare Tunnel config

### SC-28: Protection of Information at Rest
- **OS:** `~/.openclaw/` and all contents: 700/600 permissions. No world-readable sensitive files.
- **Evidence:** `find ~/.openclaw -type f -perm /004`

---

## SI — System & Information Integrity (partial)

### SI-2: Flaw Remediation
- **OS:** `unattended-upgrades` enabled. Zero pending security updates.
- **Evidence:** `apt list --upgradable | grep security`

### SI-3: Malicious Code Protection
- **OS:** ClamAV installed, daemon running, freshclam updating signatures. fail2ban active.
- **Evidence:** `systemctl status clamav-daemon`, `fail2ban-client status`
