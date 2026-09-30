# Procedure

The runbook for the hardening lab. Design and reasoning are in [PLAN.md](PLAN.md).
All commands run from the repo root on the Mac.

## Results

| date | machine | tool | before | after | delta |
|------|---------|------|--------|-------|-------|
| 2026-09-30 | ubuntu-lab (Ubuntu 24.04.5 ARM64) | Lynis 3.0.9 | 61 | 78 | +17 |
| — | windows-lab (Windows 11 ARM64) | HardeningKitty | pending | pending | |

- **Lynis warnings:** 2 → 1. The one left is the security-repo false positive (see Lab
  exceptions).
- **Lynis suggestions:** 46 → 28.
- **Raw output:** `scores/lynis-before.txt` and `scores/lynis-after.txt`.

## 1. Prerequisites

- **UTM VM `ubuntu-lab`:** 6 GB RAM, 4 cores, 40 GB disk, Shared network, IP 192.168.64.2.
- **Clean clone `ubuntu-lab-clean`:** taken after the baseline, at score 61.
- **SSH:** `.ssh/config` with `Host ubuntu-lab`, the lab-only key `.ssh/lab_ed25519` and a
  repo-local `known_hosts`. Everything goes through `ssh -F .ssh/config ubuntu-lab`.
- **sudo:** `emre` has NOPASSWD sudo on the VM (a lab exception, see below).

## 2. Baseline

```sh
scp -F .ssh/config ubuntu/baseline.sh ubuntu-lab:
ssh -F .ssh/config ubuntu-lab 'sudo bash ~/baseline.sh'
```

This patches the VM (14 packages upgraded), installs Lynis 3.0.9 and git, and records the
first score. Result: **61**.

## 3. Dry run

```sh
ubuntu/run-remote.sh ubuntu/harden.sh --dry-run
```

Result: **37 would change, 9 already OK, no errors.**

| Group | Changes | What |
|-------|--------:|------|
| patching | 3 | install apt-listchanges, apt-show-versions and debsums; add a weekly cleanup line to `20auto-upgrades`; new `52lab-unattended` (no auto-reboot, remove unused packages) |
| services | 15 | mask ModemManager, multipathd (socket and service), iscsid.socket, open-iscsi, udisks2, snapd (4 units), apport, motd-news.timer, fwupd-refresh.timer and lxd-agent; block the kernel modules dccp, sctp, rds, tipc and usb-storage |
| firewall | 2 | `ufw limit OpenSSH`, then `ufw enable` (the defaults were already deny incoming, allow outgoing) |
| auditd | 4 | install auditd; 18 rules in `60-lab.rules`; enable the service; load the rules |
| sysctl | 5 | network and kernel sysctls; block core dumps; `log_martians=1` in `/etc/ufw/sysctl.conf` (which had it at 0); apply |
| ssh | 3 | banners in `/etc/issue` and `/etc/issue.net`; `00-lab.conf` (no password or root login, `AllowUsers emre`, forwarding off) |
| accounts | 5 | `login.defs`: UMASK 027, PASS_MAX_DAYS 365, PASS_MIN_DAYS 1, SHA_CRYPT_MIN_ROUNDS 65536; install libpam-pwquality and libpam-tmpdir |

## 4. Harden

```sh
ubuntu/run-remote.sh ubuntu/harden.sh
```

Result: **37 changed, 0 errors.** Backups and the manifest are in `backups/<timestamp>/`.

Two problems showed up after the first run. Both are fixed in `harden.sh`:

1. **Wrong audit rule count.** The log said "5 audit rules loaded", but `auditctl -l` showed
   all 18. The script counted `key=`, which only appears on syscall rules; watch rules
   display as `-k`. It now counts lines.
2. **sysctl files loading in the wrong order.** `fs.protected_fifos` ended up at 1, not 2,
   because Ubuntu's `/usr/lib/sysctl.d/99-protect-links.conf` loads after `60-lab.conf`. The
   file was renamed to `99-zz-lab.conf` so it loads last. A re-run made only that change
   (3 changed, 48 already OK), which also confirmed the script is safe to re-run.

## 5. Verify SSH

Run these from a **new** terminal, not the session that ran the hardening:

```sh
# key login must work
ssh -F .ssh/config ubuntu-lab 'echo OK as $(whoami)@$(hostname)'
# -> OK as emre@ubuntu-lab

# password-only login must be refused
ssh -F .ssh/config -o PubkeyAuthentication=no -o PasswordAuthentication=yes \
    -o BatchMode=yes ubuntu-lab true
# -> emre@192.168.64.2: Permission denied (publickey).
```

If key login fails, don't close any open session. Fix it from the UTM console, or reset from
the clean clone.

## 6. Score after

```sh
ubuntu/run-remote.sh ubuntu/score.sh after
```

Result: **78** (61 → 78, +17). `score.sh` fills in the `after` column of the existing row in
`scores/SCORES.md`.

The next suggestions worth acting on:
1. stronger banner wording (Lynis looks for more legal keywords)
2. the dccp, sctp, rds and tipc protocols are still flagged, so check which blocklist format
   Lynis 3.0.9 expects
3. fail2ban
4. file integrity monitoring (AIDE)
5. process accounting and sysstat

## 7. Rollback

Each harden run is undone separately, newest first. There are two runs, so run rollback
twice:

```sh
ubuntu/run-remote.sh ubuntu/rollback.sh --dry-run   # review
ubuntu/run-remote.sh ubuntu/rollback.sh             # undoes run 2 (the sysctl rename)
ubuntu/run-remote.sh ubuntu/rollback.sh             # undoes run 1 (everything else)
```

- **Packages stay installed** unless you pass `--purge-packages`.
- **One setting survives rollback:** `kernel.unprivileged_bpf_disabled=1` stays set until a
  reboot, because the kernel won't lower it at runtime.
- **Firewall:** if ufw was off before hardening, rollback runs `ufw --force reset`.

**Full reset** (back to score 61):

```sh
utmctl stop ubuntu-lab
utmctl delete ubuntu-lab
utmctl clone ubuntu-lab-clean --name ubuntu-lab
utmctl start ubuntu-lab
```

The clone has the same MAC address and machine ID as the original, so never run both at
once.

## 8. Windows

**Pending.** The approved scope is Services, DefenderFirewall, AuditPolicy and
AccountPolicy, plus `Get-HotFix` recording (PLAN.md §3). The Windows VM hasn't been created
yet.

## Lab exceptions

These are deliberate, and they are reflected in the score:

- **NOPASSWD sudo for `emre`**, so the scripts run unattended. `harden.sh` never touches
  sudoers.
- **No GRUB password**, because it would block unattended reboots in UTM.
- **No separate `/tmp`, `/var` or `/home` partitions**, because that needs a reinstall.
- **No remote syslog or AIDE yet.**
- **`MaxSessions 4`** rather than Lynis's 2, so scp and SSH connection sharing keep working.
  **Port 22** is kept as well.
- **The Lynis "no security repository" warning is a false positive**, because Lynis 3.0.9
  can't read 24.04's `ubuntu.sources`.
- **SSH is rate-limited** by `ufw limit OpenSSH`. `run-remote.sh` uses one shared SSH
  connection so it stays under the limit.
