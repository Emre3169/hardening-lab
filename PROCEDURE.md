# Procedure

The runbook for the hardening lab. Design and reasoning are in [PLAN.md](PLAN.md).
All commands run from the repo root on the Mac.

## Results

| date | machine | tool | before | after | delta |
|------|---------|------|--------|-------|-------|
| 2026-09-30 | ubuntu-lab (Ubuntu 24.04.5 ARM64) | Lynis 3.0.9 | 61 | 78 | +17 |
| 2026-09-30 | windows-lab (Windows 11 Pro ARM64, build 26300.9457) | HardeningKitty v.0.9.4, CIS Win11 24H2 list | 3.28 | 3.47 | +0.19 |

- **Lynis warnings:** 2 → 1. The one left is the security-repo false positive (see Lab
  exceptions).
- **Lynis suggestions:** 46 → 28.
- **HardeningKitty:** 164 → 199 passed of 647 checks; Low 43 → 32, Medium 440 → 416, High 0.
- **Raw output:** `scores/lynis-{before,after}.txt` and
  `scores/hardeningkitty-{before,after}.{csv,log,json}`, plus `scores/hotfix-*.csv`.

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

## 8. Windows (windows-lab)

Run on 2026-09-30 (the VM's local date; 2026-10-01 UTC) on Windows 11 Pro ARM64, build
26300.9457, with 4 hotfixes. The scope is Services, DefenderFirewall, AuditPolicy and
AccountPolicy, plus `Get-HotFix` recording (PLAN.md §3).

**Prerequisites**
- `Host windows-lab` in `.ssh/config`: 192.168.64.3, user `emre`, the lab key. OpenSSH
  Server with PowerShell as the default shell. The SSH session runs as an elevated admin.
- The SSH firewall rule must allow 192.168.64.0/24 on every profile. Here it had to be fixed
  through UTM's guest agent first, because SSH timed out.
- Verify the host key against `C:\ProgramData\ssh\ssh_host_ed25519_key.pub`:
  `SHA256:hLPyBrxlozKsu2+mNdtZ4mqvKX5PYUB6trPbEQfqpBc`.

**8.1 Score before**
```sh
windows/run-remote.sh windows/score.ps1 before
```
On its first run this installs HardeningKitty v.0.9.4 into `C:\hardening-lab\`. It audits
against `cis_microsoft_windows_11_enterprise_24h2_machine`.
Result: **3.28**, with 164 passed of 647 (Low 43, Medium 440, High 0).

**8.2 Dry run**
```sh
windows/run-remote.sh windows/harden.ps1 -DryRun
```
Result: **54 would change, 17 already OK, no errors.**

| Group | Changes | What |
|-------|--------:|------|
| Services | 13 | disable XblAuthManager, XblGameSave, XboxNetApiSvc, XboxGipSvc, MapsBroker, lfsvc, SharedAccess, RetailDemo, WMPNetworkSvc, SSDPSrv, upnphost, DiagTrack and Spooler (RemoteRegistry and Fax were already disabled) |
| DefenderFirewall | 19 | PUA protection 2 → 1 (audit → block), network protection 0 → 1, 14 ASR rules → Audit; all 3 firewall profiles NotConfigured → explicit (inbound Block, outbound Allow, allow rules honoured, blocked connections logged, 16 MB log) |
| AuditPolicy | 10 | 7 subcategories get missing success/failure auditing (Credential Validation, User Account Management, Process Creation, Account Lockout, Audit Policy Change, Sensitive Privilege Use, Security System Extension); subcategories override legacy categories; command line in event 4688; Security log 20 MB → 1 GB |
| AccountPolicy | 12 | minimum length 0 → 14, complexity on, history 0 → 24, maximum age 42 → 365, minimum age 0 → 1, lockout 10 → 5 attempts, reset counter and duration 10 → 15 min; WDigest off, LLMNR off, NetBIOS off on 2 interfaces |

Already compliant: real-time protection, cloud protection, sample submission, Guest and
Administrator disabled, `RunAsPPL`, SMB1 off.

**8.3 Harden, verify SSH, reboot**
```sh
windows/run-remote.sh windows/harden.ps1
ssh -F .ssh/config windows-lab 'hostname; whoami'      # from a fresh connection
ssh -F .ssh/config windows-lab 'Restart-Computer -Force'
# poll SSH every 20 s, at most 15 tries, and compare LastBootUpTime before and after
```
Result: **54 changed, 0 errors, no Tamper Protection blocks.** The run is saved in
`C:\hardening-lab\backups\20261001T021903Z\` (manifest and snapshots).

SSH worked straight after hardening. After `Restart-Computer`, SSH came back on the second
poll, about 40 s, with a new boot time.

The reboot applies services, LSA and other settings that only load at boot. Score after it,
not before.

**8.4 Score after**
```sh
windows/run-remote.sh windows/score.ps1 after       # fills the after column in scores/SCORES.md
```
Result: **3.47** (+0.19), with 199 passed of 647 (Low 32, Medium 416, High 0).
35 checks went from failed to passed. Advanced audit policy now has 0 failures.

**8.5 Firewall: policy store vs local store**
- HardeningKitty's 18 firewall checks (9.x) still fail with `EnableFirewall=0 (Policy)`,
  even though the firewall is on with the intended settings.
- The checks read the **Group Policy store** (`HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall`).
  `harden.ps1` uses `Set-NetFirewallProfile`, which writes the **local store**.
- The effective firewall state is right, but the scanner can't see it.
- To make these pass, write the same values under the policy key, or with
  `Set-NetFirewallProfile -PolicyStore localhost`. Either way, check that the SSH rule
  survives, because policy-store rules and profiles take precedence over local ones.

**8.6 Top 5 remaining findings**

All the remaining failures are Medium or Low. These five are picked for security value.

| # | Finding | Now → CIS | Why it's still open |
|---|---------|-----------|---------------------|
| 1 | SMB signing not required (2.3.8.1, 2.3.9.2, 2.3.9.3) | 0 → 1 | Security Options are outside the trimmed scope. It's the best next candidate: it blocks NTLM relay, and it's three registry values. |
| 2 | Network logon rights too broad (2.2.2 includes Everyone; 2.2.16 only denies Guest) | → Administrators and Remote Desktop Users; deny local accounts | User Rights Assignment is out of scope. Getting it wrong can lock out remote administration, and SSH logs on over the network, so it needs its own careful step. |
| 3 | Firewall checks fail on the policy store (9.x, 18 checks) | Policy `EnableFirewall=0` → 1 | Not a real gap. The settings are applied in the local store (§8.5). |
| 4 | 39 service checks (Bluetooth BTAGService and bthserv, GameInput, Computer Browser, …) still Manual | → Disabled | The service list was fixed when PLAN.md was approved. Extending it is easy, but it's a scope change. |
| 5 | Cached logons 10 → 4 (2.3.7.7); printer drivers not restricted to admins (2.3.4.1) | 10 → 4; 0 → 1 | Security Options are out of scope. Cached logons only matter on a domain-joined machine, and this VM is standalone. |

The largest bucket is about 263 Group Policy checks under Administrative Templates (Windows
Components and System). Those were deliberately left out of this lab's scope.

**8.7 Rollback**
```sh
windows/run-remote.sh windows/rollback.ps1 -DryRun
windows/run-remote.sh windows/rollback.ps1          # replays manifest.json in reverse
```
- **What it restores:** service start types, registry values, Defender preferences and ASR
  rules (rules it added are removed), the Security log size, and the firewall, audit and
  security policy snapshots.
- **When `RunAsPPL` changes apply:** after the next reboot.
- **Full reset:** clone again from `windows-lab-clean`.

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
