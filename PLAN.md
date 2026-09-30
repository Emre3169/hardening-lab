# Hardening Lab Plan

OS hardening and patch lab on two UTM VMs: **ubuntu-lab** (Ubuntu 24.04 ARM64, Bash) and
**windows-lab** (Windows 11 ARM64, PowerShell). Harden each one, measure before and after,
and prove the changes can be rolled back.

Baseline: Lynis hardening index **61** (2026-09-30, Lynis 3.0.9, see `scores/`).

## Principles

- **Drop-ins over edits.** Write `/etc/ssh/sshd_config.d/00-lab.conf`, `/etc/sysctl.d/99-zz-lab.conf`,
  `/etc/audit/rules.d/60-lab.rules`, `/etc/modprobe.d/lab-blacklist.conf`, and so on. Rollback
  becomes "delete our files, restore backups". We only edit a vendor file when no drop-in
  mechanism exists, and it is backed up first.
- **Every change is a function** that checks the current state, prints `OK` (already
  compliant), `WOULD CHANGE` (dry run) or `CHANGED`, and never errors on a re-run.
- **Back up before writing.** Before any file is touched, it is copied to
  `./backups/<UTC timestamp>/<original path>`. Each run gets one timestamp. A `manifest.txt`
  lists every file backed up, created, service changed and package installed. Rollback reads
  the manifest and does not guess.
- **One tool version for before and after.** Keep apt's Lynis 3.0.9 for both runs so the two
  scores are comparable. A newer upstream Lynis goes in a later, separate row.
- **Don't lock ourselves out.** Allow ufw ssh before enabling ufw. Run `sshd -t` before
  reloading sshd. Confirm key login works before disabling password login.
- **Lab exception:** `emre` keeps `NOPASSWD: ALL` sudo so scripts run unattended. It is
  documented in README.md and PROCEDURE.md, it is not a hardening target, and it is excluded
  from the "after" narrative. It will cost some Lynis points; accept that.

## 1. Files to add

| File | Purpose |
|------|---------|
| `ubuntu/harden.sh` | CIS-style hardening. `--dry-run`, `--only <group>`, backups, manifest |
| `ubuntu/rollback.sh` | Reverses a harden run from `backups/<ts>/manifest.txt` (latest by default) |
| `ubuntu/run-remote.sh` | `scp` a script to the VM, run it with `sudo` over `ssh -F .ssh/config ubuntu-lab`, pull `~/scores` and `~/backups` back |
| `windows/harden.ps1` | Same groups for Windows. `-DryRun`, `-Only <group>`, backups, manifest |
| `windows/rollback.ps1` | Reverses a harden run from `backups\<ts>\manifest.json` |
| `PROCEDURE.md` | Step-by-step runbook (outline in §6) |
| `README.md` | What this is, layout, quick start, lab exceptions |

Also needed later, but not in this step (existing files are off-limits):
- add `backups/` to `.gitignore`, since backups can contain host keys and config
- extend `baseline.sh`, or add `score.sh`, to take a `before|after` label and fill the
  `after` column in SCORES.md instead of appending a new row

## 2. `ubuntu/harden.sh`

`sudo ./harden.sh [--dry-run] [--only patching,ssh,...]`. Requires root, uses
`set -euo pipefail`, and logs to `backups/<ts>/harden.log`. The groups run in this order:

1. **patching**: install `unattended-upgrades` and `apt-listchanges`. Enable security updates
  with `/etc/apt/apt.conf.d/20auto-upgrades` and a `52lab-unattended` drop-in: security origin
  only, no automatic reboot (it's a lab), and remove unused dependencies. Install
  `apt-show-versions` and `debsums`. Record the "no security repo" warning as a false positive
  (Lynis 3.0.9 doesn't read 24.04's deb822 `ubuntu.sources`) instead of "fixing" it.
2. **services**: disable and mask only services that are enabled on the VM. Candidates for a
  24.04 server VM (confirm first with `systemctl list-unit-files --state=enabled`):
  - `ModemManager`: no modem.
  - `multipathd`, `open-iscsi`/`iscsid`: no SAN or iSCSI storage.
  - `udisks2`: no desktop automount on a server.
  - `snapd` (plus socket and apparmor unit): no snaps needed. Masking it shrinks the attack
    surface and removes background refresh. It is disabled, not purged, so rollback is
    trivial.
  - `apport`, `whoopsie`: crash reports can leak memory contents.
  - `motd-news.timer`: phones home to Ubuntu's servers.
  - `fwupd-refresh.timer`: firmware updates are irrelevant in a VM.
  - `lxd-agent-loader`: not an LXD guest.

  Keep: `ssh`, `systemd-*`, `cron`, `rsyslog`, `unattended-upgrades` and `auditd`.
  Blacklist the kernel modules `dccp`, `sctp`, `rds`, `tipc` and `usb-storage` in
  `/etc/modprobe.d/lab-blacklist.conf`. Every unit that gets disabled is written to the
  manifest with its prior state.
3. **firewall**: `ufw default deny incoming`, `default allow outgoing`, `allow OpenSSH` (with
  rate limiting: `ufw limit OpenSSH`), turn logging on at the low level, then `ufw --force
  enable`. This also clears Lynis's "iptables loaded, no rules" warning. A dry run prints the
  rule diff.
4. **auditd**: install `auditd` and `audispd-plugins`, then write `60-lab.rules`. It watches
  identity files (`/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow`,
  `/etc/sudoers`, `/etc/sudoers.d`), `sshd_config*`, time changes, `mount`, module
  load/unload, `setuid`/`setgid` execution, and login records (`/var/log/wtmp`, `btmp`,
  `lastlog`). The rules are **not** set immutable (`-e 2`); an immutable rule set would block
  rollback without a reboot. Load them with `augenrules --load`.
5. **sysctl**: `/etc/sysctl.d/99-zz-lab.conf`. It must sort after Ubuntu's
  `99-protect-links.conf`, which otherwise sets `fs.protected_fifos` back to 1:
  - disable redirect acceptance and sending
  - disable source routing
  - `rp_filter=1`, `log_martians=1`
  - `tcp_syncookies=1`, `icmp_echo_ignore_broadcasts=1`
  - `kernel.kptr_restrict=2`, `kernel.dmesg_restrict=1`
  - `fs.protected_*`, `fs.suid_dumpable=0`
  - `kernel.unprivileged_bpf_disabled=1`

  IPv6 stays enabled but gets the same redirect settings. Apply with `sysctl --system`. Also
  disable core dumps in `limits.d`.
6. **ssh** (last, so a mistake here can't strand the earlier groups): write
  `/etc/ssh/sshd_config.d/00-lab.conf`. The `00-` prefix matters: sshd uses the first value it
  finds, and `50-cloud-init.conf` probably sets `PasswordAuthentication yes`. Settings:
  - `PasswordAuthentication no`, `KbdInteractiveAuthentication no`, `PermitRootLogin no`
  - `MaxAuthTries 3`, `MaxSessions 4`, `LoginGraceTime 30`
  - `ClientAliveInterval 300`, `ClientAliveCountMax 2`, `LogLevel VERBOSE`
  - `X11Forwarding no`, `AllowTcpForwarding no`, `AllowAgentForwarding no`, `TCPKeepAlive no`
  - `AllowUsers emre`, `Banner /etc/issue.net`

  Also set banner text in `/etc/issue` and `/etc/issue.net`. Stop if `sshd -t` fails. Stop
  if `~emre/.ssh/authorized_keys` is empty, so we can't disable password login with no key in
  place. Reload with `systemctl reload ssh`, never restart, so the current session survives.
  `MaxSessions` stays at 4, not Lynis's 2, so scp and ssh multiplexing keep working.
7. **accounts (small)**: in `login.defs`, set `UMASK 027`, `PASS_MAX_DAYS 365`,
  `PASS_MIN_DAYS 1` and `SHA_CRYPT_MIN_ROUNDS 65536`. Install `libpam-pwquality` and
  `libpam-tmpdir`. `login.defs` has no drop-in mechanism, so it's backed up and edited in
  place.

Out of scope, with the reason recorded in README.md:
- separate `/tmp`, `/var` and `/home` partitions: needs a reinstall
- GRUB password: blocks unattended reboots in UTM
- remote syslog: there's no log host
- AIDE: slow first run; maybe in phase 2

## 3. `windows/harden.ps1`

> **Approved scope (2026-09-30):** Services, DefenderFirewall, AuditPolicy and AccountPolicy,
> plus `Get-HotFix` recording. There is no WindowsUpdate group and no `windows/run-remote.sh`.
> The Windows scripts are built in a later step.

`.\harden.ps1 [-DryRun] [-Only Services,DefenderFirewall,...]`. Requires an elevated
PowerShell 5.1+ session. It uses the same backup layout (`backups\<ts>\`) and writes
`manifest.json`. Each run saves `Get-HotFix` output before and after to `scores/` so the
patch level is on record. Update settings are not changed.

1. **Services**: set startup type to Disabled for the services below. Their current startup
  types are backed up to CSV first.
  - `RemoteRegistry`: not needed
  - `XblAuthManager`, `XblGameSave`, `XboxNetApiSvc`, `XboxGipSvc`: no gaming
  - `Fax`: not used
  - `MapsBroker`: offline maps, not used
  - `lfsvc` (geolocation): not used
  - `SharedAccess` (ICS): no connection sharing
  - `RetailDemo`: not a demo unit
  - `WMPNetworkSvc`: no media sharing
  - `SSDPSrv`, `upnphost`: no UPnP
  - `DiagTrack`: telemetry

  Keep Spooler only if a printer is needed. Otherwise disable it (PrintNightmare class).
2. **DefenderFirewall**:
  - Defender: turn on real-time protection, cloud protection, PUA blocking and Network
    Protection. Set ASR rules to **Audit** first, then Block after one clean run.
  - Firewall: enable all three profiles with default inbound Block and outbound Allow, and
    turn logging on.
  - Back up Defender preferences with `Get-MpPreference`, exported to JSON. Back up firewall
    policy with `netsh advfirewall export`.
3. **AuditPolicy**: back up with `auditpol /backup`. Set the Advanced Audit Policy to CIS-level
  subcategories (logon/logoff, account logon, account and group management, process creation,
  policy change, privilege use failures, system integrity). Enable command-line capture in
  4688 process events. Increase the Security log to 1 GB.
4. **AccountPolicy**: back up with `secedit /export`, then import a templated `.inf`. It sets:
  - minimum password length 14, complexity on, history 24, maximum age 365
  - lockout after 5 attempts for 15 minutes
  - rename or disable the built-in Administrator; the Guest account stays disabled
  - also: LSA protection (`RunAsPPL`), SMBv1 off, LLMNR off, NetBIOS over TCP/IP off, WDigest
    off

The Windows VM doesn't exist yet. Prerequisites: a Win11 ARM64 ISO path in
`utm/create-windows-lab.applescript`, then TPM 2.0 enabled in the UTM GUI and SPICE guest
tools installed. The scripts run from the VM console; there is no remote runner for
Windows. Clone the VM as `windows-lab-clean` before the
first harden run.

## 4. Scoring

| Target | Tool | Raw output | Summary |
|--------|------|------------|---------|
| ubuntu-lab | `lynis audit system --no-colors` | `scores/lynis-before.txt`, `scores/lynis-after.txt` | `hardening_index` from `/var/log/lynis-report.dat` |
| windows-lab | HardeningKitty `Invoke-HardeningKitty -Mode Audit -FileFindingList <CIS Win11 list> -Log -Report` | `scores/hardeningkitty-before.{csv,log}`, `-after` | HardeningKitty score (1–6) and passed/total findings |

- Each table row: `date | machine | tool | before | after`. The `after` column of the same
  row gets filled in, so there's one row per machine and tool. A re-baseline starts a new row
  with a new date.
- Always use the same finding list and tool version for before and after. Put the version in
  the tool column, e.g. `lynis 3.0.9`, `HardeningKitty 0.9.x / CIS W11 list`.
- Record a delta, not just the two numbers. Also keep a short "top remaining findings" list
  per machine in SCORES.md so the score has context.
- HardeningKitty is installed on the Windows guest from GitHub (scipag/HardeningKitty) or
  PSGallery. Nothing is installed on macOS.

## 5. Rollback

**Ubuntu, `ubuntu/rollback.sh [--dry-run] [backups/<ts>]`**, reads the manifest in reverse:
- deletes drop-ins that we created: sshd, sysctl, audit rules, modprobe, apt unattended
- restores the backed-up files: `login.defs`, `issue`, `issue.net`, `limits.conf`
- `ufw --force reset && ufw disable`, restoring the pre-run state
- unmasks and restores each service to its recorded enabled or disabled state
- `augenrules --load`, `sysctl --system`, and reload sshd after `sshd -t` passes
- packages we installed are listed but **not** removed by default (`--purge-packages` removes
  them), because removing them rarely matters and can cascade into other packages

**Windows, `windows/rollback.ps1 [-DryRun] [-Backup <ts>]`**:
- `secedit /configure` with the exported `.inf`
- `auditpol /restore`
- `netsh advfirewall import`
- restores service startup types from the CSV
- deletes the registry values we created, and re-imports any `.reg` exports of values we
  changed
- `Set-MpPreference` from the saved JSON

**Full reset:** `utmctl stop ubuntu-lab`, delete it, then `utmctl clone ubuntu-lab-clean
--name ubuntu-lab`. The clean clone is the post-install, pre-baseline state (patched, Lynis
installed, score 61). The clone has the same MAC and machine ID as the original, so run only
one of them at a time. Rollback scripts are for quick iteration, and the clone is what to
trust when a rollback is in doubt.

Rollback is tested, not assumed: `harden` → `score` → `rollback` → `score` should return
close to 61.

## 6. PROCEDURE.md outline

1. **Prerequisites**: UTM, the VMs, `.ssh/config`, the lab exceptions (NOPASSWD sudo, no GRUB
   password), clone taken.
2. **Baseline**: `ubuntu/run-remote.sh ubuntu/baseline.sh`, then record the score.
3. **Dry run**: `ubuntu/run-remote.sh ubuntu/harden.sh --dry-run`, then review the WOULD
   CHANGE list.
4. **Harden**: `ubuntu/run-remote.sh ubuntu/harden.sh`, then check from a **new** terminal
   that `ssh -F .ssh/config ubuntu-lab` still works and that password login is refused
   (`ssh -o PubkeyAuthentication=no …` should fail).
5. **Score after**: run the Lynis audit again, which produces `lynis-after.txt` and fills the
   SCORES.md row.
6. **Before/after table**: the score delta plus a per-group checklist of what changed and
   what was deliberately skipped, and why.
7. **Rollback test**: `rollback.sh`, re-score, compare. Then do the full reset from the clone.
8. **Windows**: the same steps with the `.ps1` scripts and HardeningKitty.
9. **Commit**: scripts, scores and docs only. `backups/` and `.ssh/` are never committed.
