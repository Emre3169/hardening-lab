# hardening-lab

An OS hardening and patch lab on an Apple Silicon Mac. Each UTM VM gets hardened with a
script, scored before and after, and rolled back to prove the changes are reversible.

- **ubuntu-lab**: Ubuntu 24.04 ARM64. Bash scripts, scored with Lynis: **61 → 78**.
- **windows-lab**: Windows 11 Pro ARM64. PowerShell scripts, scored with HardeningKitty:
  **3.28 → 3.47**.

The design and its reasoning are in [PLAN.md](PLAN.md). The step-by-step runbook with the real
results is [PROCEDURE.md](PROCEDURE.md).

## Layout

```
PLAN.md                  design and decisions
ubuntu/baseline.sh       patch, install Lynis, first score (already run: index 61)
ubuntu/harden.sh         CIS-style hardening, 7 groups, --dry-run / --only
ubuntu/rollback.sh       undo a harden run from its manifest
ubuntu/score.sh          Lynis before|after, fills scores/SCORES.md
ubuntu/run-remote.sh     (Mac) copy a script to the VM, run with sudo, pull results
windows/harden.ps1       Services, DefenderFirewall, AuditPolicy, AccountPolicy; -DryRun / -Only
windows/rollback.ps1     undo a harden run from its manifest.json
windows/score.ps1        HardeningKitty before|after + Get-HotFix
windows/run-remote.sh    (Mac) copy a .ps1 to windows-lab, run elevated, pull results
utm/*.applescript        create the VMs in UTM
scores/                  raw audit output and SCORES.md (committed)
backups/                 per-run backups pulled from the VMs; Windows ones in backups/windows-lab/ (ignored)
.ssh/                    lab-only key, ssh config, known_hosts (ignored)
```

## Quick start

Run from the repo root on the Mac. Every check prints `OK` (already compliant),
`WOULD CHANGE` (dry run) or `CHANGED`. A second harden run should show only `OK`.

### Ubuntu (ubuntu-lab, 192.168.64.2)

```sh
ubuntu/run-remote.sh ubuntu/score.sh before         # Lynis; adds the SCORES.md row
ubuntu/run-remote.sh ubuntu/harden.sh --dry-run     # review every WOULD CHANGE
ubuntu/run-remote.sh ubuntu/harden.sh               # apply; backups land in backups/<ts>/
ssh -F .ssh/config ubuntu-lab true                  # still works from a NEW terminal?
ubuntu/run-remote.sh ubuntu/score.sh after          # fills the "after" column
ubuntu/run-remote.sh ubuntu/rollback.sh --dry-run   # what undo would do
```

- **Single group:** `ubuntu/run-remote.sh ubuntu/harden.sh --only ssh`.
- **Full reset:** stop the VM, delete it, then run `utmctl clone ubuntu-lab-clean --name
  ubuntu-lab`.

### Windows (windows-lab, 192.168.64.3)

The VM needs OpenSSH Server, PowerShell as the default shell, and the lab key in
`administrators_authorized_keys`.

```sh
windows/run-remote.sh windows/score.ps1 before      # installs HardeningKitty v.0.9.4 the first time
windows/run-remote.sh windows/harden.ps1 -DryRun    # review every WOULD CHANGE
windows/run-remote.sh windows/harden.ps1            # apply; snapshots + manifest.json under C:\hardening-lab\backups\<ts>\
ssh -F .ssh/config windows-lab 'hostname'           # still works?
ssh -F .ssh/config windows-lab 'Restart-Computer -Force'   # reboot, wait for SSH, then:
windows/run-remote.sh windows/score.ps1 after       # fills the "after" column
windows/run-remote.sh windows/rollback.ps1 -DryRun  # what undo would do
```

- **Single group:** `windows/run-remote.sh windows/harden.ps1 -Only Services,AuditPolicy`.
- **Keep printing:** add `-KeepSpooler`.
- **Full reset:** clone again from `windows-lab-clean`.

## Lab exceptions

These are deliberate, and they cost some score points:

- **NOPASSWD sudo for `emre`**, so scripts run unattended over SSH. `harden.sh` never touches
  sudoers. In real use, remove it.
- **No GRUB password**, because it would block unattended reboots in UTM.
- **No separate `/tmp`, `/var` or `/home` partitions**: adding them needs a reinstall.
- **No remote syslog or AIDE yet**: there's no log host, and AIDE's first run is slow.
- **The ubuntu-lab-clean clone shares the original's MAC address and machine ID.** Run only
  one of them at a time.
- **SSH is rate-limited** by `ufw limit OpenSSH`, which blocks 6+ new connections in 30 s.
  `run-remote.sh` uses one multiplexed connection to stay under that.
- **The Lynis "no security repository" warning is a false positive**, because Lynis 3.0.9
  can't read 24.04's `ubuntu.sources`.
- **Windows: SSH from the subnet** is allowed through the firewall (192.168.64.0/24) so the
  scripts can run remotely. `harden.ps1` refuses to touch the firewall unless that rule is on.
- **Windows: ASR rules run in Audit, not Block**, for a first clean pass.
- **Windows: the firewall is configured in the local store.** HardeningKitty checks the
  policy store, so its 18 firewall checks fail even though the firewall is on (PROCEDURE.md
  §8.5).
- **Windows: Security Options, User Rights Assignment and Administrative Templates are out
  of scope.** That's most of the remaining HardeningKitty findings (PROCEDURE.md §8.6).
