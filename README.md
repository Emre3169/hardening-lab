# hardening-lab

An OS hardening and patch lab on an Apple Silicon Mac. Each UTM VM gets hardened with a
script, scored before and after, and rolled back to prove the changes are reversible.

- **ubuntu-lab**: Ubuntu 24.04 ARM64. Bash scripts, scored with Lynis. Built.
- **windows-lab**: Windows 11 ARM64. PowerShell scripts, scored with HardeningKitty. Planned
  (see PLAN.md §3).

The design and its reasoning are in [PLAN.md](PLAN.md). The step-by-step runbook will be
PROCEDURE.md.

## Layout

```
PLAN.md                  design and decisions
ubuntu/baseline.sh       patch, install Lynis, first score (already run: index 61)
ubuntu/harden.sh         CIS-style hardening, 7 groups, --dry-run / --only
ubuntu/rollback.sh       undo a harden run from its manifest
ubuntu/score.sh          Lynis before|after, fills scores/SCORES.md
ubuntu/run-remote.sh     (Mac) copy a script to the VM, run with sudo, pull results
utm/*.applescript        create the VMs in UTM
scores/                  raw audit output and SCORES.md (committed)
backups/                 per-run backups and manifests pulled from the VM (ignored)
.ssh/                    lab-only key, ssh config, known_hosts (ignored)
```

## Quick start (Ubuntu)

Run from the repo root on the Mac, with `ubuntu-lab` running:

```sh
ubuntu/run-remote.sh ubuntu/harden.sh --dry-run    # review every WOULD CHANGE
ubuntu/run-remote.sh ubuntu/harden.sh              # apply; backups land in backups/<ts>/
ssh -F .ssh/config ubuntu-lab true                 # still works from a NEW terminal?
ubuntu/run-remote.sh ubuntu/score.sh after         # fills the "after" column
ubuntu/run-remote.sh ubuntu/rollback.sh --dry-run  # what undo would do
```

- **Single group:** `ubuntu/run-remote.sh ubuntu/harden.sh --only ssh`.
- **Full reset:** stop the VM, delete it, then run `utmctl clone ubuntu-lab-clean --name
  ubuntu-lab`.

Every check prints `OK` (already compliant), `WOULD CHANGE` (dry run) or `CHANGED`. A
second harden run should show only `OK`.

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
