#!/usr/bin/env bash
# Undo one harden.sh run by replaying its manifest in reverse (PLAN.md §5).
#
# Usage: sudo ./rollback.sh [--dry-run] [--purge-packages] [--force] [<timestamp> | <run dir>]
#   Default run: the newest one under ~<sudo user>/backups that changed something and
#   hasn't been rolled back. Run it repeatedly to unwind several harden runs, newest first.
#   --purge-packages  also purge packages that harden.sh installed (default: keep them)
#   --force           allow rolling back a run while a newer one is still applied
#
# Prints OK / WOULD CHANGE / CHANGED like harden.sh. For a guaranteed clean slate,
# re-clone the VM from ubuntu-lab-clean instead.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

DRY_RUN=0
PURGE=0
FORCE=0
TARGET=""

usage() {
  echo "usage: sudo $0 [--dry-run] [--purge-packages] [--force] [<timestamp> | <run dir>]"
  exit "${1:-2}"
}

while (($#)); do
  case $1 in
    -n|--dry-run) DRY_RUN=1 ;;
    --purge-packages) PURGE=1 ;;
    --force) FORCE=1 ;;
    -h|--help) usage 0 ;;
    -*) echo "unknown argument: $1" >&2; usage ;;
    *) TARGET=$1 ;;
  esac
  shift
done

if [[ $EUID -ne 0 ]]; then
  echo "run with sudo" >&2
  exit 1
fi

TARGET_USER=${SUDO_USER:-root}
TARGET_HOME=$(getent passwd "$TARGET_USER" | cut -d: -f6)
BACKUP_ROOT=${LAB_BACKUP_ROOT:-$TARGET_HOME/backups}

N_OK=0 N_WOULD=0 N_CHANGED=0
NEED_SYSCTL=0 NEED_AUDIT=0 NEED_SSH=0
PKGS=()

ok()      { N_OK=$((N_OK + 1));             printf '  %-13s %s\n' OK "$*"; }
would()   { N_WOULD=$((N_WOULD + 1));       printf '  %-13s %s\n' 'WOULD CHANGE' "$*"; }
changed() { N_CHANGED=$((N_CHANGED + 1));   printf '  %-13s %s\n' CHANGED "$*"; }
note()    { printf '  %-13s %s\n' NOTE "$*"; }
die()     { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

run() {
  local desc=$1
  shift
  if ((DRY_RUN)); then
    would "$desc"
    return 0
  fi
  "$@"
  changed "$desc"
}

# A run is pending if it recorded changes and hasn't been rolled back.
pending() {
  [[ -f $1/manifest.txt && ! -e $1/ROLLED_BACK ]] && grep -qv '^#' "$1/manifest.txt"
}

# --- pick the run -------------------------------------------------------------

shopt -s nullglob
RUNS=()
for d in "$BACKUP_ROOT"/*/; do RUNS+=("${d%/}"); done
shopt -u nullglob
# Timestamps sort chronologically; newest first.
mapfile -t RUNS < <(printf '%s\n' "${RUNS[@]}" | sort -r)

RUN_DIR=""
if [[ -n $TARGET ]]; then
  if [[ -d $TARGET ]]; then RUN_DIR=$(cd "$TARGET" && pwd); else RUN_DIR=$BACKUP_ROOT/$TARGET; fi
  pending "$RUN_DIR" || die "$RUN_DIR has no pending changes (missing, empty or already rolled back)"
  for d in "${RUNS[@]}"; do
    [[ $d == "$RUN_DIR" ]] && break
    if pending "$d" && ((FORCE == 0)); then
      die "newer run $(basename "$d") is still applied; roll it back first (or --force)"
    fi
  done
else
  for d in "${RUNS[@]}"; do
    if pending "$d"; then RUN_DIR=$d; break; fi
  done
  [[ -n $RUN_DIR ]] || die "no pending harden runs under $BACKUP_ROOT"
fi

MANIFEST=$RUN_DIR/manifest.txt
echo "== rollback.sh $(basename "$RUN_DIR")$( ((DRY_RUN)) && echo ' (dry run)')"

# --- actions ------------------------------------------------------------------

touched() {
  case $1 in
    /etc/sysctl.d/*|/etc/security/limits.d/*|/etc/ufw/sysctl.conf) NEED_SYSCTL=1 ;;
    /etc/audit/*) NEED_AUDIT=1 ;;
    /etc/ssh/*) NEED_SSH=1 ;;
  esac
}

restore_backup() {
  local path=$1 mode=$2 owner=$3 src=$RUN_DIR/files$1
  if [[ ! -f $src ]]; then
    note "no backup copy of $path in this run; skipped"
    return 0
  fi
  if [[ -f $path ]] && cmp -s "$src" "$path"; then
    ok "$path is the original"
    return 0
  fi
  touched "$path"
  run "restore $path" install -m "$mode" -o "${owner%%:*}" -g "${owner##*:}" "$src" "$path"
}

remove_created() {
  local path=$1
  if [[ ! -e $path ]]; then
    ok "$path already gone"
    return 0
  fi
  touched "$path"
  run "remove $path" rm -f -- "$path"
}

restore_unit() {
  local unit=$1 was_en=$2 was_act=$3 cur
  cur=$(systemctl is-enabled "$unit" 2> /dev/null || true)
  if [[ $cur != masked ]]; then
    ok "$unit not masked ($cur)"
    return 0
  fi
  run "unmask $unit" systemctl unmask "$unit"
  if [[ $was_en == enabled* ]]; then
    run "enable $unit (was $was_en)" systemctl enable "$unit"
  fi
  if [[ $was_act == active ]]; then
    run "start $unit (was active)" systemctl start "$unit"
  fi
}

# Files were restored before we get here (reverse order), so only the runtime state is left.
restore_ufw() {
  local was=$1 now
  now=$(ufw status | awk 'NR == 1 { print $2 }')
  if [[ $was == inactive ]]; then
    if [[ $now == inactive ]] && grep -qx '(None)' <<< "$(ufw show added)"; then
      ok "ufw inactive with no rules, as before"
    else
      run "ufw --force reset (was inactive before harden)" ufw --force reset
    fi
  else
    run "ufw reload with restored rules (was active before harden)" ufw --force enable
  fi
}

mapfile -t LINES < <(grep -v '^#' "$MANIFEST" | tac)
for line in "${LINES[@]}"; do
  IFS=$'\t' read -r kind a b c <<< "$line"
  case $kind in
    backup)  restore_backup "$a" "$b" "$c" ;;
    created) remove_created "$a" ;;
    unit)    restore_unit "$a" "$b" "$c" ;;
    ufw)     restore_ufw "$a" ;;
    pkg)     PKGS+=("$a") ;;
    *)       note "unknown manifest entry: $line" ;;
  esac
done

# --- reload what changed --------------------------------------------------------

sysctl_reload() {
  sysctl --system > /dev/null 2>&1 || note "sysctl --system reported errors; run it by hand to see them"
}

if ((NEED_SYSCTL)); then
  run "apply sysctl (sysctl --system)" sysctl_reload
  note "kernel.unprivileged_bpf_disabled=1 stays until reboot (the kernel won't lower it)"
fi
if ((NEED_AUDIT)) && command -v augenrules > /dev/null; then
  run "reload audit rules (augenrules --load)" augenrules --load
fi
if ((NEED_SSH)); then
  if ((DRY_RUN)); then
    would "sshd -t, then reload sshd"
  else
    install -d -m 0755 /run/sshd
    sshd -t || die "sshd -t FAILED after restore; sshd NOT reloaded. Fix it before closing this session."
    if systemctl is-active -q ssh.service; then
      run "reload sshd (existing sessions stay up)" systemctl reload ssh.service
    else
      note "ssh.service idle (socket activation); the next connection reads the restored config"
    fi
  fi
fi

if ((${#PKGS[@]})); then
  if ((PURGE)); then
    run "purge ${PKGS[*]}" apt-get purge -y -qq "${PKGS[@]}"
  else
    note "left installed (use --purge-packages to remove): ${PKGS[*]}"
  fi
fi

echo "== summary: $N_CHANGED changed, $N_WOULD would change, $N_OK already OK"
if ((DRY_RUN == 0)); then
  date -u +%Y%m%dT%H%M%SZ > "$RUN_DIR/ROLLED_BACK"
  chown "$TARGET_USER": "$RUN_DIR/ROLLED_BACK"
  echo "marked $(basename "$RUN_DIR") as rolled back"
fi
