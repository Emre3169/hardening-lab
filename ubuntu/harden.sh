#!/usr/bin/env bash
# CIS-style hardening for the Ubuntu 24.04 lab VM (PLAN.md §2).
#
# Usage: sudo ./harden.sh [--dry-run] [--only group[,group...]]
#   groups, in run order: patching services firewall auditd sysctl ssh accounts
#
# Every check prints OK (already compliant), WOULD CHANGE (--dry-run) or CHANGED.
# A real run copies each file to ~<sudo user>/backups/<UTC timestamp>/files/ before
# touching it and records every change in manifest.txt there; rollback.sh replays it.
# Re-running is safe: compliant items are left alone.
#
# Lab exception: the sudo user's NOPASSWD sudo is deliberately left in place.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

ALL_GROUPS=(patching services firewall auditd sysctl ssh accounts)
DRY_RUN=0
ONLY=""

usage() {
  local IFS=,
  echo "usage: sudo $0 [--dry-run] [--only ${ALL_GROUPS[*]}]"
  exit "${1:-2}"
}

while (($#)); do
  case $1 in
    -n|--dry-run) DRY_RUN=1 ;;
    --only) ONLY=${2:?--only needs a comma-separated list}; shift ;;
    --only=*) ONLY=${1#--only=} ;;
    -h|--help) usage 0 ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
  shift
done

for g in ${ONLY//,/ }; do
  [[ " ${ALL_GROUPS[*]} " == *" $g "* ]] || { echo "unknown group: $g" >&2; usage; }
done

if [[ $EUID -ne 0 ]]; then
  echo "run with sudo" >&2
  exit 1
fi

TARGET_USER=${SUDO_USER:-root}
TARGET_HOME=$(getent passwd "$TARGET_USER" | cut -d: -f6)
SSH_USER=${LAB_SSH_USER:-$TARGET_USER}
TS=$(date -u +%Y%m%dT%H%M%SZ)
BACKUP_ROOT=${LAB_BACKUP_ROOT:-$TARGET_HOME/backups}
RUN_DIR=$BACKUP_ROOT/$TS
MANIFEST=$RUN_DIR/manifest.txt

N_OK=0 N_WOULD=0 N_CHANGED=0
DIRTY=0        # set by any change (or would-be change) in the current group
APT_UPDATED=0
UFW_PREPARED=0

# --- output and bookkeeping ---------------------------------------------------

ok()      { N_OK=$((N_OK + 1));             printf '  %-13s %s\n' OK "$*"; }
would()   { N_WOULD=$((N_WOULD + 1));       printf '  %-13s %s\n' 'WOULD CHANGE' "$*"; }
changed() { N_CHANGED=$((N_CHANGED + 1));   printf '  %-13s %s\n' CHANGED "$*"; }
note()    { printf '  %-13s %s\n' NOTE "$*"; }
die()     { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# record <kind> <fields...>: append a tab-separated manifest line (real runs only).
record() {
  if ((DRY_RUN == 0)); then
    (IFS=$'\t'; printf '%s\n' "$*") >> "$MANIFEST"
  fi
}

# backup_file <path>: first time a path is touched in this run, copy it (or note
# that we are creating it) so rollback.sh can put it back.
backup_file() {
  local path=$1
  ((DRY_RUN == 0)) || return 0
  grep -qxF -- "$path" "$RUN_DIR/.seen" 2>/dev/null && return 0
  printf '%s\n' "$path" >> "$RUN_DIR/.seen"
  if [[ -e $path ]]; then
    mkdir -p "$RUN_DIR/files$(dirname "$path")"
    cp -a -- "$path" "$RUN_DIR/files$path"
    record backup "$path" "$(stat -c %a "$path")" "$(stat -c %U:%G "$path")"
  else
    record created "$path"
  fi
}

# undo_file <path>: put back this run's copy of a file (used when validation fails).
undo_file() {
  local path=$1
  if [[ -e $RUN_DIR/files$path ]]; then
    cp -a -- "$RUN_DIR/files$path" "$path"
  else
    rm -f -- "$path"
  fi
}

# run <description> <command...>: execute, or only describe it under --dry-run.
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

# --- idempotent building blocks ----------------------------------------------

ensure_pkg() {
  local p missing=()
  for p in "$@"; do
    if [[ $(dpkg-query -W -f='${Status}' "$p" 2> /dev/null) == *'install ok installed'* ]]; then
      ok "package $p installed"
    else
      missing+=("$p")
    fi
  done
  ((${#missing[@]})) || return 0
  DIRTY=1
  if ((DRY_RUN)); then
    would "install ${missing[*]}"
    return 0
  fi
  if ((APT_UPDATED == 0)); then
    apt-get update -qq
    APT_UPDATED=1
  fi
  apt-get install -y -qq "${missing[@]}" > /dev/null
  for p in "${missing[@]}"; do record pkg "$p"; done
  changed "installed ${missing[*]}"
}

# write_file <path> <mode>: make <path> hold exactly the content on stdin.
write_file() {
  local path=$1 mode=$2 tmp
  tmp=$(mktemp)
  cat > "$tmp"
  if [[ -f $path ]] && cmp -s "$tmp" "$path"; then
    rm -f "$tmp"
    ok "$path"
    return 0
  fi
  DIRTY=1
  if ((DRY_RUN)); then
    would "$path"
    if [[ -f $path ]]; then
      diff -u "$path" "$tmp" | tail -n +3 | sed 's/^/                  /' || true
    else
      sed 's/^/                  + /' "$tmp"
    fi
    rm -f "$tmp"
    return 0
  fi
  backup_file "$path"
  mkdir -p "$(dirname "$path")"
  install -m "$mode" -o root -g root "$tmp" "$path"
  rm -f "$tmp"
  changed "$path"
}

# remove_file <path>: delete a file we no longer want; the backup lets rollback restore it.
remove_file() {
  local path=$1
  if [[ ! -e $path ]]; then
    ok "$path absent"
    return 0
  fi
  DIRTY=1
  if ((DRY_RUN)); then
    would "remove $path"
    return 0
  fi
  backup_file "$path"
  rm -f -- "$path"
  changed "remove $path"
}

# set_kv <file> <key> <value>: for "KEY value" files such as /etc/login.defs.
set_kv() {
  local file=$1 key=$2 val=$3 cur
  cur=$(awk -v k="$key" '$1 == k { v = $2 } END { print v }' "$file")
  if [[ $cur == "$val" ]]; then
    ok "$file: $key $val"
    return 0
  fi
  DIRTY=1
  if ((DRY_RUN)); then
    would "$file: $key ${cur:-<unset>} -> $val"
    return 0
  fi
  backup_file "$file"
  if grep -qE "^[[:space:]]*$key[[:space:]]" "$file"; then
    sed -i -E "s/^[[:space:]]*$key[[:space:]].*/$key\t$val/" "$file"
  elif grep -qE "^[[:space:]]*#[[:space:]]*$key[[:space:]]" "$file"; then
    sed -i -E "0,/^[[:space:]]*#[[:space:]]*$key[[:space:]].*/s//$key\t$val/" "$file"
  else
    printf '%s\t%s\n' "$key" "$val" >> "$file"
  fi
  changed "$file: $key ${cur:-<unset>} -> $val"
}

# set_eq <file> <key> <value>: for key=value files; only edits a key already present.
set_eq() {
  local file=$1 key=$2 val=$3 cur
  if [[ ! -f $file ]] || ! grep -qE "^[[:space:]]*$key[[:space:]]*=" "$file"; then
    ok "$file: $key not set there"
    return 0
  fi
  cur=$(awk -F= -v k="$key" '{ g = $1; gsub(/[ \t]/, "", g) } g == k { v = $2 } END { gsub(/[ \t]/, "", v); print v }' "$file")
  if [[ $cur == "$val" ]]; then
    ok "$file: $key=$val"
    return 0
  fi
  DIRTY=1
  if ((DRY_RUN)); then
    would "$file: $key=$cur -> $val"
    return 0
  fi
  backup_file "$file"
  sed -i -E "s|^[[:space:]]*$key[[:space:]]*=.*|$key=$val|" "$file"
  changed "$file: $key=$cur -> $val"
}

# disable_unit <unit> <reason>: disable, stop and mask a unit that is enabled or running.
disable_unit() {
  local unit=$1 reason=$2 en act
  if [[ -z $(systemctl list-unit-files --no-legend "$unit" 2> /dev/null) ]]; then
    ok "$unit: not installed"
    return 0
  fi
  en=$(systemctl is-enabled "$unit" 2> /dev/null || true)
  act=$(systemctl is-active "$unit" 2> /dev/null || true)
  if [[ $en == masked ]]; then
    ok "$unit: masked"
    return 0
  fi
  if [[ $en == disabled && $act != active ]]; then
    ok "$unit: disabled and stopped"
    return 0
  fi
  DIRTY=1
  if ((DRY_RUN)); then
    would "$unit: $en/$act -> masked ($reason)"
    return 0
  fi
  record unit "$unit" "${en:-unknown}" "${act:-unknown}"
  systemctl disable --now "$unit" > /dev/null 2>&1 || true
  systemctl mask "$unit" > /dev/null 2>&1
  changed "$unit: $en/$act -> masked ($reason)"
}

# --- groups -------------------------------------------------------------------

group_patching() {
  ensure_pkg unattended-upgrades apt-listchanges apt-show-versions debsums
  write_file /etc/apt/apt.conf.d/20auto-upgrades 644 <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
  write_file /etc/apt/apt.conf.d/52lab-unattended 644 <<'EOF'
// hardening-lab (PLAN.md §2). 50unattended-upgrades already limits origins to -security.
// Lab VM: never reboot on our behalf; clean up after upgrades.
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
EOF
  note "Lynis 'no security repository' warning is a false positive: 3.0.9 can't read deb822 ubuntu.sources"
}

group_services() {
  # Sockets come before their services so nothing re-activates a stopped service.
  local entry
  for entry in \
    "ModemManager.service|no modem in a VM" \
    "multipathd.socket|no SAN multipath storage" \
    "multipathd.service|no SAN multipath storage" \
    "iscsid.socket|no iSCSI storage" \
    "iscsid.service|no iSCSI storage" \
    "open-iscsi.service|no iSCSI storage" \
    "udisks2.service|no desktop automount on a server" \
    "snapd.socket|no snaps needed; removes background refresh" \
    "snapd.service|no snaps needed; removes background refresh" \
    "snapd.seeded.service|no snaps needed" \
    "snapd.apparmor.service|no snaps needed" \
    "apport.service|crash reports can leak memory contents" \
    "whoopsie.service|crash reports can leak memory contents" \
    "motd-news.timer|phones home to Ubuntu" \
    "fwupd-refresh.timer|firmware updates are irrelevant in a VM" \
    "lxd-agent-loader.service|not an LXD guest" \
    "lxd-agent.service|not an LXD guest"; do
    disable_unit "${entry%%|*}" "${entry#*|}"
  done

  write_file /etc/modprobe.d/lab-blacklist.conf 644 <<'EOF'
# hardening-lab (PLAN.md §2): protocols and drivers this VM never uses.
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false
install usb-storage /bin/false
blacklist dccp
blacklist sctp
blacklist rds
blacklist tipc
blacklist usb-storage
EOF
}

# First ufw change of a run: remember whether ufw was active and back up its config.
ufw_prepare() {
  ((UFW_PREPARED == 0)) || return 0
  UFW_PREPARED=1
  record ufw "$(ufw status | awk 'NR == 1 { print $2 }')"
  local f
  for f in /etc/default/ufw /etc/ufw/ufw.conf /etc/ufw/user.rules /etc/ufw/user6.rules; do
    backup_file "$f"
  done
}

# fw_change <description> <ufw args...>
fw_change() {
  local desc=$1
  shift
  DIRTY=1
  if ((DRY_RUN)); then
    would "$desc"
    return 0
  fi
  ufw_prepare
  ufw "$@" > /dev/null
  changed "$desc"
}

group_firewall() {
  ensure_pkg ufw
  if ! command -v ufw > /dev/null; then
    note "ufw not installed yet (dry run); remaining firewall checks skipped"
    return 0
  fi
  if grep -q '^DEFAULT_INPUT_POLICY="DROP"' /etc/default/ufw; then ok "ufw default deny incoming"
  else fw_change "ufw default deny incoming" default deny incoming; fi

  if grep -q '^DEFAULT_OUTPUT_POLICY="ACCEPT"' /etc/default/ufw; then ok "ufw default allow outgoing"
  else fw_change "ufw default allow outgoing" default allow outgoing; fi

  # Before enabling, so the SSH session running this can't be cut off.
  if grep -qx 'ufw limit OpenSSH' <<< "$(ufw show added)"; then ok "ufw limit OpenSSH"
  else fw_change "ufw limit OpenSSH (allow, rate-limited)" limit OpenSSH; fi

  if grep -q '^LOGLEVEL=low' /etc/ufw/ufw.conf; then ok "ufw logging low"
  else fw_change "ufw logging low" logging low; fi

  if grep -q '^Status: active' <<< "$(ufw status)"; then ok "ufw active"
  else fw_change "ufw enable" --force enable; fi
}

group_auditd() {
  ensure_pkg auditd audispd-plugins
  # Not immutable (-e 2): that would block rollback until a reboot.
  write_file /etc/audit/rules.d/60-lab.rules 640 <<'EOF'
## hardening-lab (PLAN.md §2): CIS-style audit rules. Deliberately not immutable.
# identity and privilege configuration
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
# sshd configuration
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd
# time changes
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
# mounts by real users
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
# kernel module load/unload
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules
-w /usr/bin/kmod -p x -k modules
# setuid/setgid execution that ends up as root
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k setuid
-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k setgid
# login records
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins
-w /var/log/lastlog -p wa -k logins
EOF
  if systemctl is-enabled -q auditd 2> /dev/null && systemctl is-active -q auditd 2> /dev/null; then
    ok "auditd enabled and running"
  else
    DIRTY=1
    run "enable and start auditd" systemctl enable --now auditd
  fi
  if ((DIRTY)); then
    run "load audit rules (augenrules --load)" augenrules --load
    if ((DRY_RUN == 0)); then
      note "$(auditctl -l | grep -vc '^No rules') audit rules loaded"
    fi
  fi
}

SYSCTL_CONF=/etc/sysctl.d/99-zz-lab.conf

group_sysctl() {
  # 99-zz- so it loads after Ubuntu's /usr/lib/sysctl.d/99-protect-links.conf, which
  # would otherwise put fs.protected_fifos back to 1. Replaces the earlier 60-lab.conf.
  remove_file /etc/sysctl.d/60-lab.conf
  write_file "$SYSCTL_CONF" 644 <<'EOF'
# hardening-lab (PLAN.md §2)
# no ICMP redirects, accepted or sent
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
# no source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
# spoofing and floods
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
# kernel info leaks
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
# 1 is sticky until reboot (can't go back to Ubuntu's default 2 at runtime)
kernel.unprivileged_bpf_disabled = 1
# filesystem
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
fs.suid_dumpable = 0
EOF
  write_file /etc/security/limits.d/60-lab.conf 644 <<'EOF'
# hardening-lab (PLAN.md §2): no core dumps; they can contain secrets.
* hard core 0
EOF
  # ufw applies its own sysctl file when it starts; keep it from turning martian logging back off.
  set_eq /etc/ufw/sysctl.conf net/ipv4/conf/all/log_martians 1
  set_eq /etc/ufw/sysctl.conf net/ipv4/conf/default/log_martians 1
  if ((DIRTY)); then
    run "apply sysctl (sysctl --system)" sysctl_apply
  fi
}

sysctl_apply() {
  sysctl --system > /dev/null 2>&1 || note "sysctl --system reported errors; run it by hand to see them"
  local key want have
  while IFS='=' read -r key want; do
    key=${key// /} want=${want// /}
    [[ -z $key || $key == \#* ]] && continue
    have=$(sysctl -n "$key" 2> /dev/null || echo '?')
    [[ $have == "$want" ]] || note "$key is $have, expected $want"
  done < "$SYSCTL_CONF"
}

group_ssh() {
  [[ $SSH_USER != root ]] || die "ssh group needs a non-root login user (run via sudo, or set LAB_SSH_USER)"
  local ssh_home keys
  ssh_home=$(getent passwd "$SSH_USER" | cut -d: -f6)
  keys=$ssh_home/.ssh/authorized_keys
  [[ -s $keys ]] || die "$keys is empty or missing; refusing to disable password login"
  ok "$SSH_USER has authorized_keys"

  write_file /etc/issue 644 <<'EOF'
Authorized use only. This hardening-lab system may be monitored and logged.
EOF
  write_file /etc/issue.net 644 <<'EOF'
Authorized use only. This hardening-lab system may be monitored and logged.
EOF

  local conf=/etc/ssh/sshd_config.d/00-lab.conf
  DIRTY=0
  write_file "$conf" 644 <<EOF
# hardening-lab (PLAN.md §2). Named 00- on purpose: sshd keeps the first value it
# reads, and 50-cloud-init.conf may set PasswordAuthentication yes.
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
PermitEmptyPasswords no
MaxAuthTries 3
MaxSessions 4
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
LogLevel VERBOSE
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
TCPKeepAlive no
AllowUsers $SSH_USER
Banner /etc/issue.net
EOF
  ((DRY_RUN == 0)) || return 0

  # 24.04 socket-activates ssh, so /run/sshd may not exist yet; sshd -t needs it.
  install -d -m 0755 /run/sshd
  if ! sshd -t; then
    ((DIRTY)) && undo_file "$conf"
    die "sshd -t failed; $conf reverted, sshd not reloaded"
  fi
  local eff kv
  eff=$(sshd -T -C "user=$SSH_USER,host=localhost,addr=127.0.0.1")
  for kv in "passwordauthentication no" "kbdinteractiveauthentication no" "permitrootlogin no"; do
    if ! grep -qx "$kv" <<< "$eff"; then
      ((DIRTY)) && undo_file "$conf"
      die "effective sshd config lacks '$kv' (another file wins?); $conf reverted"
    fi
  done
  ok "effective sshd config: password and root login off"

  if ((DIRTY)); then
    if systemctl is-active -q ssh.service; then
      run "reload sshd (existing sessions stay up)" systemctl reload ssh.service
    else
      note "ssh.service idle (socket activation); the next connection reads the new config"
    fi
  fi
}

group_accounts() {
  set_kv /etc/login.defs UMASK 027
  set_kv /etc/login.defs PASS_MAX_DAYS 365
  set_kv /etc/login.defs PASS_MIN_DAYS 1
  set_kv /etc/login.defs SHA_CRYPT_MIN_ROUNDS 65536
  note "password ageing applies to new accounts only; existing accounts are not expired"
  ensure_pkg libpam-pwquality libpam-tmpdir
  if grep -rqsE "^[[:space:]]*$TARGET_USER[[:space:]].*NOPASSWD" /etc/sudoers /etc/sudoers.d; then
    note "lab exception kept: NOPASSWD sudo for $TARGET_USER (not changed)"
  fi
}

# --- main ---------------------------------------------------------------------

if ((DRY_RUN == 0)); then
  mkdir -p "$RUN_DIR"
  printf '# harden.sh %s  run %s\n' "${ONLY:+--only $ONLY}" "$TS" > "$MANIFEST"
  exec > >(tee -a "$RUN_DIR/harden.log") 2>&1
  # Owned by the login user so run-remote.sh can scp it back.
  trap 'chown "$TARGET_USER": "$BACKUP_ROOT"; chown -R "$TARGET_USER": "$RUN_DIR"' EXIT
fi

echo "== harden.sh $TS$( ((DRY_RUN)) && echo ' (dry run)')"
for g in "${ALL_GROUPS[@]}"; do
  if [[ -n $ONLY && ",$ONLY," != *",$g,"* ]]; then
    continue
  fi
  echo "== $g"
  DIRTY=0
  "group_$g"
done

echo "== summary: $N_CHANGED changed, $N_WOULD would change, $N_OK already OK"
if ((DRY_RUN == 0)); then
  if grep -qv '^#' "$MANIFEST"; then
    echo "backups and manifest: $RUN_DIR"
    echo "undo with: sudo ./rollback.sh $TS"
  else
    echo "nothing changed; rollback.sh will skip $RUN_DIR"
  fi
fi
