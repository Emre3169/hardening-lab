#!/usr/bin/env bash
# Baseline an Ubuntu lab VM: patch, install Lynis, record the pre-hardening score.
# Run: sudo bash baseline.sh
# Output lands in the invoking user's ~/scores (not root's), owned by that user.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a   # don't let needrestart prompt during upgrade

if [[ $EUID -ne 0 ]]; then
  echo "run with sudo" >&2
  exit 1
fi

TARGET_USER=${SUDO_USER:-root}
TARGET_HOME=$(getent passwd "$TARGET_USER" | cut -d: -f6)
SCORES="$TARGET_HOME/scores"
REPORT=/var/log/lynis-report.dat
MACHINE=$(hostname)
DATE=$(date +%F)

echo "== apt update/upgrade"
apt-get update
apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade

echo "== install lynis git"
apt-get install -y lynis git

mkdir -p "$SCORES"

echo "== lynis audit (this takes a few minutes)"
# Lynis can exit non-zero on findings; the report file is what matters.
lynis audit system --no-colors > "$SCORES/lynis-before.txt" 2>&1 || echo "lynis exited $?, continuing"

INDEX=$(grep -E '^hardening_index=' "$REPORT" | tail -1 | cut -d= -f2)
if [[ -z "$INDEX" ]]; then
  echo "hardening_index not found in $REPORT" >&2
  exit 1
fi

if [[ ! -f "$SCORES/SCORES.md" ]]; then
  cat > "$SCORES/SCORES.md" <<'EOF'
# Hardening scores

| date | machine | tool | before | after |
|------|---------|------|--------|-------|
EOF
fi
echo "| $DATE | $MACHINE | lynis $(lynis show version 2>/dev/null || echo '?') | $INDEX | |" >> "$SCORES/SCORES.md"

chown -R "$TARGET_USER": "$SCORES"

echo "Lynis hardening index ($MACHINE): $INDEX"
