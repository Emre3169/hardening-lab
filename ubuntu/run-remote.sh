#!/usr/bin/env bash
# Copy a lab script to the VM, run it there with sudo, then pull ~/scores and ~/backups
# back into the repo (PLAN.md §1). Runs on the Mac; bash 3.2 compatible.
#
# Usage: ubuntu/run-remote.sh <script> [args...]
#   ubuntu/run-remote.sh ubuntu/harden.sh --dry-run
#   ubuntu/run-remote.sh ubuntu/score.sh after
#
# All traffic goes through `ssh -F .ssh/config ubuntu-lab` over ONE multiplexed
# connection: after hardening, ufw's `limit OpenSSH` blocks an address that opens
# 6+ new connections in 30 s, which a plain scp/ssh/scp sequence would hit.
# The VM is the source of truth for scores/: pulled files overwrite the local copies.
set -euo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)
HOST=${LAB_HOST:-ubuntu-lab}

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <script> [args...]" >&2
  exit 2
fi
SCRIPT=$1
shift
[[ -f $SCRIPT ]] || { echo "no such script: $SCRIPT" >&2; exit 2; }
NAME=$(basename "$SCRIPT")

SSH_OPTS=(-F "$REPO/.ssh/config"
  -o BatchMode=yes -o ConnectTimeout=10
  -o ServerAliveInterval=30 -o ServerAliveCountMax=6
  -o ControlMaster=auto -o "ControlPath=/tmp/lab-ssh-$(id -u)-%C" -o ControlPersist=120)

close_master() { ssh "${SSH_OPTS[@]}" -O exit "$HOST" 2> /dev/null || true; }
trap close_master EXIT

# sshd may still be starting after a VM boot: at most 10 tries, 5 s apart.
tries=0
until ssh "${SSH_OPTS[@]}" "$HOST" true 2> /dev/null; do
  tries=$((tries + 1))
  if [[ $tries -ge 10 ]]; then
    echo "cannot reach $HOST after 10 tries" >&2
    exit 1
  fi
  sleep 5
done

ssh "${SSH_OPTS[@]}" "$HOST" 'mkdir -p ~/lab'
scp "${SSH_OPTS[@]}" -q "$SCRIPT" "$HOST:lab/$NAME"

ARGS=""
for a in "$@"; do ARGS="$ARGS $(printf '%q' "$a")"; done

echo "== $HOST: sudo ./$NAME$ARGS"
set +e
ssh "${SSH_OPTS[@]}" "$HOST" "cd ~/lab && sudo bash ./$NAME$ARGS"
rc=$?
set -e

# Pull results even when the script failed, so logs and partial backups come back.
for d in scores backups; do
  if ssh "${SSH_OPTS[@]}" "$HOST" "test -d ~/$d"; then
    scp "${SSH_OPTS[@]}" -q -r "$HOST:$d" "$REPO/"
    echo "pulled ~/$d -> $d/"
  fi
done

echo "== $NAME exited $rc"
exit $rc
