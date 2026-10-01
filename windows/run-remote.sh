#!/usr/bin/env bash
# Copy a lab script to windows-lab, run it elevated over ssh, then pull results back
# (PLAN.md section 1). Runs on the Mac; bash 3.2 compatible.
#
# Usage: windows/run-remote.sh <script.ps1> [args...]
#   windows/run-remote.sh windows/harden.ps1 -DryRun
#   windows/run-remote.sh windows/harden.ps1 -Only Services,AuditPolicy
#   windows/run-remote.sh windows/score.ps1 before
#
# The VM's ssh default shell is PowerShell, so args are parsed by PowerShell (arrays like
# Services,AuditPolicy work). Execution policy is bypassed for that one process only.
# Afterwards C:\hardening-lab\scores\* is copied into scores/ and C:\hardening-lab\backups\
# into backups/windows-lab/ (gitignored). After score.ps1 the scores/SCORES.md row is filled:
# "before" adds a row, "after" fills the after column of the matching open row.
set -euo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)
HOST=${LAB_WIN_HOST:-windows-lab}
REMOTE_DIR='C:/hardening-lab'

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <script.ps1> [args...]" >&2
  exit 2
fi
SCRIPT=$1
shift
[[ -f $SCRIPT ]] || { echo "no such script: $SCRIPT" >&2; exit 2; }
NAME=$(basename "$SCRIPT")

# WarnWeakCrypto=no: Windows' OpenSSH 9.5 has no post-quantum key exchange; the warning is noise here.
SSH_OPTS=(-F "$REPO/.ssh/config" -o BatchMode=yes -o ConnectTimeout=10
  -o ServerAliveInterval=30 -o ServerAliveCountMax=6 -o WarnWeakCrypto=no)

# Windows has no ufw-style rate limit, but keep retries bounded: 10 tries, 10 s apart.
tries=0
until ssh "${SSH_OPTS[@]}" "$HOST" 'exit 0' 2> /dev/null; do
  tries=$((tries + 1))
  if [[ $tries -ge 10 ]]; then
    echo "cannot reach $HOST after 10 tries" >&2
    exit 1
  fi
  sleep 10
done

ssh "${SSH_OPTS[@]}" "$HOST" "New-Item -ItemType Directory -Force -Path '$REMOTE_DIR' | Out-Null"
scp "${SSH_OPTS[@]}" -q "$SCRIPT" "$HOST:$REMOTE_DIR/$NAME"

ARGS="$*"
echo "== $HOST: $NAME $ARGS"
set +e
ssh "${SSH_OPTS[@]}" "$HOST" \
  "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force; & '$REMOTE_DIR/$NAME' $ARGS; if (-not \$?) { exit 1 }"
rc=$?
set -e

# Pull results even when the script failed, so logs and partial backups come back.
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
for d in scores backups; do
  if ssh "${SSH_OPTS[@]}" "$HOST" "if (Test-Path '$REMOTE_DIR/$d') { exit 0 } else { exit 1 }"; then
    scp "${SSH_OPTS[@]}" -q -r "$HOST:$REMOTE_DIR/$d" "$TMP/"
    if [[ $d == scores ]]; then
      mkdir -p "$REPO/scores"
      cp -p "$TMP/scores/"* "$REPO/scores/"
      echo "pulled $REMOTE_DIR/scores -> scores/"
    else
      mkdir -p "$REPO/backups/windows-lab"
      cp -Rp "$TMP/backups/"* "$REPO/backups/windows-lab/" 2> /dev/null || true
      echo "pulled $REMOTE_DIR/backups -> backups/windows-lab/"
    fi
  fi
done

# Fill scores/SCORES.md from the summary score.ps1 wrote.
if [[ $NAME == score.ps1 && $rc -eq 0 ]]; then
  LABEL=$(printf '%s\n' "$@" | grep -m1 -xE 'before|after' || true)
  if [[ -n $LABEL && -f $REPO/scores/hardeningkitty-$LABEL.json ]]; then
    python3 - "$REPO/scores/SCORES.md" "$REPO/scores/hardeningkitty-$LABEL.json" <<'PY'
import json, sys
table, summary = sys.argv[1], sys.argv[2]
s = json.load(open(summary, encoding="utf-8-sig"))   # PowerShell 5.1 writes a BOM
score = f'{s["score"]:.2f}'
lines = open(table, encoding="utf-8").read().splitlines()
def cells(l): return [c.strip() for c in l.strip().strip("|").split("|")]
if s["label"] == "before":
    lines.append(f'| {s["date"]} | {s["machine"]} | {s["tool"]} | {score} | |')
    msg = f'new row, before = {score}'
else:
    idx = None
    for i, l in enumerate(lines):
        c = cells(l) if l.startswith("|") else []
        if len(c) == 5 and c[1] == s["machine"] and c[2] == s["tool"] and c[4] == "" and c[3] not in ("before", ""):
            idx = i
    if idx is None:
        sys.exit(f'no open row for {s["machine"]} / {s["tool"]}; run score.ps1 before first')
    c = cells(lines[idx]); c[4] = score
    lines[idx] = "| " + " | ".join(c) + " |"
    msg = f'after = {score} (before {c[3]}, delta {float(score) - float(c[3]):+.2f})'
open(table, "w", encoding="utf-8").write("\n".join(lines) + "\n")
print(f"  CHANGED       scores/SCORES.md: {msg}")
PY
  fi
fi

echo "== $NAME exited $rc"
exit $rc
