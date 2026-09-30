#!/usr/bin/env bash
# Run a Lynis audit and record it in ~<sudo user>/scores (PLAN.md §4).
#
# Usage: sudo ./score.sh before|after [--force]
#   before  save lynis-before.txt and add a new row: date | machine | tool | index | (blank)
#   after   save lynis-after.txt and fill the "after" column of the newest open row for
#           this machine and tool (same Lynis version, so the scores are comparable)
#   --force overwrite an existing lynis-<label>.txt
set -euo pipefail

LABEL=""
FORCE=0

usage() {
  echo "usage: sudo $0 before|after [--force]"
  exit "${1:-2}"
}

while (($#)); do
  case $1 in
    before|after) LABEL=$1 ;;
    --force) FORCE=1 ;;
    -h|--help) usage 0 ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
  shift
done
[[ -n $LABEL ]] || usage

ok()      { printf '  %-13s %s\n' OK "$*"; }
changed() { printf '  %-13s %s\n' CHANGED "$*"; }
note()    { printf '  %-13s %s\n' NOTE "$*"; }
die()     { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

if [[ $EUID -ne 0 ]]; then
  echo "run with sudo" >&2
  exit 1
fi
command -v lynis > /dev/null || die "lynis not installed; run baseline.sh first"

TARGET_USER=${SUDO_USER:-root}
TARGET_HOME=$(getent passwd "$TARGET_USER" | cut -d: -f6)
SCORES=$TARGET_HOME/scores
TABLE=$SCORES/SCORES.md
OUT=$SCORES/lynis-$LABEL.txt
REPORT=/var/log/lynis-report.dat
MACHINE=$(hostname)
TOOL="lynis $(lynis show version)"

if [[ -e $OUT && $FORCE -eq 0 ]]; then
  die "$OUT exists; use --force to overwrite"
fi
mkdir -p "$SCORES"

echo "== lynis audit ($LABEL), takes a few minutes"
# Lynis can exit non-zero on findings; the report file is what matters.
lynis audit system --no-colors > "$OUT" 2>&1 || note "lynis exited $?, continuing"
changed "$OUT"

INDEX=$(grep -E '^hardening_index=' "$REPORT" | tail -1 | cut -d= -f2)
[[ -n $INDEX ]] || die "hardening_index not found in $REPORT"

if [[ -f $TABLE ]]; then
  ok "$TABLE exists"
else
  cat > "$TABLE" <<'EOF'
# Hardening scores

| date | machine | tool | before | after |
|------|---------|------|--------|-------|
EOF
  changed "$TABLE (new)"
fi

if [[ $LABEL == before ]]; then
  printf '| %s | %s | %s | %s | |\n' "$(date +%F)" "$MACHINE" "$TOOL" "$INDEX" >> "$TABLE"
  changed "$TABLE: new row, before = $INDEX"
else
  tmp=$(mktemp "$SCORES/.SCORES.XXXXXX")
  # Fill column 6 ("after") of the last row for this machine+tool whose after is blank.
  if awk -F'|' -v m="$MACHINE" -v t="$TOOL" -v v="$INDEX" '
      function trim(s) { gsub(/^[ \t]+|[ \t]+$/, "", s); return s }
      { line[NR] = $0 }
      NF >= 7 && trim($3) == m && trim($4) == t && trim($5) ~ /^[0-9]+$/ && trim($6) == "" { last = NR }
      END {
        if (!last) exit 3
        for (i = 1; i <= NR; i++) {
          if (i != last) { print line[i]; continue }
          n = split(line[i], f, "|"); f[6] = " " v " "
          s = f[1]; for (j = 2; j <= n; j++) s = s "|" f[j]
          print s
        }
      }' "$TABLE" > "$tmp"; then
    chmod 644 "$tmp"
    mv "$tmp" "$TABLE"
    row=$(grep -F "| $MACHINE | $TOOL |" "$TABLE" | tail -1)
    before=$(awk -F'|' '{ gsub(/ /, "", $5); print $5 }' <<< "$row")
    changed "$TABLE: after = $INDEX (before $before, delta $((INDEX - before)))"
  else
    rm -f "$tmp"
    die "no open row for $MACHINE / $TOOL in $TABLE; run 'score.sh before' first"
  fi
fi

chown -R "$TARGET_USER": "$SCORES"
echo "Lynis hardening index ($MACHINE, $LABEL): $INDEX"
