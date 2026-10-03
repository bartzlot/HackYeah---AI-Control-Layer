#!/usr/bin/env bash
# TASKS.md state changes as atomic compare-and-swap on origin/main.
# Every change is one commit touching only TASKS.md, made in a throwaway worktree
# on top of a fresh origin/main and pushed to main. A rejected push means someone
# else changed TASKS.md first: refetch, re-validate, retry. Two agents can never
# both claim the same task.
#
#   scripts/task.sh next                 open tasks for your piece with all deps done
#   scripts/task.sh list                 all tasks on origin/main
#   scripts/task.sh claim T-101          [ ] -> [~]  (deps must be [x], piece must match)
#   scripts/task.sh done T-101           [~] -> [x]  (only the claimer)
#   scripts/task.sh block T-101 "why"    -> [!]
#   scripts/task.sh release T-101        [~]/[!] -> [ ]
#   scripts/task.sh add "[w3] title | deps: T-303"   new task, next free id in the piece range
#
# Piece = current branch prefix (w1-x -> w1, main -> lead). TASK_FORCE=1 skips piece/owner checks.
set -euo pipefail

verb="${1:-}"; arg="${2:-}"; reason="${3:-}"
root="$(git rev-parse --show-toplevel)"
branch="$(git -C "$root" branch --show-current)"
piece="${branch%%-*}"; [ "$branch" = main ] && piece=lead
who="${piece}/$(git -C "$root" config user.name | tr -c 'A-Za-z0-9._\n' _)@$(hostname -s 2>/dev/null || hostname)"

edit() { # $1 = input file, writes new content to stdout; exit 2 not found, 3 rejected
  awk -v verb="$verb" -v id="$arg" -v who="$who" -v mypiece="$piece" -v force="${TASK_FORCE:-0}" \
      -v reason="$reason" -v ts="$(date -u +%Y-%m-%dT%H:%MZ)" '
    function tid(l) { return match(l, /T-[0-9]+/) ? substr(l, RSTART, RLENGTH) : "" }
    function ptag(l,  r) { match(l, /T-[0-9]+/); r = substr(l, RSTART + RLENGTH)
      return match(r, /^ \[[a-z0-9]+\]/) ? substr(r, RSTART + 2, RLENGTH - 3) : "" }
    function depsok(l,  d, a, n, i, bad) { bad = ""
      if (match(l, /deps: [^|]*/)) { d = substr(l, RSTART + 6, RLENGTH - 6); n = split(d, a, "[ ,]+")
        for (i = 1; i <= n; i++) if (a[i] ~ /^T-/ && st[a[i]] != "x") bad = bad " " a[i] }
      return bad }
    FNR == NR { if ($0 ~ /^- \[.\] T-[0-9]+ /) { st[tid($0)] = substr($0, 4, 1)
        n0 = substr(tid($0), 3) + 0; if (int(n0 / 100) == want) max = (n0 > max ? n0 : max) }
      next }
    BEGIN { want = (mypiece ~ /^w[1-5]$/ ? substr(mypiece, 2) + 0 : 0)
      if (verb == "add" && match(id, /^\[[a-z0-9]+\]/)) { t = substr(id, 2, RLENGTH - 2)
        want = (t ~ /^w[1-5]$/ ? substr(t, 2) + 0 : (t == "any" ? 9 : 0)) } }
    { line = $0; cur = substr(line, 4, 1)
      if (verb == "next") { if (line ~ /^- \[ \] T-/ && (ptag(line) == mypiece || ptag(line) == "any") && depsok(line) == "") print line; next }
      if (verb == "add" || line !~ /^- \[.\] T-[0-9]+ / || tid(line) != id) { print line; next }
      found = 1; p = ptag(line)
      if (verb == "claim") {
        if (cur != " ") err = "not open, status [" cur "]: " line
        else if (p != mypiece && p != "any" && force != "1") err = "piece [" p "] is not yours [" mypiece "]"
        else if ((b = depsok(line)) != "") err = "deps not done:" b
        else line = "- [~]" substr(line, 6) " | claimed: " who " " ts
      } else if (verb == "done") {
        if (cur != "~") err = "not claimed, status [" cur "]"
        else if (index(line, "claimed: " who " ") == 0 && force != "1") err = "claimed by someone else: " line
        else line = "- [x]" substr(line, 6) " | done: " ts
      } else if (verb == "block") {
        if (cur == "x") err = "already done"
        else { sub(/ \| blocked: .*$/, "", line); line = "- [!]" substr(line, 6) " | blocked: " reason " (" who " " ts ")" }
      } else if (verb == "release") {
        if (cur != "~" && cur != "!") err = "nothing to release, status [" cur "]"
        else { sub(/ \| (claimed|blocked): .*$/, "", line); line = "- [ ]" substr(line, 6) }
      } else err = "unknown verb " verb
      print line }
    END {
      if (verb == "add") { if (id !~ /^\[[a-z0-9]+\] /) { print "add: expected \"[piece] title | deps: ...\"" > "/dev/stderr"; exit 3 }
        nid = (max ? max + 1 : want * 100 + 1); printf "- [ ] T-%03d %s\n", nid, id; exit }
      if (verb == "next") exit
      if (!found) { print id ": not found" > "/dev/stderr"; exit 2 }
      if (err != "") { print id ": " err > "/dev/stderr"; exit 3 } }
  ' "$1" "$1"
}

case "$verb" in
  list) git -C "$root" fetch -q origin main; git -C "$root" show origin/main:TASKS.md | grep -E '^- \[.\] T-'; exit ;;
  next) git -C "$root" fetch -q origin main; f="$(mktemp)"; git -C "$root" show origin/main:TASKS.md > "$f"; edit "$f"; rm -f "$f"; exit ;;
  claim|done|block|release|add) [ -n "$arg" ] || { echo "usage: $0 $verb <arg>" >&2; exit 1; } ;;
  *) sed -n '2,20p' "$0"; exit 1 ;;
esac

wt="$(mktemp -d)/wt"
trap 'git -C "$root" worktree remove --force "$wt" >/dev/null 2>&1 || true' EXIT
git -C "$root" fetch -q origin main
git -C "$root" worktree add -q --detach "$wt" origin/main
for attempt in 1 2 3 4 5 6 7 8; do
  git -C "$wt" fetch -q origin main && git -C "$wt" reset -q --hard origin/main
  edit "$wt/TASKS.md" > "$wt/TASKS.md.new"   # exits non-zero (set -e) on invalid transition
  mv "$wt/TASKS.md.new" "$wt/TASKS.md"
  git -C "$wt" commit -q -m "task: $verb ${arg%% |*} ($who)" -- TASKS.md
  if git -C "$wt" push -q origin HEAD:main 2>/dev/null; then
    echo "OK $verb ${arg%% |*} by $who"
    if [ "$verb" = add ]; then tail -n 1 "$wt/TASKS.md"; else grep -E "^- \[.\] $arg " "$wt/TASKS.md"; fi
    git -C "$root" fetch -q origin main; exit 0
  fi
  echo "push rejected (attempt $attempt), someone changed TASKS.md first; retrying" >&2
  sleep $((RANDOM % 3 + 1))
done
echo "gave up after 8 attempts" >&2; exit 4
