#!/bin/bash
# Basic tests for statusline

# Isolate from the user's global git config so throwaway test repos
# can commit without hitting commit.gpgsign / signing-key prompts.
export GIT_CONFIG_GLOBAL=/dev/null

PASS=0
FAIL=0

pass() {
  echo "PASS: $1"
  PASS=$((PASS + 1))
}
fail() {
  echo "FAIL: $1"
  FAIL=$((FAIL + 1))
}

# Build if needed
[ -x ./statusline ] || make

# Test 1: Help output
if ./statusline --help 2>&1 | grep -q "Usage:"; then
  pass "help output"
else
  fail "help output"
fi

# Test 2: Claude mode with JSON input (nested schema, real Claude Code shape)
OUT=$(echo '{"model":{"display_name":"test-model"}}' | ./statusline 2>&1)
if echo "$OUT" | grep -q "test-model"; then
  pass "claude mode parses model name"
else
  fail "claude mode parses model name"
fi

# Test 2a: Claude mode strips "Claude " prefix
OUT=$(echo '{"model":{"display_name":"Claude Sonnet 4.6"}}' | ./statusline 2>&1)
if echo "$OUT" | grep -q '\[Sonnet 4\.6\]' && ! echo "$OUT" | grep -q 'Claude'; then
  pass "claude mode strips Claude prefix"
else
  fail "claude mode strips Claude prefix"
fi

# Test 2b: Claude mode renders cost, lines, durations from nested cost block
OUT=$(echo '{"model":{"display_name":"X"},"cost":{"total_cost_usd":1.426,"total_lines_added":122,"total_lines_removed":3,"total_duration_ms":783478,"total_api_duration_ms":367185}}' | ./statusline 2>&1)
if echo "$OUT" | grep -q '\$1\.43' &&
  echo "$OUT" | grep -q '+122' &&
  echo "$OUT" | grep -q -- '-3' &&
  echo "$OUT" | grep -q '6m7s/13m3s'; then
  pass "claude mode renders cost block"
else
  fail "claude mode renders cost block (got: $OUT)"
fi

# Test 2c: Claude mode reads context_window.used_percentage directly
OUT=$(echo '{"model":{"display_name":"X"},"context_window":{"used_percentage":42}}' | ./statusline 2>&1)
if echo "$OUT" | grep -q '42%'; then
  pass "claude mode renders context percentage"
else
  fail "claude mode renders context percentage"
fi

# Test 2c1: token-based context fallback (no used/remaining percentages)
OUT=$(echo '{"model":{"display_name":"X"},"context_window":{"context_window_size":200000,"current_usage":{"input_tokens":15000,"cache_creation_input_tokens":2000,"cache_read_input_tokens":80000}}}' | ./statusline 2>&1)
if echo "$OUT" | grep -q '48%' && echo "$OUT" | grep -q '97k/200k'; then
  pass "claude mode token-based context fallback"
else
  fail "claude mode token-based context fallback (got: $OUT)"
fi

# Test 2c2: token fallback excludes output_tokens (matches used_percentage)
OUT=$(echo '{"model":{"display_name":"X"},"context_window":{"context_window_size":200000,"current_usage":{"input_tokens":15000,"output_tokens":3000,"cache_creation_input_tokens":2000,"cache_read_input_tokens":80000}}}' | ./statusline 2>&1)
if echo "$OUT" | grep -q '48%' && ! echo "$OUT" | grep -q '50%'; then
  pass "claude mode fallback excludes output_tokens"
else
  fail "claude mode fallback excludes output_tokens (got: $OUT)"
fi

# Test 2c3: used_percentage wins over token data
OUT=$(echo '{"model":{"display_name":"X"},"context_window":{"used_percentage":10,"context_window_size":200000,"current_usage":{"input_tokens":80000,"cache_read_input_tokens":40000}}}' | ./statusline 2>&1)
if echo "$OUT" | grep -q '10%'; then
  pass "claude mode used_percentage wins over tokens"
else
  fail "claude mode used_percentage wins over tokens (got: $OUT)"
fi

# Test 2c4: remaining_percentage wins over token data
OUT=$(echo '{"model":{"display_name":"X"},"context_window":{"remaining_percentage":60,"context_window_size":200000,"current_usage":{"input_tokens":80000,"cache_read_input_tokens":40000}}}' | ./statusline 2>&1)
if echo "$OUT" | grep -q '40%'; then
  pass "claude mode remaining_percentage wins over tokens"
else
  fail "claude mode remaining_percentage wins over tokens (got: $OUT)"
fi

# Test 2c5: absolute counts shown alongside used_percentage when tokens present
OUT=$(echo '{"model":{"display_name":"X"},"context_window":{"used_percentage":11,"context_window_size":1000000,"current_usage":{"input_tokens":6,"cache_read_input_tokens":100489}}}' | ./statusline 2>&1)
if echo "$OUT" | grep -q '11%' && echo "$OUT" | grep -q '100k/1.0M'; then
  pass "claude mode shows absolute counts with used_percentage"
else
  fail "claude mode shows absolute counts with used_percentage (got: $OUT)"
fi

# Test 2c6: size=0 does not crash and produces no percentage
OUT=$(echo '{"model":{"display_name":"X"},"context_window":{"context_window_size":0,"current_usage":{"input_tokens":15000}}}' | ./statusline 2>&1)
RC=$?
if [ $RC -eq 0 ] && ! echo "$OUT" | grep -qE '[0-9]+%'; then
  pass "claude mode size=0 no crash, no percentage"
else
  fail "claude mode size=0 no crash, no percentage (rc=$RC, got: $OUT)"
fi

# Test 2c7: context_window:null does not crash
OUT=$(echo '{"model":{"display_name":"X"},"context_window":null}' | ./statusline 2>&1)
RC=$?
if [ $RC -eq 0 ] && echo "$OUT" | grep -q '\[X\]'; then
  pass "claude mode null context_window no crash"
else
  fail "claude mode null context_window no crash (rc=$RC, got: $OUT)"
fi

# Test 2d: Claude mode renders 5h rate limit
OUT=$(echo '{"model":{"display_name":"X"},"rate_limits":{"five_hour":{"used_percentage":17}}}' | ./statusline 2>&1)
if echo "$OUT" | grep -q '5h:17%'; then
  pass "claude mode renders 5h rate limit"
else
  fail "claude mode renders 5h rate limit"
fi

# Test 2e: Claude mode handles minimal JSON (no fields beyond model)
OUT=$(echo '{"model":{"display_name":"X"}}' | ./statusline 2>&1)
if echo "$OUT" | grep -q '\[X\]'; then
  pass "claude mode handles minimal JSON"
else
  fail "claude mode handles minimal JSON"
fi

# Test 2f: Claude mode handles unparseable JSON
OUT=$(echo 'not json at all' | ./statusline 2>&1)
if echo "$OUT" | grep -q 'Unknown'; then
  pass "claude mode handles bad JSON"
else
  fail "claude mode handles bad JSON"
fi

# Test 2g: exact backward-compatible output (locks SPACE/PIPE separators)
J='{"model":{"display_name":"X"},"workspace":{"current_dir":"/no/such/proj"},"context_window":{"used_percentage":67},"cost":{"total_cost_usd":1.43,"total_lines_added":122,"total_lines_removed":3,"total_api_duration_ms":367185,"total_duration_ms":783478},"rate_limits":{"five_hour":{"used_percentage":4}}}'
OUT=$(echo "$J" | NO_COLOR=1 ./statusline --claude)
L1=$(echo "$OUT" | sed -n '1p')
L2=$(echo "$OUT" | sed -n '2p')
EXP2='████████⣿⣿⣿⣿ 67% | $1.43 | +122/-3 | 5h:4% | ⏱ 6m7s/13m3s'
if [ "$L1" = "[X] 📁 proj" ] && [ "$L2" = "$EXP2" ]; then
  pass "claude exact backward-compatible output"
else
  fail "claude exact output (got L1=[$L1] L2=[$L2])"
fi

# Test 2h: effort level and thinking indicator
OUT=$(echo '{"model":{"display_name":"X"},"effort":{"level":"high"},"thinking":{"enabled":true}}' | NO_COLOR=1 ./statusline --claude | sed -n '1p')
if echo "$OUT" | grep -q '·high' && echo "$OUT" | grep -q '✻'; then
  pass "claude renders effort and thinking"
else
  fail "claude renders effort and thinking (got: $OUT)"
fi

# Test 2i: 7-day rate limit and 5-hour reset countdown
OUT=$(echo '{"model":{"display_name":"X"},"rate_limits":{"five_hour":{"used_percentage":17,"resets_at":9999999999},"seven_day":{"used_percentage":42}}}' | NO_COLOR=1 ./statusline --claude)
if echo "$OUT" | grep -q '5h:17%(' && echo "$OUT" | grep -q '7d:42%'; then
  pass "claude renders 7d limit and 5h countdown"
else
  fail "claude renders 7d limit and 5h countdown (got: $OUT)"
fi

# Test 2j: PR badge
OUT=$(echo '{"model":{"display_name":"X"},"pr":{"number":1234,"review_state":"approved"}}' | NO_COLOR=1 ./statusline --claude | sed -n '1p')
if echo "$OUT" | grep -q '#1234'; then
  pass "claude renders PR badge"
else
  fail "claude renders PR badge (got: $OUT)"
fi

# Test 2k: agent, session name, output style, vim mode
OUT=$(echo '{"model":{"display_name":"X"},"vim":{"mode":"INSERT"},"agent":{"name":"debugger"},"session_name":"sess","output_style":{"name":"concise"}}' | NO_COLOR=1 ./statusline --claude | sed -n '1p')
if echo "$OUT" | grep -q 'INSERT' && echo "$OUT" | grep -q 'debugger' &&
  echo "$OUT" | grep -q 'sess' && echo "$OUT" | grep -q 'concise'; then
  pass "claude renders vim/agent/session/style"
else
  fail "claude renders vim/agent/session/style (got: $OUT)"
fi

# Test 2k1: default output style is suppressed
OUT=$(echo '{"model":{"display_name":"X"},"output_style":{"name":"default"}}' | NO_COLOR=1 ./statusline --claude | sed -n '1p')
if [ "$OUT" = "[X]" ]; then
  pass "claude suppresses default output style"
else
  fail "claude suppresses default output style (got: $OUT)"
fi

# Test 2l: COLUMNS truncation drops low-priority segments
J2='{"model":{"display_name":"X"},"workspace":{"current_dir":"/no/such/proj"},"agent":{"name":"debugger"},"session_name":"sessionnamehere"}'
FULL=$(echo "$J2" | NO_COLOR=1 ./statusline --claude | sed -n '1p')
NARROW=$(echo "$J2" | NO_COLOR=1 COLUMNS=20 ./statusline --claude | sed -n '1p')
if echo "$FULL" | grep -q 'sessionnamehere' && ! echo "$NARROW" | grep -q 'sessionnamehere' &&
  echo "$NARROW" | grep -q '\[X\]'; then
  pass "claude COLUMNS truncation drops low-priority segments"
else
  fail "claude COLUMNS truncation (full=[$FULL] narrow=[$NARROW])"
fi

# Test 2m: NO_COLOR suppresses OSC 8 links even when forced
OUT=$(echo '{"model":{"display_name":"X"},"workspace":{"current_dir":"/no/such/proj","repo":{"host":"github.com","owner":"o","name":"r"}}}' | NO_COLOR=1 FORCE_HYPERLINK=1 ./statusline --claude)
if echo "$OUT" | grep -q $'\033]8'; then
  fail "NO_COLOR suppresses OSC 8 links"
else
  pass "NO_COLOR suppresses OSC 8 links"
fi

# Test 2n: FORCE_HYPERLINK emits OSC 8 repo link
OUT=$(echo '{"model":{"display_name":"X"},"workspace":{"current_dir":"/no/such/proj","repo":{"host":"github.com","owner":"o","name":"r"}}}' | FORCE_HYPERLINK=1 ./statusline --claude)
if echo "$OUT" | grep -q $'\033]8;;https://github.com/o/r'; then
  pass "FORCE_HYPERLINK emits OSC 8 repo link"
else
  fail "FORCE_HYPERLINK emits OSC 8 repo link"
fi

# Test 2o: subagent mode emits one JSON line per task with an id
OUT=$(echo '{"columns":80,"tasks":[{"id":"t1","name":"explore","type":"Explore","status":"in_progress","tokenCount":15400},{"id":"t2","name":"review","status":"completed","label":"code-review","tokenCount":2300}]}' | NO_COLOR=1 ./statusline --subagent)
if [ "$(echo "$OUT" | wc -l | tr -d ' ')" = "2" ] &&
  echo "$OUT" | grep -q '"id":"t1"' && echo "$OUT" | grep -q '"id":"t2"'; then
  pass "subagent emits a row per task"
else
  fail "subagent emits a row per task (got: $OUT)"
fi

# Test 2o1: subagent output is valid JSON per line (if jq available)
if command -v jq > /dev/null 2>&1; then
  BAD=0
  while IFS= read -r line; do
    echo "$line" | jq -e . > /dev/null 2>&1 || BAD=1
  done <<< "$OUT"
  if [ "$BAD" -eq 0 ]; then
    pass "subagent output is valid JSON lines"
  else
    fail "subagent output is valid JSON lines"
  fi
else
  pass "subagent JSON validation skipped (jq not available)"
fi

# Test 2o2: subagent skips tasks without an id
OUT=$(echo '{"tasks":[{"name":"noid","status":"running"}]}' | ./statusline --subagent)
if [ -z "$OUT" ]; then
  pass "subagent skips tasks without id"
else
  fail "subagent skips tasks without id (got: $OUT)"
fi

# Test 2o3: subagent with no tasks key produces no output
OUT=$(echo '{"columns":80}' | ./statusline --subagent)
if [ -z "$OUT" ]; then
  pass "subagent with no tasks produces no output"
else
  fail "subagent with no tasks produces no output (got: $OUT)"
fi

# Test 2o4: json_escape produces valid JSON for quotes/backslashes/tabs in name
if command -v jq > /dev/null 2>&1; then
  OUT=$(echo '{"tasks":[{"id":"t1","name":"a\"b\\c\tnext"}]}' | NO_COLOR=1 ./statusline --subagent)
  if echo "$OUT" | jq -e . > /dev/null 2>&1; then
    pass "subagent json_escape yields valid JSON for special chars"
  else
    fail "subagent json_escape yields valid JSON for special chars (got: $OUT)"
  fi
else
  pass "subagent json_escape test skipped (jq not available)"
fi

# Test 2o5: subagent dispatch via STATUSLINE_MODE env var
OUT=$(echo '{"tasks":[{"id":"z","name":"n","status":"completed"}]}' | STATUSLINE_MODE=subagent NO_COLOR=1 ./statusline)
if echo "$OUT" | grep -q '"id":"z"'; then
  pass "subagent dispatch via STATUSLINE_MODE"
else
  fail "subagent dispatch via STATUSLINE_MODE (got: $OUT)"
fi

# Test 2p: resets_at in milliseconds is normalized to a sane countdown
OUT=$(echo '{"model":{"display_name":"X"},"rate_limits":{"five_hour":{"used_percentage":17,"resets_at":9999999999000}}}' | NO_COLOR=1 ./statusline --claude)
if echo "$OUT" | grep -q '5h:17%('; then
  pass "claude normalizes millisecond resets_at"
else
  fail "claude normalizes millisecond resets_at (got: $OUT)"
fi

# Test 2q: token-count overflow (>512 jsmn tokens) degrades to [Unknown], no crash
BIG='{"model":{"display_name":"X"}'
for i in $(seq 1 600); do BIG="$BIG,\"k$i\":$i"; done
BIG="$BIG}"
OUT=$(printf '%s' "$BIG" | ./statusline --claude 2>&1)
RC=$?
if [ $RC -eq 0 ] && echo "$OUT" | grep -q 'Unknown'; then
  pass "claude token overflow degrades to [Unknown]"
else
  fail "claude token overflow degrades to [Unknown] (rc=$RC, got: $OUT)"
fi

# Test 2r1: Antigravity mode with JSON input (explicit flag)
OUT=$(echo '{"model":{"display_name":"Gemini 3.5 Flash"},"product":"antigravity"}' | ./statusline --antigravity 2>&1)
if echo "$OUT" | grep -q '\[3.5 Flash\]'; then
  pass "antigravity mode parses model name with explicit flag"
else
  fail "antigravity mode parses model name with explicit flag (got: $OUT)"
fi

# Test 2r2: Antigravity mode auto-detection (no flags, default Claude mode detects product)
OUT=$(echo '{"model":{"display_name":"Gemini 3.5 Flash"},"product":"antigravity"}' | ./statusline 2>&1)
if echo "$OUT" | grep -q '\[3.5 Flash\]'; then
  pass "antigravity mode auto-detected by product field"
else
  fail "antigravity mode auto-detected by product field (got: $OUT)"
fi

# Test 2r3: Antigravity mode renders agent state, plan tier, conversation id, email, sandbox
J_AG='{"model":{"display_name":"Gemini 3.5 Flash (Medium)"},"product":"antigravity","agent_state":"working","sandbox":{"enabled":true},"plan_tier":"Google AI Pro","conversation_id":"8dedc981-2ea7-4e84-bc31-4a50a38de9bb","email":"johnweldon4@gmail.com","workspace":{"current_dir":"/no/such/proj"}}'
OUT=$(echo "$J_AG" | NO_COLOR=1 ./statusline --antigravity)
L1=$(echo "$OUT" | sed -n '1p')
if echo "$L1" | grep -q '\[3.5 Flash (Medium)\]' &&
   echo "$L1" | grep -q 'working' &&
   echo "$L1" | grep -q 'sandbox' &&
   echo "$L1" | grep -q 'proj' &&
   echo "$L1" | grep -q 'Google AI Pro' &&
   echo "$L1" | grep -q '#8dedc981' &&
   echo "$L1" | grep -q 'johnweldon4@gmail.com'; then
  pass "antigravity mode renders all line 1 segments"
else
  fail "antigravity mode renders all line 1 segments (got: $L1)"
fi

# Test 2r4: Antigravity mode renders context window metrics, Cache hit, exceeds 200k, version
J_AG2='{"model":{"display_name":"X"},"product":"antigravity","version":"1.0.5","exceeds_200k_tokens":true,"context_window":{"context_window_size":1000000,"total_input_tokens":58533,"total_output_tokens":17039,"used_percentage":5.85,"current_usage":{"input_tokens":534,"cache_read_input_tokens":57116}}}'
OUT=$(echo "$J_AG2" | NO_COLOR=1 ./statusline --antigravity)
L2=$(echo "$OUT" | sed -n '2p')
if echo "$L2" | grep -q '5%' &&
   echo "$L2" | grep -q '58k/1.0M' &&
   echo "$L2" | grep -q '17k out' &&
   echo "$L2" | grep -q '99%' &&
   echo "$L2" | grep -q '>200k' &&
   echo "$L2" | grep -q 'v1.0.5'; then
  pass "antigravity mode renders all line 2 segments"
else
  fail "antigravity mode renders all line 2 segments (got: $L2)"
fi

# Test 2r5: Antigravity fallback context calculation when total_input_tokens is 0
J_AG3='{"model":{"display_name":"X"},"product":"antigravity","context_window":{"context_window_size":100000,"total_input_tokens":0,"total_output_tokens":0,"current_usage":{"input_tokens":5000,"cache_creation_input_tokens":2000,"cache_read_input_tokens":8000}}}'
OUT=$(echo "$J_AG3" | NO_COLOR=1 ./statusline --antigravity)
L2=$(echo "$OUT" | sed -n '2p')
if echo "$L2" | grep -q '15%' && echo "$L2" | grep -q '15k/100k'; then
  pass "antigravity mode fallback context calculation"
else
  fail "antigravity mode fallback context calculation (got: $L2)"
fi

# Test 2r6: Antigravity cache hit rate correctness (includes cache creation tokens in denom)
if echo "$L2" | grep -q '53%'; then
  pass "antigravity mode cache hit rate includes cache creation tokens"
else
  fail "antigravity mode cache hit rate includes cache creation tokens (got: $L2, expected to find 53%)"
fi

# Test 2r7: Antigravity empty string key suppression
J_AG4='{"model":{"display_name":"X"},"product":"antigravity","conversation_id":"","email":"","plan_tier":"","version":""}'
OUT=$(echo "$J_AG4" | NO_COLOR=1 ./statusline --antigravity)
if echo "$OUT" | grep -q '#' || echo "$OUT" | grep -q '✉' || echo "$OUT" | grep -q '⭐' || echo "$OUT" | grep -q 'v'; then
  fail "antigravity mode did not suppress empty string values (got: $OUT)"
else
  pass "antigravity mode suppresses empty string values"
fi



# Test 3: Bash mode output
OUT=$(./statusline --bash 2>&1)
if echo "$OUT" | grep -q '\$'; then
  pass "bash mode shows prompt"
else
  fail "bash mode shows prompt"
fi

# Test 4: NO_COLOR disables colors
OUT=$(echo '{"display_name":"test"}' | NO_COLOR=1 ./statusline 2>&1)
if echo "$OUT" | grep -q $'\033'; then
  fail "NO_COLOR disables escape codes"
else
  pass "NO_COLOR disables escape codes"
fi

# Test 5: Exit code display
OUT=$(./statusline --bash --exit-code=42 2>&1)
if echo "$OUT" | grep -q "42"; then
  pass "exit code displayed"
else
  fail "exit code displayed"
fi

# Test 6: Invalid numeric args don't crash
OUT=$(./statusline --bash --exit-code=abc --jobs=xyz 2>&1)
if [ $? -eq 0 ]; then
  pass "invalid args handled gracefully"
else
  fail "invalid args handled gracefully"
fi

# Test 7: Jobs count display
OUT=$(./statusline --bash --jobs=3 2>&1)
if echo "$OUT" | grep -q "3 jobs"; then
  pass "jobs count displayed"
else
  fail "jobs count displayed"
fi

# --- Git dirty detection tests ---

SL="$(pwd)/statusline"
ORIG_DIR="$(pwd)"

setup_repo() {
  local d
  d=$(mktemp -d)
  cd "$d" || return 1
  git init -q
  git config user.email "test@test"
  git config user.name "Test"
  echo "hello" > file.txt
  git add file.txt
  git commit -q -m "initial"
  echo "$d"
}

cleanup_repo() {
  cd "$ORIG_DIR" || true
  rm -rf "$1"
}

# Test 8: Clean repo has no dirty indicator
TMPD=$(setup_repo)
cd "$TMPD"
OUT=$(NO_COLOR=1 "$SL" --bash 2>&1)
if echo "$OUT" | grep -q '\*'; then
  fail "clean repo shows no dirty indicator"
else
  pass "clean repo shows no dirty indicator"
fi
cleanup_repo "$TMPD"

# Test 9: Modified tracked file detected as dirty
TMPD=$(setup_repo)
cd "$TMPD"
echo "modified" > file.txt
OUT=$(NO_COLOR=1 "$SL" --bash 2>&1)
if echo "$OUT" | grep -q '\*'; then
  pass "modified file detected as dirty"
else
  fail "modified file detected as dirty"
fi
cleanup_repo "$TMPD"

# Test 10: Deleted tracked file detected as dirty
TMPD=$(setup_repo)
cd "$TMPD"
rm file.txt
OUT=$(NO_COLOR=1 "$SL" --bash 2>&1)
if echo "$OUT" | grep -q '\*'; then
  pass "deleted file detected as dirty"
else
  fail "deleted file detected as dirty"
fi
cleanup_repo "$TMPD"

# Test 11: Mode change detected as dirty
TMPD=$(setup_repo)
cd "$TMPD"
chmod +x file.txt
OUT=$(NO_COLOR=1 "$SL" --bash 2>&1)
if echo "$OUT" | grep -q '\*'; then
  pass "mode change detected as dirty"
else
  fail "mode change detected as dirty"
fi
cleanup_repo "$TMPD"

# Test 12: Staged-only change detected as dirty
TMPD=$(setup_repo)
cd "$TMPD"
echo "staged" > file.txt
git add file.txt
sleep 1
touch .git/index
OUT=$(NO_COLOR=1 "$SL" --bash 2>&1)
if echo "$OUT" | grep -q '\*'; then
  pass "staged change detected as dirty"
else
  fail "staged change detected as dirty"
fi
cleanup_repo "$TMPD"

# Test 13: Stash indicator displayed
TMPD=$(setup_repo)
cd "$TMPD"
echo "stash me" > file.txt
git stash -q
OUT=$(NO_COLOR=1 "$SL" --bash 2>&1)
if echo "$OUT" | grep -qF '$'; then
  pass "stash indicator displayed"
else
  fail "stash indicator displayed"
fi
cleanup_repo "$TMPD"

# Test 14: Detached HEAD shows short SHA
TMPD=$(setup_repo)
cd "$TMPD"
SHA=$(git rev-parse HEAD)
git checkout -q "$SHA"
OUT=$(NO_COLOR=1 "$SL" --bash 2>&1)
SHORT="${SHA:0:7}"
if echo "$OUT" | grep -q "($SHORT)"; then
  pass "detached HEAD shows short SHA"
else
  fail "detached HEAD shows short SHA"
fi
cleanup_repo "$TMPD"

# Test 15: Worktree dirty detection
TMPD=$(setup_repo)
cd "$TMPD"
git worktree add -q ../wt-test -b wt-branch 2> /dev/null
if [ -d "../wt-test" ]; then
  cd "../wt-test"
  echo "dirty" > file.txt
  OUT=$(NO_COLOR=1 "$SL" --bash 2>&1)
  cd "$ORIG_DIR"
  if echo "$OUT" | grep -q '\*'; then
    pass "worktree dirty detection"
  else
    fail "worktree dirty detection"
  fi
  rm -rf "$(dirname "$TMPD")/wt-test"
else
  pass "worktree dirty detection (skipped: git worktree not available)"
fi
cleanup_repo "$TMPD"

# --- Bash cwd path truncation tests ---
# Bash mode renders the cwd from getcwd(), so each case builds a real tree and
# runs the binary inside it (a fabricated path via stdin would not apply).

# Rendered cwd token: line 2 of bash output, between the first ':' (the
# user@host separator) and the following space. NO_COLOR keeps it plain.
bash_cwd() {
  sed -n '2p' | sed 's/[^:]*://; s/ .*//'
}
run_cwd() { # $1=dir  $2=HOME
  (
    cd "$1" || exit 1
    HOME="$2" NO_COLOR=1 "$SL" --bash
  ) | bash_cwd
}

# Test 16: deep HOME path abbreviates interior dirs, keeps current dir full
TMPD=$(mktemp -d)
TMPD=$(cd "$TMPD" && pwd -P)
mkdir -p "$TMPD/build/src/github.com/johnweldon/statusline"
TOK=$(run_cwd "$TMPD/build/src/github.com/johnweldon/statusline" "$TMPD")
if [ "$TOK" = "~/b/s/g/j/statusline" ]; then
  pass "bash cwd deep HOME path truncates to initials"
else
  fail "bash cwd deep HOME path (got: $TOK)"
fi
rm -rf "$TMPD"

# Test 17: deep absolute path keeps single leading '/', no '//', leaf full
TMPD=$(mktemp -d)
TMPD=$(cd "$TMPD" && pwd -P)
mkdir -p "$TMPD/usr/local/share/man/man1/extra"
TOK=$(run_cwd "$TMPD/usr/local/share/man/man1/extra" /nonexistent)
if printf '%s' "$TOK" | grep -q '/m/m/extra$' && ! printf '%s' "$TOK" | grep -q '//'; then
  pass "bash cwd deep absolute path single leading slash"
else
  fail "bash cwd deep absolute path (got: $TOK)"
fi
rm -rf "$TMPD"

# Test 18: at-threshold HOME path (interior 3) renders unchanged
TMPD=$(mktemp -d)
TMPD=$(cd "$TMPD" && pwd -P)
mkdir -p "$TMPD/a/b/c/d"
TOK=$(run_cwd "$TMPD/a/b/c/d" "$TMPD")
if [ "$TOK" = "~/a/b/c/d" ]; then
  pass "bash cwd at-threshold path unchanged"
else
  fail "bash cwd at-threshold path (got: $TOK)"
fi
rm -rf "$TMPD"

# Test 19: hidden interior dir keeps dot + next codepoint
TMPD=$(mktemp -d)
TMPD=$(cd "$TMPD" && pwd -P)
mkdir -p "$TMPD/.config/nvim/lua/plugins/foo"
TOK=$(run_cwd "$TMPD/.config/nvim/lua/plugins/foo" "$TMPD")
if [ "$TOK" = "~/.c/n/l/p/foo" ]; then
  pass "bash cwd hidden dir keeps dot plus letter"
else
  fail "bash cwd hidden dir (got: $TOK)"
fi
rm -rf "$TMPD"

# Test 20: cwd == HOME renders a bare '~'
TMPD=$(mktemp -d)
TMPD=$(cd "$TMPD" && pwd -P)
TOK=$(run_cwd "$TMPD" "$TMPD")
if [ "$TOK" = "~" ]; then
  pass "bash cwd HOME itself renders tilde"
else
  fail "bash cwd HOME itself (got: $TOK)"
fi
rm -rf "$TMPD"

# Test 21: multibyte interior dir keeps the whole first codepoint
TMPD=$(mktemp -d)
TMPD=$(cd "$TMPD" && pwd -P)
if mkdir -p "$TMPD/éfoo/bar/baz/qux/leaf" 2> /dev/null && [ -d "$TMPD/éfoo/bar/baz/qux/leaf" ]; then
  TOK=$(run_cwd "$TMPD/éfoo/bar/baz/qux/leaf" "$TMPD")
  if [ "$TOK" = "~/é/b/b/q/leaf" ]; then
    pass "bash cwd multibyte interior keeps whole codepoint"
  else
    fail "bash cwd multibyte interior (got: $TOK)"
  fi
else
  pass "bash cwd multibyte interior (skipped: cannot create multibyte dir)"
fi
rm -rf "$TMPD"

# Test 22: HOME must be a full path component, not a string prefix
TMPD=$(mktemp -d)
TMPD=$(cd "$TMPD" && pwd -P)
mkdir -p "$TMPD/weldon2/p/q/r/s/leaf"
TOK=$(run_cwd "$TMPD/weldon2/p/q/r/s/leaf" "$TMPD/weldon")
if ! printf '%s' "$TOK" | grep -q '~' && printf '%s' "$TOK" | grep -q '/leaf$'; then
  pass "bash cwd HOME prefix requires full component"
else
  fail "bash cwd HOME prefix boundary (got: $TOK)"
fi
rm -rf "$TMPD"

# Test 23: literal '..name' interior dir keeps only its first '.', never '..'
TMPD=$(mktemp -d)
TMPD=$(cd "$TMPD" && pwd -P)
mkdir -p "$TMPD/..config/aa/bb/cc/dd/ee"
TOK=$(run_cwd "$TMPD/..config/aa/bb/cc/dd/ee" "$TMPD")
if [ "$TOK" = "~/./a/b/c/d/ee" ]; then
  pass "bash cwd dotdot-name interior never renders as .."
else
  fail "bash cwd dotdot-name interior (got: $TOK)"
fi
rm -rf "$TMPD"

# Summary
echo ""
echo "Results: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ]
