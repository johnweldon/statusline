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

# Test 2: Claude mode with JSON input
OUT=$(echo '{"display_name":"test-model"}' | ./statusline 2>&1)
if echo "$OUT" | grep -q "test-model"; then
  pass "claude mode parses model name"
else
  fail "claude mode parses model name"
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

# Summary
echo ""
echo "Results: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ]
