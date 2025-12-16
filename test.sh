#!/bin/bash
# Basic tests for statusline

PASS=0
FAIL=0

pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }

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

# Summary
echo ""
echo "Results: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ]
