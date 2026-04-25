# statusline

Fast status line generator for bash prompts and Claude Code.

## Build

```bash
make
make install        # /usr/local/bin/statusline + bashline symlink
make install-claude # ~/.claude/statusline
```

## Usage

**Bash mode** (use `bashline` symlink for automatic `--bash --ps1`):

```bash
bashline --exit-code=$? --shlvl=$SHLVL --jobs=N
```

**Claude mode** (reads Claude Code's statusline JSON from stdin):

```bash
echo '{"model":{"display_name":"Opus 4.7"}}' | statusline
```

## Options

```
--bash         Bash prompt mode
--claude       Claude Code mode (default)
--ps1          PS1-compatible escape sequences
--exit-code=N  Last command exit code
--jobs=N       Background jobs count
--shlvl=N      Shell nesting level (reads $SHLVL by default)
```

## Bash Integration

Add to `~/.bashrc` or `~/.bash_prompt`:

```bash
if command -v bashline >/dev/null 2>&1; then
  set_bash_prompt() {
    PS1='$(bashline --ps1 --exit-code=$? --shlvl=$SHLVL --jobs=\j)'
  }
  PROMPT_COMMAND=set_bash_prompt
fi
```

The `--ps1` flag outputs raw control characters (SOH/STX) for correct cursor positioning when used in command substitution. The `\j` is a bash PS1 escape that expands to the job count.

## Claude Code Integration

Add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "StatusLine": [
      {
        "matcher": "",
        "hooks": [{ "type": "command", "command": "~/.claude/statusline" }]
      }
    ]
  }
}
```

## Display

**Bash mode** (two lines):

```
[venv] -ssh- user@host:~/path (branch) * context|ns [N jobs] (shlvl)
HH:MM:SS N $
```

**Claude mode** (two lines):

```
[Model] 📁 folder | 🌿 branch
████████░░░░ 67% | $1.43 | +122/-3 | 5h:4% | ⏱ 6m7s/13m3s ↻99%
```

The fields on line 2 are read from Claude Code's statusline JSON: context window usage, total cost USD, lines added/removed, 5-hour rate-limit usage, total/API duration, and cache hit rate (from `cache_read_input_tokens / (input_tokens + cache_read_input_tokens)`).

## Features

- Git branch from `.git/HEAD`; dirty detection by spawning `git diff-index --quiet HEAD --`
- In-progress merge/rebase/cherry-pick/revert/bisect detected via `.git/*_HEAD` files (no spawn)
- Stash indicator from `.git/refs/stash`
- K8s context/namespace from `$KUBECONFIG` or `~/.kube/config`
- Claude Code: model, folder, branch, context bar, cost, lines, rate limit, duration, cache hit rate
- Virtualenv, SSH indicator, shell level (bash mode)
- Respects `NO_COLOR` environment variable
- JSON parsing via vendored `jsmn` (single-header, MIT, see `LICENSE-jsmn`)

## Environment Variables

| Variable          | Description                            |
| ----------------- | -------------------------------------- |
| `NO_COLOR`        | Disable colored output (any value)     |
| `STATUSLINE_MODE` | Default mode: `bash` or `claude`       |
| `KUBECONFIG`      | Kubernetes config file path            |
| `VIRTUAL_ENV`     | Python virtualenv path (bash mode)     |
| `SSH_TTY`         | Detected for SSH indicator (bash mode) |

## Platform Support

Any POSIX system with `posix_spawn`. Tested on macOS (arm64) and Linux (glibc, x86_64). UTC timestamps are parsed with inline calendar arithmetic, with no dependency on `timegm` or `TZ` manipulation.

- **macOS**: Supported
- **Linux**: Supported
- **BSD**: Should work
- **Windows**: Not supported
