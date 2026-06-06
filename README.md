# statusline

Fast status line generator for bash prompts and Claude Code.

## Build

```bash
make
make install        # /usr/local/bin/statusline + bashline symlink
make install-claude # ~/.claude/statusline
make help           # list all targets
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
--antigravity  Antigravity (Gemini) mode
--subagent     Subagent status line (JSON-lines output)
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

To render subagent rows as well, add the top-level `subagentStatusLine` entry:

```json
{
  "subagentStatusLine": {
    "type": "command",
    "command": "~/.claude/statusline --subagent"
  }
}
```

## Antigravity Integration

To build and install the binary directly to your Antigravity data directory, run:

```bash
make install-antigravity
```

This copies the built `statusline` binary to `~/.gemini/antigravity-cli/statusline`. Once installed, configure Antigravity to use it by running the slash command in your chat session:

```text
/statusline ~/.gemini/antigravity-cli/statusline
```

*(Alternatively, you can run `make install` or `make install-local` and configure with `/statusline ~/.local/bin/statusline` or `/statusline /usr/local/bin/statusline`)*.

The statusline binary auto-detects if the input JSON is from Antigravity (by checking the `"product"` field on stdin for `antigravity` or `antigravity-cli`) and automatically formats the output for Antigravity (Gemini).

## Display


**Bash mode** (two lines):

```
[venv] -ssh- user@host:~/path (branch) * context|ns [N jobs] (shlvl)
HH:MM:SS N $
```

The working directory is shown relative to `$HOME` as `~`. When it has four or more parent directories, each parent is abbreviated to its initial while the current directory is kept in full, so `~/build/src/github.com/johnweldon/statusline` renders as `~/b/s/g/j/statusline` (hidden `.name` dirs keep two characters, e.g. `.config` becomes `.c`).

**Claude mode** (two lines):

```
[Model] ·high ✻ 📁 folder | 🌿 branch | NORMAL | #1234 ✓ | 🤖 agent | name
████████⣿⣿⣿⣿ 67% 100k/200k | $1.43 | +122/-3 | 5h:17%(2h12m) 7d:42% | ⏱ 6m7s/13m3s ↻99%
```

Line 1 shows the model (with reasoning `effort.level` and a `✻` when extended thinking is on), the working-directory basename (clickable to the GitHub repo when the terminal supports OSC 8), the git branch, vim mode, an open-PR badge (`✓`/`✗`/`…`/`draft`, linked to the PR), the active agent name, the custom session name, and a non-default output style. Each is shown only when present in the JSON.

Line 2 is read from Claude Code's statusline JSON: context window usage and absolute tokens, total cost USD, lines added/removed, 5-hour and 7-day rate-limit usage (the 5-hour shows a reset countdown), total/API duration, and cache hit rate (from `cache_read_input_tokens / (input_tokens + cache_read_input_tokens)`).

When `COLUMNS` is set (Claude Code v2.1.153+ exports it), lower-priority segments are dropped to fit the terminal width; the model, folder, and context percentage are kept longest. When `COLUMNS` is unset the full line is emitted.

**Antigravity mode** (two lines):

```
[Model] 🤖 state | 📦 sandbox | 📁 folder | 🌿 branch | ⭐ tier | #conv_id | ✉ email
████████⣿⣿⣿⣿ 6% 58k/1.0M (17k out) ↻99% | ⚠️ >200k | v1.0.5
```

Line 1 shows the model name (with "Gemini " prefix stripped), active agent state (`🤖 idle`/`🤖 thinking`/`🤖 working`), sandbox status (`📦 sandbox` if enabled), working-directory basename (clickable to repo), git branch, plan tier (e.g. `⭐ Google AI Pro`), truncated conversation/session ID (`#8dedc981`), and user email (`✉ johnweldon4@gmail.com`).

Line 2 shows context window usage percentage, absolute tokens (input/total), output tokens, cache hit rate (`↻ 99%`), a warning badge if context exceeds 200k tokens (`⚠️ >200k`), and the antigravity CLI version.

Antigravity mode uses the payload's `terminal_width` field for width-aware truncation when present, falling back to terminal detection or `COLUMNS`.

**Subagent mode** (`--subagent`): reads the `subagentStatusLine` JSON (base fields plus `columns` and a `tasks[]` array) and writes one JSON line per row to override, e.g.:

```
{"id":"t1","content":"▸ explore-code · Explore · 15k"}
```

A status glyph (`▸` running, `✓` done, `✗` failed, `·` pending), the task name, label/type, and token count are rendered, truncated to the `columns` width. Tasks with no `id` are skipped (keeping their default row).

## Features

- Git branch from `.git/HEAD`; dirty detection by spawning `git diff-index --quiet HEAD --`
- In-progress merge/rebase/cherry-pick/revert/bisect detected via `.git/*_HEAD` files (no spawn)
- Stash indicator from `.git/refs/stash`
- K8s context/namespace from `$KUBECONFIG` or `~/.kube/config`
- Claude Code: model, effort/thinking, folder (repo link), branch, vim mode, PR badge, agent, session name, output style, context bar, cost, lines, 5h/7d rate limits with reset countdown, duration, cache hit rate
- Width-aware truncation driven by `COLUMNS` (Claude/subagent modes) or `terminal_width` (Antigravity mode)
- OSC 8 clickable links (repo, PR) when the terminal supports them
- Subagent status line (`--subagent`): per-task JSON-lines row overrides
- Virtualenv, SSH indicator, shell level (bash mode)
- Bash mode abbreviates deep working directories: with four or more parent dirs, each parent collapses to its initial and the current dir is kept full
- Respects `NO_COLOR` environment variable
- JSON parsing via vendored `jsmn` (single-header, MIT, see `LICENSE-jsmn`)

## Environment Variables

| Variable           | Description                                       |
| ------------------ | ------------------------------------------------- |
| `NO_COLOR`         | Disable colored output (any value)                |
| `STATUSLINE_MODE`  | Default mode: `bash`, `claude`, `antigravity`, or `subagent` |
| `COLUMNS`          | Terminal width; drives width-aware truncation     |
| `FORCE_HYPERLINK`  | Force OSC 8 links even if the terminal is unknown |
| `TERM_PROGRAM`     | Used to detect OSC 8 hyperlink support            |
| `KUBECONFIG`       | Kubernetes config file path                       |
| `VIRTUAL_ENV`      | Python virtualenv path (bash mode)                |
| `SSH_TTY`          | Detected for SSH indicator (bash mode)            |

## Platform Support

Any POSIX system with `posix_spawn`. Tested on macOS (arm64) and Linux (glibc, x86_64). UTC timestamps are parsed with inline calendar arithmetic, with no dependency on `timegm` or `TZ` manipulation.

- **macOS**: Supported
- **Linux**: Supported
- **BSD**: Should work
- **Windows**: Not supported
