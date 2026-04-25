// statusline - Fast status line generator for bash and Claude Code
// Usage: statusline [--bash|--claude] [--ps1] [--exit-code=N] [--jobs=N]
#define _GNU_SOURCE
#ifndef VERSION
#define VERSION "unknown"
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define JSMN_STATIC
#define JSMN_PARENT_LINKS
#include "jsmn.h"

#define BUF_SIZE 65536
#define PATH_MAX_LEN 4096
#define MAX_TOKENS 256
#define GIT_REF_PREFIX "ref: refs/heads/"
#define GIT_REF_PREFIX_LEN 16

enum { MODE_CLAUDE, MODE_BASH };
enum { FMT_RAW, FMT_PS1 };

static char g_input[BUF_SIZE];
static int g_mode = MODE_CLAUDE;
static int g_fmt = FMT_RAW;
static int g_no_color = 0;
static int g_exit_code = 0;
static int g_jobs = 0;
static int g_shlvl = 0;

// Colors
#define RST "\033[0m"
#define DIM "\033[2m"
#define RED "\033[0;31m"
#define BLD_RED "\033[1;31m"
#define RED_F "\033[31m"
#define GRN_F "\033[32m"
#define YEL_F "\033[33m"
#define YEL "\033[0;33m"
#define BLD_YEL "\033[1;33m"
#define GRN "\033[1;32m"
#define DIM_GRN "\033[0;32m"
#define CYN_F "\033[36m"
#define CYN "\033[0;36m"
#define BLD_CYN "\033[1;36m"
#define BRIGHT_BLU "\033[94m"
#define BRIGHT_CYN "\033[96m"
#define WHT_F "\033[37m"
#define WHT "\033[0;37m"
#define BLD_WHT "\033[1;37m"

static void color(const char *c) {
  if (g_no_color)
    return;
  if (g_fmt == FMT_PS1)
    printf("\001%s\002", c);
  else
    printf("%s", c);
}

static int pathcat(char *out, size_t sz, const char *a, const char *b) {
  int n = snprintf(out, sz, "%s/%s", a, b);
  return n >= 0 && (size_t)n < sz;
}

// ==================== JSON path helpers (over jsmn) ====================

// Find a token by dot-separated path (e.g. "model.display_name").
// Returns the value-token index, or -1 if any segment is missing.
static int jp_find(const char *buf, jsmntok_t *t, int n, const char *path) {
  if (n <= 0)
    return -1;
  int cur = 0;
  const char *p = path;
  while (*p) {
    const char *seg = p;
    while (*p && *p != '.')
      p++;
    size_t seglen = (size_t)(p - seg);

    if (t[cur].type != JSMN_OBJECT)
      return -1;
    int found = -1;
    for (int i = cur + 1; i < n; i++) {
      if (t[i].parent == cur && t[i].type == JSMN_STRING) {
        size_t klen = (size_t)(t[i].end - t[i].start);
        if (klen == seglen && strncmp(buf + t[i].start, seg, seglen) == 0) {
          found = i + 1;
          break;
        }
      }
    }
    if (found < 0)
      return -1;
    cur = found;
    if (*p == '.')
      p++;
  }
  return cur;
}

static int jp_is_null(const char *buf, jsmntok_t *tok) {
  return tok->type == JSMN_PRIMITIVE && (tok->end - tok->start) == 4 &&
         strncmp(buf + tok->start, "null", 4) == 0;
}

static int jp_str(const char *buf, jsmntok_t *t, int n, const char *path,
                  char *out, size_t sz) {
  int i = jp_find(buf, t, n, path);
  if (i < 0 || t[i].type != JSMN_STRING)
    return 0;
  size_t len = (size_t)(t[i].end - t[i].start);
  if (len >= sz)
    len = sz - 1;
  memcpy(out, buf + t[i].start, len);
  out[len] = '\0';
  return 1;
}

static long jp_long(const char *buf, jsmntok_t *t, int n, const char *path,
                    long dflt) {
  int i = jp_find(buf, t, n, path);
  if (i < 0 || t[i].type != JSMN_PRIMITIVE || jp_is_null(buf, &t[i]))
    return dflt;
  char *endp;
  long v = strtol(buf + t[i].start, &endp, 10);
  if (endp == buf + t[i].start)
    return dflt;
  return v;
}

static double jp_dbl(const char *buf, jsmntok_t *t, int n, const char *path,
                     double dflt) {
  int i = jp_find(buf, t, n, path);
  if (i < 0 || t[i].type != JSMN_PRIMITIVE || jp_is_null(buf, &t[i]))
    return dflt;
  char *endp;
  double v = strtod(buf + t[i].start, &endp);
  if (endp == buf + t[i].start)
    return dflt;
  return v;
}

// ==================== stdin ====================

static void read_stdin(void) {
  if (g_mode != MODE_CLAUDE || isatty(STDIN_FILENO))
    return;
  size_t n, total = 0;
  while ((n = fread(g_input + total, 1, sizeof(g_input) - total - 1, stdin)) >
         0) {
    total += n;
    if (total >= sizeof(g_input) - 1)
      break;
  }
  if (ferror(stdin))
    total = 0;
  g_input[total] = '\0';
}

// ==================== bash-mode env blocks ====================

static void pr_venv(void) {
  if (g_mode != MODE_BASH)
    return;
  const char *v = getenv("VIRTUAL_ENV");
  if (!v || !*v)
    return;
  const char *n = strrchr(v, '/');
  color(BLD_WHT);
  printf("[%s]", n ? n + 1 : v);
  color(RST);
  printf(" ");
}

static void pr_ssh(void) {
  if (g_mode != MODE_BASH)
    return;
  if (!getenv("SSH_TTY"))
    return;
  color(YEL);
  printf("-ssh-");
  color(RST);
  printf(" ");
}

static void pr_shlvl(void) {
  if (g_mode != MODE_BASH || g_shlvl <= 1)
    return;
  color(BLD_CYN);
  printf("(%d)", g_shlvl);
  color(RST);
  printf(" ");
}

// ==================== git ====================

// start==NULL uses getcwd; otherwise searches starting from `start`.
static int find_git(const char *start, char *gitdir, char *worktree,
                    size_t sz) {
  char cwd[PATH_MAX_LEN];
  if (start) {
    snprintf(cwd, sizeof(cwd), "%s", start);
  } else if (!getcwd(cwd, sizeof(cwd))) {
    return 0;
  }
  while (*cwd) {
    char dotgit[PATH_MAX_LEN];
    if (!pathcat(dotgit, sizeof(dotgit), cwd, ".git"))
      return 0;
    struct stat st;
    if (stat(dotgit, &st) == 0) {
      if (S_ISDIR(st.st_mode)) {
        snprintf(gitdir, sz, "%s", dotgit);
        snprintf(worktree, sz, "%s", cwd);
        return 1;
      }
      if (S_ISREG(st.st_mode)) {
        FILE *f = fopen(dotgit, "r");
        if (!f)
          return 0;
        char line[PATH_MAX_LEN];
        if (!fgets(line, sizeof(line), f)) {
          fclose(f);
          return 0;
        }
        fclose(f);
        line[strcspn(line, "\n\r")] = '\0';
        if (strncmp(line, "gitdir: ", 8) != 0)
          return 0;
        const char *gd = line + 8;
        if (gd[0] == '/')
          snprintf(gitdir, sz, "%s", gd);
        else
          pathcat(gitdir, sz, cwd, gd);
        snprintf(worktree, sz, "%s", cwd);
        return 1;
      }
    }
    char *p = strrchr(cwd, '/');
    if (!p || p == cwd)
      break;
    *p = '\0';
  }
  return 0;
}

// Fills br with branch name or short SHA; returns 1 on success.
static int git_branch_name(const char *gitdir, char *br, size_t sz) {
  char hp[PATH_MAX_LEN];
  if (!pathcat(hp, sizeof(hp), gitdir, "HEAD"))
    return 0;
  FILE *f = fopen(hp, "r");
  if (!f)
    return 0;
  char head[256];
  if (!fgets(head, sizeof(head), f)) {
    fclose(f);
    return 0;
  }
  fclose(f);
  head[strcspn(head, "\n")] = '\0';
  if (strncmp(head, GIT_REF_PREFIX, GIT_REF_PREFIX_LEN) == 0)
    snprintf(br, sz, "%s", head + GIT_REF_PREFIX_LEN);
  else
    snprintf(br, sz, "%.7s", head);
  return 1;
}

extern char **environ;

// Exit 0 = clean, 1 = dirty, anything else = treat as clean.
static int git_dirty(const char *gitdir, const char *worktree) {
  char path[PATH_MAX_LEN];
  const char *ops[] = {"MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD",
                       "REBASE_HEAD", "BISECT_LOG"};
  for (size_t i = 0; i < sizeof(ops) / sizeof(ops[0]); i++) {
    if (pathcat(path, sizeof(path), gitdir, ops[i]) && access(path, F_OK) == 0)
      return 1;
  }
  posix_spawn_file_actions_t fa;
  if (posix_spawn_file_actions_init(&fa) != 0)
    return 0;
  if (posix_spawn_file_actions_addopen(&fa, 0, "/dev/null", O_RDONLY, 0) != 0 ||
      posix_spawn_file_actions_addopen(&fa, 1, "/dev/null", O_WRONLY, 0) != 0 ||
      posix_spawn_file_actions_addopen(&fa, 2, "/dev/null", O_WRONLY, 0) != 0) {
    posix_spawn_file_actions_destroy(&fa);
    return 0;
  }
  char *argv[] = {"git",        "-C",      (char *)worktree,
                  "diff-index", "--quiet", "HEAD",
                  "--",         NULL};
  pid_t pid;
  int rc = posix_spawnp(&pid, "git", &fa, NULL, argv, environ);
  posix_spawn_file_actions_destroy(&fa);
  if (rc != 0)
    return 0;
  int status = 0;
  while (waitpid(pid, &status, 0) < 0) {
    if (errno != EINTR)
      return 0;
  }
  if (!WIFEXITED(status))
    return 0;
  return WEXITSTATUS(status) == 1;
}

static int git_has_stash(const char *gitdir) {
  char path[PATH_MAX_LEN];
  return pathcat(path, sizeof(path), gitdir, "refs/stash") &&
         access(path, F_OK) == 0;
}

// Bash-mode git block: (branch) [*] [$]
static void pr_git(void) {
  char gd[PATH_MAX_LEN], wt[PATH_MAX_LEN];
  if (!find_git(NULL, gd, wt, sizeof(gd)))
    return;
  char br[256];
  if (!git_branch_name(gd, br, sizeof(br)))
    return;
  color(RED);
  printf("(%s)", br);
  color(RST);
  if (git_dirty(gd, wt)) {
    color(BLD_RED);
    printf(" *");
    color(RST);
  }
  if (git_has_stash(gd)) {
    color(YEL);
    printf(" $");
    color(RST);
  }
  printf(" ");
}

// ==================== k8s ====================
// Minimal YAML parser for kubeconfig; assumes standard kubectl formatting.

static void pr_k8s(void) {
  char kc[PATH_MAX_LEN];
  const char *e = getenv("KUBECONFIG");
  if (e && *e) {
    snprintf(kc, sizeof(kc), "%s", e);
    char *p = strchr(kc, ':');
    if (p)
      *p = '\0';
  } else {
    const char *h = getenv("HOME");
    if (!h)
      return;
    snprintf(kc, sizeof(kc), "%s/.kube/config", h);
  }
  FILE *f = fopen(kc, "r");
  if (!f)
    return;
  char line[1024], ctx[1024] = "", ns[256] = "";
  int in_ctx = 0, found = 0;
  while (fgets(line, sizeof(line), f)) {
    if (!*ctx && strncmp(line, "current-context:", 16) == 0) {
      char *v = line + 16;
      while (*v == ' ')
        v++;
      snprintf(ctx, sizeof(ctx), "%s", v);
      ctx[strcspn(ctx, "\n\r")] = '\0';
      rewind(f);
    } else if (*ctx) {
      if (strncmp(line, "contexts:", 9) == 0) {
        found = 1;
        continue;
      }
      if (!found)
        continue;
      if (line[0] != ' ' && line[0] != '-' && line[0] != '\n')
        break;
      char *np = strstr(line, "name:");
      if (np) {
        char *v = np + 5;
        while (*v == ' ')
          v++;
        char nm[256];
        snprintf(nm, sizeof(nm), "%s", v);
        nm[strcspn(nm, "\n\r")] = '\0';
        in_ctx = strcmp(nm, ctx) == 0;
      }
      if (in_ctx && (np = strstr(line, "namespace:"))) {
        char *v = np + 10;
        while (*v == ' ')
          v++;
        snprintf(ns, sizeof(ns), "%s", v);
        ns[strcspn(ns, "\n\r")] = '\0';
        break;
      }
    }
  }
  fclose(f);
  if (!*ctx)
    return;
  color(GRN);
  printf("%s", ctx);
  if (*ns) {
    color(WHT);
    printf("|");
    color(DIM_GRN);
    printf("%s", ns);
  }
  color(RST);
  printf(" ");
}

// ==================== common (bash-mode) ====================

static void pr_userhost(void) {
  char hn[256] = "unknown";
  if (gethostname(hn, sizeof(hn)) != 0)
    hn[0] = '?', hn[1] = '\0';
  hn[sizeof(hn) - 1] = '\0';
  char *p = strchr(hn, '.');
  if (p)
    *p = '\0';
  struct passwd *pw = getpwuid(getuid());
  color(CYN);
  printf("%s", pw ? pw->pw_name : "?");
  color(BLD_CYN);
  printf("@%s", hn);
  color(RST);
}

static void pr_cwd(void) {
  char cwd[PATH_MAX_LEN];
  if (!getcwd(cwd, sizeof(cwd)))
    return;
  color(BLD_YEL);
  const char *h = getenv("HOME");
  size_t hl = h ? strlen(h) : 0;
  // Only abbreviate HOME when it's a full-path-component prefix of cwd,
  // so HOME=/Users/weldon doesn't match cwd=/Users/weldon2.
  if (h && hl > 0 && strncmp(cwd, h, hl) == 0 &&
      (cwd[hl] == '\0' || cwd[hl] == '/'))
    printf("~%s", cwd + hl);
  else
    printf("%s", cwd);
  color(RST);
}

static void pr_time(void) {
  time_t now = time(NULL);
  struct tm *t = localtime(&now);
  if (!t) {
    color(WHT);
    printf("--:--:--");
    color(RST);
    return;
  }
  color(WHT);
  printf("%02d:%02d:%02d", t->tm_hour, t->tm_min, t->tm_sec);
  color(RST);
}

static void pr_prompt(void) {
  if (g_mode != MODE_BASH)
    return;
  pr_time();
  printf(" ");
  if (g_exit_code) {
    color(BLD_RED);
    printf("%d ", g_exit_code);
  }
  color(geteuid() == 0 ? BLD_RED : RST);
  printf("%c", geteuid() == 0 ? '#' : '$');
  color(RST);
  printf(" ");
}

// ==================== Claude mode ====================

// Strip leading "Claude " prefix if present; else return input.
static const char *short_model(const char *full) {
  if (strncmp(full, "Claude ", 7) == 0)
    return full + 7;
  return full;
}

// "1h2m" / "2m3s" / "5s". Empty string for ms <= 0.
static void fmt_duration_ms(char *out, size_t sz, long ms) {
  if (ms <= 0) {
    out[0] = '\0';
    return;
  }
  long total_sec = ms / 1000;
  long hours = total_sec / 3600;
  long minutes = (total_sec % 3600) / 60;
  long seconds = total_sec % 60;
  if (hours > 0)
    snprintf(out, sz, "%ldh%ldm", hours, minutes);
  else if (minutes > 0)
    snprintf(out, sz, "%ldm%lds", minutes, seconds);
  else
    snprintf(out, sz, "%lds", seconds);
}

// 12-char progress bar colored by usage threshold.
static void pr_progress_bar(int pct) {
  if (pct < 0)
    pct = 0;
  if (pct > 100)
    pct = 100;
  const int width = 12;
  int filled = pct * width / 100;
  int empty = width - filled;
  const char *fill_color = (pct < 50) ? GRN_F : (pct < 80) ? YEL_F : RED_F;
  color(fill_color);
  for (int i = 0; i < filled; i++)
    fputs("\xE2\x96\x88", stdout); // U+2588 FULL BLOCK
  color(DIM);
  for (int i = 0; i < empty; i++)
    fputs("\xE2\xA3\xBF", stdout); // U+28FF BRAILLE PATTERN DOTS-12345678
  color(RST);
}

static const char *path_basename(const char *p) {
  size_t len = strlen(p);
  while (len > 1 && p[len - 1] == '/')
    len--;
  const char *s = p;
  for (size_t i = 0; i < len; i++)
    if (p[i] == '/')
      s = p + i + 1;
  return s;
}

static void pr_sep(void) {
  color(DIM);
  printf("|");
  color(RST);
}

// Line 1: [Model] 📁 folder | 🌿 branch
static void pr_claude_line1(const char *buf, jsmntok_t *t, int n) {
  char model[256];
  if (!jp_str(buf, t, n, "model.display_name", model, sizeof(model)))
    snprintf(model, sizeof(model), "Unknown");
  color(WHT_F);
  printf("[%s]", short_model(model));
  color(RST);

  char cur_dir[PATH_MAX_LEN] = "";
  if (!jp_str(buf, t, n, "workspace.current_dir", cur_dir, sizeof(cur_dir)))
    jp_str(buf, t, n, "cwd", cur_dir, sizeof(cur_dir));
  if (cur_dir[0]) {
    printf(" ");
    color(BRIGHT_BLU);
    printf("\xF0\x9F\x93\x81 %s", path_basename(cur_dir)); // U+1F4C1 FOLDER
    color(RST);

    char gd[PATH_MAX_LEN], wt[PATH_MAX_LEN];
    if (find_git(cur_dir, gd, wt, sizeof(gd))) {
      char br[256];
      if (git_branch_name(gd, br, sizeof(br))) {
        printf(" ");
        pr_sep();
        printf(" ");
        color(BRIGHT_CYN);
        printf("\xF0\x9F\x8C\xBF %s", br); // U+1F33F HERB
        color(RST);
      }
    }
  }
}

// Line 2: bar N% | $cost | +a/-r | 5h:N% | ⏱ api/total ↻cache%
static void pr_claude_line2(const char *buf, jsmntok_t *t, int n) {
  int any = 0;

  // Context usage: prefer the direct field, fall back to 100 - remaining.
  long ctx = jp_long(buf, t, n, "context_window.used_percentage", -1);
  if (ctx < 0) {
    long rem = jp_long(buf, t, n, "context_window.remaining_percentage", -1);
    if (rem >= 0)
      ctx = 100 - rem;
  }
  if (ctx >= 0) {
    pr_progress_bar((int)ctx);
    printf(" ");
    color(WHT_F);
    printf("%ld%%", ctx);
    color(RST);
    any = 1;
  }

  // Cost (always shown when present).
  double cost = jp_dbl(buf, t, n, "cost.total_cost_usd", -1.0);
  if (cost >= 0) {
    if (any) {
      printf(" ");
      pr_sep();
      printf(" ");
    }
    color(YEL_F);
    printf("$%.2f", cost);
    color(RST);
    any = 1;
  }

  // Lines added / removed.
  long added = jp_long(buf, t, n, "cost.total_lines_added", 0);
  long removed = jp_long(buf, t, n, "cost.total_lines_removed", 0);
  if (added > 0 || removed > 0) {
    if (any) {
      printf(" ");
      pr_sep();
      printf(" ");
    }
    color(GRN_F);
    printf("+%ld", added);
    color(RST);
    printf("/");
    color(RED_F);
    printf("-%ld", removed);
    color(RST);
    any = 1;
  }

  // 5-hour rate limit. Value may be integer or float; cast to long via dbl.
  int ri = jp_find(buf, t, n, "rate_limits.five_hour.used_percentage");
  if (ri >= 0 && t[ri].type == JSMN_PRIMITIVE && !jp_is_null(buf, &t[ri])) {
    char *endp;
    double rv = strtod(buf + t[ri].start, &endp);
    if (endp != buf + t[ri].start) {
      long rate = (long)rv;
      if (any) {
        printf(" ");
        pr_sep();
        printf(" ");
      }
      const char *rc = (rate < 50) ? GRN_F : (rate < 80) ? YEL_F : RED_F;
      color(rc);
      printf("5h:%ld%%", rate);
      color(RST);
      any = 1;
    }
  }

  // Duration (api / total).
  long api_ms = jp_long(buf, t, n, "cost.total_api_duration_ms", 0);
  long tot_ms = jp_long(buf, t, n, "cost.total_duration_ms", 0);
  char api_s[32], tot_s[32];
  fmt_duration_ms(api_s, sizeof(api_s), api_ms);
  fmt_duration_ms(tot_s, sizeof(tot_s), tot_ms);
  if (tot_s[0]) {
    if (any) {
      printf(" ");
      pr_sep();
      printf(" ");
    }
    color(CYN_F);
    if (api_s[0])
      printf("\xE2\x8F\xB1 %s/%s", api_s, tot_s); // U+23F1 STOPWATCH
    else
      printf("\xE2\x8F\xB1 %s", tot_s);
    color(RST);
    any = 1;
  }

  // Cache hit rate: read / (input + read).
  long in_tok =
      jp_long(buf, t, n, "context_window.current_usage.input_tokens", 0);
  long cr_tok = jp_long(
      buf, t, n, "context_window.current_usage.cache_read_input_tokens", 0);
  long denom = in_tok + cr_tok;
  if (denom > 0) {
    long cache_pct = cr_tok * 100 / denom;
    if (cache_pct > 0) {
      printf(" ");
      color(DIM);
      printf("\xE2\x86\xBB%ld%%", cache_pct); // U+21BB CLOCKWISE OPEN ARROW
      color(RST);
      any = 1;
    }
  }
}

static void pr_claude(void) {
  jsmn_parser p;
  jsmntok_t toks[MAX_TOKENS];
  jsmn_init(&p);
  int n = jsmn_parse(&p, g_input, strlen(g_input), toks, MAX_TOKENS);
  if (n < 1) {
    color(WHT_F);
    printf("[Unknown]");
    color(RST);
    return;
  }
  pr_claude_line1(g_input, toks, n);
  printf("\n");
  pr_claude_line2(g_input, toks, n);
}

// ==================== argparse ====================

static int parse_int(const char *s) {
  char *end;
  long val = strtol(s, &end, 10);
  if (*end != '\0' || val < 0 || val > INT_MAX)
    return 0;
  return (int)val;
}

static void usage(const char *prog) {
  fprintf(stderr, "Usage: %s [OPTIONS]\n", prog);
  fprintf(stderr, "  --bash         Bash prompt mode\n");
  fprintf(stderr, "  --claude       Claude Code mode (default)\n");
  fprintf(stderr, "  --ps1          PS1-compatible escapes\n");
  fprintf(stderr, "  --exit-code=N  Last exit code\n");
  fprintf(stderr, "  --jobs=N       Background jobs\n");
  fprintf(stderr, "  --shlvl=N      Shell level\n");
  fprintf(stderr, "  --version      Show version\n");
}

static void parse_args(int argc, char **argv) {
  const char *prog = strrchr(argv[0], '/');
  prog = prog ? prog + 1 : argv[0];
  if (strcmp(prog, "bashline") == 0) {
    g_mode = MODE_BASH;
    g_fmt = FMT_PS1;
  }
  const char *em = getenv("STATUSLINE_MODE");
  if (em) {
    if (strcmp(em, "bash") == 0)
      g_mode = MODE_BASH;
    else if (strcmp(em, "claude") == 0)
      g_mode = MODE_CLAUDE;
  }
  const char *es = getenv("SHLVL");
  if (es)
    g_shlvl = parse_int(es);
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--bash") == 0)
      g_mode = MODE_BASH;
    else if (strcmp(argv[i], "--claude") == 0)
      g_mode = MODE_CLAUDE;
    else if (strcmp(argv[i], "--ps1") == 0)
      g_fmt = FMT_PS1;
    else if (strncmp(argv[i], "--exit-code=", 12) == 0)
      g_exit_code = parse_int(argv[i] + 12);
    else if (strncmp(argv[i], "--jobs=", 7) == 0)
      g_jobs = parse_int(argv[i] + 7);
    else if (strncmp(argv[i], "--shlvl=", 8) == 0)
      g_shlvl = parse_int(argv[i] + 8);
    else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
      usage(argv[0]);
      exit(0);
    } else if (strcmp(argv[i], "-V") == 0 ||
               strcmp(argv[i], "--version") == 0) {
      printf("statusline %s\n", VERSION);
      exit(0);
    }
  }
}

int main(int argc, char **argv) {
  if (getenv("NO_COLOR"))
    g_no_color = 1;
  parse_args(argc, argv);
  read_stdin();

  if (g_mode == MODE_CLAUDE) {
    pr_claude();
  } else {
    printf("\n");
    pr_venv();
    pr_ssh();
    pr_userhost();
    printf(":");
    pr_cwd();
    printf(" ");
    pr_git();
    pr_k8s();
    if (g_jobs > 0) {
      color(YEL);
      printf("[%d job%s]", g_jobs, g_jobs > 1 ? "s" : "");
      color(RST);
      printf(" ");
    }
    pr_shlvl();
    printf("\n");
    pr_prompt();
  }
  fflush(stdout);
  return 0;
}
