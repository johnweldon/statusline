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
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define JSMN_STATIC
#define JSMN_PARENT_LINKS
#include "jsmn.h"

#define BUF_SIZE 65536
#define PATH_MAX_LEN 4096
// Claude payload counts ~125 jsmn tokens with every field present; 512 leaves
// headroom for added_dirs[] and future fields. Subagent tasks[] is far larger.
#define MAX_TOKENS 512
#define MAX_TOKENS_SUB 4096
#define GIT_REF_PREFIX "ref: refs/heads/"
#define GIT_REF_PREFIX_LEN 16

enum { MODE_CLAUDE, MODE_BASH, MODE_SUBAGENT, MODE_ANTIGRAVITY };
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

// Find a token by dot-separated path, starting from object token `root`
// (e.g. "model.display_name"). Returns the value-token index, or -1 if any
// segment is missing.
static int jp_find_from(const char *buf, jsmntok_t *t, int n, int root,
                        const char *path) {
  if (n <= 0 || root < 0 || root >= n)
    return -1;
  int cur = root;
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

static int jp_find(const char *buf, jsmntok_t *t, int n, const char *path) {
  return jp_find_from(buf, t, n, 0, path);
}

static int jp_is_null(const char *buf, jsmntok_t *tok) {
  return tok->type == JSMN_PRIMITIVE && (tok->end - tok->start) == 4 &&
         strncmp(buf + tok->start, "null", 4) == 0;
}

static int jp_str_from(const char *buf, jsmntok_t *t, int n, int root,
                       const char *path, char *out, size_t sz) {
  int i = jp_find_from(buf, t, n, root, path);
  if (i < 0 || t[i].type != JSMN_STRING)
    return 0;
  size_t len = (size_t)(t[i].end - t[i].start);
  if (len >= sz)
    len = sz - 1;
  memcpy(out, buf + t[i].start, len);
  out[len] = '\0';
  return 1;
}

static int jp_str(const char *buf, jsmntok_t *t, int n, const char *path,
                  char *out, size_t sz) {
  return jp_str_from(buf, t, n, 0, path, out, sz);
}

static long jp_long_from(const char *buf, jsmntok_t *t, int n, int root,
                         const char *path, long dflt) {
  int i = jp_find_from(buf, t, n, root, path);
  if (i < 0 || t[i].type != JSMN_PRIMITIVE || jp_is_null(buf, &t[i]))
    return dflt;
  char *endp;
  errno = 0;
  long v = strtol(buf + t[i].start, &endp, 10);
  if (endp == buf + t[i].start || errno == ERANGE)
    return dflt;
  return v;
}

static long jp_long(const char *buf, jsmntok_t *t, int n, const char *path,
                    long dflt) {
  return jp_long_from(buf, t, n, 0, path, dflt);
}

// 1 = true, 0 = false, dflt if missing/null/not a boolean primitive.
static int jp_bool(const char *buf, jsmntok_t *t, int n, const char *path,
                   int dflt) {
  int i = jp_find(buf, t, n, path);
  if (i < 0 || t[i].type != JSMN_PRIMITIVE || jp_is_null(buf, &t[i]))
    return dflt;
  char c = buf[t[i].start];
  if (c == 't')
    return 1;
  if (c == 'f')
    return 0;
  return dflt;
}

// Resolve a dot-path to an array token; return its index or -1.
static int jp_find_array(const char *buf, jsmntok_t *t, int n,
                         const char *path) {
  int i = jp_find(buf, t, n, path);
  if (i < 0 || t[i].type != JSMN_ARRAY)
    return -1;
  return i;
}

// Return the token index of the next direct child of array token `arr` at or
// after `from`, or -1 when exhausted. jsmn sets each element's parent to the
// array token (nested objects/arrays point at their own container), so the
// parent==arr test selects only top-level elements. Pass the previous result
// plus its subtree (i.e. prev+1) as `from` to walk all elements in order.
static int jp_array_next(jsmntok_t *t, int n, int arr, int from) {
  for (int i = from; i < n; i++)
    if (t[i].parent == arr)
      return i;
  return -1;
}

static double jp_dbl(const char *buf, jsmntok_t *t, int n, const char *path,
                     double dflt) {
  int i = jp_find(buf, t, n, path);
  if (i < 0 || t[i].type != JSMN_PRIMITIVE || jp_is_null(buf, &t[i]))
    return dflt;
  char *endp;
  errno = 0;
  double v = strtod(buf + t[i].start, &endp);
  if (endp == buf + t[i].start || errno == ERANGE)
    return dflt;
  return v;
}

// ==================== stdin ====================

static void read_stdin(void) {
  if (g_mode == MODE_BASH || isatty(STDIN_FILENO))
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

// Interior parent dirs above which the bash cwd slug is abbreviated to
// initials. "Interior" excludes the root marker (~ or /) and the current
// dir, which is always shown in full.
#define PATH_TRUNC_INTERIOR 3

// Index just past the first UTF-8 codepoint of seg[i..len), so a multibyte
// name is never split mid-character.
static size_t cwd_cp_next(const char *seg, size_t i, size_t len) {
  if (i >= len)
    return i;
  unsigned char c = (unsigned char)seg[i++];
  if (c >= 0xC2) {
    int extra = (c >= 0xF0) ? 3 : (c >= 0xE0) ? 2 : 1;
    while (extra-- > 0 && i < len && ((unsigned char)seg[i] & 0xC0) == 0x80)
      i++;
  }
  return i;
}

// Bytes to keep when abbreviating an interior component: the first codepoint,
// plus a second only for a hidden ".name" dir so it reads as ".x" not a bare
// ".". Literal "." / ".." are kept whole; a "..name" dir keeps only its first
// '.' so it never renders as a misleading "..".
static size_t cwd_keep(const char *seg, size_t len) {
  if (len == 0)
    return 0;
  if (seg[0] == '.') {
    if (len <= 2)
      return len;
    if (seg[1] == '.')
      return cwd_cp_next(seg, 0, len);
    return cwd_cp_next(seg, cwd_cp_next(seg, 0, len), len);
  }
  return cwd_cp_next(seg, 0, len);
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
  char root = '\0';
  const char *rem = cwd;
  if (h && hl > 0 && strncmp(cwd, h, hl) == 0 &&
      (cwd[hl] == '\0' || cwd[hl] == '/')) {
    root = '~';
    rem = cwd + hl;
  }
  // Count '/'-delimited components in the remainder; "interior" excludes the
  // current (last) dir.
  int nseg = 0;
  for (const char *p = rem; *p;) {
    if (*p == '/') {
      p++;
      continue;
    }
    while (*p && *p != '/')
      p++;
    nseg++;
  }
  int interior = nseg > 0 ? nseg - 1 : 0;
  if (interior <= PATH_TRUNC_INTERIOR) {
    // Shallow path: byte-for-byte identical to the pre-truncation output.
    if (root == '~')
      printf("~%s", cwd + hl);
    else
      printf("%s", cwd);
  } else {
    // Abbreviate every interior dir to its initial codepoint(s); keep the
    // current dir in full. A '/' precedes each component (the home case is
    // prefixed with '~'); the leading '/' of an absolute path is supplied by
    // the first component's separator, so no "//" appears.
    if (root == '~')
      putchar('~');
    int i = 0;
    for (const char *p = rem; *p;) {
      if (*p == '/') {
        p++;
        continue;
      }
      const char *s = p;
      while (*p && *p != '/')
        p++;
      size_t seglen = (size_t)(p - s);
      putchar('/');
      size_t keep = (i == nseg - 1) ? seglen : cwd_keep(s, seglen);
      fwrite(s, 1, keep, stdout);
      i++;
    }
  }
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

// Strip leading "Claude " or "Gemini " prefix if present; else return input.
static const char *short_model(const char *full) {
  if (strncmp(full, "Claude ", 7) == 0)
    return full + 7;
  if (strncmp(full, "Gemini ", 7) == 0)
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

// Compact token count: "999", "12k", "1.2M".
static void fmt_tokens(char *out, size_t sz, long n) {
  if (n < 0)
    n = 0;
  if (n < 1000)
    snprintf(out, sz, "%ld", n);
  else if (n < 1000000)
    snprintf(out, sz, "%ldk", n / 1000);
  else
    snprintf(out, sz, "%.1fM", n / 1000000.0);
}

static const char *path_basename(const char *p) {
  static char buf[PATH_MAX_LEN];
  size_t len = strlen(p);
  while (len > 1 && p[len - 1] == '/')
    len--;
  const char *s = p;
  for (size_t i = 0; i < len; i++)
    if (p[i] == '/')
      s = p + i + 1;
  size_t blen = (p + len) - s;
  if (blen >= sizeof(buf))
    blen = sizeof(buf) - 1;
  memcpy(buf, s, blen);
  buf[blen] = '\0';
  return buf;
}

// ==================== segments (width-aware emission) ====================
// Claude-mode lines are built as segments first, then emitted: when COLUMNS is
// set, low-priority segments are dropped to fit. `vis` tracks display width
// (escapes contribute 0); `sep` is the join style to the previous kept segment.

enum { SEP_NONE, SEP_SPACE, SEP_PIPE };

#define SEG_BUF 512
typedef struct {
  char text[SEG_BUF];
  size_t len;
  int vis;  // display columns, excluding escape sequences
  int prio; // lower kept first; 0 is never dropped
  int sep;  // SEP_* join to the previous kept segment
  int used;
} seg_t;

// Append literal bytes (no display-width change): colors, escapes, glyphs.
static void seg_raw(seg_t *s, const char *str) {
  while (*str && s->len < sizeof(s->text) - 1)
    s->text[s->len++] = *str++;
  s->text[s->len] = '\0';
}

// Append a color code, mirroring color() (respects NO_COLOR / PS1 wrapping).
static void seg_color(seg_t *s, const char *c) {
  if (g_no_color)
    return;
  if (g_fmt == FMT_PS1) {
    seg_raw(s, "\001");
    seg_raw(s, c);
    seg_raw(s, "\002");
  } else {
    seg_raw(s, c);
  }
}

// Append formatted plain text; display width = its codepoint count. Always
// call as seg_addf(s, "%s", userdata): a user string used as the format would
// be a format-string bug (caught by -Wformat-security via the attribute).
static void seg_addf(seg_t *s, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
static void seg_addf(seg_t *s, const char *fmt, ...) {
  char tmp[SEG_BUF];
  va_list ap;
  va_start(ap, fmt);
  int w = vsnprintf(tmp, sizeof(tmp), fmt, ap);
  va_end(ap);
  if (w < 0)
    return;
  // Count display width only on the bytes seg_raw actually appended (it stops
  // at SEG_BUF), so a near-full segment doesn't overstate its width. Codepoints
  // (non-continuation bytes) approximate columns; wide chars (emoji, CJK) in
  // data strings undercount by one per glyph, which only softens truncation.
  size_t before = s->len;
  seg_raw(s, tmp);
  for (size_t i = before; i < s->len; i++)
    if (((unsigned char)s->text[i] & 0xC0) != 0x80)
      s->vis++;
}

// Append a UTF-8 glyph with an explicit display width (2 for emoji, 1 for
// arrows) since terminal width can't be derived from the bytes.
static void seg_addglyph(seg_t *s, const char *utf8, int cols) {
  seg_raw(s, utf8);
  s->vis += cols;
}

// 12-char progress bar (buffered twin of pr_progress_bar).
static void seg_progress_bar(seg_t *s, int pct) {
  if (pct < 0)
    pct = 0;
  if (pct > 100)
    pct = 100;
  const int width = 12;
  int filled = pct * width / 100;
  const char *fc = (pct < 50) ? GRN_F : (pct < 80) ? YEL_F : RED_F;
  seg_color(s, fc);
  for (int i = 0; i < filled; i++)
    seg_raw(s, "\xE2\x96\x88"); // U+2588 FULL BLOCK
  seg_color(s, DIM);
  for (int i = 0; i < width - filled; i++)
    seg_raw(s, "\xE2\xA3\xBF"); // U+28FF BRAILLE PATTERN DOTS-12345678
  seg_color(s, RST);
  s->vis += width;
}

// 1 if the terminal likely supports OSC 8 hyperlinks (cached).
static int hyperlinks_ok(void) {
  static int cached = -1;
  if (cached >= 0)
    return cached;
  cached = 0;
  if (g_no_color || g_fmt == FMT_PS1)
    return cached;
  const char *force = getenv("FORCE_HYPERLINK");
  if (force && *force) {
    cached = 1;
    return cached;
  }
  if (getenv("VTE_VERSION")) {
    cached = 1;
    return cached;
  }
  const char *tp = getenv("TERM_PROGRAM");
  if (tp && (strcmp(tp, "iTerm.app") == 0 || strcmp(tp, "WezTerm") == 0 ||
             strcmp(tp, "vscode") == 0 || strcmp(tp, "ghostty") == 0))
    cached = 1;
  return cached;
}

// Append `text` as an OSC 8 hyperlink to `url` when supported, else plain text.
// Display width counts only the visible `text`.
static void seg_link(seg_t *s, const char *url, const char *text) {
  // Only emit the link form if the open + url + text + close all fit; otherwise
  // a truncated sequence would leave the terminal in active-hyperlink mode.
  size_t need = 5 + strlen(url) + 1 + strlen(text) + 7;
  if (hyperlinks_ok() && s->len + need < sizeof(s->text)) {
    seg_raw(s, "\033]8;;");
    seg_raw(s, url);
    seg_raw(s, "\a");
    seg_addf(s, "%s", text);
    seg_raw(s, "\033]8;;\a");
  } else {
    seg_addf(s, "%s", text);
  }
}

static int sep_cols(int sep) {
  return sep == SEP_PIPE ? 3 : sep == SEP_SPACE ? 1 : 0;
}

// Total display width of the kept segments in display order, including the
// separators between consecutive kept segments (the first kept gets none).
static int line_width(seg_t *segs, int count) {
  int w = 0, first = 1;
  for (int i = 0; i < count; i++) {
    if (!segs[i].used)
      continue;
    if (!first)
      w += sep_cols(segs[i].sep);
    w += segs[i].vis;
    first = 0;
  }
  return w;
}

static size_t buf_app(char *out, size_t sz, size_t pos, const char *str) {
  while (*str && pos < sz - 1)
    out[pos++] = *str++;
  out[pos] = '\0';
  return pos;
}

// Append a color code into a buffer, mirroring color().
static size_t buf_color(char *out, size_t sz, size_t pos, const char *c) {
  if (g_no_color)
    return pos;
  if (g_fmt == FMT_PS1) {
    pos = buf_app(out, sz, pos, "\001");
    pos = buf_app(out, sz, pos, c);
    pos = buf_app(out, sz, pos, "\002");
  } else {
    pos = buf_app(out, sz, pos, c);
  }
  return pos;
}

// Decide which segments fit `budget` columns (0 = unlimited), then render them
// in display order into `out`. prio 0 is always kept; higher prios are added
// cheapest-first while the line fits. The first kept segment emits no
// separator, matching the original "first shown" behavior.
static void seg_render(seg_t *segs, int count, int budget, char *out,
                       size_t sz) {
  if (budget <= 0) {
    for (int i = 0; i < count; i++)
      segs[i].used = 1;
  } else {
    int maxprio = 0;
    for (int i = 0; i < count; i++) {
      segs[i].used = (segs[i].prio == 0);
      if (segs[i].prio > maxprio)
        maxprio = segs[i].prio;
    }
    for (int pr = 1; pr <= maxprio; pr++) {
      for (int i = 0; i < count; i++) {
        if (segs[i].used || segs[i].prio != pr)
          continue;
        segs[i].used = 1;
        if (line_width(segs, count) > budget)
          segs[i].used = 0;
      }
    }
  }
  size_t pos = 0;
  out[0] = '\0';
  int first = 1;
  for (int i = 0; i < count; i++) {
    if (!segs[i].used)
      continue;
    if (!first) {
      if (segs[i].sep == SEP_PIPE) {
        pos = buf_app(out, sz, pos, " ");
        pos = buf_color(out, sz, pos, DIM);
        pos = buf_app(out, sz, pos, "|");
        pos = buf_color(out, sz, pos, RST);
        pos = buf_app(out, sz, pos, " ");
      } else if (segs[i].sep == SEP_SPACE) {
        pos = buf_app(out, sz, pos, " ");
      }
    }
    pos = buf_app(out, sz, pos, segs[i].text);
    first = 0;
  }
}

static void seg_emit_line(seg_t *segs, int count, int budget) {
  char line[8192];
  seg_render(segs, count, budget, line, sizeof(line));
  fputs(line, stdout);
}

// COLUMNS budget for width-aware truncation; <=0 means unlimited.
static int term_columns(void) {
  struct winsize w;
  if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == 0 && w.ws_col > 0)
    return w.ws_col;
  const char *c = getenv("COLUMNS");
  if (!c || !*c)
    return 0;
  char *endp;
  long v = strtol(c, &endp, 10);
  if (*endp != '\0' || v <= 0 || v > 100000)
    return 0;
  return (int)v;
}

// Line 1: [Model] [·effort ✻] 📁 folder | 🌿 branch | [vim] [PR] [agent] [name]
static void pr_claude_line1(const char *buf, jsmntok_t *t, int n) {
  seg_t segs[16];
  memset(segs, 0, sizeof(segs));
  int c = 0;
  seg_t *s;

#define PUSH_SEG(prio_val, sep_val) \
  (c < 16 ? (s = &segs[c++], s->prio = (prio_val), s->sep = (sep_val), s) : NULL)

  // Model (always present; prio 0, no leading separator).
  char model[256];
  if (!jp_str(buf, t, n, "model.display_name", model, sizeof(model)))
    snprintf(model, sizeof(model), "Unknown");
  if (PUSH_SEG(0, SEP_NONE)) {
    seg_color(s, WHT_F);
    seg_addf(s, "[%s]", short_model(model));
    seg_color(s, RST);
  }

  // Effort + extended-thinking, adjacent to the model name.
  char effort[32];
  int has_effort = jp_str(buf, t, n, "effort.level", effort, sizeof(effort)) && effort[0] != '\0';
  int thinking = jp_bool(buf, t, n, "thinking.enabled", 0);
  if (has_effort || thinking) {
    if (PUSH_SEG(2, SEP_SPACE)) {
      seg_color(s, DIM);
      if (has_effort)
        seg_addf(s, "\xC2\xB7%s", effort); // U+00B7 MIDDLE DOT
      if (thinking) {
        if (has_effort)
          seg_addf(s, " ");
        seg_addglyph(s, "\xE2\x9C\xBB", 1); // U+273B TEARDROP-SPOKED ASTERISK
      }
      seg_color(s, RST);
    }
  }

  // Folder (basename), linked to the repo when supported.
  char cur_dir[PATH_MAX_LEN] = "";
  if (!jp_str(buf, t, n, "workspace.current_dir", cur_dir, sizeof(cur_dir)))
    jp_str(buf, t, n, "cwd", cur_dir, sizeof(cur_dir));
  if (cur_dir[0]) {
    if (PUSH_SEG(0, SEP_SPACE)) {
      seg_color(s, BRIGHT_BLU);
      seg_addglyph(s, "\xF0\x9F\x93\x81", 2); // U+1F4C1 FOLDER
      seg_addf(s, " ");
      char host[128], owner[128], repo[128];
      if (hyperlinks_ok() &&
          jp_str(buf, t, n, "workspace.repo.host", host, sizeof(host)) &&
          jp_str(buf, t, n, "workspace.repo.owner", owner, sizeof(owner)) &&
          jp_str(buf, t, n, "workspace.repo.name", repo, sizeof(repo))) {
        char url[512];
        snprintf(url, sizeof(url), "https://%s/%s/%s", host, owner, repo);
        seg_link(s, url, path_basename(cur_dir));
      } else {
        seg_addf(s, "%s", path_basename(cur_dir));
      }
      seg_color(s, RST);
    }

    char gd[PATH_MAX_LEN], wt[PATH_MAX_LEN];
    if (find_git(cur_dir, gd, wt, sizeof(gd))) {
      char br[256];
      if (git_branch_name(gd, br, sizeof(br)) && br[0] != '\0') {
        if (PUSH_SEG(1, SEP_PIPE)) {
          seg_color(s, BRIGHT_CYN);
          seg_addglyph(s, "\xF0\x9F\x8C\xBF", 2); // U+1F33F HERB
          seg_addf(s, " %s", br);
          seg_color(s, RST);
        }
      }
    }
  }

  // Vim mode.
  char vim[32];
  if (jp_str(buf, t, n, "vim.mode", vim, sizeof(vim)) && vim[0] != '\0') {
    if (PUSH_SEG(2, SEP_PIPE)) {
      seg_color(s, DIM);
      seg_addf(s, "%s", vim);
      seg_color(s, RST);
    }
  }

  // Open PR badge, linked to the PR url when supported.
  long pr_num = jp_long(buf, t, n, "pr.number", -1);
  if (pr_num >= 0) {
    char state[32] = "", url[512] = "";
    jp_str(buf, t, n, "pr.review_state", state, sizeof(state));
    jp_str(buf, t, n, "pr.url", url, sizeof(url));
    const char *col = WHT_F, *mark = "";
    if (strcmp(state, "approved") == 0)
      col = GRN_F, mark = " \xE2\x9C\x93"; // U+2713 CHECK MARK
    else if (strcmp(state, "changes_requested") == 0)
      col = RED_F, mark = " \xE2\x9C\x97"; // U+2717 BALLOT X
    else if (strcmp(state, "pending") == 0)
      col = YEL_F, mark = " \xE2\x80\xA6"; // U+2026 HORIZONTAL ELLIPSIS
    else if (strcmp(state, "draft") == 0)
      col = DIM, mark = " draft";
    char label[64];
    snprintf(label, sizeof(label), "#%ld%s", pr_num, mark);
    if (PUSH_SEG(3, SEP_PIPE)) {
      seg_color(s, col);
      if (url[0] && hyperlinks_ok())
        seg_link(s, url, label);
      else
        seg_addf(s, "%s", label);
      seg_color(s, RST);
    }
  }

  // Named agent.
  char agent[128];
  if (jp_str(buf, t, n, "agent.name", agent, sizeof(agent)) && agent[0] != '\0') {
    if (PUSH_SEG(3, SEP_PIPE)) {
      seg_color(s, CYN_F);
      seg_addglyph(s, "\xF0\x9F\xA4\x96", 2); // U+1F916 ROBOT FACE
      seg_addf(s, " %s", agent);
      seg_color(s, RST);
    }
  }

  // Custom session name.
  char sess[128];
  if (jp_str(buf, t, n, "session_name", sess, sizeof(sess)) && sess[0] != '\0') {
    if (PUSH_SEG(4, SEP_PIPE)) {
      seg_color(s, DIM);
      seg_addf(s, "%s", sess);
      seg_color(s, RST);
    }
  }

  // Output style (skip the implicit default to avoid noise).
  char style[64];
  if (jp_str(buf, t, n, "output_style.name", style, sizeof(style)) &&
      style[0] != '\0' && strcmp(style, "default") != 0) {
    if (PUSH_SEG(5, SEP_PIPE)) {
      seg_color(s, DIM);
      seg_addf(s, "%s", style);
      seg_color(s, RST);
    }
  }

  seg_emit_line(segs, c, term_columns());
#undef PUSH_SEG
}

// "2h12m" / "13m" / "<1m" from a positive second count. Empty if secs <= 0.
static void fmt_countdown(char *out, size_t sz, long secs) {
  if (secs <= 0) {
    out[0] = '\0';
    return;
  }
  // Rate-limit windows top out around a week; clamp so a bogus reset
  // timestamp can't produce absurd output (and bounds h for the buffer).
  if (secs > 7 * 24 * 3600)
    secs = 7 * 24 * 3600;
  long h = secs / 3600;
  long m = (secs % 3600) / 60;
  if (h > 0)
    snprintf(out, sz, "%ldh%ldm", h, m);
  else if (m > 0)
    snprintf(out, sz, "%ldm", m);
  else
    snprintf(out, sz, "<1m");
}

// Read a 0-100 percentage that may be an integer or float; -1 if absent/null.
static long jp_pct(const char *buf, jsmntok_t *t, int n, const char *path) {
  int i = jp_find(buf, t, n, path);
  if (i < 0 || t[i].type != JSMN_PRIMITIVE || jp_is_null(buf, &t[i]))
    return -1;
  char *endp;
  errno = 0;
  double v = strtod(buf + t[i].start, &endp);
  if (endp == buf + t[i].start || errno == ERANGE)
    return -1;
  return (long)v;
}

// Seconds until a Unix-epoch-seconds reset, or 0 if absent/past. Tolerates a
// millisecond value (docs say seconds, but normalize defensively).
static long secs_until(const char *buf, jsmntok_t *t, int n, const char *path) {
  long resets = jp_long(buf, t, n, path, 0);
  if (resets <= 0)
    return 0;
  if (resets > 100000000000L) // implausible as seconds -> treat as ms
    resets /= 1000;
  long d = resets - (long)time(NULL);
  return d > 0 ? d : 0;
}

// Clamp a token count to a sane range so downstream `tok * 100` arithmetic
// cannot overflow signed long on malformed input. 100M is far above any real
// context window.
static long clamp_tok(long v) { return (v < 0 || v > 100000000L) ? 0 : v; }

// Line 2: bar N% used/size | $cost | +a/-r | 5h:N%(reset) 7d:M% | ⏱ api/total
// ↻%
static void pr_claude_line2(const char *buf, jsmntok_t *t, int n) {
  seg_t segs[16];
  memset(segs, 0, sizeof(segs));
  int c = 0;
  seg_t *s;

#define PUSH_SEG(prio_val, sep_val) \
  (c < 16 ? (s = &segs[c++], s->prio = (prio_val), s->sep = (sep_val), s) : NULL)

  // Read token data once: used downstream for the bar, absolute counts,
  // the token-based fallback %, and the cache hit rate.
  long size = jp_long(buf, t, n, "context_window.context_window_size", 0);
  long in_tok = clamp_tok(
      jp_long(buf, t, n, "context_window.current_usage.input_tokens", 0));
  long ccr_tok = clamp_tok(
      jp_long(buf, t, n,
              "context_window.current_usage.cache_creation_input_tokens", 0));
  long cr_tok = clamp_tok(jp_long(
      buf, t, n, "context_window.current_usage.cache_read_input_tokens", 0));
  // Input-only sum, matching how Claude Code computes used_percentage
  // (input + cache creation + cache read; output_tokens are excluded).
  long used_tok = in_tok + ccr_tok + cr_tok;

  // Context %: used_percentage > 100 - remaining_percentage > tokens / size.
  long ctx = jp_long(buf, t, n, "context_window.used_percentage", -1);
  if (ctx < 0) {
    long rem = jp_long(buf, t, n, "context_window.remaining_percentage", -1);
    if (rem >= 0)
      ctx = 100 - rem;
  }
  if (ctx < 0 && size > 0 && used_tok > 0)
    ctx = used_tok >= size ? 100 : (used_tok * 100 / size);
  if (ctx >= 0) {
    if (PUSH_SEG(0, SEP_NONE)) {
      seg_progress_bar(s, (int)ctx);
      seg_addf(s, " ");
      seg_color(s, WHT_F);
      seg_addf(s, "%ld%%", ctx);
      seg_color(s, RST);
    }
    if (size > 0 && used_tok > 0) {
      char ut[16], st[16];
      fmt_tokens(ut, sizeof(ut), used_tok);
      fmt_tokens(st, sizeof(st), size);
      if (PUSH_SEG(3, SEP_SPACE)) {
        seg_color(s, DIM);
        seg_addf(s, "%s/%s", ut, st);
        seg_color(s, RST);
      }
    }
  }

  // Cost (always shown when present).
  double cost = jp_dbl(buf, t, n, "cost.total_cost_usd", -1.0);
  if (cost >= 0) {
    if (PUSH_SEG(1, SEP_PIPE)) {
      seg_color(s, YEL_F);
      seg_addf(s, "$%.2f", cost);
      seg_color(s, RST);
    }
  }

  // Lines added / removed.
  long added = jp_long(buf, t, n, "cost.total_lines_added", 0);
  long removed = jp_long(buf, t, n, "cost.total_lines_removed", 0);
  if (added > 0 || removed > 0) {
    if (PUSH_SEG(4, SEP_PIPE)) {
      seg_color(s, GRN_F);
      seg_addf(s, "+%ld", added);
      seg_color(s, RST);
      seg_addf(s, "/");
      seg_color(s, RED_F);
      seg_addf(s, "-%ld", removed);
      seg_color(s, RST);
    }
  }

  // Rate limits: 5-hour (with reset countdown) and 7-day windows.
  long rate5 = jp_pct(buf, t, n, "rate_limits.five_hour.used_percentage");
  long rate7 = jp_pct(buf, t, n, "rate_limits.seven_day.used_percentage");
  if (rate5 >= 0 || rate7 >= 0) {
    if (PUSH_SEG(2, SEP_PIPE)) {
      int first_rl = 1;
      if (rate5 >= 0) {
        const char *rc = (rate5 < 50) ? GRN_F : (rate5 < 80) ? YEL_F : RED_F;
        seg_color(s, rc);
        seg_addf(s, "5h:%ld%%", rate5);
        seg_color(s, RST);
        char cd[16];
        fmt_countdown(cd, sizeof(cd),
                      secs_until(buf, t, n, "rate_limits.five_hour.resets_at"));
        if (cd[0]) {
          seg_color(s, DIM);
          seg_addf(s, "(%s)", cd);
          seg_color(s, RST);
        }
        first_rl = 0;
      }
      if (rate7 >= 0) {
        if (!first_rl)
          seg_addf(s, " ");
        const char *rc = (rate7 < 50) ? GRN_F : (rate7 < 80) ? YEL_F : RED_F;
        seg_color(s, rc);
        seg_addf(s, "7d:%ld%%", rate7);
        seg_color(s, RST);
      }
    }
  }

  // Duration (api / total).
  long api_ms = jp_long(buf, t, n, "cost.total_api_duration_ms", 0);
  long tot_ms = jp_long(buf, t, n, "cost.total_duration_ms", 0);
  char api_s[32], tot_s[32];
  fmt_duration_ms(api_s, sizeof(api_s), api_ms);
  fmt_duration_ms(tot_s, sizeof(tot_s), tot_ms);
  if (tot_s[0]) {
    if (PUSH_SEG(3, SEP_PIPE)) {
      seg_color(s, CYN_F);
      seg_addglyph(s, "\xE2\x8F\xB1", 1); // U+23F1 STOPWATCH
      if (api_s[0])
        seg_addf(s, " %s/%s", api_s, tot_s);
      else
        seg_addf(s, " %s", tot_s);
      seg_color(s, RST);
    }
  }

  // Cache hit rate: read / (input + cache_creation + read). Reuses tokens read at top.
  long denom = in_tok + ccr_tok + cr_tok;
  if (denom > 0) {
    long cache_pct = cr_tok * 100 / denom;
    if (cache_pct > 0) {
      if (PUSH_SEG(5, SEP_SPACE)) {
        seg_color(s, DIM);
        seg_addglyph(s, "\xE2\x86\xBB", 1); // U+21BB CLOCKWISE OPEN ARROW
        seg_addf(s, "%ld%%", cache_pct);
        seg_color(s, RST);
      }
    }
  }

  seg_emit_line(segs, c, term_columns());
#undef PUSH_SEG
}

static void pr_antigravity_line1(const char *buf, jsmntok_t *t, int n) {
  seg_t segs[16];
  memset(segs, 0, sizeof(segs));
  int c = 0;
  seg_t *s;

#define PUSH_SEG(prio_val, sep_val) \
  (c < 16 ? (s = &segs[c++], s->prio = (prio_val), s->sep = (sep_val), s) : NULL)

  // Model (always present; prio 0, no leading separator)
  char model[256];
  if (!jp_str(buf, t, n, "model.display_name", model, sizeof(model)))
    snprintf(model, sizeof(model), "Unknown");
  if (PUSH_SEG(0, SEP_NONE)) {
    seg_color(s, WHT_F);
    seg_addf(s, "[%s]", short_model(model));
    seg_color(s, RST);
  }

  // Agent State
  char state[64];
  if (jp_str(buf, t, n, "agent_state", state, sizeof(state)) && state[0] != '\0') {
    if (PUSH_SEG(1, SEP_SPACE)) {
      const char *col = WHT_F;
      if (strcmp(state, "idle") == 0) {
        col = DIM;
      } else if (strcmp(state, "thinking") == 0 || strcmp(state, "working") == 0) {
        col = CYN_F;
      }
      seg_color(s, col);
      seg_addglyph(s, "\xF0\x9F\xA4\x96", 2); // U+1F916 ROBOT FACE
      seg_addf(s, " %s", state);
      seg_color(s, RST);
    }
  }

  // Sandbox
  int sandbox = jp_bool(buf, t, n, "sandbox.enabled", 0);
  if (sandbox) {
    if (PUSH_SEG(2, SEP_PIPE)) {
      seg_color(s, YEL_F);
      seg_addglyph(s, "\xF0\x9F\x93\xA6", 2); // U+1F4E6 PACKAGE
      seg_addf(s, " sandbox");
      seg_color(s, RST);
    }
  }

  // Folder (basename), linked to the repo when supported
  char cur_dir[PATH_MAX_LEN] = "";
  if (!jp_str(buf, t, n, "workspace.current_dir", cur_dir, sizeof(cur_dir)))
    jp_str(buf, t, n, "cwd", cur_dir, sizeof(cur_dir));
  if (cur_dir[0]) {
    if (PUSH_SEG(0, SEP_SPACE)) {
      seg_color(s, BRIGHT_BLU);
      seg_addglyph(s, "\xF0\x9F\x93\x81", 2); // U+1F4C1 FOLDER
      seg_addf(s, " ");
      char host[128], owner[128], repo[128];
      if (hyperlinks_ok() &&
          jp_str(buf, t, n, "workspace.repo.host", host, sizeof(host)) &&
          jp_str(buf, t, n, "workspace.repo.owner", owner, sizeof(owner)) &&
          jp_str(buf, t, n, "workspace.repo.name", repo, sizeof(repo))) {
        char url[512];
        snprintf(url, sizeof(url), "https://%s/%s/%s", host, owner, repo);
        seg_link(s, url, path_basename(cur_dir));
      } else {
        seg_addf(s, "%s", path_basename(cur_dir));
      }
      seg_color(s, RST);
    }

    char gd[PATH_MAX_LEN], wt[PATH_MAX_LEN];
    if (find_git(cur_dir, gd, wt, sizeof(gd))) {
      char br[256];
      if (git_branch_name(gd, br, sizeof(br)) && br[0] != '\0') {
        if (PUSH_SEG(1, SEP_PIPE)) {
          seg_color(s, BRIGHT_CYN);
          seg_addglyph(s, "\xF0\x9F\x8C\xBF", 2); // U+1F33F HERB
          seg_addf(s, " %s", br);
          seg_color(s, RST);
        }
      }
    }
  }

  // Plan Tier
  char tier[128];
  if (jp_str(buf, t, n, "plan_tier", tier, sizeof(tier)) && tier[0] != '\0') {
    if (PUSH_SEG(3, SEP_PIPE)) {
      seg_color(s, YEL_F);
      seg_addglyph(s, "\xE2\xAD\x90", 2); // U+2B50 WHITE MEDIUM STAR
      seg_addf(s, " %s", tier);
      seg_color(s, RST);
    }
  }

  // Conversation ID
  char conv_id[128];
  if (jp_str(buf, t, n, "conversation_id", conv_id, sizeof(conv_id)) && conv_id[0] != '\0') {
    if (PUSH_SEG(4, SEP_PIPE)) {
      seg_color(s, DIM);
      seg_addf(s, "#%.8s", conv_id);
      seg_color(s, RST);
    }
  } else if (jp_str(buf, t, n, "session_id", conv_id, sizeof(conv_id)) && conv_id[0] != '\0') {
    if (PUSH_SEG(4, SEP_PIPE)) {
      seg_color(s, DIM);
      seg_addf(s, "#%.8s", conv_id);
      seg_color(s, RST);
    }
  }

  // Email
  char email[128];
  if (jp_str(buf, t, n, "email", email, sizeof(email)) && email[0] != '\0') {
    if (PUSH_SEG(5, SEP_PIPE)) {
      seg_color(s, DIM);
      seg_addglyph(s, "\xE2\x9C\x89", 1); // U+2709 ENVELOPE
      seg_addf(s, " %s", email);
      seg_color(s, RST);
    }
  }

  seg_emit_line(segs, c, term_columns());
#undef PUSH_SEG
}

static void pr_antigravity_line2(const char *buf, jsmntok_t *t, int n) {
  seg_t segs[16];
  memset(segs, 0, sizeof(segs));
  int c = 0;
  seg_t *s;

#define PUSH_SEG(prio_val, sep_val) \
  (c < 16 ? (s = &segs[c++], s->prio = (prio_val), s->sep = (sep_val), s) : NULL)

  // Context window size & usage
  long size = jp_long(buf, t, n, "context_window.context_window_size", 0);
  long in_tok = clamp_tok(
      jp_long(buf, t, n, "context_window.total_input_tokens", 0));
  long out_tok = clamp_tok(
      jp_long(buf, t, n, "context_window.total_output_tokens", 0));

  // Fallback to current_usage input tokens if total_input_tokens is 0
  if (in_tok == 0) {
    long in_curr = clamp_tok(jp_long(buf, t, n, "context_window.current_usage.input_tokens", 0));
    long ccr_curr = clamp_tok(jp_long(buf, t, n, "context_window.current_usage.cache_creation_input_tokens", 0));
    long cr_curr = clamp_tok(jp_long(buf, t, n, "context_window.current_usage.cache_read_input_tokens", 0));
    in_tok = in_curr + ccr_curr + cr_curr;
  }

  long ctx = jp_pct(buf, t, n, "context_window.used_percentage");
  if (ctx < 0) {
    long rem = jp_pct(buf, t, n, "context_window.remaining_percentage");
    if (rem >= 0)
      ctx = 100 - rem;
  }
  if (ctx < 0 && size > 0 && in_tok > 0)
    ctx = in_tok >= size ? 100 : (in_tok * 100 / size);

  if (ctx >= 0) {
    if (PUSH_SEG(0, SEP_NONE)) {
      seg_progress_bar(s, (int)ctx);
      seg_addf(s, " ");
      seg_color(s, WHT_F);
      seg_addf(s, "%ld%%", ctx);
      seg_color(s, RST);
    }

    if (size > 0 && in_tok > 0) {
      char ut[16], st[16];
      fmt_tokens(ut, sizeof(ut), in_tok);
      fmt_tokens(st, sizeof(st), size);
      if (PUSH_SEG(1, SEP_SPACE)) {
        seg_color(s, DIM);
        seg_addf(s, "%s/%s", ut, st);
        seg_color(s, RST);
      }
    }
  }

  // Output tokens
  if (out_tok > 0) {
    if (PUSH_SEG(2, SEP_SPACE)) {
      char ot[16];
      fmt_tokens(ot, sizeof(ot), out_tok);
      seg_color(s, DIM);
      seg_addf(s, "(%s out)", ot);
      seg_color(s, RST);
    }
  }

  // Cache hit rate (including cache creation tokens for mathematical correctness)
  long in_curr = clamp_tok(
      jp_long(buf, t, n, "context_window.current_usage.input_tokens", 0));
  long ccr_curr = clamp_tok(
      jp_long(buf, t, n, "context_window.current_usage.cache_creation_input_tokens", 0));
  long cr_curr = clamp_tok(
      jp_long(buf, t, n, "context_window.current_usage.cache_read_input_tokens", 0));
  long denom = in_curr + ccr_curr + cr_curr;
  if (denom > 0) {
    long cache_pct = cr_curr * 100 / denom;
    if (cache_pct > 0) {
      if (PUSH_SEG(1, SEP_SPACE)) {
        seg_color(s, DIM);
        seg_addglyph(s, "\xE2\x86\xBB", 1); // U+21BB CLOCKWISE OPEN ARROW
        seg_addf(s, "%ld%%", cache_pct);
        seg_color(s, RST);
      }
    }
  }

  // Exceeds 200k tokens warning
  int exceeds_200k = jp_bool(buf, t, n, "exceeds_200k_tokens", 0);
  if (exceeds_200k) {
    if (PUSH_SEG(2, SEP_PIPE)) {
      seg_color(s, YEL_F);
      seg_addglyph(s, "\xE2\x9A\xA0", 1); // U+26A0 WARNING SIGN
      seg_addf(s, " >200k");
      seg_color(s, RST);
    }
  }

  // Version
  char version[64];
  if (jp_str(buf, t, n, "version", version, sizeof(version)) && version[0] != '\0') {
    if (PUSH_SEG(3, SEP_PIPE)) {
      seg_color(s, DIM);
      seg_addf(s, "v%s", version);
      seg_color(s, RST);
    }
  }

  // Defensive cost
  double cost = jp_dbl(buf, t, n, "cost.total_cost_usd", -1.0);
  if (cost >= 0) {
    if (PUSH_SEG(1, SEP_PIPE)) {
      seg_color(s, YEL_F);
      seg_addf(s, "$%.2f", cost);
      seg_color(s, RST);
    }
  }

  seg_emit_line(segs, c, term_columns());
#undef PUSH_SEG
}

static void pr_antigravity_parsed(const char *buf, jsmntok_t *t, int n) {
  pr_antigravity_line1(buf, t, n);
  printf("\n");
  pr_antigravity_line2(buf, t, n);
}

static void pr_antigravity(void) {
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
  pr_antigravity_parsed(g_input, toks, n);
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
  char prod[64] = "";
  if (jp_str(g_input, toks, n, "product", prod, sizeof(prod)) &&
      strcmp(prod, "antigravity") == 0) {
    pr_antigravity_parsed(g_input, toks, n);
    return;
  }
  pr_claude_line1(g_input, toks, n);
  printf("\n");
  pr_claude_line2(g_input, toks, n);
}

// ==================== subagent mode ====================

// JSON-string-escape `in` into `out`. Control bytes (including ANSI ESC) become
// \uXXXX; the consumer renders the decoded ANSI/OSC sequences as-is.
static void json_escape(char *out, size_t sz, const char *in) {
  size_t p = 0;
  for (; *in && p < sz - 1; in++) {
    unsigned char ch = (unsigned char)*in;
    char tmp[8];
    const char *esc = NULL;
    switch (ch) {
    case '"':
      esc = "\\\"";
      break;
    case '\\':
      esc = "\\\\";
      break;
    case '\n':
      esc = "\\n";
      break;
    case '\r':
      esc = "\\r";
      break;
    case '\t':
      esc = "\\t";
      break;
    default:
      if (ch < 0x20) {
        snprintf(tmp, sizeof(tmp), "\\u%04x", ch);
        esc = tmp;
      }
      break;
    }
    if (esc) {
      while (*esc && p < sz - 1)
        out[p++] = *esc++;
    } else {
      out[p++] = (char)ch;
    }
  }
  out[p] = '\0';
}

// Render one subagent row override: {"id":"<id>","content":"<body>"}.
// The `status` enum is undocumented, so match tolerantly with a neutral
// default.
static void pr_subagent_row(const char *buf, jsmntok_t *t, int n, int el,
                            int cols) {
  char id[128];
  if (!jp_str_from(buf, t, n, el, "id", id, sizeof(id)))
    return; // no id -> keep the default row
  char name[256] = "", status[64] = "", label[256] = "";
  jp_str_from(buf, t, n, el, "name", name, sizeof(name));
  jp_str_from(buf, t, n, el, "status", status, sizeof(status));
  if (!jp_str_from(buf, t, n, el, "label", label, sizeof(label)))
    jp_str_from(buf, t, n, el, "type", label, sizeof(label));
  long tokc = jp_long_from(buf, t, n, el, "tokenCount", -1);

  seg_t segs[8];
  memset(segs, 0, sizeof(segs));
  int c = 0;
  seg_t *s;

#define PUSH_SEG(prio_val, sep_val) \
  (c < 8 ? (s = &segs[c++], s->prio = (prio_val), s->sep = (sep_val), s) : NULL)

  const char *col = DIM, *gl = "\xC2\xB7"; // U+00B7 pending/unknown
  if (strstr(status, "complet") || strstr(status, "done") ||
      strstr(status, "success") || strstr(status, "finish"))
    col = GRN_F, gl = "\xE2\x9C\x93"; // U+2713 CHECK MARK
  else if (strstr(status, "fail") || strstr(status, "error") ||
           strstr(status, "cancel"))
    col = RED_F, gl = "\xE2\x9C\x97"; // U+2717 BALLOT X
  else if (strstr(status, "run") || strstr(status, "progress") ||
           strstr(status, "active") || strstr(status, "work"))
    col = CYN_F, gl = "\xE2\x96\xB8"; // U+25B8 BLACK RIGHT-POINTING TRIANGLE
  if (PUSH_SEG(0, SEP_NONE)) {
    seg_color(s, col);
    seg_addglyph(s, gl, 1);
    seg_color(s, RST);
  }

  if (name[0]) {
    if (PUSH_SEG(0, SEP_SPACE)) {
      seg_color(s, WHT_F);
      seg_addf(s, "%s", name);
      seg_color(s, RST);
    }
  }
  if (label[0]) {
    if (PUSH_SEG(2, SEP_SPACE)) {
      seg_color(s, DIM);
      seg_addf(s, "\xC2\xB7 %s", label);
      seg_color(s, RST);
    }
  }
  if (tokc >= 0) {
    char tk[16];
    fmt_tokens(tk, sizeof(tk), tokc);
    if (PUSH_SEG(1, SEP_SPACE)) {
      seg_color(s, DIM);
      seg_addf(s, "\xC2\xB7 %s", tk);
      seg_color(s, RST);
    }
  }

  char body[4096], ebody[8192], eid[256];
  seg_render(segs, c, cols, body, sizeof(body));
  json_escape(ebody, sizeof(ebody), body);
  json_escape(eid, sizeof(eid), id);
  printf("{\"id\":\"%s\",\"content\":\"%s\"}\n", eid, ebody);
#undef PUSH_SEG
}

static void pr_subagent(void) {
  static jsmntok_t toks[MAX_TOKENS_SUB];
  jsmn_parser p;
  jsmn_init(&p);
  int n = jsmn_parse(&p, g_input, strlen(g_input), toks, MAX_TOKENS_SUB);
  if (n < 1)
    return;
  long cols = jp_long(g_input, toks, n, "columns", 0);
  if (cols <= 0 || cols > 100000) // bound before the (int) cast below
    cols = term_columns();
  int arr = jp_find_array(g_input, toks, n, "tasks");
  if (arr < 0)
    return;
  for (int el = jp_array_next(toks, n, arr, arr + 1); el >= 0;
       el = jp_array_next(toks, n, arr, el + 1)) {
    if (toks[el].type == JSMN_OBJECT)
      pr_subagent_row(g_input, toks, n, el, (int)cols);
  }
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
  fprintf(stderr, "  --antigravity  Antigravity (Gemini) mode\n");
  fprintf(stderr,
          "  --subagent     Subagent status line (JSON-lines output)\n");
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
  } else if (strcmp(prog, "subagentline") == 0) {
    g_mode = MODE_SUBAGENT;
  } else if (strcmp(prog, "antigravityline") == 0) {
    g_mode = MODE_ANTIGRAVITY;
  }
  const char *em = getenv("STATUSLINE_MODE");
  if (em) {
    if (strcmp(em, "bash") == 0)
      g_mode = MODE_BASH;
    else if (strcmp(em, "claude") == 0)
      g_mode = MODE_CLAUDE;
    else if (strcmp(em, "subagent") == 0)
      g_mode = MODE_SUBAGENT;
    else if (strcmp(em, "antigravity") == 0)
      g_mode = MODE_ANTIGRAVITY;
  }
  const char *es = getenv("SHLVL");
  if (es)
    g_shlvl = parse_int(es);
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--bash") == 0)
      g_mode = MODE_BASH;
    else if (strcmp(argv[i], "--claude") == 0)
      g_mode = MODE_CLAUDE;
    else if (strcmp(argv[i], "--antigravity") == 0)
      g_mode = MODE_ANTIGRAVITY;
    else if (strcmp(argv[i], "--subagent") == 0)
      g_mode = MODE_SUBAGENT;
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
  } else if (g_mode == MODE_ANTIGRAVITY) {
    pr_antigravity();
  } else if (g_mode == MODE_SUBAGENT) {
    pr_subagent();
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
