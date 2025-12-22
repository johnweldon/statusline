// statusline - Fast status line generator for bash and Claude Code
// Usage: statusline [--bash|--claude] [--ps1] [--exit-code=N] [--jobs=N]
#define _GNU_SOURCE
#ifndef VERSION
#define VERSION "unknown"
#endif
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define BLOCK_HOURS     5
#define CACHE_TTL_SECS  60
#define BUF_SIZE        65536
#define PATH_MAX_LEN    4096
#define MAX_FILES_CHECK 200

#define JSONL_EXT       ".jsonl"
#define JSONL_EXT_LEN   6
#define TS_PREFIX       "\"timestamp\":\""
#define USAGE_PREFIX    "\"usage\":{"
#define GIT_REF_PREFIX  "ref: refs/heads/"
#define GIT_REF_PREFIX_LEN 16

typedef struct {
  time_t start;
  long tokens;
} block_info_t;

typedef struct {
  char path[PATH_MAX_LEN];
  time_t mtime;
} file_entry_t;

static int cmp_file_mtime_desc(const void *a, const void *b) {
  const file_entry_t *fa = a, *fb = b;
  if (fb->mtime > fa->mtime) return 1;
  if (fb->mtime < fa->mtime) return -1;
  return 0;
}

enum { MODE_CLAUDE, MODE_BASH };
enum { FMT_RAW, FMT_PS1 };

static char g_input[BUF_SIZE];
static char g_cache_path[PATH_MAX_LEN];
static int g_mode = MODE_CLAUDE;
static int g_fmt = FMT_RAW;
static int g_no_color = 0;
static int g_exit_code = 0;
static int g_jobs = 0;
static int g_shlvl = 0;

// Colors
#define RST "\033[0m"
#define MAG "\033[1;35m"
#define BLU "\033[1;34m"
#define DIM_BLU "\033[0;34m"
#define CYN "\033[0;36m"
#define BLD_CYN "\033[1;36m"
#define RED "\033[0;31m"
#define BLD_RED "\033[1;31m"
#define YEL "\033[0;33m"
#define BLD_YEL "\033[1;33m"
#define GRN "\033[1;32m"
#define DIM_GRN "\033[0;32m"
#define WHT "\033[0;37m"
#define BLD_WHT "\033[1;37m"

static void color(const char *c) {
  if (g_no_color) return;
  if (g_fmt == FMT_PS1) printf("\001%s\002", c);
  else printf("%s", c);
}

// Safe path construction - returns 1 on success
static int pathcat(char *out, size_t sz, const char *a, const char *b) {
  int n = snprintf(out, sz, "%s/%s", a, b);
  return n >= 0 && (size_t)n < sz;
}

// Extract quoted value after prefix into out, returns length or 0
static size_t extract_quoted(const char *s, const char *prefix, char *out, size_t sz) {
  char *p = strstr(s, prefix);
  if (!p) return 0;
  p += strlen(prefix);
  char *q = strchr(p, '"');
  if (!q || q <= p) return 0;
  size_t len = (size_t)(q - p);
  if (len >= sz) return 0;
  memcpy(out, p, len);
  out[len] = '\0';
  return len;
}

// JSON helpers
static int json_str(const char *json, const char *key, char *out, size_t sz) {
  char pat[256];
  snprintf(pat, sizeof(pat), "\"%s\":\"", key);
  const char *s = strstr(json, pat);
  if (!s) return 0;
  s += strlen(pat);
  const char *e = strchr(s, '"');
  if (!e) return 0;
  size_t n = (size_t)(e - s);
  if (n >= sz) n = sz - 1;
  memcpy(out, s, n);
  out[n] = '\0';
  return 1;
}

static long json_long(const char *json, const char *key) {
  char pat[256];
  snprintf(pat, sizeof(pat), "\"%s\":", key);
  const char *s = strstr(json, pat);
  if (!s) return -1;
  s += strlen(pat);
  while (*s == ' ' || *s == '\t') s++;
  if (*s == '"') return -1;
  return strtol(s, NULL, 10);
}

static time_t parse_iso(const char *ts) {
  struct tm tm = {0};
  int y, mo, d, h, mi, se;
  if (sscanf(ts, "%d-%d-%dT%d:%d:%d", &y, &mo, &d, &h, &mi, &se) != 6) return 0;
  tm.tm_year = y - 1900; tm.tm_mon = mo - 1; tm.tm_mday = d;
  tm.tm_hour = h; tm.tm_min = mi; tm.tm_sec = se;
#ifdef __APPLE__
  return timegm(&tm);
#else
  char *tz = getenv("TZ");
  setenv("TZ", "UTC", 1); tzset();
  time_t r = mktime(&tm);
  if (tz) setenv("TZ", tz, 1); else unsetenv("TZ");
  tzset();
  return r;
#endif
}

// Read stdin for claude mode
static void read_stdin(void) {
  if (g_mode != MODE_CLAUDE || isatty(STDIN_FILENO)) return;
  size_t n, total = 0;
  while ((n = fread(g_input + total, 1, sizeof(g_input) - total - 1, stdin)) > 0) {
    total += n;
    if (total >= sizeof(g_input) - 1) break;
  }
  if (ferror(stdin)) total = 0;
  g_input[total] = '\0';
}

// Claude: model and context info
static void pr_claude_info(void) {
  if (g_mode != MODE_CLAUDE) return;
  char model[128] = "Unknown";
  json_str(g_input, "display_name", model, sizeof(model));
  long in = json_long(g_input, "input_tokens");
  long cw = json_long(g_input, "cache_creation_input_tokens");
  long cr = json_long(g_input, "cache_read_input_tokens");
  long win = json_long(g_input, "context_window_size");

  color(MAG); printf("[%s]", model); color(RST); printf(" ");
  if (in >= 0 && win > 0) {
    long cur = in + (cw > 0 ? cw : 0) + (cr > 0 ? cr : 0);
    if (cur < 0) cur = LONG_MAX; // Overflow protection
    long pct = (cur >= win) ? 100 : (win >= 100 ? cur / (win / 100) : cur * 100 / win);
    color(BLU); printf("%ld%%", pct); color(RST); printf(" ");
    color(DIM_BLU); printf("(%ld/%ld)", cur, win); color(RST); printf(" ");
    if (cr > 0 || cw > 0) {
      color(CYN); printf("[cache: r:%ld w:%ld]", cr > 0 ? cr : 0, cw > 0 ? cw : 0);
      color(RST); printf(" ");
    }
  }
}

// Extract token counts from usage JSON
static long extract_tokens(const char *line) {
  char *u = strstr(line, USAGE_PREFIX);
  if (!u) return 0;
  long total = 0;
  // Parse input_tokens, output_tokens, cache_creation_input_tokens, cache_read_input_tokens
  const char *keys[] = {"input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens"};
  for (size_t i = 0; i < sizeof(keys)/sizeof(keys[0]); i++) {
    long v = json_long(u, keys[i]);
    if (v > 0) {
      if (total > LONG_MAX - v) return LONG_MAX; // Saturate on overflow
      total += v;
    }
  }
  return total;
}

// Claude: find block start and count tokens
// Collects JSONL files, sorts by mtime descending (newest first), then processes
static block_info_t find_block_info(time_t now) {
  block_info_t info = {0, 0};
  const char *home = getenv("HOME");
  if (!home) return info;
  char path[PATH_MAX_LEN];
  if (snprintf(path, sizeof(path), "%s/.claude/projects", home) < 0) return info;
  DIR *pd = opendir(path);
  if (!pd) return info;

  time_t cutoff = now - BLOCK_HOURS * 3600;
  file_entry_t *files = malloc(MAX_FILES_CHECK * sizeof(file_entry_t));
  if (!files) { closedir(pd); return info; }
  int nfiles = 0;
  struct dirent *pe;

  // Phase 1: Collect all eligible JSONL files
  while ((pe = readdir(pd))) {
    if (pe->d_name[0] == '.') continue;
    char ppath[PATH_MAX_LEN];
    if (!pathcat(ppath, sizeof(ppath), path, pe->d_name)) continue;
    DIR *sd = opendir(ppath);
    if (!sd) continue;
    struct dirent *se;
    while ((se = readdir(sd)) && nfiles < MAX_FILES_CHECK) {
      size_t len = strlen(se->d_name);
      if (len < JSONL_EXT_LEN + 1 || strcmp(se->d_name + len - JSONL_EXT_LEN, JSONL_EXT)) continue;
      char fpath[PATH_MAX_LEN];
      if (!pathcat(fpath, sizeof(fpath), ppath, se->d_name)) continue;
      struct stat st;
      if (stat(fpath, &st) || !S_ISREG(st.st_mode) || st.st_mtime < cutoff) continue;
      snprintf(files[nfiles].path, sizeof(files[nfiles].path), "%s", fpath);
      files[nfiles].mtime = st.st_mtime;
      nfiles++;
    }
    closedir(sd);
  }
  closedir(pd);

  // Phase 2: Sort by mtime descending (newest first)
  if (nfiles > 1)
    qsort(files, (size_t)nfiles, sizeof(file_entry_t), cmp_file_mtime_desc);

  // Phase 3: Process files in sorted order
  for (int i = 0; i < nfiles; i++) {
    FILE *f = fopen(files[i].path, "r");
    if (!f) continue;
    char line[8192], ts[64], msg_id[64], last_msg_id[64] = "";
    int found_start = 0;
    time_t line_ts = 0;
    while (fgets(line, sizeof(line), f)) {
      // Extract timestamp
      if (extract_quoted(line, TS_PREFIX, ts, sizeof(ts))) {
        line_ts = parse_iso(ts);
        if (!found_start && line_ts >= cutoff && line_ts <= now) {
          if (!info.start || line_ts < info.start) info.start = line_ts;
          found_start = 1;
        }
      }
      // Count tokens for messages in block, dedupe by message ID
      if (line_ts >= cutoff && line_ts <= now && strstr(line, USAGE_PREFIX)) {
        if (extract_quoted(line, "\"id\":\"", msg_id, sizeof(msg_id)) &&
            strcmp(msg_id, last_msg_id) != 0) {
          long tokens = extract_tokens(line);
          if (tokens > 0 && info.tokens <= LONG_MAX - tokens)
            info.tokens += tokens;
          snprintf(last_msg_id, sizeof(last_msg_id), "%s", msg_id);
        }
      }
    }
    fclose(f);
  }
  free(files);
  if (info.start) info.start -= info.start % 3600; // Round to hour
  return info;
}

// Format large numbers with K/M suffix
static void print_tokens(long tokens) {
  if (tokens >= 1000000) printf("%.1fM", tokens / 1000000.0);
  else if (tokens >= 1000) printf("%.0fK", tokens / 1000.0);
  else printf("%ld", tokens);
}

static void pr_block_time(void) {
  if (g_mode != MODE_CLAUDE) return;
  time_t now = time(NULL);
  block_info_t info = {0, 0};

  int fd = open(g_cache_path, O_RDWR | O_CREAT | O_NOFOLLOW, 0600);
  if (fd >= 0 && flock(fd, LOCK_EX) == 0) {
    FILE *c = fdopen(fd, "r+");
    if (c) {
      time_t ct;
      char ver[4] = "";
      if (fscanf(c, "%3[^:]:%ld:%ld:%ld", ver, &ct, &info.start, &info.tokens) == 4 &&
          strcmp(ver, "v1") == 0 && ct <= now && now - ct < CACHE_TTL_SECS && info.start > 0) {
        // Use cached values
      } else {
        info = find_block_info(now);
        rewind(c);
        if (ftruncate(fd, 0) == 0) {
          fprintf(c, "v1:%ld:%ld:%ld", now, info.start, info.tokens);
          fflush(c);
        }
      }
      fclose(c);
    } else {
      flock(fd, LOCK_UN);
      close(fd);
    }
  } else if (fd >= 0) {
    close(fd); // flock failed
  }
  if (!info.start) return;
  long secs = info.start + BLOCK_HOURS * 3600 - now;
  if (secs <= 0) return;
  int h = secs / 3600, m = (secs % 3600) / 60;
  color(YEL);
  if (h > 0) printf("[%dh %dm", h, m);
  else printf("[%dm", m);
  if (info.tokens > 0) {
    printf(" ");
    print_tokens(info.tokens);
  }
  printf("]");
  color(RST); printf(" ");
}

// Bash: virtualenv, ssh, shlvl
static void pr_venv(void) {
  if (g_mode != MODE_BASH) return;
  const char *v = getenv("VIRTUAL_ENV");
  if (!v || !*v) return;
  const char *n = strrchr(v, '/');
  color(BLD_WHT); printf("[%s]", n ? n + 1 : v); color(RST); printf(" ");
}

static void pr_ssh(void) {
  if (g_mode != MODE_BASH) return;
  if (!getenv("SSH_TTY")) return;
  color(YEL); printf("-ssh-"); color(RST); printf(" ");
}

static void pr_shlvl(void) {
  if (g_mode != MODE_BASH || g_shlvl <= 1) return;
  color(BLD_CYN); printf("(%d)", g_shlvl); color(RST); printf(" ");
}

// Git
static int find_git(char *out, size_t sz) {
  char cwd[PATH_MAX_LEN];
  if (!getcwd(cwd, sizeof(cwd))) return 0;
  while (*cwd) {
    if (!pathcat(out, sz, cwd, ".git")) return 0;
    struct stat st;
    if (stat(out, &st) == 0) return 1;
    char *p = strrchr(cwd, '/');
    if (!p || p == cwd) break;
    *p = '\0';
  }
  return 0;
}

// Heuristic dirty detection - compares .git/index mtime against common directories.
// Trade-offs vs `git status`:
// - Speed: O(1) stat calls vs O(n) file scanning
// - False positives: Directory mtime changes on read access, not just writes
// - False negatives: Modified files in unchecked directories won't be detected
// Checked directories: . src lib cmd pkg internal test tests bin scripts
static int git_dirty(const char *gd) {
  char path[PATH_MAX_LEN];
  if (!pathcat(path, sizeof(path), gd, "index")) return 0;
  struct stat idx;
  if (stat(path, &idx)) return 0;
  const char *checks[] = {"MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD"};
  for (size_t i = 0; i < sizeof(checks)/sizeof(checks[0]); i++) {
    if (pathcat(path, sizeof(path), gd, checks[i]) && access(path, F_OK) == 0)
      return 1;
  }
  char wt[PATH_MAX_LEN];
  snprintf(wt, sizeof(wt), "%s", gd);
  char *p = strrchr(wt, '/');
  if (p) *p = '\0';
  const char *dirs[] = {".", "src", "lib", "cmd", "pkg", "internal", "test", "tests", "bin", "scripts"};
  for (size_t i = 0; i < sizeof(dirs)/sizeof(dirs[0]); i++) {
    struct stat st;
    if (pathcat(path, sizeof(path), wt, dirs[i]) &&
        stat(path, &st) == 0 && st.st_mtime > idx.st_mtime)
      return 1;
  }
  return 0;
}

static void pr_git(void) {
  char gd[PATH_MAX_LEN];
  if (!find_git(gd, sizeof(gd))) return;
  char hp[PATH_MAX_LEN];
  if (!pathcat(hp, sizeof(hp), gd, "HEAD")) return;
  FILE *f = fopen(hp, "r");
  if (!f) return;
  char head[256];
  if (!fgets(head, sizeof(head), f)) { fclose(f); return; }
  fclose(f);
  head[strcspn(head, "\n")] = '\0';
  char br[256];
  if (strncmp(head, GIT_REF_PREFIX, GIT_REF_PREFIX_LEN) == 0) {
    strncpy(br, head + GIT_REF_PREFIX_LEN, sizeof(br) - 1);
    br[sizeof(br) - 1] = '\0';
  } else {
    strncpy(br, head, 7);
    br[7] = '\0';
  }
  color(RED); printf("(%s)", br); color(RST);
  if (git_dirty(gd)) { color(BLD_RED); printf(" *"); color(RST); }
  printf(" ");
}

// K8s - minimal YAML parser for kubeconfig.
// Assumes standard kubectl formatting; no support for anchors or complex YAML.
static void pr_k8s(void) {
  char kc[PATH_MAX_LEN];
  const char *e = getenv("KUBECONFIG");
  if (e && *e) {
    strncpy(kc, e, sizeof(kc) - 1);
    kc[sizeof(kc) - 1] = '\0';
    char *p = strchr(kc, ':');
    if (p) *p = '\0';
  } else {
    const char *h = getenv("HOME");
    if (!h) return;
    snprintf(kc, sizeof(kc), "%s/.kube/config", h);
  }
  FILE *f = fopen(kc, "r");
  if (!f) return;
  char line[1024], ctx[256] = "", ns[256] = "";
  int in_ctx = 0, found = 0;
  while (fgets(line, sizeof(line), f)) {
    if (!*ctx && strncmp(line, "current-context:", 16) == 0) {
      char *v = line + 16; while (*v == ' ') v++;
      strncpy(ctx, v, sizeof(ctx) - 1);
      ctx[sizeof(ctx) - 1] = '\0';
      ctx[strcspn(ctx, "\n\r")] = '\0';
      rewind(f);
    } else if (*ctx) {
      if (strncmp(line, "contexts:", 9) == 0) { found = 1; continue; }
      if (!found) continue;
      if (line[0] != ' ' && line[0] != '-' && line[0] != '\n') break;
      char *np = strstr(line, "name:");
      if (np) {
        char *v = np + 5; while (*v == ' ') v++;
        char nm[256];
        strncpy(nm, v, sizeof(nm) - 1);
        nm[sizeof(nm) - 1] = '\0';
        nm[strcspn(nm, "\n\r")] = '\0';
        in_ctx = strcmp(nm, ctx) == 0;
      }
      if (in_ctx && (np = strstr(line, "namespace:"))) {
        char *v = np + 10; while (*v == ' ') v++;
        strncpy(ns, v, sizeof(ns) - 1);
        ns[sizeof(ns) - 1] = '\0';
        ns[strcspn(ns, "\n\r")] = '\0';
        break;
      }
    }
  }
  fclose(f);
  if (!*ctx) return;
  color(GRN); printf("%s", ctx);
  if (*ns) { color(WHT); printf("|"); color(DIM_GRN); printf("%s", ns); }
  color(RST); printf(" ");
}

// Common
static void pr_userhost(void) {
  char hn[256] = "unknown";
  if (gethostname(hn, sizeof(hn)) != 0) hn[0] = '?', hn[1] = '\0';
  hn[sizeof(hn) - 1] = '\0';
  char *p = strchr(hn, '.'); if (p) *p = '\0';
  struct passwd *pw = getpwuid(getuid());
  color(CYN); printf("%s", pw ? pw->pw_name : "?");
  color(BLD_CYN); printf("@%s", hn); color(RST);
}

static void pr_cwd(void) {
  char cwd[PATH_MAX_LEN];
  if (!getcwd(cwd, sizeof(cwd))) return;
  color(BLD_YEL);
  if (g_mode == MODE_BASH) {
    const char *h = getenv("HOME");
    if (h && strncmp(cwd, h, strlen(h)) == 0) printf("~%s", cwd + strlen(h));
    else printf("%s", cwd);
  } else printf("%s", cwd);
  color(RST);
}

static void pr_time(void) {
  time_t now = time(NULL);
  struct tm *t = localtime(&now);
  if (!t) { color(WHT); printf("--:--:--"); color(RST); return; }
  color(WHT); printf("%02d:%02d:%02d", t->tm_hour, t->tm_min, t->tm_sec); color(RST);
}

static void pr_prompt(void) {
  if (g_mode != MODE_BASH) return;
  pr_time(); printf(" ");
  if (g_exit_code) { color(BLD_RED); printf("%d ", g_exit_code); }
  color(geteuid() == 0 ? BLD_RED : RST);
  printf("%c", geteuid() == 0 ? '#' : '$');
  color(RST); printf(" ");
}

static int parse_int(const char *s) {
  char *end;
  long val = strtol(s, &end, 10);
  if (*end != '\0' || val < 0 || val > INT_MAX) return 0;
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
  if (strcmp(prog, "bashline") == 0) { g_mode = MODE_BASH; g_fmt = FMT_PS1; }
  const char *em = getenv("STATUSLINE_MODE");
  if (em) {
    if (strcmp(em, "bash") == 0) g_mode = MODE_BASH;
    else if (strcmp(em, "claude") == 0) g_mode = MODE_CLAUDE;
  }
  const char *es = getenv("SHLVL");
  if (es) g_shlvl = parse_int(es);
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--bash") == 0) g_mode = MODE_BASH;
    else if (strcmp(argv[i], "--claude") == 0) g_mode = MODE_CLAUDE;
    else if (strcmp(argv[i], "--ps1") == 0) g_fmt = FMT_PS1;
    else if (strncmp(argv[i], "--exit-code=", 12) == 0) g_exit_code = parse_int(argv[i] + 12);
    else if (strncmp(argv[i], "--jobs=", 7) == 0) g_jobs = parse_int(argv[i] + 7);
    else if (strncmp(argv[i], "--shlvl=", 8) == 0) g_shlvl = parse_int(argv[i] + 8);
    else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) { usage(argv[0]); exit(0); }
    else if (strcmp(argv[i], "-V") == 0 || strcmp(argv[i], "--version") == 0) { printf("statusline %s\n", VERSION); exit(0); }
  }
}

int main(int argc, char **argv) {
  const char *tmp = getenv("TMPDIR");
  snprintf(g_cache_path, sizeof(g_cache_path), "%s/.statusline_cache_%u",
           tmp ? tmp : "/tmp", (unsigned)getuid());
  if (getenv("NO_COLOR")) g_no_color = 1;
  parse_args(argc, argv);
  read_stdin();

  if (g_mode == MODE_CLAUDE) {
    pr_claude_info(); pr_block_time();
    pr_userhost(); printf(":"); pr_cwd(); printf(" ");
    pr_git(); pr_k8s(); pr_time();
  } else {
    printf("\n");
    pr_venv(); pr_ssh();
    pr_userhost(); printf(":"); pr_cwd(); printf(" ");
    pr_git(); pr_k8s();
    if (g_jobs > 0) { color(YEL); printf("[%d job%s]", g_jobs, g_jobs > 1 ? "s" : ""); color(RST); printf(" "); }
    pr_shlvl();
    printf("\n"); pr_prompt();
  }
  fflush(stdout);
  return 0;
}
