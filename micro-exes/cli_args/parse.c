/*
 * Freestanding argv-ish tokenizer for GetCommandLineA output.
 * Subset of Windows command-line rules: spaces separate tokens; "..." quotes.
 */

#include "parse.h"

#define MAX_TOKENS 24
#define TOK_LEN 96

unsigned str_len(const char *s) {
  unsigned n = 0;
  if (!s) {
    return 0;
  }
  while (s[n] != 0) {
    n++;
  }
  return n;
}

int str_eq(const char *a, const char *b) {
  unsigned i = 0;
  if (!a || !b) {
    return 0;
  }
  for (;;) {
    if (a[i] != b[i]) {
      return 0;
    }
    if (a[i] == 0) {
      return 1;
    }
    i++;
  }
}

static const char *skip_ws(const char *p) {
  while (*p == ' ' || *p == '\t') {
    p++;
  }
  return p;
}

/* Copy next token into out (NUL-terminated). Advances *pp. Returns 1 on success. */
static int next_token(const char **pp, char *out, unsigned out_len) {
  const char *p;
  unsigned i = 0;
  int in_quote = 0;

  if (!pp || !*pp || !out || out_len == 0) {
    return 0;
  }
  p = skip_ws(*pp);
  if (*p == 0) {
    *pp = p;
    return 0;
  }

  while (*p != 0) {
    char c = *p;
    if (in_quote) {
      if (c == '"') {
        in_quote = 0;
        p++;
        continue;
      }
      if (c == '\\' && p[1] == '"') {
        if (i + 1 < out_len) {
          out[i++] = '"';
        }
        p += 2;
        continue;
      }
      if (i + 1 < out_len) {
        out[i++] = c;
      }
      p++;
      continue;
    }
    if (c == '"') {
      in_quote = 1;
      p++;
      continue;
    }
    if (c == ' ' || c == '\t') {
      break;
    }
    if (i + 1 < out_len) {
      out[i++] = c;
    }
    p++;
  }
  out[i] = 0;
  *pp = p;
  return 1;
}

/* Tokenize full cmdline; returns token count (includes argv[0]). */
static int tokenize_all(const char *cmdline, char toks[][TOK_LEN], int max_toks) {
  const char *p = cmdline;
  int n = 0;
  if (!cmdline) {
    return 0;
  }
  while (n < max_toks && next_token(&p, toks[n], TOK_LEN)) {
    n++;
  }
  return n;
}

int cmdline_has_flag(const char *cmdline, const char *flag) {
  char toks[MAX_TOKENS][TOK_LEN];
  int n = tokenize_all(cmdline, toks, MAX_TOKENS);
  int i;
  /* Skip argv[0]. */
  for (i = 1; i < n; i++) {
    if (str_eq(toks[i], flag)) {
      return 1;
    }
  }
  return 0;
}

int cmdline_get_n(const char *cmdline, int *out_n) {
  char toks[MAX_TOKENS][TOK_LEN];
  int n = tokenize_all(cmdline, toks, MAX_TOKENS);
  int i;
  for (i = 1; i + 1 < n; i++) {
    if (str_eq(toks[i], "-n") && toks[i + 1][0] >= '0' &&
        toks[i + 1][0] <= '9' && toks[i + 1][1] == 0) {
      if (out_n) {
        *out_n = toks[i + 1][0] - '0';
      }
      return 1;
    }
  }
  return 0;
}

int cmdline_get_m(const char *cmdline, char *buf, unsigned buf_len) {
  char toks[MAX_TOKENS][TOK_LEN];
  int n = tokenize_all(cmdline, toks, MAX_TOKENS);
  int i;
  unsigned j;
  for (i = 1; i + 1 < n; i++) {
    if (str_eq(toks[i], "-m") && toks[i + 1][0] != 0) {
      if (buf && buf_len > 0) {
        for (j = 0; toks[i + 1][j] != 0 && j + 1 < buf_len; j++) {
          buf[j] = toks[i + 1][j];
        }
        buf[j] = 0;
      }
      return 1;
    }
  }
  if (buf && buf_len > 0) {
    buf[0] = 0;
  }
  return 0;
}

int cmdline_has_i(const char *cmdline) { return cmdline_has_flag(cmdline, "-i"); }
