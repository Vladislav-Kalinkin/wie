/*
 * Minimal freestanding command-line helpers (no CRT).
 * Clean room: used only by cli_args micro-PE.
 */
#ifndef WIE_CLI_ARGS_PARSE_H
#define WIE_CLI_ARGS_PARSE_H

/* Returns 1 if needle is a whole argv token after argv[0], else 0. */
int cmdline_has_flag(const char *cmdline, const char *flag);

/* If "-n <digit>" is present, write digit value 0..9 into *out_n and return 1. */
int cmdline_get_n(const char *cmdline, int *out_n);

/*
 * If "-m <token>" is present, copy token into buf (NUL-terminated, max buf_len-1)
 * and return 1. Quoted tokens are accepted without surrounding quotes.
 */
int cmdline_get_m(const char *cmdline, char *buf, unsigned buf_len);

/* Returns 1 if token "-i" is present after argv[0]. */
int cmdline_has_i(const char *cmdline);

/* Case-sensitive equality of two C strings. */
int str_eq(const char *a, const char *b);

/* Length of a C string (no CRT). */
unsigned str_len(const char *s);

#endif
