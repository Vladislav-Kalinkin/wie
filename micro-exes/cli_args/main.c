/*
 * Micro-PE: pseudo-CLI flags + interactive console stdin/stdout via kernel32.
 *
 * Freestanding PE64. Clean room: Microsoft Learn semantics only.
 *
 * Expected host invocation (interactive):
 *   wie-cli run-micro cli_args.exe -- -n 3 -m hi -i
 *   → guest prints prompt; type a line; guest echoes cli_args:got:…
 *
 * Deterministic CI (inject, no TTY):
 *   wie-cli run-micro cli_args.exe --stdin fixture -- -n 3 -m hi -i
 *
 * Exit codes:
 *   0 — ok
 *   1 — stdout GetStdHandle / WriteFile / GetFileType failed
 *   2 — command line missing required -n 3 (or parse fail)
 *   3 — -i set but stdin handle / ReadFile / empty payload failed
 *   4 — -m missing or message WriteFile failed
 *
 * Docs: GetCommandLineA, GetStdHandle, GetFileType, ReadFile, WriteFile,
 *       ExitProcess (Microsoft Learn). Default console line input:
 *       ReadFile on STD_INPUT completes after a line terminator.
 */

#include <windows.h>
#include "parse.h"

static const char k_banner[] = "cli_args:ok\n";
static const char k_prompt[] = "cli_args:input\n";
static const char k_got_prefix[] = "cli_args:got:";

void entry(void) {
  HANDLE hout;
  HANDLE hin;
  DWORD written = 0;
  DWORD nread = 0;
  DWORD ftype;
  const char *cmdline;
  int n_val = -1;
  char msg[64];
  char inbuf[256];
  unsigned i;
  int want_stdin;

  hout = GetStdHandle(STD_OUTPUT_HANDLE);
  if (hout == INVALID_HANDLE_VALUE || hout == NULL) {
    ExitProcess(1);
  }

  ftype = GetFileType(hout);
  if (ftype != FILE_TYPE_CHAR) {
    ExitProcess(1);
  }

  if (!WriteFile(hout, k_banner, (DWORD)str_len(k_banner), &written, NULL) ||
      written != (DWORD)str_len(k_banner)) {
    ExitProcess(1);
  }

  cmdline = GetCommandLineA();
  if (cmdline == NULL || cmdline[0] == 0) {
    ExitProcess(2);
  }

  if (!cmdline_get_n(cmdline, &n_val) || n_val != 3) {
    ExitProcess(2);
  }

  if (!cmdline_get_m(cmdline, msg, sizeof(msg))) {
    ExitProcess(4);
  }
  /* Echo -m value plus newline. */
  {
    char line[80];
    unsigned len = 0;
    for (i = 0; msg[i] != 0 && len + 1 < sizeof(line); i++) {
      line[len++] = msg[i];
    }
    if (len + 1 < sizeof(line)) {
      line[len++] = '\n';
    }
    line[len] = 0;
    if (!WriteFile(hout, line, (DWORD)len, &written, NULL) || written != len) {
      ExitProcess(4);
    }
  }

  want_stdin = cmdline_has_i(cmdline);
  if (want_stdin) {
    hin = GetStdHandle(STD_INPUT_HANDLE);
    if (hin == INVALID_HANDLE_VALUE || hin == NULL) {
      ExitProcess(3);
    }
    ftype = GetFileType(hin);
    if (ftype != FILE_TYPE_CHAR) {
      ExitProcess(3);
    }

    if (!WriteFile(hout, k_prompt, (DWORD)str_len(k_prompt), &written, NULL) ||
        written != (DWORD)str_len(k_prompt)) {
      ExitProcess(1);
    }

    for (i = 0; i < sizeof(inbuf); i++) {
      inbuf[i] = 0;
    }
    /* Interactive: content comes from console ReadFile, never from argv. */
    if (!ReadFile(hin, inbuf, (DWORD)(sizeof(inbuf) - 1), &nread, NULL)) {
      ExitProcess(3);
    }
    if (nread == 0) {
      ExitProcess(3);
    }

    if (!WriteFile(hout, k_got_prefix, (DWORD)str_len(k_got_prefix), &written,
                   NULL) ||
        written != (DWORD)str_len(k_got_prefix)) {
      ExitProcess(1);
    }
    if (!WriteFile(hout, inbuf, nread, &written, NULL) || written != nread) {
      ExitProcess(1);
    }
  }

  ExitProcess(0);
}
