#include <windows.h>

#define CHECK(cond, code)                                                      \
  do {                                                                         \
    if (!(cond))                                                               \
      ExitProcess(code);                                                       \
  } while (0)

void test_movs(void) {
  unsigned char src[16] = {1, 2,  3,  4,  5,  6,  7,  8,
                           9, 10, 11, 12, 13, 14, 15, 16};
  unsigned char dst[16] = {0};

  __builtin_memcpy(dst, src, 16);

  for (int i = 0; i < 16; i++) {
    CHECK(dst[i] == src[i], 1 + i);
  }
}

void test_stos(void) {
  unsigned char buf[16] = {0};

  __builtin_memset(buf, 0xAA, 16);

  for (int i = 0; i < 16; i++) {
    CHECK(buf[i] == 0xAA, 17 + i);
  }
}

void test_scas(void) {
  unsigned char haystack[16] = {0, 1, 2,  3,  4,  5,  6,  7,
                                8, 9, 10, 11, 12, 13, 14, 15};
  unsigned char needle = 7;
  int found = 0;

  for (int i = 0; i < 16; i++) {
    if (haystack[i] == needle) {
      found = 1;
      break;
    }
  }
  CHECK(found == 1, 33);
}

void test_cmps(void) {
  unsigned char a[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  unsigned char b[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  unsigned char c[8] = {1, 2, 3, 4, 5, 6, 7, 9};

  CHECK(__builtin_memcmp(a, b, 8) == 0, 34);
  CHECK(__builtin_memcmp(a, c, 8) != 0, 35);
}

void test_df(void) {
  unsigned char src[16] = {1, 2,  3,  4,  5,  6,  7,  8,
                           9, 10, 11, 12, 13, 14, 15, 16};
  unsigned char dst[16] = {0};
  __builtin_memmove(dst, src, 16);

  for (int i = 0; i < 16; i++) {
    CHECK(dst[i] == src[i], 36 + i);
  }
}

void entry(void) {
  test_movs();
  test_stos();
  test_scas();
  test_cmps();
  test_df();
  ExitProcess(0);
}
