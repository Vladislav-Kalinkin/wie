#include <windows.h>

#define CHECK(cond, code)                                                      \
  do {                                                                         \
    if (!(cond))                                                               \
      ExitProcess(code);                                                       \
  } while (0)

int add(int a, int b) { return a + b; }

int compute(int x, int y) {
  int t = x * y;
  int u = x + y;
  if (t > u) {
    return t - u;
  } else {
    return u - t;
  }
}

int factorial(int n) {
  if (n <= 1)
    return 1;
  return n * factorial(n - 1);
}

int multi_args(int a1, int a2, int a3, int a4, int a5, int a6) {
  return a1 + a2 + a3 + a4 + a5 + a6;
}

void entry(void) {
  int a = 10, b = 3;
  CHECK(a + b == 13, 1);
  CHECK(a - b == 7, 2);
  CHECK(a * b == 30, 3);
  CHECK(a / b == 3, 4);
  CHECK(a % b == 1, 5);

  int x = 0b1010, y = 0b1100;
  CHECK((x & y) == 0b1000, 6);
  CHECK((x | y) == 0b1110, 7);
  CHECK((x ^ y) == 0b0110, 8);
  CHECK((~x) == -11, 9);
  CHECK((x << 2) == 40, 10);
  CHECK((x >> 1) == 5, 11);
  int neg = -8;
  CHECK((neg >> 2) == -2, 12);

  if (a > b) {
    // ok
  } else {
    ExitProcess(13);
  }

  int max = (a > b) ? a : b;
  CHECK(max == 10, 14);

  CHECK(add(5, 7) == 12, 15);

  CHECK(compute(6, 4) == 14, 16); // 24 - 10 = 14
  CHECK(compute(2, 8) == 6, 17);  // 16 - 10 = 6

  CHECK(factorial(5) == 120, 18);

  int sum = 0;
  for (int i = 0; i < 10; i++) {
    sum += i;
  }
  CHECK(sum == 45, 19);

  int prod = 1;
  int j = 1;
  while (j <= 5) {
    prod *= j;
    j++;
  }
  CHECK(prod == 120, 20);

  int nested = 0;
  for (int i = 0; i < 3; i++) {
    for (int k = 0; k < 3; k++) {
      nested += i * k;
    }
  }
  CHECK(nested == 9, 21);

  int arr[5] = {2, 4, 6, 8, 10};
  CHECK(arr[0] == 2, 22);
  CHECK(arr[2] == 6, 23);
  CHECK(arr[4] == 10, 24);

  int *ptr = arr;
  ptr[1] = 100;
  CHECK(arr[1] == 100, 25);

  int cmp1 = 5, cmp2 = 5;
  if (cmp1 == cmp2) { /* ok */
  } else {
    ExitProcess(26);
  }
  if (cmp1 != 10) { /* ok */
  } else {
    ExitProcess(27);
  }
  if (cmp1 < 10) { /* ok */
  } else {
    ExitProcess(28);
  }
  if (cmp1 <= 5) { /* ok */
  } else {
    ExitProcess(29);
  }
  if (cmp1 > 0) { /* ok */
  } else {
    ExitProcess(30);
  }
  if (cmp1 >= 5) { /* ok */
  } else {
    ExitProcess(31);
  }
  int sum6 = multi_args(1, 2, 3, 4, 5, 6);
  CHECK(sum6 == 21, 32);
  int *p = arr + 3;
  CHECK(*p == 8, 33);
  p--;
  CHECK(*p == 6, 34);

  ExitProcess(0);
}
