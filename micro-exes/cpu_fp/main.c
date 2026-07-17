#include <windows.h>

#define CHECK(cond, code)                                                      \
  do {                                                                         \
    if (!(cond))                                                               \
      ExitProcess(code);                                                       \
  } while (0)

#define EPS_F 0.0001f
#define EPS_D 0.0001

void entry(void) {
  float a = 10.0f, b = 3.0f;
  float sum_f = a + b;
  float diff_f = a - b;
  float mul_f = a * b;
  float div_f = a / b;

  CHECK(sum_f == 13.0f, 1);
  CHECK(diff_f == 7.0f, 2);
  CHECK(mul_f == 30.0f, 3);
  float expected_div = 10.0f / 3.0f;
  float diff_div = div_f - expected_div;
  if (diff_div < 0)
    diff_div = -diff_div;
  CHECK(diff_div < EPS_F, 4);

  CHECK(a > b, 5);

  double d1 = 10.0, d2 = 3.0;
  double sum_d = d1 + d2;
  double diff_d = d1 - d2;
  double mul_d = d1 * d2;
  double div_d = d1 / d2;

  CHECK(sum_d == 13.0, 6);
  CHECK(diff_d == 7.0, 7);
  CHECK(mul_d == 30.0, 8);
  double expected_div_d = 10.0 / 3.0;
  double diff_div_d = div_d - expected_div_d;
  if (diff_div_d < 0)
    diff_div_d = -diff_div_d;
  CHECK(diff_div_d < EPS_D, 9);

  CHECK(d1 > d2, 10);

  float f2 = (float)d1;
  CHECK(f2 == 10.0f, 11);

  double d3 = (double)a;
  CHECK(d3 == 10.0, 12);

  ExitProcess(0);
}
