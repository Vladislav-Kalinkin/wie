#include <windows.h>

void entry(void) {
  volatile unsigned long long counter = 0;
  volatile unsigned long long limit = 100000000ULL;
  if (counter < limit) {
    do {
      volatile unsigned long long tmp = counter ^ 0xDEADBEEF;
      tmp = tmp * 3 + 1;
      (void)tmp;

      counter++;
    } while (counter < limit);
  }

  ExitProcess(0);
}
