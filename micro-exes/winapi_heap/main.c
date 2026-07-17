#include <windows.h>

#define CHECK(cond, code)                                                      \
  do {                                                                         \
    if (!(cond))                                                               \
      ExitProcess(code);                                                       \
  } while (0)

void entry(void) {
  HANDLE heap;
  void *p, *q;
  SIZE_T sz;

  // 1. Получение кучи процесса
  heap = GetProcessHeap();
  CHECK(heap != NULL, 1);

  // 2. HeapAlloc: выделить 64 байта
  p = HeapAlloc(heap, 0, 64);
  CHECK(p != NULL, 2);

  // 3. HeapSize: проверить размер
  sz = HeapSize(heap, 0, p);
  CHECK(sz >= 64, 3);

  // 4. Записать что-то в память (проверка доступности)
  *(char *)p = 0x41; // 'A'
  CHECK(*(char *)p == 0x41, 4);

  // 5. HeapReAlloc: увеличить до 128 байт
  q = HeapReAlloc(heap, 0, p, 128);
  CHECK(q != NULL, 5);
  // Проверить, что данные сохранились (если переместилось – ок)
  CHECK(*(char *)q == 0x41, 6);

  // 6. HeapSize после ReAlloc
  sz = HeapSize(heap, 0, q);
  CHECK(sz >= 128, 7);

  // 7. HeapFree: освободить
  CHECK(HeapFree(heap, 0, q) != 0, 8);

  // 8. Попытаться освободить уже освобождённый блок – должно вернуть FALSE
  //    и установить ERROR_INVALID_HANDLE (но на самом деле поведение может быть
  //    разным, для простоты проверяем, что возвращает FALSE)
  SetLastError(0);
  BOOL result = HeapFree(heap, 0, q);
  CHECK(result == 0, 9);
  CHECK(GetLastError() != 0, 10);

  // 9. HeapAlloc с нулевым размером – возвращает NULL (документировано)
  p = HeapAlloc(heap, 0, 0);
  CHECK(p == NULL, 11);

  // 10. HeapReAlloc с нулевым размером – освобождает блок и возвращает NULL
  q = HeapAlloc(heap, 0, 64);
  CHECK(q != NULL, 12);
  p = HeapReAlloc(heap, 0, q, 0);
  CHECK(p == NULL, 13);

  ExitProcess(0);
}
