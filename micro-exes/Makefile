# Build PE64 micro-tests for WIE.
# Requires: x86_64-w64-mingw32-gcc (Homebrew mingw-w64).
# Clean room: freestanding micros + one ordinary CRT-linked program.

# Force mingw cross-compiler (do not use make's default CC=cc).
MINGW_CC ?= x86_64-w64-mingw32-gcc
OUT      := out
CFLAGS   := -O2 -ffreestanding -fno-stack-protector -fno-asynchronous-unwind-tables
LDFLAGS  := -nostdlib -Wl,--subsystem,console -Wl,--entry,entry
# Ordinary CRT-linked apps (independent-style): full toolchain defaults.
CRT_CFLAGS := -O2

.PHONY: all clean heap_alloc process_ids heap_core write_file read_file modules relative_path crt_hello long_loop cpu_math cpu_string cpu_fp winapi_heap cli_args tls_basic cs_reenter thread_create_join cs_two_threads event_handshake interlocked_basic mt_stress vfs_roundtrip

all: heap_alloc process_ids heap_core write_file read_file modules relative_path crt_hello long_loop cpu_math cpu_string cpu_fp winapi_heap cli_args tls_basic cs_reenter thread_create_join cs_two_threads event_handshake interlocked_basic mt_stress vfs_roundtrip

$(OUT):
	mkdir -p $(OUT)

heap_alloc: $(OUT)/heap_alloc.exe
process_ids: $(OUT)/process_ids.exe
heap_core: $(OUT)/heap_core.exe
write_file: $(OUT)/write_file.exe
read_file: $(OUT)/read_file.exe
modules: $(OUT)/modules.exe
relative_path: $(OUT)/relative_path.exe
crt_hello: $(OUT)/crt_hello.exe
long_loop: $(OUT)/long_loop.exe
cpu_math: $(OUT)/cpu_math.exe
cpu_string: $(OUT)/cpu_string.exe
cpu_fp: $(OUT)/cpu_fp.exe
winapi_heap: $(OUT)/winapi_heap.exe
cli_args: $(OUT)/cli_args.exe
tls_basic: $(OUT)/tls_basic.exe
cs_reenter: $(OUT)/cs_reenter.exe
thread_create_join: $(OUT)/thread_create_join.exe
cs_two_threads: $(OUT)/cs_two_threads.exe
event_handshake: $(OUT)/event_handshake.exe
interlocked_basic: $(OUT)/interlocked_basic.exe
mt_stress: $(OUT)/mt_stress.exe
vfs_roundtrip: $(OUT)/vfs_roundtrip.exe

$(OUT)/heap_alloc.exe: heap_alloc/main.c | $(OUT)
	$(MINGW_CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lkernel32
	@echo "built $@"

$(OUT)/process_ids.exe: process_ids/main.c | $(OUT)
	$(MINGW_CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lkernel32
	@echo "built $@"

$(OUT)/heap_core.exe: heap_core/main.c | $(OUT)
	$(MINGW_CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lkernel32
	@echo "built $@"

$(OUT)/write_file.exe: write_file/main.c | $(OUT)
	$(MINGW_CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lkernel32
	@echo "built $@"

$(OUT)/read_file.exe: read_file/main.c | $(OUT)
	$(MINGW_CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lkernel32
	@echo "built $@"

$(OUT)/modules.exe: modules/main.c | $(OUT)
	$(MINGW_CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lkernel32
	@echo "built $@"

$(OUT)/relative_path.exe: relative_path/main.c | $(OUT)
	$(MINGW_CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lkernel32
	@echo "built $@"

# Normal Windows console + CRT (UCRT api-ms-win-crt-*), not freestanding.
$(OUT)/crt_hello.exe: crt_hello/main.c | $(OUT)
	$(MINGW_CC) $(CRT_CFLAGS) -o $@ $<
	@echo "built $@"


$(OUT)/long_loop.exe: long_loop/main.c | $(OUT)
	$(MINGW_CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lkernel32
	@echo "built $@"

$(OUT)/cpu_math.exe: cpu_math/main.c | $(OUT)
	$(MINGW_CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lkernel32
	@echo "built $@"

$(OUT)/cpu_string.exe: cpu_string/main.c | $(OUT)
	$(MINGW_CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lkernel32
	@echo "built $@"

$(OUT)/cpu_fp.exe: cpu_fp/main.c | $(OUT)
	$(MINGW_CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lkernel32
	@echo "built $@"

$(OUT)/winapi_heap.exe: winapi_heap/main.c | $(OUT)
	$(MINGW_CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lkernel32
	@echo "built $@"

$(OUT)/cli_args.exe: cli_args/main.c cli_args/parse.c | $(OUT)
	$(MINGW_CC) $(CFLAGS) $(LDFLAGS) -o $@ cli_args/main.c cli_args/parse.c -lkernel32
	@echo "built $@"

$(OUT)/tls_basic.exe: tls_basic/main.c | $(OUT)
	$(MINGW_CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lkernel32
	@echo "built $@"

$(OUT)/cs_reenter.exe: cs_reenter/main.c | $(OUT)
	$(MINGW_CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lkernel32
	@echo "built $@"

$(OUT)/thread_create_join.exe: thread_create_join/main.c | $(OUT)
	$(MINGW_CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lkernel32
	@echo "built $@"

$(OUT)/cs_two_threads.exe: cs_two_threads/main.c | $(OUT)
	$(MINGW_CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lkernel32
	@echo "built $@"

$(OUT)/event_handshake.exe: event_handshake/main.c | $(OUT)
	$(MINGW_CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lkernel32
	@echo "built $@"

$(OUT)/interlocked_basic.exe: interlocked_basic/main.c | $(OUT)
	$(MINGW_CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lkernel32
	@echo "built $@"

$(OUT)/mt_stress.exe: mt_stress/main.c | $(OUT)
	$(MINGW_CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lkernel32
	@echo "built $@"

$(OUT)/vfs_roundtrip.exe: vfs_roundtrip/main.c | $(OUT)
	$(MINGW_CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lkernel32
	@echo "built $@"

# ── C++ exception tests (static, full CRT) ─────────────────────────
MINGW_CXX ?= x86_64-w64-mingw32-g++
CPPFLAGS   := -static -O2

cpp_exes: $(OUT)/cpp_throw.exe $(OUT)/cpp_dtor.exe $(OUT)/cpp_multi_catch.exe $(OUT)/cpp_types.exe $(OUT)/cpp_threads.exe

$(OUT)/cpp_throw.exe: cpp_exceptions/cpp_throw/main.cpp | $(OUT)
	$(MINGW_CXX) $(CPPFLAGS) -o $@ $<
	@echo "built $@"

$(OUT)/cpp_dtor.exe: cpp_exceptions/cpp_dtor/main.cpp | $(OUT)
	$(MINGW_CXX) $(CPPFLAGS) -o $@ $<
	@echo "built $@"

$(OUT)/cpp_multi_catch.exe: cpp_exceptions/cpp_multi_catch/main.cpp | $(OUT)
	$(MINGW_CXX) $(CPPFLAGS) -o $@ $<
	@echo "built $@"

$(OUT)/cpp_types.exe: cpp_exceptions/cpp_types/main.cpp | $(OUT)
	$(MINGW_CXX) $(CPPFLAGS) -o $@ $<
	@echo "built $@"

$(OUT)/cpp_threads.exe: cpp_exceptions/cpp_threads/main.cpp | $(OUT)
	$(MINGW_CXX) $(CPPFLAGS) -o $@ $<
	@echo "built $@"

# ── DLL loader tests ────────────────────────────────────────────
# Flags for shared library (DLL) builds.
DLL_CFLAGS   := -O2 -shared
# Flags for freestanding EXEs that test DLL loading.
DLL_EXE_CFLAGS := -O2 -ffreestanding -fno-stack-protector -fno-asynchronous-unwind-tables
DLL_EXE_LDFLAGS := -nostdlib -Wl,--subsystem,console -Wl,--entry,entry

# DLLs
DLL_BASIC_OBJS    := $(OUT)/dll_basic_funcs.dll
DLL_ORDINAL_OBJS  := $(OUT)/dll_ordinal_funcs.dll
DLL_MATH_OBJS     := $(OUT)/dll_math_funcs.dll

# EXEs
DLL_TEST_EXES := \
  $(OUT)/dll_basic.exe \
  $(OUT)/dll_not_found.exe \
  $(OUT)/dll_ordinal.exe \
  $(OUT)/dll_refcount.exe \
  $(OUT)/dll_multi_dll.exe

.PHONY: dll_tests

dll_tests: $(DLL_BASIC_OBJS) $(DLL_ORDINAL_OBJS) $(DLL_MATH_OBJS) $(DLL_TEST_EXES)

# ── DLL build rules ────────────────────────────────────────────

$(OUT)/dll_basic_funcs.dll: dll_tests/basic/dll.c | $(OUT)
	$(MINGW_CC) $(DLL_CFLAGS) -o $@ $< -lkernel32
	@echo "built $@"

$(OUT)/dll_ordinal_funcs.dll: dll_tests/ordinal/dll.c | $(OUT)
	$(MINGW_CC) $(DLL_CFLAGS) -o $@ $< -lkernel32
	@echo "built $@"

$(OUT)/dll_math_funcs.dll: dll_tests/refcount/dll.c | $(OUT)
	$(MINGW_CC) $(DLL_CFLAGS) -o $@ $< -lkernel32
	@echo "built $@"

# ── DLL test EXE build rules ───────────────────────────────────

$(OUT)/dll_basic.exe: dll_tests/basic/main.c $(OUT)/dll_basic_funcs.dll | $(OUT)
	$(MINGW_CC) $(DLL_EXE_CFLAGS) $(DLL_EXE_LDFLAGS) -o $@ $< -lkernel32
	@echo "built $@"

$(OUT)/dll_not_found.exe: dll_tests/not_found/main.c | $(OUT)
	$(MINGW_CC) $(DLL_EXE_CFLAGS) $(DLL_EXE_LDFLAGS) -o $@ $< -lkernel32
	@echo "built $@"

$(OUT)/dll_ordinal.exe: dll_tests/ordinal/main.c $(OUT)/dll_ordinal_funcs.dll | $(OUT)
	$(MINGW_CC) $(DLL_EXE_CFLAGS) $(DLL_EXE_LDFLAGS) -o $@ $< -lkernel32
	@echo "built $@"

$(OUT)/dll_refcount.exe: dll_tests/refcount/main.c $(OUT)/dll_math_funcs.dll | $(OUT)
	$(MINGW_CC) $(DLL_EXE_CFLAGS) $(DLL_EXE_LDFLAGS) -o $@ $< -lkernel32
	@echo "built $@"

$(OUT)/dll_multi_dll.exe: dll_tests/multi_dll/main.c $(OUT)/dll_basic_funcs.dll $(OUT)/dll_math_funcs.dll | $(OUT)
	$(MINGW_CC) $(DLL_EXE_CFLAGS) $(DLL_EXE_LDFLAGS) -o $@ $< -lkernel32
	@echo "built $@"

clean:
	rm -rf $(OUT)
