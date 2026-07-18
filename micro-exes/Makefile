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

.PHONY: all clean heap_alloc process_ids heap_core write_file read_file modules relative_path crt_hello long_loop cpu_math cpu_string cpu_fp winapi_heap cli_args

all: heap_alloc process_ids heap_core write_file read_file modules relative_path crt_hello long_loop cpu_math cpu_string cpu_fp winapi_heap cli_args

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

clean:
	rm -rf $(OUT)
