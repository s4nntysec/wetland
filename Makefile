# wetland — Makefile (zero external deps: crypto is vendored Monocypher)
#
#   make                 build native binaries into ./bin
#   make test            build + run unit and end-to-end tests
#   make windows         cross-build Windows .exe into ./dist/windows (needs mingw-w64)
#   make CROSS=aarch64-linux-gnu   cross-build for another Linux arch
#   make install         install into $(PREFIX)/bin (default /usr/local)
#   make clean
#
# Native OS is auto-detected; macOS and Linux both build out of the box.

CC      ?= cc
PREFIX  ?= /usr/local
BINDIR   = $(PREFIX)/bin

UNAME_S := $(shell uname -s)

CFLAGS  ?= -O2 -g
CFLAGS  += -std=c11 -Wall -Wextra -Wno-unused-parameter -D_GNU_SOURCE
CPPFLAGS += -Isrc

# Detect a native Windows toolchain (MSYS2/MinGW/Cygwin shells).
ifneq (,$(findstring MINGW,$(UNAME_S))$(findstring MSYS,$(UNAME_S))$(findstring CYGWIN,$(UNAME_S)))
  WIN_NATIVE = 1
endif

ifdef WIN_NATIVE
  LIBS_CLIENT = -lws2_32 -lbcrypt
  LIBS_RELAY  = -lws2_32 -lbcrypt
else ifeq ($(UNAME_S),Linux)
  # forkpty lives in -lutil on Linux; it's in libc on macOS/BSD.
  LIBS_CLIENT = -lutil
  LIBS_RELAY  =
else
  LIBS_CLIENT =
  LIBS_RELAY  =
endif

MONO       = src/monocypher/monocypher.c
COMMON_SRC = src/wld_crypto.c src/wld_net.c $(MONO)
CLIENT_SRC = src/client.c src/wld_tunnel.c $(COMMON_SRC)
RELAY_SRC  = src/relay.c $(COMMON_SRC)

BIN = bin/wld bin/wetland-relay

.PHONY: all clean test install windows

all: $(BIN)

bin:
	@mkdir -p bin

bin/wld: $(CLIENT_SRC) | bin
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $(CLIENT_SRC) $(LIBS_CLIENT)

bin/wetland-relay: $(RELAY_SRC) | bin
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $(RELAY_SRC) $(LIBS_RELAY)

bin/test_crypto: tests/test_crypto.c $(COMMON_SRC) | bin
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ tests/test_crypto.c $(COMMON_SRC)

test: all bin/test_crypto
	./bin/test_crypto
	./tests/test_e2e.sh

# --- Windows cross-compile (mingw-w64) ---
MINGW ?= x86_64-w64-mingw32-gcc
WINCFLAGS = -O2 -std=c11 -Wall -Wextra -Wno-unused-parameter -Isrc
WINLIBS   = -lws2_32 -lbcrypt

windows:
	@mkdir -p dist/windows
	$(MINGW) $(WINCFLAGS) -o dist/windows/wld.exe $(CLIENT_SRC) $(WINLIBS)
	$(MINGW) $(WINCFLAGS) -o dist/windows/wetland-relay.exe $(RELAY_SRC) $(WINLIBS)
	@echo "built dist/windows/{wld,wetland-relay}.exe"

install: all
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 bin/wld $(DESTDIR)$(BINDIR)/wld
	install -m 0755 bin/wetland-relay $(DESTDIR)$(BINDIR)/wetland-relay

clean:
	rm -rf bin dist
