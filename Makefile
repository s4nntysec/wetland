# wetland — Makefile
#
# Targets:
#   make            build wld and wetland-relay into ./bin
#   make test       build and run unit + end-to-end tests
#   make install    install into $(PREFIX)/bin   (default /usr/local)
#   make clean

CC      ?= cc
PREFIX  ?= /usr/local
BINDIR   = $(PREFIX)/bin

CFLAGS  ?= -O2 -g
CFLAGS  += -std=c11 -Wall -Wextra -Wno-unused-parameter -D_GNU_SOURCE
CPPFLAGS += -Isrc

# OpenSSL (prefer pkg-config, fall back to -lssl -lcrypto)
OPENSSL_CFLAGS := $(shell pkg-config --cflags libcrypto 2>/dev/null)
OPENSSL_LIBS   := $(shell pkg-config --libs libcrypto 2>/dev/null || echo -lcrypto)
CFLAGS  += $(OPENSSL_CFLAGS)

LIBS_CLIENT = $(OPENSSL_LIBS) -lutil
LIBS_RELAY  = $(OPENSSL_LIBS)

COMMON_SRC = src/wld_crypto.c src/wld_net.c
CLIENT_SRC = src/client.c src/wld_tunnel.c $(COMMON_SRC)
RELAY_SRC  = src/relay.c $(COMMON_SRC)

BIN = bin/wld bin/wetland-relay

.PHONY: all clean test install

all: $(BIN)

bin:
	@mkdir -p bin

bin/wld: $(CLIENT_SRC) | bin
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $(CLIENT_SRC) $(LIBS_CLIENT)

bin/wetland-relay: $(RELAY_SRC) | bin
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $(RELAY_SRC) $(LIBS_RELAY)

bin/test_crypto: tests/test_crypto.c $(COMMON_SRC) | bin
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ tests/test_crypto.c $(COMMON_SRC) $(OPENSSL_LIBS)

test: all bin/test_crypto
	./bin/test_crypto
	./tests/test_e2e.sh

install: all
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 bin/wld $(DESTDIR)$(BINDIR)/wld
	install -m 0755 bin/wetland-relay $(DESTDIR)$(BINDIR)/wetland-relay

clean:
	rm -rf bin
