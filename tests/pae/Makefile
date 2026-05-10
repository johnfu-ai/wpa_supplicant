# Makefile for PAE unit tests
#
# Implements: #19 REQ-F-LOGON-001 (Logon Process state machine — test harness)
# See: IEEE 802.1X-2020, Clause 12
#
# Build from this directory:
#   make test

CC      ?= gcc
CFLAGS  += -DCONFIG_IEEE8021X_2020 -DCONFIG_IEEE8021X_2020_LOGON
CFLAGS  += -I../../src
SRC_PAE  = ../../src/pae

test_ieee802_1x_logon: test_ieee802_1x_logon.c $(SRC_PAE)/ieee802_1x_logon.c
	$(CC) $(CFLAGS) -o $@ $^

test: test_ieee802_1x_logon
	./test_ieee802_1x_logon

clean:
	rm -f test_ieee802_1x_logon
