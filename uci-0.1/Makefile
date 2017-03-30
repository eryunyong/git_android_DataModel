CROSS_COMPILE = arm-linux-androideabi-
CC              = $(CROSS_COMPILE)gcc

export CC
SHLIB_FILE=libuci.so

CFLAGS := -Wall -O2 -g
LIBS=-lc
SHLIB_FLAGS=-shared -Wl,-soname,$(SHLIB_FILE)
LIBUCI_DEPS= file.c history.c list.c util.c glob.c uci.h  uci_internal.h glob.h

all: $(SHLIB_FILE) uci

libuci-shared.o:libuci.c $(LIBUCI_DEPS)
	$(CC) $(CFLAGS) -fPIC -c -o $@ $<

$(SHLIB_FILE): libuci-shared.o
	$(CC) $(SHLIB_FLAGS) -fPIC -o $(SHLIB_FILE) $^ $(LIBS)

uci: cli.o $(SHLIB_FILE)
	$(CC) -o $@ $< -L. -luci

clean:
	rm -f uci *.[oa] *.so* *.dylib*

FORCE: ;
.PHONY: FORCE
