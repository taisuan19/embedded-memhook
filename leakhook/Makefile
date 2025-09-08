CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -fPIC
LDFLAGS ?= -ldl -pthread

all: libleakhook.so

libleakhook.so: leakhook.c
	$(CC) $(CFLAGS) -shared -o $@ $< $(LDFLAGS)

clean:
	$(RM) libleakhook.so

.PHONY: all clean
