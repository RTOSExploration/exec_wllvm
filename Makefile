.PHONY: clean

CC = gcc
CFLAGS = -fPIC -O2 -g -Wall -Wextra -Wno-unused-parameter
LDFLAGS = -lsyscall_intercept -shared

libexec_wllvm.so: hook.c
	$(CC) $< $(CFLAGS) $(LDFLAGS) -o $@

clean:
	rm -f libexec_wllvm.so
