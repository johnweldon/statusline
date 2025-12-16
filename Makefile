CC      = cc
CFLAGS  = -O2 -Wall -Wextra -Wformat -Wformat-security -fstack-protector-strong
PREFIX  = /usr/local/bin
CLAUDE  = $(HOME)/.claude

.DEFAULT_GOAL := statusline

all: statusline

statusline: statusline.c
	$(CC) $(CFLAGS) -o $@ $<

install: statusline
	install -m 755 statusline $(PREFIX)/statusline
	ln -sf statusline $(PREFIX)/bashline

install-claude: statusline
	install -m 755 statusline $(CLAUDE)/statusline

test: statusline
	./test.sh

clean:
	rm -f statusline

uninstall:
	rm -f $(PREFIX)/statusline $(PREFIX)/bashline $(CLAUDE)/statusline

.PHONY: all install install-claude test clean uninstall
