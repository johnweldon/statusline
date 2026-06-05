CC      = cc
CFLAGS  = -O2 -Wall -Wextra -Wformat -Wformat-security -fstack-protector-strong
PREFIX  = /usr/local/bin
CLAUDE  = $(HOME)/.claude
ANTIGRAVITY = $(HOME)/.gemini/antigravity-cli
VERSION = $(shell git describe --tags --always --dirty 2>/dev/null || echo "unknown")

.DEFAULT_GOAL := statusline

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' | \
		sed -e 's|[$$](PREFIX)|$(PREFIX)|g' -e 's|[$$](CLAUDE)|$(CLAUDE)|g' \
		    -e 's|[$$](HOME)|$(HOME)|g'

all: statusline ## Build everything (alias for statusline)

statusline: statusline.c ## Build the statusline binary (default)
	$(CC) $(CFLAGS) -DVERSION=\"$(VERSION)\" -o $@ $<

install: statusline ## Install binary and symlinks to $(PREFIX)
	install -m 755 statusline $(PREFIX)/statusline
	ln -sf statusline $(PREFIX)/bashline
	ln -sf statusline $(PREFIX)/subagentline
	ln -sf statusline $(PREFIX)/antigravityline

install-local: statusline ## Install binary and symlinks to $(HOME)/.local/bin
	install -m 755 statusline $(HOME)/.local/bin/statusline
	ln -sf statusline $(HOME)/.local/bin/bashline
	ln -sf statusline $(HOME)/.local/bin/subagentline
	ln -sf statusline $(HOME)/.local/bin/antigravityline

install-claude: statusline ## Install binary to $(CLAUDE)
	install -m 755 statusline $(CLAUDE)/statusline

install-antigravity: statusline ## Install binary to $(ANTIGRAVITY)
	install -m 755 statusline $(ANTIGRAVITY)/statusline


test: statusline ## Build, then run the test suite
	./test.sh

clean: ## Remove the built binary
	rm -f statusline

uninstall: ## Remove all installed binaries and symlinks
	rm -f $(PREFIX)/statusline $(PREFIX)/bashline $(PREFIX)/subagentline $(PREFIX)/antigravityline $(CLAUDE)/statusline $(ANTIGRAVITY)/statusline

.PHONY: help all install install-local install-claude install-antigravity test clean uninstall
