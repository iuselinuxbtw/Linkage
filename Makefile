NAME = linkage
INSTALL_DIR = /usr/bin/

RUSTFLAGS=-C link-arg=-s

all: build install

build:
	export RUSTFLAGS="%(RUSTFLAGS)"
	cargo build --release

install:
	cp -f target/release/linkage_cli $(INSTALL_DIR)$(NAME)
	chmod +x $(INSTALL_DIR)$(NAME)

uninstall:
	rm -f $(INSTALL_DIR)$(NAME)