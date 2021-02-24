RUSTFLAGS=-C link-arg=-s

make:
	export RUSTFLAGS="%(RUSTFLAGS)"
	cargo build --release

install:
	cp -f target/release/linkage_cli /usr/bin/linkage
	chmod +x /usr/bin/linkage

uninstall:
	rm -f /usr/bin/linkage