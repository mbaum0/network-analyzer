build:
	cargo build --release

set-permissions:
	sudo setcap cap_net_admin=eip target/release/network-analyzer
	sudo setcap cap_net_raw=eip target/release/network-analyzer

run:
	./target/release/network-analyzer

all: build set-permissions run
