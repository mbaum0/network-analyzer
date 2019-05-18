
COLOR ?= always # valid options: {always, auto, never}
CARGO = cargo --color $(COLOR)

TARGET_NAME = network-analyzer
TARGET_RELEASE = ./target/release/$(TARGET_NAME)
TARGET_DEBUG = ./target/debug/$(TARGET_NAME)

.PHONY: all build build-release clean set-permissions run

all: clean build set-permissions run

build:
	@$(CARGO) build

build-release:
	@$(CARGO) build --release

clean:
	@$(CARGO) clean

run:
	@$(CARGO) run

set-permissions:
	@sudo setcap cap_net_admin=eip $(TARGET_DEBUG) > /dev/null
	@sudo setcap cap_net_raw=eip $(TARGET_DEBUG) > /dev/null
