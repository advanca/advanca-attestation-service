include ../buildenv.mk

APP_NAME := isv_app

.PHONY: check_env all clean install

target: all check_env

all:
	cargo build --release

clean:
	cargo clean

install: guard-INSTALL_DIR
	cp target/release/$(APP_NAME) $(INSTALL_DIR)/bin/
