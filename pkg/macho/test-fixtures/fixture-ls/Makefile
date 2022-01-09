ROOT=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
CACHE_DIR=$(ROOT)/../assets

BIN=$(CACHE_DIR)/ls_signed

.PHONY: check-mac all
all: check-mac $(BIN)

$(BIN):
	cp /bin/ls $(BIN)

.PHONY: check-mac
check-mac:
	@if [ $(shell uname) != "Darwin" ]; then echo "must run this on a mac" && exit 1; fi;

.PHONY: clean
clean:
	rm -f $(BIN)*