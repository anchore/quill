ROOT=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
CACHE_DIR=$(ROOT)/../assets

# an unsigned, universal (arm64 + x86_64) dylib, used as a nested binary within an app bundle
# fixture to exercise multi-architecture code resource sealing
BIN=$(CACHE_DIR)/nested_universal_dylib

.PHONY: all
all: check $(BIN)

$(BIN): lib.c
	clang -arch arm64 -arch x86_64 -dynamiclib -o $(BIN) lib.c

.PHONY: check
check:
	@if [ $(shell uname) != "Darwin" ]; then echo "must run this on a mac" && exit 1; fi;

.PHONY: clean
clean:
	rm -f $(BIN)
