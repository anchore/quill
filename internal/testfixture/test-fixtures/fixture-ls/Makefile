ROOT=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
CACHE_DIR=$(ROOT)/../assets

BIN=$(CACHE_DIR)/ls_universal_signed
EXTRACTED_BIN=$(CACHE_DIR)/ls_x86_64_signed

.PHONY: check all
all: check $(BIN) $(EXTRACTED_BIN)

$(BIN):
	cp /bin/ls $(BIN)

$(EXTRACTED_BIN): $(BIN)
	cp $(BIN) $(BIN).tmp
	lipo $(BIN) -thin x86_64 -output $(EXTRACTED_BIN)
	mv $(BIN).tmp $(BIN)

.PHONY: check-mac
check:
	@if [ $(shell uname) != "Darwin" ]; then echo "must run this on a mac" && exit 1; fi;
	@if [ $(shell uname -m) != "x86_64" ]; then echo "must run this on x86_64" && exit 1; fi;

.PHONY: clean
clean:
	rm -f $(BIN)*