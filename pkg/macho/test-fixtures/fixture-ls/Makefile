ROOT=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
CACHE_DIR=$(ROOT)/../assets

BIN=$(CACHE_DIR)/ls_universal_signed
EXTRACTED_BIN=$(CACHE_DIR)/ls_x86_64_signed

.PHONY: check-mac all
all: check-mac $(BIN) $(EXTRACTED_BIN)

$(BIN):
	cp /bin/ls $(BIN)

$(EXTRACTED_BIN): $(BIN)
	cp $(BIN) $(BIN).tmp
	lipo $(BIN) -thin x86_64 -output $(EXTRACTED_BIN)
	mv $(BIN).tmp $(BIN)

.PHONY: check-mac
check-mac:
	@if [ $(shell uname) != "Darwin" ]; then echo "must run this on a mac" && exit 1; fi;

.PHONY: clean
clean:
	rm -f $(BIN)*