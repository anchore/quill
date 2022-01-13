ROOT=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
CACHE_DIR=$(ROOT)/../assets

BIN=$(CACHE_DIR)/syft_signed

.PHONY: all
all: $(BIN)

$(BIN):
	curl -sSfL https://github.com/anchore/syft/releases/download/v0.35.0/syft_0.35.0_darwin_amd64.zip \
		-o $(CACHE_DIR)/syft_0.35.0_darwin_amd64.zip
	cd $(CACHE_DIR) && tar -xvzf syft_0.35.0_darwin_amd64.zip syft
	mv $(CACHE_DIR)/syft $(BIN)
	rm -f $(CACHE_DIR)/syft_0.35.0_darwin_amd64.zip

.PHONY: clean
clean:
	rm -f $(BIN)*