ROOT=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
CACHE_DIR=$(ROOT)/../assets

SIGNED_BIN=$(CACHE_DIR)/syft_signed
UNSIGNED_BIN=$(CACHE_DIR)/syft_unsigned

.PHONY: all
all: $(SIGNED_BIN) $(UNSIGNED_BIN)

$(SIGNED_BIN):
	curl -sSfL https://github.com/anchore/syft/releases/download/v0.35.0/syft_0.35.0_darwin_amd64.zip \
		-o $(CACHE_DIR)/syft_0.35.0_darwin_amd64.zip
	cd $(CACHE_DIR) && tar -xvzf syft_0.35.0_darwin_amd64.zip syft
	mv $(CACHE_DIR)/syft $(BIN)
	rm -f $(CACHE_DIR)/syft_0.35.0_darwin_amd64.zip

$(UNSIGNED_BIN):
	GOBIN=$(shell realpath $(CACHE_DIR)) go install github.com/anchore/syft@v0.35.0
	mv $(CACHE_DIR)/syft $(CACHE_DIR)/syft_unsigned

.PHONY: clean
clean:
	rm -f $(BIN)*