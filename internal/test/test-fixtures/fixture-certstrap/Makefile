REPO_ROOT=$(shell git rev-parse --show-toplevel)
ROOT=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
CACHE_DIR=$(ROOT)/../assets
NAME=certstrap

# note: the top-level makefile defines this
TMP_DIR=$(REPO_ROOT)/.tmp
CERTSTRAP_BIN=$(TMP_DIR)/certstrap
CERTSTEAP_CMD=$(CERTSTRAP_BIN) --depot-path $(DEPO_PATH)
DEPO_PATH=$(CACHE_DIR)/$(NAME)

PASSPHRASE=topsykretts

CA_ROOT_NAME=$(NAME)-root
CERT_ROOT_PATH=$(DEPO_PATH)/$(CA_ROOT_NAME).crt

CA_INTERMEDIATE_NAME=$(NAME)-intermediate
CERT_INTERMEDIATE_PATH=$(DEPO_PATH)/$(CA_INTERMEDIATE_NAME).crt

CERT_LEAF_NAME=$(NAME)-leaf
CERT_LEAF_PATH=$(DEPO_PATH)/$(CERT_LEAF_NAME).crt

CHAIN_PATH=$(DEPO_PATH)/$(NAME)-chain.cert.pem

.PHONY: all
all: $(DEPO_PATH)

# initialize CA root
$(DEPO_PATH):
	$(CERTSTEAP_CMD) \
		init \
			--common-name $(CA_ROOT_NAME) \
			--passphrase $(PASSPHRASE)

	# request intermediate cert
	$(CERTSTEAP_CMD) \
		request-cert \
			--common-name $(CA_INTERMEDIATE_NAME) \
			--passphrase $(PASSPHRASE)

	$(CERTSTEAP_CMD) \
		sign \
			$(CA_INTERMEDIATE_NAME) \
			--CA $(CA_ROOT_NAME) \
			--passphrase $(PASSPHRASE) \
			--intermediate

	# request leaf cert
	$(CERTSTEAP_CMD) \
		request-cert \
			--common-name $(CERT_LEAF_NAME) \
			--passphrase $(PASSPHRASE)

	$(CERTSTEAP_CMD) \
		sign \
			$(CERT_LEAF_NAME) \
			--passphrase $(PASSPHRASE)\
			--CA $(CA_INTERMEDIATE_NAME)

	# sanity check: should be able to verify the full chain with openssl
	cat $(CA_ROOT_PATH).crt > $(CHAIN_PATH)
	cat $(CA_INTERMEDIATE_PATH).crt >> $(CHAIN_PATH)
	openssl verify -CAfile $(CHAIN_PATH) $(CERT_LEAF_PATH)

.PHONY: clean
clean:
	rm -rf $(DEPO_PATH)
