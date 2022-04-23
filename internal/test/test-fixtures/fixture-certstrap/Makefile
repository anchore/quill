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
CA_ROOT_CERT_PATH=$(DEPO_PATH)/$(CA_ROOT_NAME).crt

CA_INTERMEDIATE_NAME=$(NAME)-intermediate
CA_INTERMEDIATE_CERT_PATH=$(DEPO_PATH)/$(CA_INTERMEDIATE_NAME).crt
CA_INTERMEDIATE_KEY_PATH=$(DEPO_PATH)/$(CA_INTERMEDIATE_NAME).key

CERT_LEAF_NAME=$(NAME)-leaf
CERT_LEAF_PATH=$(DEPO_PATH)/$(CERT_LEAF_NAME).crt
CERT_LEAF_KEY_PATH=$(DEPO_PATH)/$(CERT_LEAF_NAME).key

CHAIN_PATH=$(DEPO_PATH)/$(NAME)-chain.pem
P12_PATH=$(DEPO_PATH)/$(NAME).p12
P12_PASSWORD=$(PASSPHRASE)

KEYCHAIN_NAME=quill-test-$(NAME)
# note, you could do this with /Library/Keychains/System.keychain , but is not recommended
KEYCHAIN_PATH="${HOME}/Library/Keychains/$(KEYCHAIN_NAME)-db"
KEYCHAIN_PASSWORD=$(PASSPHRASE)

IDENTITY=$(NAME)-code-signing-id

.PHONY: all
all: $(P12_PATH)


# initialize root + intermediate CA (a pseudo-real chain)
$(CA_INTERMEDIATE_CERT_PATH):
	$(CERTSTEAP_CMD) \
		init \
			--common-name $(CA_ROOT_NAME) \
			--expires '25 years' \
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
			--expires '25 years' \
			--passphrase $(PASSPHRASE) \
			--intermediate


$(CERT_LEAF_PATH): $(CA_INTERMEDIATE_CERT_PATH)
	./create-code-signing-certificate.sh \
		$(DEPO_PATH) \
		$(CA_INTERMEDIATE_CERT_PATH) \
		$(CA_INTERMEDIATE_KEY_PATH) \
		$(IDENTITY)

	# sanity check: should be able to verify the full chain with openssl
	cat $(CA_ROOT_CERT_PATH) > $(CHAIN_PATH)
	cat $(CA_INTERMEDIATE_CERT_PATH) >> $(CHAIN_PATH)
	openssl verify -CAfile $(CHAIN_PATH) $(CERT_LEAF_PATH)


$(P12_PATH): $(CERT_LEAF_PATH)
	openssl pkcs12 \
          -export \
          -out $(P12_PATH) \
          -inkey $(CERT_LEAF_KEY_PATH) \
          -in $(CERT_LEAF_PATH) \
          -passin "pass:$(PASSPHRASE)" \
          -passout "pass:$(P12_PASSWORD)"


.PHONY: install-trust
install-trust:
	@if [ ! -f "$(KEYCHAIN_PATH)" ]; then \
  		security create-keychain -p "$(KEYCHAIN_PASSWORD)" "$(KEYCHAIN_NAME)"; \
  	else \
  	  echo "keychain '$(KEYCHAIN_NAME)' already exists"; \
  	fi

	# import the cert into the keychain
	# note: set the partition list for this certificate's private key to include "apple-tool:" and "apple:" allows the codesign command to access this keychain item without an interactive user prompt.
	security import $(P12_PATH) -P $(P12_PASSWORD) -f pkcs12 -k $(KEYCHAIN_PATH) -T /usr/bin/codesign
	security set-key-partition-list -S "apple-tool:,apple:,codesign:" -s -k "$(KEYCHAIN_PASSWORD)" $(KEYCHAIN_PATH)
	security add-trusted-cert -d -r trustRoot -k $(KEYCHAIN_PATH) $(CERT_LEAF_PATH)

	# add the keychain to the search path (otherwise codesign will not see an identity)
	./add-keychain.sh "${KEYCHAIN_NAME}"

	# make certain there are identities that can be used for codesigning
	security find-identity -p codesigning $(KEYCHAIN_PATH) | grep -C 30 $(IDENTITY)

	security list-keychains | grep "${KEYCHAIN_NAME}"


.PHONY: clean
clean:
	rm -rf $(DEPO_PATH)
