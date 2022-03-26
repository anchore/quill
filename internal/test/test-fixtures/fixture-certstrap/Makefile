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

CHAIN_PATH=$(DEPO_PATH)/$(NAME)-chain.cert.pem
P12_PATH=$(DEPO_PATH)/$(NAME).p12
P12_PASSWORD=$(PASSPHRASE)


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
	./create-code-signing-cert-request.sh \
		$(DEPO_PATH) \
		$(CA_INTERMEDIATE_CERT_PATH) \
		$(CA_INTERMEDIATE_KEY_PATH)

	$(CERTSTEAP_CMD) \
		sign \
			$(CERT_LEAF_NAME) \
			--CA $(CA_INTERMEDIATE_NAME) \
			--expires '25 years' \
			--passphrase $(PASSPHRASE)

	# verify the certificate: we should see our x509 extensions needed for codesigning
	bash -c "openssl x509 -text -noout -in $(CERT_LEAF_PATH) | grep -A1 'X509v3' || (echo 'could not find x509 extensions in certificate' && false)"

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


.PHONY: clean
clean:
	rm -rf $(DEPO_PATH)
