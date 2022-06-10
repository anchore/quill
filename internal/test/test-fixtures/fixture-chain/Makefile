SHELL = bash
ROOT=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
CACHE_DIR=$(ROOT)/../assets
NAME=chain
BASE=$(CACHE_DIR)/$(NAME)

# note: these values are controlled by root.config
CA_ROOT_KEY=$(BASE)-ca-key.pem
CA_ROOT_CSR=$(BASE)-ca-csr.pem
CA_ROOT_CERT=$(BASE)-ca-cert.pem
ROOT_STORE=./root_ca

# note: these values are controlled by intermediate.config
CA_INT_KEY=$(BASE)-ca-int-key.pem
CA_INT_CSR=$(BASE)-ca-int-csr.pem
CA_INT_CERT=$(BASE)-ca-int-cert.pem
INT_STORE=./intermediate_ca

LEAF_KEY=$(BASE)-leaf-key.pem
LEAF_CSR=$(BASE)-leaf-csr.pem
LEAF_CERT=$(BASE)-leaf-cert.pem

CHAIN=$(BASE).pem
P12_FILE=$(BASE).p12
P12_PASSWORD=123456

# note: the identity is controlled by leaf_req.config
IDENTITY="quill-test-leaf"
KEYCHAIN_NAME=quill-test-$(NAME)
KEYCHAIN_PATH="${HOME}/Library/Keychains/$(KEYCHAIN_NAME)-db"
KEYCHAIN_PASSWORD=123456

# for debuggin:
# security verify-cert -v -p codeSign -k ~/Library/Keychains/quill-test-chain-db -c /Users/wagoodman/code/quill/internal/test/test-fixtures/assets/chain-leaf-cert.pem

.PHONY:
all: $(CHAIN)

# see https://superuser.com/questions/126121/how-to-create-my-own-certificate-chain
$(CHAIN):
	# create the private key for the root CA
	#   - out: output file
	#   - key bitcount
	openssl genrsa \
		-out $(CA_ROOT_KEY) \
		2048

	# create the csr for the root CA
	#   - key: private key associated with the csr
	#   - out: output file
	#   - config: contains config for generating the csr such as the distinguished name
	openssl req \
		-new \
		-key $(CA_ROOT_KEY) \
		-out $(CA_ROOT_CSR) \
		-config root_req.config

	# create the root CA cert
	#   - batch: don't prompt
	#   - in: csr file
	#   - out:  output certificate file
	#   - selfsign: create a self-signed certificate
	#   - extfile: extensions that must be present for CAs that sign certificates
	#   - days: 825 days (https://support.apple.com/en-us/HT210176)
	openssl ca \
		-batch \
		-in $(CA_ROOT_CSR) \
		-out $(CA_ROOT_CERT) \
		-config root.config \
		-selfsign \
		-extfile ca.ext \
		-days 825

	# create the private key for the intermediate CA
	#   - out: output file
	#   - key bitcount
	openssl genrsa \
		-out $(CA_INT_KEY) \
		2048

	# create the csr for the intermediate CA
	#   - key: private key associated with the csr
	#   - out: output file
	#   - config: contains config for generating the csr such as the distinguished name
	openssl req \
		-new \
		-key $(CA_INT_KEY) \
		-out $(CA_INT_CSR) \
		-config intermediate_req.config

	# create the intermediate CA cert
	#   - batch: don't prompt
	#   - in: csr file
	#   - out:  output certificate file
	#   - config: CA configuration file (note: root is still issuing)
	#   - extfile: extensions that must be present for CAs that sign certificates
	#   - days: 825 days (https://support.apple.com/en-us/HT210176)
	openssl ca \
		-batch \
		-in $(CA_INT_CSR) \
		-out $(CA_INT_CERT) \
		-config root.config \
		-extfile ca.ext \
		-days 825

	# create the private key for the leaf certificate
	#   - out: output file
	#   - key bitcount
	openssl genrsa \
		-out $(LEAF_KEY) \
		2048

	# create the csr for the leaf certificate
	#   - key: private key associated with the csr
	#   - out: output file
	#   - config: contains config for generating the csr such as the distinguished name
	openssl req \
		-new \
		-key $(LEAF_KEY) \
		-out $(LEAF_CSR) \
		-config leaf_req.config

	# create the leaf certificate (note: no ca.ext. this certificate is not a CA)
	#   - batch: don't prompt
	#   - in: csr file
	#   - out:  output certificate file
	#   - config: CA configuration file (note: intermediate is issuing)
	#   - extfile: extensions that must be present for the leaf code signing certificate
	#   - days: 825 days (https://support.apple.com/en-us/HT210176)
	openssl ca \
		-batch \
		-in $(LEAF_CSR) \
		-out $(LEAF_CERT) \
		-config intermediate.config \
		-days 825

	# verify the certificate chain
	#   - x509_strict: strict adherence to rules
	#   - CAfile: root certificate
	#   - untrusted: file with all intermediates
	#   - arg: the leaf certificate to verify
	openssl verify \
		-x509_strict \
		-CAfile $(CA_ROOT_CERT) \
		-untrusted $(CA_INT_CERT) \
		$(LEAF_CERT)

	cat $(LEAF_CERT) > $(CHAIN)
	cat $(CA_INT_CERT) >> $(CHAIN)
	cat $(CA_ROOT_CERT) >> $(CHAIN)

	# at this point we have a valid chain, but can we code sign? lets check the x509 extensions...
	openssl x509 -text -noout -in $(LEAF_CERT) | grep -A1 'X509v3'

	# export cert and private key to .p12 file
	openssl pkcs12 -export \
				   -out $(P12_FILE) \
				   -inkey $(LEAF_KEY) \
				   -in $(CHAIN) \
				   -passout pass:$(P12_PASSWORD)

.PHONY:
trust: $(LEAF_CERT) $(CHAIN) $(P12_FILE) ## create a signed binary
	$(call title,Signing "$(NAME)")
	@if [ ! -f "$(KEYCHAIN_PATH)" ]; then \
  		security create-keychain -p "$(KEYCHAIN_PASSWORD)" "$(KEYCHAIN_NAME)"; \
  	else \
  	  echo "keychain '$(KEYCHAIN_NAME)' already exists"; \
  	fi

	# import the cert into the keychain if it is not already trusted by the system
	# note: set the partition list for this certificate's private key to include "apple-tool:" and "apple:" allows the codesign command to access this keychain item without an interactive user prompt.
	security verify-cert -k $(KEYCHAIN_PATH) -c $(CHAIN) || \
		(\
			security import $(P12_FILE) -P $(P12_PASSWORD) -f pkcs12 -k $(KEYCHAIN_PATH) -T /usr/bin/codesign && \
			security set-key-partition-list -S "apple-tool:,apple:,codesign:" -s -k "$(KEYCHAIN_PASSWORD)" $(KEYCHAIN_PATH) &&\
			security add-trusted-cert -d -r trustRoot -k $(KEYCHAIN_PATH) $(CHAIN) \
		)

	# make certain there are identities that can be used for codesigning
	security find-identity -p codesigning $(KEYCHAIN_PATH) | grep -C 30 $(IDENTITY)

	# add the keychain to the search path (otherwise codesign will not see an identity)
	./add-keychain.sh "${KEYCHAIN_NAME}"
	security list-keychains | grep "${KEYCHAIN_NAME}"


.PHONY: clean
clean:
	rm -f $(BASE)*
	rm -f $(ROOT_STORE)/*
	rm -f $(INT_STORE)/*
	rm -f store/*.pem
	touch $(ROOT_STORE)/index
	touch $(INT_STORE)/index
	echo '00' > $(ROOT_STORE)/serial
	echo '00' > $(INT_STORE)/serial

