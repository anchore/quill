SHELL = bash
ROOT=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
CACHE_DIR=$(ROOT)/../assets
NAME=chain-with-ou
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
IDENTITY="quill-test-leaf-with-ou"
KEYCHAIN_NAME=quill-test-$(NAME)
KEYCHAIN_PATH="${HOME}/Library/Keychains/$(KEYCHAIN_NAME)-db"
KEYCHAIN_PASSWORD=123456

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

	# show the subject including OU field
	@echo "Leaf certificate subject:"
	openssl x509 -noout -subject -in $(LEAF_CERT)

	# export cert and private key to .p12 file
	openssl pkcs12 -export \
				   -out $(P12_FILE) \
				   -inkey $(LEAF_KEY) \
				   -in $(CHAIN) \
				   -passout pass:$(P12_PASSWORD)

.PHONY:
clean:
	rm -f $(BASE)*
	rm -f $(ROOT_STORE)/*
	rm -f $(INT_STORE)/*
	rm -f store/*.pem
	touch $(ROOT_STORE)/index
	touch $(INT_STORE)/index
	echo '00' > $(ROOT_STORE)/serial
	echo '00' > $(INT_STORE)/serial
