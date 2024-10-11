SHELL = bash
ROOT=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
CACHE_DIR=$(ROOT)/../assets
NAME=x509

BOLD := $(shell tput -T linux bold)
CYAN := $(shell tput -T linux setaf 6)
PURPLE := $(shell tput -T linux setaf 5)
TITLE := $(BOLD)$(PURPLE)
RESET := $(shell tput -T linux sgr0)

DOMAIN_FILE=$(BASE)-domain.ext

IDENTITY=$(shell hostname)
CN=$(IDENTITY).local
PASSWORD=5w0rdf15h

BASE=$(CACHE_DIR)/$(NAME)
KEY_FILE=$(BASE)-key.pem
CSR_FILE=$(BASE)-csr.pem
CERT_FILE=$(BASE)-cert.pem

CA_IDENTITY=$(shell hostname)
CA_CN=$(IDENTITY).local

CA_KEY_FILE=$(BASE)-ca-key.pem
CA_CSR_FILE=$(BASE)-ca-csr.pem
CA_CERT_FILE=$(BASE)-ca-cert.pem

define title
    @printf '$(TITLE)$(1)$(RESET)\n'
endef


.PHONY: all
all: signing-material


.PHONY: signing-material
signing-material: $(CA_KEY_FILE) $(CA_CERT_FILE) $(KEY_FILE) $(CERT_FILE) ## create private key and self-signed certificate


$(KEY_FILE): ## create a private key
	$(call title,Creating (encrypted) private key)
	openssl genrsa \
		-des3 \
		-out $(KEY_FILE) \
		-passout pass:$(PASSWORD) 2048


$(CERT_FILE): $(KEY_FILE) $(CA_KEY_FILE) $(CA_CERT_FILE) $(DOMAIN_FILE) ## create a self-signed certificate
	$(call title,Creating certificate)
	# create CSR
	openssl req \
		-new \
		-key $(KEY_FILE) \
		-out $(CSR_FILE) \
		-config /etc/ssl/openssl.cnf \
		-passin pass:$(PASSWORD) \
		-subj "/C=US/ST=QuillTacular/L=NiQuill/O=Quillamanjaro/CN=$(CN)"

	# create the certificate
	openssl x509 \
		-req \
		-days 100000 \
		-in $(CSR_FILE) \
		-signkey $(KEY_FILE) \
		-out $(CERT_FILE) \
		-CAkey $(CA_KEY_FILE) \
		-extfile $(DOMAIN_FILE) \
		-CAcreateserial \
		-passin pass:$(PASSWORD)

	rm $(CSR_FILE)


$(CA_KEY_FILE): ## create a private key
	$(call title,Creating CA private key)
	openssl genrsa \
		-out $(CA_KEY_FILE) \
		-passout pass:$(CA_PASSWORD) 2048


$(CA_CERT_FILE): $(CA_KEY_FILE) $(DOMAIN_FILE) ## create a self-signed certificate (for a root CA)
	$(call title,Creating CA certificate)
	# create CSR
	openssl req \
		-new \
		-key $(CA_KEY_FILE) \
		-out $(CA_CSR_FILE) \
		-config /etc/ssl/openssl.cnf \
		-subj "/C=US/ST=ca-QuillTacular/L=ca-NiQuill/O=ca-Quillamanjaro/CN=$(CA_CN)"

	# create the certificate
	openssl x509 \
		-req \
		-days 100000 \
		-in $(CA_CSR_FILE) \
		-signkey $(CA_KEY_FILE) \
		-out $(CA_CERT_FILE) \
		-extfile $(DOMAIN_FILE) \
		-CAcreateserial

	rm $(CA_CSR_FILE)


$(DOMAIN_FILE):
	$(call title,Creating domain extension file)
	./create-domain.sh $(DOMAIN_FILE) $(CA_CN)

	@cat $(DOMAIN_FILE)


.PHONY: clean
clean:
	rm -f $(BASE)*