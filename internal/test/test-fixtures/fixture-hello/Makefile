ROOT=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
CACHE_DIR=$(ROOT)/../assets
NAME=hello

BOLD := $(shell tput -T linux bold)
CYAN := $(shell tput -T linux setaf 6)
PURPLE := $(shell tput -T linux setaf 5)
TITLE := $(BOLD)$(PURPLE)
RESET := $(shell tput -T linux sgr0)

KEYCHAIN_NAME=quill-test-$(NAME)
# note, you could do this with /Library/Keychains/System.keychain , but is not recommended
KEYCHAIN_PATH="${HOME}/Library/Keychains/$(KEYCHAIN_NAME)-db"
KEYCHAIN_PASSWORD=5w0rdf15h
EXT_FILE=$(CACHE_DIR)/$(NAME)-config.ext
P12_PASSWORD=TopsyKretts

IDENTITY=quill-test-hello
CN=$(IDENTITY)

BIN=$(CACHE_DIR)/$(NAME)
ADHOC_SIGNED_BIN=$(BIN)_adhoc_signed
SIGNED_BIN=$(BIN)_signed

KEY_FILE=$(BIN)-key.pem
CSR_FILE=$(BIN)-csr.pem
CERT_FILE=$(BIN)-cert.pem
# combination of the cert and private key (pkcs12)
P12_FILE=$(BIN).p12

define title
    @printf '$(TITLE)$(1)$(RESET)\n'
endef


.PHONY: all
all: check signing-material build


.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(BOLD)$(CYAN)%-25s$(RESET)%s\n", $$1, $$2}'


.PHONY: check
check:
	@if [ $(shell uname) != "Darwin" ]; then echo "must run this on a mac" && exit 1; fi;
	@if [ $(shell uname -m) != "x86_64" ]; then echo "must run this on x86_64" && exit 1; fi;


# $(SIGNED_BIN)
.PHONY: build
build: $(BIN) $(ADHOC_SIGNED_BIN) $(SIGNED_BIN) ## build and sign target binaries


$(BIN): ## create an unsigned binary
	$(call title,Building "$(NAME)")
	cd $(ROOT) && \
		gcc -Wall $(NAME).c -o $(BIN)


$(ADHOC_SIGNED_BIN): $(BIN) ## create a "adhoc" signed binary
	$(call title,Ad-hoc signing of "$(NAME)")
	cp $(BIN) $(ADHOC_SIGNED_BIN).tmp

	codesign -f --options runtime --verbose=4 --timestamp -s - $(ADHOC_SIGNED_BIN).tmp
	mv $(ADHOC_SIGNED_BIN).tmp $(ADHOC_SIGNED_BIN)

	# signing information
	codesign -d --verbose=4 $(ADHOC_SIGNED_BIN)
	codesign -verify --verbose=4 $(ADHOC_SIGNED_BIN)


$(SIGNED_BIN): $(P12_FILE) $(BIN) ## create a signed binary
	$(call title,Signing "$(NAME)")
	@if [ ! -f "$(KEYCHAIN_PATH)" ]; then \
  		security create-keychain -p "$(KEYCHAIN_PASSWORD)" "$(KEYCHAIN_NAME)"; \
  	else \
  	  echo "keychain '$(KEYCHAIN_NAME)' already exists"; \
  	fi

	# import the cert into the keychain if it is not already trusted by the system
	# note: set the partition list for this certificate's private key to include "apple-tool:" and "apple:" allows the codesign command to access this keychain item without an interactive user prompt.
	security verify-cert -k $(KEYCHAIN_PATH) -c $(CERT_FILE) || \
		(\
			security import $(P12_FILE) -P $(P12_PASSWORD) -f pkcs12 -k $(KEYCHAIN_PATH) -T /usr/bin/codesign && \
			security set-key-partition-list -S "apple-tool:,apple:,codesign:" -s -k "$(KEYCHAIN_PASSWORD)" $(KEYCHAIN_PATH) &&\
			security add-trusted-cert -d -r trustRoot -k $(KEYCHAIN_PATH) $(CERT_FILE) \
		)

	# make certain there are identities that can be used for codesigning
	security find-identity -p codesigning $(KEYCHAIN_PATH) | grep -C 30 $(IDENTITY)

	# add the keychain to the search path (otherwise codesign will not see an identity)
	./add-keychain.sh "${KEYCHAIN_NAME}"
	security list-keychains | grep "${KEYCHAIN_NAME}"

	# sign the binary
	cp $(BIN) $(SIGNED_BIN).tmp

	codesign -s $(IDENTITY) --keychain $(KEYCHAIN_PATH) $(SIGNED_BIN).tmp

	mv $(SIGNED_BIN).tmp $(SIGNED_BIN)

	# signing information
	codesign -d --verbose=4 --keychain $(KEYCHAIN_PATH) $(SIGNED_BIN)
	codesign -verify --keychain $(KEYCHAIN_PATH) --verbose=4 $(SIGNED_BIN)


.PHONY: signing-material
signing-material: $(KEY_FILE) $(CERT_FILE)  ## create private key and self-signed certificate


$(EXT_FILE):
	$(call title,Creating cert extension file)
	./create-extension.sh $(EXT_FILE) $(CN)

	@cat $(EXT_FILE)

$(KEY_FILE): ## create a private key
	$(call title,Creating private key)
	openssl genrsa -out $(KEY_FILE) 2048


$(CERT_FILE) $(P12_FILE): $(EXT_FILE) $(KEY_FILE) ## create a self-signed certificate
	$(call title,Creating certificate)
	# create CSR
	openssl req -new -key $(KEY_FILE) \
					 -out $(CSR_FILE) \
					 -config $(EXT_FILE) \
					 -subj "/C=US/ST=QuillTacular/L=NiQuill/O=Quillamanjaro/CN=$(CN)"

	# we should see X509 v3 extensions for codesigning in the CSR
	openssl req -in $(CSR_FILE) -noout -text | grep -A1 "X509v3"

	# create the certificate
	# note: Extensions in certificates are not transferred to certificate requests and vice versa. This means that
	# just because the CSR has x509 v3 extensions doesn't mean that you'll see these extensions in the cert output.
	# To prove this do:
	# 	openssl x509 -text -noout -in server.crt | grep -A10 "X509v3 extensions:"
	# ... and you will see no output (if -extenion is not used). (see https://www.openssl.org/docs/man1.1.0/man1/x509.html#BUGS)
	# To get the extensions, use "-extensions codesign_reqext" when creating the cert. The codesign_reqext value matches
	# the section name in the ext file used in CSR / cert creation (-extfile and -config).
	openssl x509 -req \
				 -days 10000 \
				 -in $(CSR_FILE) \
				 -signkey $(KEY_FILE) \
				 -out $(CERT_FILE) \
				 -extfile $(EXT_FILE) \
				 -extensions codesign_reqext

	# we should see our extensions
	openssl x509 -text -noout -in $(CERT_FILE) | grep -A1 "X509v3"

	# export cert and private key to .p12 file
	openssl pkcs12 -export \
				   -out $(P12_FILE) \
				   -inkey $(KEY_FILE) \
				   -in $(CERT_FILE) \
				   -passout pass:$(P12_PASSWORD)

	rm $(CSR_FILE)


.PHONY: clean
clean:
	rm -f $(BIN)*
	rm -f $(EXT_FILE)
	security delete-keychain $(KEYCHAIN_NAME) || true
	rm -f $(KEYCHAIN_PATH)