ROOT=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
CACHE_DIR=$(ROOT)/../cache
NAME=hello

BOLD := $(shell tput -T linux bold)
CYAN := $(shell tput -T linux setaf 6)
PURPLE := $(shell tput -T linux setaf 5)
TITLE := $(BOLD)$(PURPLE)
RESET := $(shell tput -T linux sgr0)

IDENTITY=$(hostname)
CN=$(IDENTITY).local

BIN=$(CACHE_DIR)/$(NAME)
ADHOC_SIGNED_BIN=$(BIN)_adhoc_signed
SIGNED_BIN=$(BIN)_signed

KEY_FILE=$(BIN)-key.pem
CSR_FILE=$(BIN)-csr.pem
CERT_FILE=$(BIN)-cert.pem

define title
    @printf '$(TITLE)$(1)$(RESET)\n'
endef


.PHONY: all
all: check-mac signing-material build


.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(BOLD)$(CYAN)%-25s$(RESET)%s\n", $$1, $$2}'


.PHONY: check-mac
check-mac:
	@if [ $(shell uname) != "Darwin" ]; then echo "must run this on a mac" && exit 1; fi;


# $(SIGNED_BIN)
.PHONY: build
build: $(BIN) $(ADHOC_SIGNED_BIN) ## build and sign target binaries


$(BIN): ## create an unsigned binary
	$(call title,Building "$(NAME)")
	cd $(ROOT) && \
		gcc -Wall $(NAME).c -o $(BIN)


$(ADHOC_SIGNED_BIN): $(BIN) ## create a "adhoc" signed binary
	$(call title,Ad-hoc signing of "$(NAME)")
	cp $(BIN) $(ADHOC_SIGNED_BIN).tmp

	codesign -fs - $(ADHOC_SIGNED_BIN).tmp
	mv $(ADHOC_SIGNED_BIN).tmp $(ADHOC_SIGNED_BIN)

	# signing information
	codesign -dvv $(ADHOC_SIGNED_BIN)


#$(SIGNED_BIN): $(KEY_FILE) $(CERT_FILE) $(BIN) ## create a "adhoc" signed binary
#	$(call title,Signing "$(NAME)")
#	cp $(BIN) $(SIGNED_BIN).tmp
#
#	# TODO: replace with signing step
#	# codesign -fs - $(SIGNED_BIN).tmp
#	mv $(SIGNED_BIN).tmp $(SIGNED_BIN)
#
#	# signing information
#	codesign -dvv $(SIGNED_BIN)


.PHONY: signing-material
signing-material: $(KEY_FILE) $(CERT_FILE) ## create private key and self-signed certificate


$(KEY_FILE): ## create a private key
	$(call title,Creating private key)
	openssl genrsa -out $(KEY_FILE) 2048


$(CERT_FILE): $(KEY_FILE) ## create a self-signed certificate
	$(call title,Creating certificate)
	# create CSR
	openssl req -new -key $(KEY_FILE) \
					 -out $(CSR_FILE) \
					 -config /etc/ssl/openssl.cnf \
					 -subj "/C=US/ST=Test/L=Test/O=Test/CN=$(CN)"

	# create the certificate
	openssl x509 -req -days 10 \
				 -in $(CSR_FILE) \
				 -signkey $(KEY_FILE) \
				 -out $(CERT_FILE) \
				 -extfile /etc/ssl/openssl.cnf

	rm $(CSR_FILE)


.PHONY: clean
clean:
	rm -f $(BIN)*