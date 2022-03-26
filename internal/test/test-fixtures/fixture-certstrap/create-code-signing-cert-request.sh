#!/usr/bin/env bash
set -eu


## terminal goodies
RED='\033[0;31m'
BOLD=$(tput -T linux bold)
RESET='\033[0m'

function error() {
  echo -e "${RED}${BOLD}error: $@${RESET}"
}

function exit_with_error() {
  error $@
  exit 1
}

function exit_with_message() {
  success $@
  exit 0
}

set -x

DIR=$1
CA_CERT_PATH=$2
CA_CERT_KEY_PATH=$3
# note: this is derived from the Makefile
NAME=certstrap-leaf

FILE_PREFIX=$DIR/$NAME
IDENTITY=${NAME}-code-signing-id

## OpenSSL material

KEY_PASSWORD="topsykretts"
P12_PASSWORD=${KEY_PASSWORD}

# note: this is defined by the Makefile
KEY_FILE=$FILE_PREFIX.key
# note: this is defined by the Makefile
CSR_FILE=$FILE_PREFIX.csr
# note: this is defined by the Makefile
CERT_FILE=$FILE_PREFIX.crt
EXT_FILE=$FILE_PREFIX-ext.cnf
P12_FILE=$FILE_PREFIX.p12

EXT_SECTION=codesign_reqext


# configure the openssl extensions
cat << EOF > "$EXT_FILE"
  [ req ]
  default_bits          = 2048                  # RSA key size
  encrypt_key           = yes                   # Protect private key
  default_md            = sha256                # MD to use
  utf8                  = yes                   # Input is UTF-8
  string_mask           = utf8only              # Emit UTF-8 strings
  prompt                = yes                   # Prompt for DN
  distinguished_name    = codesign_dn           # DN template
  req_extensions        = $EXT_SECTION          # Desired extensions
  [ codesign_dn ]
  commonName            = $IDENTITY
  commonName_max        = 64
  [ $EXT_SECTION ]
  keyUsage              = critical,digitalSignature
  extendedKeyUsage      = critical,codeSigning
  subjectKeyIdentifier  = hash
EOF

# check what the CA cert can be used for (no automatic verification, just for debugging)
openssl x509 -purpose -in "$CA_CERT_PATH" -inform PEM

# create the private key
openssl genrsa \
          -des3 \
          -out "$KEY_FILE" \
          -passout "pass:$KEY_PASSWORD" \
         2048

# create the csr
openssl req \
          -new \
          -key "$KEY_FILE" \
          -out "$CSR_FILE" \
          -passin "pass:$KEY_PASSWORD" \
          -config "$EXT_FILE" \
          -subj "/CN=$IDENTITY"

# verify the csr: we should see X509 v3 extensions for codesigning in the CSR
openssl req -in "$CSR_FILE" -noout -text | grep -A1 "X509v3" || exit_with_error "could not find x509 extensions in CSR"
