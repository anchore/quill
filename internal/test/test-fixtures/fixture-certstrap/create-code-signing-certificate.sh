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
IDENTITY=$4

# note: this is derived from the Makefile
NAME=certstrap-leaf
FILE_PREFIX=$DIR/$NAME

## OpenSSL material

KEY_PASSWORD="topsykretts"

# note: this is defined by the Makefile
KEY_FILE=$FILE_PREFIX.key
# note: this is defined by the Makefile
CERT_FILE=$FILE_PREFIX.crt
# note: this is defined by the Makefile
CSR_FILE=$FILE_PREFIX.csr
EXT_FILE=$FILE_PREFIX-ext.cnf

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

  # note: Extensions in certificates are not transferred to certificate requests and vice versa. This means that
  # just because the CSR has x509 v3 extensions doesn't mean that you'll see these extensions in the cert output.
  # To prove this do:
  # 	openssl x509 -text -noout -in server.crt | grep -A10 "X509v3 extensions:"
  # ... and you will see no output (if -extensions is not used). (see https://www.openssl.org/docs/man1.1.0/man1/x509.html#BUGS)
  # To get the extensions, use "-extensions codesign_reqext" when creating the cert. The codesign_reqext value matches
  # the section name in the ext file used in CSR / cert creation (-extfile and -config).
  openssl x509 \
            -req \
            -days 100000 \
            -in "$CSR_FILE" \
            -out "$CERT_FILE" \
            -extfile "$EXT_FILE" \
            -CA "${CA_CERT_PATH}" \
            -CAkey "${CA_CERT_KEY_PATH}" \
            -CAcreateserial \
            -passin "pass:$KEY_PASSWORD" \
            -extensions $EXT_SECTION

  # verify the certificate: we should see our extensions
  openssl x509 -text -noout -in "$CERT_FILE" | grep -A1 'X509v3' || exit_with_error "could not find x509 extensions in certificate"
  openssl x509 -text -noout -in "$CERT_FILE" | grep -A1 'X509v3' | grep 'Code Signing' || exit_with_error "could not find Code Signing x509 extension in certificate"
