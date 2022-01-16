#!/usr/bin/env bash
set -ue

DEST=$1
DN=$2

cat << EOF > ${DEST}
[ req ]
default_bits          = 2048                            # RSA key size
encrypt_key           = yes                               # Protect private key
default_md            = sha256                        # MD to use
utf8                  = yes                              # Input is UTF-8
string_mask           = utf8only                       # Emit UTF-8 strings
prompt                = yes                              # Prompt for DN
distinguished_name    = codesign_dn               # DN template
req_extensions        = codesign_reqext          # Desired extensions


[ codesign_dn ]
commonName            = $DN
commonName_max        = 64

[ codesign_reqext ]
keyUsage              = critical,digitalSignature
extendedKeyUsage      = critical,codeSigning
subjectKeyIdentifier  = hash

EOF