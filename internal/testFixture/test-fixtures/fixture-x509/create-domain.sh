#!/usr/bin/env bash
set -ue

DEST=$1
DOMAIN=$2

cat << EOF > ${DEST}
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
subjectAltName = @alt_names
[alt_names]
DNS.1 = ${DOMAIN}

EOF