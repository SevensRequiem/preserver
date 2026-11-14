#!/bin/bash
# Regenerates the TLS test fixtures: a P-256 CA and a leaf for 127.0.0.1/localhost, valid 100 years.
set -euo pipefail
cd "$(dirname "$0")"
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
openssl ecparam -name prime256v1 -genkey -noout -out "$t/ca.key"
openssl req -x509 -new -key "$t/ca.key" -subj /CN=preserver-test-ca -days 36500 \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign \
    -outform DER -out ca.der
openssl ecparam -name prime256v1 -genkey -noout -out "$t/leaf.key"
openssl pkcs8 -topk8 -nocrypt -in "$t/leaf.key" -outform DER -out leaf.key.der
openssl req -new -key "$t/leaf.key" -subj /CN=127.0.0.1 -out "$t/leaf.csr"
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1,DNS:localhost\n' > "$t/ext"
openssl x509 -req -in "$t/leaf.csr" -CA ca.der -CAform DER -CAkey "$t/ca.key" -CAserial "$t/ca.srl" -CAcreateserial \
    -days 36500 -extfile "$t/ext" -outform DER -out leaf.der
