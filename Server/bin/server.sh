#!/bin/bash

basedir=$(pwd)
dir="${basedir}/ca"

cd $dir

openssl genrsa -aes256 \
      -out intermediate/private/server.key.pem -passout pass:foobar 2048

chmod 400 intermediate/private/server.key.pem


# Create CSR
openssl req -config intermediate/openssl.cnf \
      -passin pass:foobar \
      -batch \
      -key intermediate/private/server.key.pem \
      -new -sha256 -out intermediate/csr/server.csr.pem

create certificate
openssl ca -config intermediate/openssl.cnf \
      -subj '/C=US/ST=New York/O=Daria Ltd/OU=Daria Ltd Web Services/CN=duckduckgo.com' \
      -passin pass:foobar \
      -batch \
      -extensions server_cert -days 375 -notext -md sha256 \
      -in intermediate/csr/server.csr.pem \
      -out intermediate/certs/server.cert.pem

chmod 444 intermediate/certs/server.cert.pem

# openssl req -new -x509 -sha256 -in intermediate/csr/server.csr.pem  -subj "/CN=duckduckgo.com" -passin pass:foobar -out intermediate/certs/server.cert.pem

# verify certificate
openssl x509 -noout -text \
      -in intermediate/certs/server.cert.pem

openssl verify -CAfile intermediate/certs/ca-chain.cert.pem \
      intermediate/certs/server.cert.pem