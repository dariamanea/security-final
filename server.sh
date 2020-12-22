#!/bin/bash

basedir=$(pwd)
dir="${basedir}/ca"

cd $dir

openssl genrsa -aes256 \
      -out intermediate/private/www.example.com.key.pem -passout pass:foobar 2048

chmod 400 intermediate/private/www.example.com.key.pem


# Create CSR
openssl req -config intermediate/openssl.cnf \
      -passin pass:foobar \
      -batch \
      -key intermediate/private/www.example.com.key.pem \
      -new -sha256 -out intermediate/csr/www.example.com.csr.pem

# create certificate
openssl ca -config intermediate/openssl.cnf \
      -subj '/C=US/ST=New York/O=Daria Ltd/OU=Daria Ltd Web Services/CN=www.example.com' \
      -passin pass:foobar \
      -batch \
      -extensions server_cert -days 375 -notext -md sha256 \
      -in intermediate/csr/www.example.com.csr.pem \
      -out intermediate/certs/www.example.com.cert.pem

chmod 444 intermediate/certs/www.example.com.cert.pem

# verufy certificate
openssl x509 -noout -text \
      -in intermediate/certs/www.example.com.cert.pem

openssl verify -CAfile intermediate/certs/ca-chain.cert.pem \
      intermediate/certs/www.example.com.cert.pem

      