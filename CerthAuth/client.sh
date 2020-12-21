#!/bin/bash

basedir=$(pwd)
dir="${basedir}/ca"
cd $dir

openssl genrsa -aes256 \
      -out intermediate/private/dem2184@columbia.edu.key.pem -passout pass:foobar 2048

chmod 400 intermediate/private/dem2184@columbia.edu.key.pem


# Create CSR
openssl req -config intermediate/openssl.cnf \
      -passin pass:foobar \
      -batch \
      -key intermediate/private/dem2184@columbia.edu.key.pem \
      -new -sha256 -out intermediate/csr/dem2184@columbia.edu.csr.pem

# Generate Client Certificate
openssl ca -config intermediate/openssl.cnf \
      -subj '/C=US/ST=New York/O=Daria Ltd/OU=Daria Ltd Web Services/CN=dem2184@columbia.edu' \
      -batch \
      -passin pass:foobar \
      -extensions usr_cert -days 375 -notext -md sha256 \
      -in intermediate/csr/dem2184@columbia.edu.csr.pem \
      -out intermediate/certs/dem2184@columbia.edu.cert.pem

chmod 444 intermediate/certs/dem2184@columbia.edu.cert.pem

# verify certificate
openssl x509 -noout -text \
      -in intermediate/certs/dem2184@columbia.edu.cert.pem

openssl verify -CAfile intermediate/certs/ca-chain.cert.pem \
      intermediate/certs/dem2184@columbia.edu.cert.pem

      