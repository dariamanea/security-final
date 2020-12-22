#!/bin/bash

basedir=$(pwd)
dir="${basedir}/ca"
cd $dir

openssl genrsa -aes256 \
      -out intermediate/private/${1}.key.pem -passout pass:foobar 2048

chmod 400 intermediate/private/${1}.key.pem


# Create CSR
openssl req -config intermediate/openssl.cnf \
      -passin pass:foobar \
      -batch \
      -key intermediate/private/${1}.key.pem \
      -new -sha256 -out intermediate/csr/${1}.csr.pem

# Generate Client Certificate
openssl ca -config intermediate/openssl.cnf \
      -subj '/C=US/ST=New York/O=Daria Ltd/OU=Daria Ltd Web Services/CN=${1}' \
      -batch \
      -passin pass:foobar \
      -extensions usr_cert  -days 375 -notext -md sha256 \
      -in intermediate/csr/${1}.csr.pem \
      -out intermediate/certs/${1}.cert.pem

chmod 444 intermediate/certs/${1}.cert.pem

# verify certificate
openssl x509 -noout -text \
      -in intermediate/certs/${1}.cert.pem

openssl verify -CAfile intermediate/certs/ca-chain.cert.pem \
      intermediate/certs/${1}.cert.pem

# move certificate to where it's supposed to be 
 sudo cp intermediate/certs/${1}.cert.pem ../Server/users/${1}/certificates/${1}.certificate.cert.pem

      