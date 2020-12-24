#!/bin/bash

basedir=$(pwd)
dir="${basedir}/ca"
cd $dir


# generates private key that will be used to create CSR
openssl genrsa -aes256 \
      -out intermediate/private/${1}.key.pem -passout pass:foobar 2048

chmod 400 intermediate/private/${1}.key.pem


# Create CSR
openssl req -config intermediate/openssl.cnf \
      -passin pass:foobar \
      -batch \
      -key intermediate/private/${1}.key.pem \
      -new -sha256 -out intermediate/csr/${1}.csr.pem

# copies the content of the CSR to an file that will be read and send later
# to the server

cp intermediate/csr/${1}.csr.pem ../Client/users/${1}/publicKey
cp intermediate/csr/${1}.csr.pem ../csr.txt
