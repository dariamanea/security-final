#!/bin/bash

# # generates private key that will be used to create CSR
# openssl genrsa -aes256 -out ${1}.key.pem -passout pass:foobar 2048
openssl genrsa -out ${1}.key.pem -passout pass:foobar 2048
chmod 400 ${1}.key.pem


# # Create CSR
#openssl req -config intermediate/openssl.cnf

openssl req  \
      -passin pass:foobar \
      -subj  "/CN=${1}" \
      -batch \
      -key ${1}.key.pem \
      -new -sha256 -out ${1}.csr.pem

# copies the content of the CSR to an file that will be read and send later
# to the server


cp ${1}.csr.pem ../users/${1}/publicKey
cp ${1}.csr.pem csr.txt
