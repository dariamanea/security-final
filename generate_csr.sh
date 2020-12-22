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

cp intermediate/csr/${1}.csr.pem ../csr.txt
