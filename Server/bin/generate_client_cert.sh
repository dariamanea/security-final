#!/bin/bash

basedir=$(pwd)
dir="${basedir}/ca"
cd $dir


# # Generate Client Certificate

openssl x509 -req \
    -in ../csr.txt \
    -CA     intermediate/certs/intermediate.cert.pem  \
    -CAkey  intermediate/private/intermediate.key.pem \
    -extensions usr_cert \
    -passin pass:foobar \
    -out intermediate/certs/${1}.cert.pem   \
    -set_serial 01 \
    -days 365


#chmod 444 intermediate/certs/${1}.cert.pem

 cp intermediate/certs/${1}.cert.pem    ../../users/${1}/certificates/
 mv intermediate/certs/${1}.cert.pem ../cert_temp.txt

