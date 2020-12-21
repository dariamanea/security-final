#!/bin/bash

# script that creates CA 

basedir=$(pwd)
dirca="${basedir}/ca"

mkdir -p $dirca 


cp ca_config.txt $dirca/openssl.cnf
sed -i -e "s#DIR_CA_PLACEHOLDER#$dirca#g" ${dirca}/openssl.cnf

cd $dirca
 mkdir certs crl newcerts private 
 chmod 700 private
 touch index.txt
 echo 1000 >  serial


openssl genrsa -aes256 -out private/ca.key.pem -passout pass:foobar 4096


openssl genrsa -aes256 -out private/ca.key.pem -passout pass:foobar 4096
chmod 400 private/ca.key.pem


openssl req -config openssl.cnf \
      -passin pass:foobar \
      -batch \
      -key private/ca.key.pem \
      -new -x509 -days 7300 -sha256 -extensions v3_ca \
      -out certs/ca.cert.pem 
       

chmod 444 certs/ca.cert.pem
openssl x509 -noout -text -in certs/ca.cert.pem
