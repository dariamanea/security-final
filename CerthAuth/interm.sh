#!/bin/bash

basedir=$(pwd)
dirint="$basedir/ca/intermediate"
dirca="$basedir/ca"

mkdir -p $dirint

cp intermediate_config.txt ${dirint}/openssl.cnf
sed -i -e "s#DIR_INTERMEDIATE_PLACEHOLDER#${dirint}#g" ${dirint}/openssl.cnf


cd $dirint
mkdir certs crl csr newcerts private
chmod 700 private
touch index.txt
echo 1000 >  serial
echo 1000 > $dirint/crlnumber

openssl genrsa -aes256 -out ${dirint}/private/ca.key.pem -passout pass:foobar 4096

cd $dirca
openssl genrsa -aes256 \
      -out ${dirint}/private/intermediate.key.pem -passout pass:foobar 4096

chmod 400 ${dirint}/private/intermediate.key.pem

openssl req -config  ${dirint}/openssl.cnf \
      -passin pass:foobar \
      -batch -new -sha256 \
      -key ${dirint}/private/intermediate.key.pem \
      -out ${dirint}/csr/intermediate.csr.pem


#echo "dirint: $dirint"
#cd $dirca
# create intermediate certificate
openssl ca -config $dirca/openssl.cnf \
      -passin pass:foobar \
      -batch \
      -extensions v3_intermediate_ca \
      -days 3650 -notext -md sha256 \
      -in ${dirint}/csr/intermediate.csr.pem \
      -out ${dirint}/certs/intermediate.cert.pem


chmod 444 ${dirint}/certs/intermediate.cert.pem

openssl x509 -noout -text \
      -in ${dirint}/certs/intermediate.cert.pem

echo "Verifying intermediate certificate: "
openssl verify -CAfile certs/ca.cert.pem \
      ${dirint}/certs/intermediate.cert.pem

# Create chain certificate
cat ${dirint}/certs/intermediate.cert.pem \
      certs/ca.cert.pem > ${dirint}/certs/ca-chain.cert.pem

chmod 444 ${dirint}/certs/ca-chain.cert.pem

