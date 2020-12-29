#!/bin/bash

cert_path=${1}

ret1=$(openssl rsa  -noout -modulus -in ${cert_path}/key.pem 2>/dev/null              | openssl md5)
ret2=$(openssl x509 -noout -modulus -in ${cert_path}/certificate.cert.pem 2>/dev/null | openssl md5)

if [ "$ret1" == "$ret2" ]; then 
    exit 0;
else 
    exit 1;
fi    