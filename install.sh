#!/bin/bash

 # Making group 
 
sudo addgroup server

sudo useradd -g server -m server -p security


##### root directory

 
chmod +x *
 ./create-server-structure.sh
 ./create-client-structure.sh


###### changing to server

cd Server/bin


# create private key 
# openssl ecparam -genkey -name prime256v1 -noout -out server-private-key.pem

sudo chown server: server-private-key.pem
sudo chmod g+rw server-private-key.pem

# create public key 
# openssl ec -in server-private-key.pem -pubout -out server-public-key.pem

sudo chown server: server-public-key.pem
sudo chmod g+rw server-public-key.pem

# create certificate for server
# openssl req -new -x509 -sha256 -key server-private-key.pem -subj "/CN=duckduckgo.com" -out server-certificate.pem

sudo chown server: server-certificate.pem
sudo chmod g+rw,o+rw server-certificate.pem


sudo chown server: users.txt

chmod +x *
make server

sudo chown server: server
sudo chmod g+s server

./ca_interm.sh

###### changing to client

cd ../../
cd Client/bin
make getcert
make sendmsg
make recvmsg
chmod +x *

#############

