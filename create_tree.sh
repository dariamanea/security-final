#!/bin/bash

chmod +x *
# ./create-server-structure.sh
# ./create-client-structure.sh
make server 
make getcert

mv server Server/bin
mv ca_config.txt Server/bin
mv intermediate_config.txt Server/bin
mv interm.sh Server/bin
mv generate_client_cert.sh Server/bin
mv ca_interm.sh Server/bin
mv ca.sh Server/bin
mv users.txt Server/bin

mv getcert Client/bin
mv generate_csr.sh Client/bin