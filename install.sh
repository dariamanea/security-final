#!/bin/bash

chmod +x *
 ./create-server-structure.sh
 ./create-client-structure.sh

cd Server/bin
chmod +x *
make server
./ca_interm.sh


cd ../../
cd Client/bin
make getcert
make sendmsg
make recmsg
chmod +x *

