# security-final
Final project for Security I

December 23, 2020

Daria Manea, Qiran (Tony) Li, Jacob Jordan

NOTES
```
The script creates a shell user and group called "server" with password "security"
There were difficulties with properly implementing some of the certificate and encryption functions. 
In addition, we were not able to achieve the shedding and deshedding safety features as well as the containers we wanted.
```

0. DEPENDANCIES 
```
sudo apt-get update
sudo apt-get install build-essential
sudo apt-get install icdiff
sudo apt-get install libssl-dev
```

I. SOURCE TREE CONTENTS
```
1. install-priv.sh
2. getcert.cpp
3. changepw.cpp
4. sendmsg.cpp
5. recvmsg.cpp
6. server.cpp
7. users.txt
8. Makefile
9. create-server-structure.sh
10. create-client-structure.sh
```


II. HOW TO EXECUTE
```
1. Move files to an empty directory
2. Execute the following:

sudo bash install-priv.sh

3. Move to Server/bin and execute the following:

./server

4. Move to Client/bin and execute the four programs as a user:

./getcert, ./changepw, ./sendmsg, ./recvmsg

Note:
user logs in to sendmsg and recvmsg with username and password
A message should be in a file in the Client/bin and user gives filename when prompted
recvmsg prints message to stdout
sendmsg can only accept one recipient at a time
```

IV. ARCHITECTURE
```
The server is based on the example given here: https://quuxplusone.github.io/blog/2020/01/24/openssl-part-1/ to create HTTPS server and clients with TLS handshake. The client programs edit the HTTPS message and the server reads the top line of the body to determine what is requested. The server file is also set to user and group security, with g+s bit enabled as well.

>Home Directory
  >Server
    >bin
      >server.cpp
      >users.txt
    >users
      >example user
        >certificate
        >mailbox
    >serverCert
  >Client
    >bin
      >getcert.cpp
      >changepw.cpp
      >sendmsg.cpp
      >recvmsg.cpp
    >users
      >example user
        >certificate
        >mailbox
        >hashedPassword
    >certAuth
```


V. TESTING
```
Functionality testing was conducted to ensure a user can send and receive messages. There was also testing to make sure that a user password could not be read by others.
```

# Below is not part of submission

Run the following commands in the same folder as server:

```
$ openssl ecparam -genkey -name prime256v1 -noout -out server-private-key.pem

$ openssl ec -in server-private-key.pem -pubout -out server-public-key.pem

$ openssl req -new -x509 -sha256 -key server-private-key.pem -subj "/CN=duckduckgo.com" -out server-certificate.pem
```


To compile server.cpp use the following:
```
$ make 
$ ./server
```
or 

```
$ g++ -o server server.cpp -I /usr/local/ssl/include -L /usr/local/ssl/lib -lssl -lcrypto -lycrypt -Wall
```

