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
$ g++ -o server server.cpp -I /usr/local/ssl/include -L /usr/local/ssl/lib -lssl -lcrypto -Wall -std=c++17 -lstdc++fs -lcrypt
```

