# This is the Makefile for server.c
# To compile, simply type "make" at the command line.
# To remove all object code, type "make clean" (this removes
# all ".o" and ".a" files)

# Executable file "cstore"
server: server.o
	#gcc -o server server.o -lcrypt
	g++ -o server server.cpp -I /usr/local/ssl/include -L /usr/local/ssl/lib -lssl -lcrypto -lcrypt -Wall


client: client.cpp
	g++ -o client login.cpp -I /usr/local/ssl/include -L /usr/local/ssl/lib -lssl -lcrypto -lcrypt -Wall

connectTLS.o: connectTLS.o
	gcc -lssl -lcrypto connectTLS.c

clean:
	rm -f *~ *.o *.a

#^^^This space must be a TAB!!.
