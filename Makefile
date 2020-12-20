# This is the Makefile for cstore.c
# To compile, simply type "make" at the command line.
# To remove all object code, type "make clean" (this removes
# all ".o" and ".a" files)

# Executable file "cstore" 
server: server.o
	gcc -o server server.o

server.o: server.c
	gcc -c server.c

connectTLS.o: connectTLS.o
	gcc -lssl -lcrypto connectTLS.c

clean:
	rm -f *~ *.o *.a

# test: 
	# ./build-cstore.sh
#^^^This space must be a TAB!!.
