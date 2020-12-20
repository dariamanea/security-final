/*
Program:
launchServer: creates socket for listening using TLS

checkPassword: given hashed password and username, checks if it matches the stored hashed password for that user.

recv: server should be able to receive the public key from the user and then store it if it’s a new one. Creates a certificate for user, stores on server and returns it

changePassword: given hashed password and username, deletes stored hashed password for user and adds new one
sendRcptCert: send should be able to check if the users’ certificate is valid or correct and send the request document (recipient certificate) back

sendMsg: send should be able to check if the users’ certificate is valid or correct and send the request document (message) back

storeMsg: store message in respective recipient mailbox on server side

check: check if the request it’s valid (ex: if there are any messages pending for that user, we should reject)
*/

#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <stddef.h>

#define MAXPW 32

// #define DEBUG 1

#ifdef DEBUG
#define PRINTDBG printf
#else
#define PRINTDBG(...)
#endif


int checkPassword (char *username, char *hashed_password){
// given hashed password and username, checks if it
// matches the stored hashed password for that user.

}

int changePassword (){
    // given hashed password and username, 
    // deletes stored hashed password for user and adds new one
 
}


int main (int argc, char **argv)
{

}