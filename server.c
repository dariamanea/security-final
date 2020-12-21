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
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>


// #define DEBUG 1

#ifdef DEBUG
#define PRINTDBG printf
#else
#define PRINTDBG(...)
#endif

/*
This function searches for the given username in the Server/users folder
*/
int validateUsername(char *dirname, char *username) {

    // return 0 if username found
    // return 1 if username not found
	// return 2 if users folder can't be opened

	DIR *dp;
	struct dirent **list;
	int i = 0 ; 

	int count = scandir(dirname, &list, NULL, alphasort );	
	if( count < 0 ){
		//perror("Couldn't open the directory");
		return 2;
	 }
	
	//PRINTDBG("Recipient : %s : %d\n", recipient, strlen(recipient));
	
	for(i=0; i < count; i++) {
		//PRINTDBG("dir: %s %d \n", list[i]->d_name, strlen(list[i]->d_name));
		if (strcmp(list[i]->d_name, username) == 0) {
			return 0;		
		}	
	}
	 
   	return 1;
}

/*
This function looks for the given username in the fileName and stores 
the whole line that begins with tha username in the parameter line_returned
*/
int findLine (char *fileName, char *username, char line_returned[]){
    FILE* file = fopen(fileName, "r"); 
    char line[256];
    
    while (fgets(line, sizeof(line), file)) {
        strcpy(line_returned, line); 
        username = strtok(line, " ");
        if  (strcmp(username, "polypose") == 0)
        {
            PRINTDBG("FOUND!");
            break;
        }
    }
    
    PRINTDBG("line is:  %s\n", line_returned); 
    fclose(file);
    return 0;
}

/*
This function takes a line (supposed to be from users.txt), parses it by using strtok on white space
and returns to the username, salt and password parameters
the username, hashed pasword (salt) and password

*****
Ex. of line: 
char line[] = "polypose $6$mojxgG.mliBuOu8B$yZqwF2jVIDiA8iddJd1OGz5HGdUnSunUDc/t/tjJ3OAd9fzfzqrxnaYH8ZA5kmpJprDcyhUy3Zvj5Py0FjG3L/ lure_leagued";
*****

*/
int processLine(char line[], char **username, char **salt, char **password) {
  
  char * pch;
  PRINTDBG ("Splitting string into tokens:\n");
  pch = strtok(line, " ");
  *username = pch; 

  pch = strtok (NULL, " ");
  *salt = pch; 

  pch = strtok (NULL, " ");
  *password = pch; 

    PRINTDBG ("%s\n",*username);
    PRINTDBG ("%s\n",*salt);
    PRINTDBG ("%s\n",*password);

  return 0;
}

int checkPassword (char *username, char *givenPassword){
// given hashed password and username, checks if it
// matches the stored hashed password for that user.
    /*
    1. check if username is in the user folder  
    2. check if given password mathces with stored information
    */

    char *salt=NULL;
    char *stored_password=NULL;
  
    if (validateUsername("./Server/users", "polypose") == 0) 
        PRINTDBG("Found username!"); 
        else {
            PRINTDBG("This user was not found: '%s'\n", username);
            //return 1; 
        }
    
    PRINTDBG("before process line \n");

    char *fName = "users.txt"; 
    char line[256]; 
    findLine(fName, username, line); 
    processLine(line, &username, &salt, &stored_password); 
    
    PRINTDBG("after  process line, stored psw is %s \n", stored_password);

    //check 
        char * c;
        c = crypt (givenPassword, salt); 
        if (strcmp(c, salt) == 0)
        {
                PRINTDBG("ok\n");
                return 0; 
        }
        else
        {
                PRINTDBG("bad\n");
                return 1; 
        }
    }

// TODO
int changePassword (){
    // given hashed password and username, 
    // deletes stored hashed password for user and adds new one
 
}



int main(int argc, char *argv[])
{
   
        char password[100] = "";
        char username[100] = "";
        strcpy(password, getpass("Enter username: ")); 
        strcpy(password, getpass("Enter password: ")); 


        char *psw = (char *)malloc(strlen(password)+1);
         strcpy(psw,password);

        char *usr = (char *)malloc(strlen(username)+1);
         strcpy(usr,username);


        if (checkPassword(usr, psw) ==0) 
            printf("Logged in successfully!\n");
        else 
            printf ("Wrong password or user.\n");
        
        return 0;
}
