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

#include <memory>
#include <signal.h>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <unistd.h>
#include <vector>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <stddef.h>
#include <iostream>
#include <fstream>
#include <crypt.h>
#include <sys/stat.h>
#define S_ISDIR(mode) __S_ISTYPE((mode), __S_IFDIR)
#include <streambuf>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

using namespace std;

// #define DEBUG 1

#ifdef DEBUG
#define PRINTDBG printf
#else
#define PRINTDBG(...)
#endif

//Found at: https://codeforwin.org/2018/03/c-program-check-file-or-directory-exists-not.html
int isDirectoryExists(const char *path)
{

    struct stat stats;

    stat(path, &stats);

    // Check for file existence
    if (S_ISDIR(stats.st_mode))
        return 1;

    return 0;
}

int countFilesInDirectories (char* dirname, char* recipient ) {

	//DIR *dp;
	struct dirent **list;
	//int i = 0 ;
	char mailbox[300];

	// generate mailbox path for recipient
	strcpy(mailbox, dirname);
	strcat(mailbox,"/");
	strcat(mailbox,recipient);
	//PRINTDBG("Mailbox: %s \n", mailbox);


	int count = scandir(mailbox, &list, NULL, alphasort );
	if( count < 0 ){
		 //perror("Couldn't open the directory");
		 exit(2);
	 }

	return count - 2;
}

std::string getMsg(char* username){
    //*********************************************FILE PATH HERE******************************************

    char *path;
    path = (char *) malloc(151);
    strcpy(path, "../users");
    strcat(path, username);
	strcat(path, "/mailbox");

    if(isDirectoryExists(path)==1){
        //printf("Directory found\n");
        //check number of files in subdirectory
        bool fileFound = false;
        int i = 1;
        char realFile[160];
        //strcpy(realFile, path);
        //strcat(realFile, "/");
        while (fileFound == false){
            char filePath[160];
            strcpy(filePath, path);
            //cout << filePath << "\n";
            strcat(filePath, "/");
            //cout << filePath << "\n";
            if (i < 10){
                string fileNum = to_string(i);
                const char *cFileNum = fileNum.c_str();
                char fileName[5];
                strcpy(fileName, "0000");
                strcat(fileName, cFileNum);
                strcat(filePath, fileName);
            } else if (i < 100){
                string fileNum = to_string(i);
                const char *cFileNum = fileNum.c_str();
                char fileName[5];
                strcpy(fileName, "000");
                strcat(fileName, cFileNum);
                strcat(filePath, fileName);
            } else if (i < 1000){
                string fileNum = to_string(i);
                const char *cFileNum = fileNum.c_str();
                char fileName[5];
                strcpy(fileName, "00");
                strcat(fileName, cFileNum);
                strcat(filePath, fileName);
            } else if (i < 10000){
                string fileNum = to_string(i);
                const char *cFileNum = fileNum.c_str();
                char fileName[5];
                strcpy(fileName, "0");
                strcat(fileName, cFileNum);
                strcat(filePath, fileName);
            } else {
                string fileNum = to_string(i);
                const char *cFileNum = fileNum.c_str();
                strcat(filePath, cFileNum);
            }

            strcat(filePath, ".txt");
            //Check if file exists
            ifstream checkFile;
            checkFile.open(filePath);
            if (checkFile) {
                //cout << "file exists" << "\n";
                //i++;
                std::string msg = "";
                if(checkFile.is_open()){
                    std::string tp;
                    while(getline(checkFile, tp)){
                        msg += tp + "\n";
                    }
                }
                checkFile.close();
                return msg;
            } else {
                //cout << "file does not exist" << "\n";
                i++;
                checkFile.close();
                strcpy(realFile, filePath);
                //fileFound = true;
            }
        }
    }
        std::string msg = "No messages";
        return msg;
}

//stores message from client in rcpt mailbox
int storeMessage(std::string& target, std::string& msg){
    //std::string delimiter = " ";
    //std::string target = rcpts.substr(0, rcpts.find(delimiter));
    //rcpts.erase(0, rcpts.find(delimiter) + delimiter.length());

    //*****************************************FILE PATH HERE***************************************
    char *path;
    path = (char *) malloc(151);
    strcpy(path, "../users");
    strcat(path, target.c_str());
	strcat(path, "/mailbox");
    //cout << path << "\n";

    //Check valid rcpt
    if(isDirectoryExists(path)==1){
        //printf("Directory found\n");
        //check number of files in subdirectory
        bool fileFound = false;
        int i = 1;
        char realFile[160];
        //strcpy(realFile, path);
        //strcat(realFile, "/");
        while (fileFound == false){
            char filePath[160];
            strcpy(filePath, path);
            //cout << filePath << "\n";
            strcat(filePath, "/");
            //cout << filePath << "\n";
            if (i < 10){
                string fileNum = to_string(i);
                const char *cFileNum = fileNum.c_str();
                char fileName[5];
                strcpy(fileName, "0000");
                strcat(fileName, cFileNum);
                strcat(filePath, fileName);
            } else if (i < 100){
                string fileNum = to_string(i);
                const char *cFileNum = fileNum.c_str();
                char fileName[5];
                strcpy(fileName, "000");
                strcat(fileName, cFileNum);
                strcat(filePath, fileName);
            } else if (i < 1000){
                string fileNum = to_string(i);
                const char *cFileNum = fileNum.c_str();
                char fileName[5];
                strcpy(fileName, "00");
                strcat(fileName, cFileNum);
                strcat(filePath, fileName);
            } else if (i < 10000){
                string fileNum = to_string(i);
                const char *cFileNum = fileNum.c_str();
                char fileName[5];
                strcpy(fileName, "0");
                strcat(fileName, cFileNum);
                strcat(filePath, fileName);
            } else {
                string fileNum = to_string(i);
                const char *cFileNum = fileNum.c_str();
                strcat(filePath, cFileNum);
            }

            strcat(filePath, ".txt");
            //Check if file exists
            ifstream checkFile;
            checkFile.open(filePath);
            if (checkFile) {
                //cout << "file exists" << "\n";
                i++;
                checkFile.close();
            } else {
                //cout << "file does not exist" << "\n";
                strcpy(realFile, filePath);
                fileFound = true;
            }
        }

        //Create file and write to it from stdin
        //cout << realFile << "\n";
        std::ofstream outfile (realFile);
        //std::string line;


        outfile << msg;

        outfile.close();
        free(path);
        path = NULL;
        return 0;
    }
    return 1;
}

/*
This function searches for the given username in the Server/users folder
*/
int validateUsername(const char *dirname, char *username) {

    // return 0 if username found
    // return 1 if username not found
	// return 2 if users folder can't be opened

	//DIR *dp;
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
the whole line that begins with that username in the parameter line_returned
*/
int findLine (const char *fileName, const char *username, char line_returned[]){

    FILE* file = fopen(fileName, "r");
    char line[256];
    char *found_username;


    while (fgets(line, sizeof(line), file)) {
        strcpy(line_returned, line);
        found_username = strtok(line, " ");
        // printf ("username given %s\n", username);
        // printf ("username found %s\n", found_username);
        // printf ("comapare %d\n", strcmp(found_username, username));

        if  (strcmp(found_username, username) == 0)
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
and returns to the username, salt   and password parameters
the username, hashed pasword (salt) 
*****
Ex. of line:
char line[] = "polypose $6$mojxgG.mliBuOu8B$yZqwF2jVIDiA8iddJd1OGz5HGdUnSunUDc/t/tjJ3OAd9fzfzqrxnaYH8ZA5kmpJprDcyhUy3Zvj5Py0FjG3L/";
*****
*/
int processLine(char line[], char **username, char **salt) {
  
  char * pch;
  PRINTDBG ("Splitting string into tokens:\n");
  pch = strtok(line, " ");
  *username = pch; 

  pch = strtok (NULL, " ");
  *salt = pch; 

  pch = strtok (NULL, " ");
//   *password = pch; 

    PRINTDBG ("%s\n",*username);
    PRINTDBG ("%s\n",*salt);
    // PRINTDBG ("%s\n",*password);

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
    // char *stored_password=NULL;
  
    if (validateUsername("./Server/users", username) == 0) 
        PRINTDBG("Found username!"); 
        else {
            PRINTDBG("This user was not found: '%s'\n", username);
            //return 1; 
        }
    
    PRINTDBG("before process line \n");

    char *fName = "users.txt"; 
    char line[256]; 

    findLine(fName, username, line); 
    processLine(line, &username, &salt); 
    
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
        return 2; 
    }

/*
   

    int changePassword (char* username,const char* newPassword) {
        // given newly added password and username,
        // deletes stored hashed password for user and adds new one
    		// with the same salt

    		char *salt=NULL;
        char *stored_password=NULL;

    		if (validateUsername("./Server/users", username) == 0) {
    			PRINTDBG("Found username!");
    		}
        else {
    			PRINTDBG("This user was not found: '%s'\n", username);
        }
    		PRINTDBG("before process line \n");

    		const char *fName = "users.txt";
        char line[256];

        findLine(fName, username, line);

        processLine(line, &username, &salt, &stored_password);

        const char* newsalt = crypt_gensalt(salt,0,newPassword,strlen(newPassword));
        char* newhash = crypt(newPassword,newsalt);


        std::string modify = std::string(username) + " " + std::string(newhash) + " " + newPassword;
        std::string str(username);

    		int delete_line = 0;
    		FILE* file = fopen(fName, "r");
    		char *found_username;

        while (fgets(line, sizeof(line), file)) {
            found_username = strtok(line, " ");
            if  (strcmp(found_username, str.c_str()) == 0)
            {
                PRINTDBG("FOUND!");
                break;
            }
            delete_line += 1;
        }

    		FILE *fileptr1, *fileptr2;
    		char ch;
    	  int temp = 0;
    		fileptr1 = fopen(fName, "r");
    		ch = getc(fileptr1);
    	   while (ch != EOF) {
    	        ch = getc(fileptr1);
    	    }
    			rewind(fileptr1);
    			fileptr2 = fopen("replica.c", "w");
    			ch = getc(fileptr1);
    	    while (ch != EOF)
    	    {
    	        ch = getc(fileptr1);
    	        if (ch == '\n') temp++;
    	            if (temp != delete_line)
    	            {
    	                putc(ch, fileptr2);
    	            }
    	    }
         // putc('\n',fileptr2);
          fputs(modify.c_str(), fileptr2);
    			fclose(fileptr1);
    	    fclose(fileptr2);
    	    remove(fName);
    			rename("replica.c", fName);
        return 0;
    }

*/

// generate user certificate
int gen_user_cert (char *username){
    char *str =(char*) malloc (100);
    strcpy(str, "./generate_client_cert.sh ");
    strcat(str, username); 
    printf("%s", str);
    system(str); 
    free(str);
    return 0; 
}

    		


//**********************SERVER FUNCTIONS BELOW**************************

namespace my {

template<class T> struct DeleterOf;
template<> struct DeleterOf<BIO> { void operator()(BIO *p) const { BIO_free_all(p); } };
template<> struct DeleterOf<BIO_METHOD> { void operator()(BIO_METHOD *p) const { BIO_meth_free(p); } };
template<> struct DeleterOf<SSL_CTX> { void operator()(SSL_CTX *p) const { SSL_CTX_free(p); } };

template<class OpenSSLType>
using UniquePtr = std::unique_ptr<OpenSSLType, DeleterOf<OpenSSLType>>;

my::UniquePtr<BIO> operator|(my::UniquePtr<BIO> lower, my::UniquePtr<BIO> upper)
{
    BIO_push(upper.get(), lower.release());
    return upper;
}

class StringBIO {
    std::string str_;
    my::UniquePtr<BIO_METHOD> methods_;
    my::UniquePtr<BIO> bio_;
public:
    StringBIO(StringBIO&&) = delete;
    StringBIO& operator=(StringBIO&&) = delete;

    explicit StringBIO() {
        methods_.reset(BIO_meth_new(BIO_TYPE_SOURCE_SINK, "StringBIO"));
        if (methods_ == nullptr) {
            throw std::runtime_error("StringBIO: error in BIO_meth_new");
        }
        BIO_meth_set_write(methods_.get(), [](BIO *bio, const char *data, int len) -> int {
            std::string *str = reinterpret_cast<std::string*>(BIO_get_data(bio));
            str->append(data, len);
            return len;
        });
        bio_.reset(BIO_new(methods_.get()));
        if (bio_ == nullptr) {
            throw std::runtime_error("StringBIO: error in BIO_new");
        }
        BIO_set_data(bio_.get(), &str_);
        BIO_set_init(bio_.get(), 1);
    }
    BIO *bio() { return bio_.get(); }
    std::string str() && { return std::move(str_); }
};

[[noreturn]] void print_errors_and_exit(const char *message)
{
    fprintf(stderr, "%s\n", message);
    ERR_print_errors_fp(stderr);
    exit(1);
}

[[noreturn]] void print_errors_and_throw(const char *message)
{
    my::StringBIO bio;
    ERR_print_errors(bio.bio());
    throw std::runtime_error(std::string(message) + "\n" + std::move(bio).str());
}

std::string receive_some_data(BIO *bio)
{
    char buffer[1024];
    int len = BIO_read(bio, buffer, sizeof(buffer));
    if (len < 0) {
        my::print_errors_and_throw("error in BIO_read");
    } else if (len > 0) {
        return std::string(buffer, len);
    } else if (BIO_should_retry(bio)) {
        return receive_some_data(bio);
    } else {
        my::print_errors_and_throw("empty BIO_read");
    }
}

std::vector<std::string> split_headers(const std::string& text)
{
    std::vector<std::string> lines;
    const char *start = text.c_str();
    while (const char *end = strstr(start, "\r\n")) {
        lines.push_back(std::string(start, end));
        start = end + 2;
    }
    return lines;
}

std::string receive_http_message(BIO *bio)
{
    std::string headers = my::receive_some_data(bio);
    char *end_of_headers = strstr(&headers[0], "\r\n\r\n");
    while (end_of_headers == nullptr) {
        headers += my::receive_some_data(bio);
        end_of_headers = strstr(&headers[0], "\r\n\r\n");
    }
    std::string body = std::string(end_of_headers+4, &headers[headers.size()]);
    headers.resize(end_of_headers+2 - &headers[0]);
    size_t content_length = 0;
    for (const std::string& line : my::split_headers(headers)) {
        if (const char *colon = strchr(line.c_str(), ':')) {
            auto header_name = std::string(&line[0], colon);
            if (header_name == "Content-Length") {
                content_length = std::stoul(colon+1);
            }
        }
    }
    while (body.size() < content_length) {
        body += my::receive_some_data(bio);
    }
		std::cout << "check body" << std::endl;
    //check body
    std::string delimiter = "\r\n";
    std::string task = body.substr(0, body.find(delimiter));

    //getcert response
    if(task=="login"){
	    printf("task is login\n");
	    body.erase(0, body.find(delimiter) + delimiter.length());
	    std::string username = body.substr(0, body.find(delimiter));
	    body.erase(0, body.find(delimiter) + delimiter.length());
	    std::string password = body.substr(0, body.find(delimiter));

	    int n = username.length();
	    char usr[n+1];
	    strcpy(usr, username.c_str());
	    int m = password.length();
	    char psw[m+1];
	    strcpy(psw, password.c_str());
	    //printf("%s\n", usr);
	    //printf("%s\n", psw);
	    if (checkPassword(usr, psw) == 0){
		    return "Logged in.\n";
	    }

    }

    //sendmsg response
    if(task=="send"){
        printf("task is send\n");
	    body.erase(0, body.find(delimiter) + delimiter.length());
	    std::string username = body.substr(0, body.find(delimiter));
	    body.erase(0, body.find(delimiter) + delimiter.length());
	    std::string password = body.substr(0, body.find(delimiter));
        body.erase(0, body.find(delimiter) + delimiter.length());
	    std::string rcpt_list = body.substr(0, body.find(delimiter));
        body.erase(0, body.find(delimiter) + delimiter.length());
	    std::string msg = body.substr(0, body.find(delimiter));

	    int n = username.length();
	    char usr[n+1];
	    strcpy(usr, username.c_str());
	    int m = password.length();
	    char psw[m+1];
	    strcpy(psw, password.c_str());
	    //printf("%s\n", usr);
	    //printf("%s\n", psw);
        if (checkPassword(usr, psw) == 1){
		    return "Wrong password or user.\n";
	    }
        cout << "Hello\n";
        cout << rcpt_list << "\n";
        //printf("%s\n", rcpt_list.c_str());
        //printf("%s\n", msg.c_str());
       //printf("Entering storeMessage\n");
        if (storeMessage(rcpt_list, body) == 0){
            return "Message sent!\n";
        } else return "Message did not send\n";
    }

/*
    if (task == "newpass"){
        printf("task is newpass\n");
	    body.erase(0, body.find(delimiter) + delimiter.length());
	    std::string username = body.substr(0, body.find(delimiter));
	    body.erase(0, body.find(delimiter) + delimiter.length());
	    std::string password = body.substr(0, body.find(delimiter));
        body.erase(0, body.find(delimiter) + delimiter.length());
        std::string newpass = body.substr(0, body.find(delimiter));

	    int n = username.length();
	    char usr[n+1];
	    strcpy(usr, username.c_str());
	    int m = password.length();
	    char psw[m+1];
        strcpy(psw, password.c_str());
        int p = newpass.length();
        char newpsw[p+1];
        strcpy(newpsw, newpass.c_str());

	    //printf("%s\n", usr);
	    //printf("%s\n", psw);
	    if (checkPassword(usr, psw) == 1){
		    return "Wrong password or user.\n";
	    }
        //*******************************FILE PATH here******************************************
        char path[5] = "../users";
        if (countFilesInDirectories(path, usr) > 0){
            return "Please read mail before changing password\n";
        }
        if (changePassword(usr, newpsw) == 0){
            return "Password changed!\n";
        } else return "Password failed to update\n";
    }

*/
    // Receive CSR and return user certificate  
    if(task=="sendCSR"){
        printf("task is getcert\n");
        
        body.erase(0, body.find(delimiter) + delimiter.length());
	    std::string username = body.substr(0, body.find(delimiter));

	    body.erase(0, body.find(delimiter) + delimiter.length());
	    std::string data = body.substr(0, body.find(delimiter));

        int user_size = username.length();
	    char usr[user_size+1];
	    strcpy(usr, username.c_str());


	    int n = data.length();
	    char data_content[n+1];
	    strcpy(data_content, data.c_str());
	    printf("%s\n", data_content);

        // Writes CSR to a file
        std::ofstream outfile ("server_csr.txt");
        outfile << data_content << std::endl;
        outfile.close();    
        gen_user_cert(usr);

        //  read cert from cert_temp.txt and store into a string 
        ifstream ifs ("cert_temp.txt");
        string cert;
        getline (ifs, cert, (char) ifs.eof());

        // return certificate to client
        return cert;
	  
    }

    if(task=="recv"){
	    printf("task is login\n");
	    body.erase(0, body.find(delimiter) + delimiter.length());
	    std::string username = body.substr(0, body.find(delimiter));
	    body.erase(0, body.find(delimiter) + delimiter.length());
	    std::string password = body.substr(0, body.find(delimiter));

	    int n = username.length();
	    char usr[n+1];
	    strcpy(usr, username.c_str());
	    int m = password.length();
	    char psw[m+1];
	    strcpy(psw, password.c_str());
	    //printf("%s\n", usr);
	    //printf("%s\n", psw);
	    if (checkPassword(usr, psw) == 1){
		    return "Incorrect username or password.\n";
	    }
        return getMsg(usr);

    }
    return "Reached end of checks - something went wrong I think.\n";
}

void send_http_response(BIO *bio, const std::string& body)
{
    std::string response = "HTTP/1.1 200 OK\r\n";
    response += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    response += "\r\n";

    BIO_write(bio, response.data(), response.size());
    BIO_write(bio, body.data(), body.size());
    BIO_flush(bio);
}

my::UniquePtr<BIO> accept_new_tcp_connection(BIO *accept_bio)
{
    if (BIO_do_accept(accept_bio) <= 0) {
        return nullptr;
    }
    return my::UniquePtr<BIO>(BIO_pop(accept_bio));
}

} // namespace my


//*********************************MAIN FUNCTION***********************************
int main(int argc, char *argv[])
{

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
    SSL_load_error_strings();
    auto ctx = my::UniquePtr<SSL_CTX>(SSL_CTX_new(SSLv23_method()));
#else
    auto ctx = my::UniquePtr<SSL_CTX>(SSL_CTX_new(TLS_method()));
    SSL_CTX_set_min_proto_version(ctx.get(), TLS1_2_VERSION);
#endif

    if (SSL_CTX_use_certificate_file(ctx.get(), "server-certificate.pem", SSL_FILETYPE_PEM) <= 0) {
        my::print_errors_and_exit("Error loading server certificate");
    }
    if (SSL_CTX_use_PrivateKey_file(ctx.get(), "server-private-key.pem", SSL_FILETYPE_PEM) <= 0) {
        my::print_errors_and_exit("Error loading server private key");
    }

    auto accept_bio = my::UniquePtr<BIO>(BIO_new_accept("10000"));
    if (BIO_do_accept(accept_bio.get()) <= 0) {
        my::print_errors_and_exit("Error in BIO_do_accept (binding to port 8080)");
    }

    static auto shutdown_the_socket = [fd = BIO_get_fd(accept_bio.get(), nullptr)]() {
        close(fd);
    };
    signal(SIGINT, [](int) { shutdown_the_socket(); });

    while (auto bio = my::accept_new_tcp_connection(accept_bio.get())) {
        bio = std::move(bio)
            | my::UniquePtr<BIO>(BIO_new_ssl(ctx.get(), 0))
            ;
        try {
            std::string request = my::receive_http_message(bio.get());
            printf("Got request:\n");
            printf("%s\n", request.c_str());
            my::send_http_response(bio.get(), request);
        } catch (const std::exception& ex) {
            printf("Worker exited with exception:\n%s\n", ex.what());
        }
    }
    printf("\nClean exit!\n");

}
