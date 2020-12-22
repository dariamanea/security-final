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

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>


// #define DEBUG 1

#ifdef DEBUG
#define PRINTDBG printf
#else
#define PRINTDBG(...)
#endif



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

    if (validateUsername("./Server/users", username) == 0)
        PRINTDBG("Found username!");
        else {
            PRINTDBG("This user was not found: '%s'\n", username);
            //return 1;
        }

    PRINTDBG("before process line \n");

    const char *fName = "users.txt";
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
        return 2;
    }



int changePassword (char* username,char* newPassword){
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
		char modify[100];
		strcpy(modify, username);
		strcat(modify," ");
		char* newhash = crypt(newPassword,salt);
		strcat(modify, newhash);
		strcat(modify, " ");
		strcat(modify, newPassword);


		int delete_line = 0;
		FILE* file = fopen(fName, "r");
		char *found_username;
    while (fgets(line, sizeof(line), file)) {
        found_username = strtok(line, " ");
        if  (strcmp(found_username, username) == 0)
        {
            PRINTDBG("FOUND!");
            break;
        }
				delete_line += 1;
    }

		FILE *fileptr1, *fileptr2;
		char ch;
	  int temp = 1;
		fileptr1 = fopen(fName, "r");
		ch = getc(fileptr1);
	   while (ch != EOF)
	    {
	        printf("%c", ch);
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
	            } else {
									fputs(modify, fileptr2);
							}
	    }
			fclose(fileptr1);
	    fclose(fileptr2);
	    remove(fName);
			rename("replica.c", fName);
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
	    printf("%s\n", usr);
	    printf("%s\n", psw);
	    if (checkPassword(usr, psw) == 0){
		    return "Logged in successfully!\n";
	    }

    }
    return "Wrong password or user.\n";
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
