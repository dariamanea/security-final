#include <memory>
#include <stdarg.h>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <bits/stdc++.h>
#include <cstdint>
#include <experimental/filesystem>
#include <sys/types.h>
#include <dirent.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/asn1.h>
#include <openssl/conf.h>

using namespace std;

// Smart pointers to wrap openssl C types that need explicit free
using BIO_ptr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using X509_ptr = std::unique_ptr<X509, decltype(&X509_free)>;
using ASN1_TIME_ptr = std::unique_ptr<ASN1_TIME, decltype(&ASN1_STRING_free)>;


/*
This function calls the script client.sh with argument $1=username. 
This will create a CSR and then a certificate on the server side and 
store it in the user's 
*/
int gen_user_certs (char *username){
    // char str[100];
    char *str = (char*)malloc(sizeof(char) * 100);

    strcpy(str, "./client.sh ");
    printf ("COMMAND IS : %s\n", str);
    strcat(str, username); 
    system(str);

    printf ("COMMAND IS : %s\n", str);
    free(str);
    return 0; 
}


int gen_server_certs (){
    
    system("./server.sh");
    return 0; 
}

//SERVER BELOW

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
    char buffer[5000];
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
    return headers + "\r\n" + body;
}



void send_http_request_login(BIO *bio, const std::string& line, const std::string& host, const std::string& name, const std::string& pass)
{
    
    std::string request = line + "\r\n";
    request += "Host: " + host + "\r\n";
    request += "\r\n";
    request += std::string("login") + "\r\n";
    request += name + "\r\n";
    request += pass + "\r\n";



    BIO_write(bio, request.data(), request.size());
    BIO_flush(bio);
}

void send_http_request(BIO *bio, const std::string& header, const std::string& host, const std::string& task, const std::string& name, const std::string& data)
{
    cout << "send_HTTP_request TASK is : " << task << endl;
    std::string request = header + "\r\n";
    request += "Host: " + host + "\r\n";
    request += "\r\n";
    
    // set task
    request +=  task + "\r\n";

    // set name 
    request += name + "\r\n";
    
    // set data
    request += data + "\r\n";

    
    //request += pass + "\r\n";

    BIO_write(bio, request.data(), request.size());
    BIO_flush(bio);
}


SSL *get_ssl(BIO *bio)
{
    SSL *ssl = nullptr;
    BIO_get_ssl(bio, &ssl);
    if (ssl == nullptr) {
        my::print_errors_and_exit("Error in BIO_get_ssl");
    }
    return ssl;
}

void verify_the_certificate(SSL *ssl, const std::string& expected_hostname)
{
    int err = SSL_get_verify_result(ssl);
    if (err != X509_V_OK) {
        const char *message = X509_verify_cert_error_string(err);
        fprintf(stderr, "Certificate verification error: %s (%d)\n", message, err);
        exit(1);
    }
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert == nullptr) {
        fprintf(stderr, "No certificate was presented by the server\n");
        exit(1);
    }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    if (X509_check_host(cert, expected_hostname.data(), expected_hostname.size(), 0, nullptr) != 1) {
        fprintf(stderr, "Certificate verification error: X509_check_host\n");
        exit(1);
    }
#else
    // X509_check_host is called automatically during verification,
    // because we set it up in main().
    (void)expected_hostname;
#endif
}


// Convert the contents of an openssl BIO to a std::string
std::string bio_to_string(const BIO_ptr& bio, const int& max_len)
{
    // We are careful to do operations based on explicit lengths, not depending
    // on null terminated character streams except where we ensure the terminator

    // Create a buffer and zero it out
    char buffer[max_len];
    memset(buffer, 0, max_len);
    // Read one smaller than the buffer to make sure we end up with a null
    // terminator no matter what
    BIO_read(bio.get(), buffer, max_len - 1);
    return std::string(buffer);
}


} // namespace my

// generate User CSR
int gen_user_CSR (char *username){
    char *str =(char*) malloc (100);
    strcpy(str, "./generate_csr.sh ");
    strcat(str, username); 
    printf("%s", str);
    system(str); 
    // free(str);
    return 0; 
}

std::string request_cert(BIO *bio, char *username){
    
    //generate user CSR    
    gen_user_CSR(username);

    //std::string inFile = "csr.txt";

    char csr_file[250];    
    strcpy(csr_file, "../users/");
    strcat(csr_file, username); 
    strcat(csr_file, "/certificates/csr.pem"); 
    
    BIO_ptr input(BIO_new(BIO_s_file()), BIO_free);
    if (BIO_read_filename(input.get(), csr_file) <= 0)
    {
        std::cout << "Error reading file" << endl;
        return "Error readin file";
    }

    // Put the contents of the BIO into a C++ string    
    std::string cert_details = my::bio_to_string(input, 42768);
    BIO_reset(input.get());


    my::send_http_request(bio, "POST / HTTP/1.1", "duckduckgo.com", "sendCSR", username, cert_details);
    std::string response = my::receive_http_message(bio);
    printf("%s", response.c_str()); 
    
    // char *str = (char*)malloc(sizeof(char) * 100);
    char cert_file[250];
    strcpy(cert_file, "../users/");
    strcat(cert_file, username); 
    strcat(cert_file, "/certificates/certificate.cert.pem"); 

    //  create file at location with the name stored in 'cert_file' 
    ofstream MyFile(cert_file);

    char *end_of_headers = strstr(&response[0], "-----BEGIN CERTIFICATE-----");
    while (end_of_headers == nullptr) {
        response +=  my::receive_http_message(bio);
        end_of_headers = strstr(&response[0], "-----BEGIN CERTIFICATE-----");
    }
    MyFile <<  end_of_headers;
    MyFile.close();


    return cert_details; 
}


auto init_bio(){

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
    SSL_load_error_strings();
#endif

/* Set up the SSL context */

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    auto ctx = my::UniquePtr<SSL_CTX>(SSL_CTX_new(SSLv23_client_method()));
#else
    auto ctx = my::UniquePtr<SSL_CTX>(SSL_CTX_new(TLS_client_method()));
#endif

if (SSL_CTX_load_verify_locations(ctx.get(), "server-certificate.pem", nullptr) != 1) {
    // if (SSL_CTX_load_verify_locations(ctx.get(), "server.cert.pem", "ca-chain.cert.pem") != 1) {

    my::print_errors_and_exit("Error setting up trust store");
}


    auto bio = my::UniquePtr<BIO>(BIO_new_connect("localhost:10000"));
if (bio == nullptr) {
    my::print_errors_and_exit("Error in BIO_new_connect");
}
if (BIO_do_connect(bio.get()) <= 0) {
    my::print_errors_and_exit("Error in BIO_do_connect");
}


auto ssl_bio = std::move(bio)
    | my::UniquePtr<BIO>(BIO_new_ssl(ctx.get(), 1))
    ;
SSL_set_tlsext_host_name(my::get_ssl(ssl_bio.get()), "duckduckgo.com");

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    SSL_set1_host(my::get_ssl(ssl_bio.get()), "duckduckgo.com");
#endif
    if (BIO_do_handshake(ssl_bio.get()) <= 0) {
        my::print_errors_and_exit("Error in BIO_do_handshake");
    }
    my::verify_the_certificate(my::get_ssl(ssl_bio.get()), "duckduckgo.com");

    return ssl_bio;

    // my::send_http_request_login(ssl_bio.get(), "GET / HTTP/1.1", "duckduckgo.com", name, pass);
    // std::string response = my::receive_http_message(ssl_bio.get());
    // printf("%s", response.c_str());
}

int main(int argc, char *argv[])
{


    /***
    
    TODO: 
        - login faild is password is wrong
        - validate username ...
    
    ***/



    //std::string name = "polypose";
    //std::string pass = "lure_leagued";

    //std::string name = "wamara";
    //std::string pass = "stirrer_hewer's";


    // read the options parameters
    if 	(argc != 2) {
        cout << "Provide your username as first parameter\n";
        cout << "Example: ./getcert polypose \n";
        return 1;
    }

    char user[100];
    strcpy(user, argv[1]);


    // TODO
    char str_info[100] = "Enter password for '";
    strcat(str_info, user);
    strcat(str_info, "' : ");
    
    std::string pass = getpass(str_info);

    auto ssl_bio = init_bio();

    my::send_http_request_login(ssl_bio.get(), "GET / HTTP/1.1", "duckduckgo.com", user, pass);
    std::string response = my::receive_http_message(ssl_bio.get());

     char *end_of_headers = strstr(&response[0], "Wrong password");

    if (end_of_headers != nullptr) {
        cout << "Wrong password\n";
        return 1; 
    }

    auto ssl_bio2 = init_bio();
    // Second HTTP request that sends CSR to server
    std::string csr = request_cert(ssl_bio2.get(), user);

    return 0;

}