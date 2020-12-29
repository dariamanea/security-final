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

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/asn1.h>
#include <openssl/conf.h>
#include <openssl/cms.h>

using namespace std;

// Smart pointers to wrap openssl C types that need explicit free
using BIO_ptr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using X509_ptr = std::unique_ptr<X509, decltype(&X509_free)>;
using ASN1_TIME_ptr = std::unique_ptr<ASN1_TIME, decltype(&ASN1_STRING_free)>;

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
    return headers + "\r\n" + body;
}

void send_http_request(BIO *bio, const std::string& line, const std::string& host, const std::string& name, const std::string& pass, const std::string& rcpt_list, const std::string& file_name)
{
    std::string request = line + "\r\n";
    request += "Host: " + host + "\r\n";
    request += "\r\n";
    request += std::string("send") + "\r\n";
    request += name + "\r\n";
    request += pass + "\r\n";
    request += rcpt_list + "\r\n";

    std::fstream f;
    std::string msg = "";
    printf("%s\n", file_name.c_str());
    f.open(file_name);
    if(f.is_open()){
        std::string tp;
        
        while(getline(f, tp)){
            msg += tp + "\n";
        }

    }
    request += msg + "\r\n";
    printf("%s\n", msg.c_str());

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

int encMessage (char *cert_name, char *input_file, char *enc_file){

    BIO *in = NULL, *out = NULL, *tbio = NULL;
    X509 *rcert = NULL;
    STACK_OF(X509) *recips = NULL;
    CMS_ContentInfo *cms = NULL;
    int ret = 1;

    /*
     * On OpenSSL 1.0.0 and later only:
     * for streaming set CMS_STREAM
     */
    int flags = CMS_STREAM;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Read in recipient certificate */
    tbio = BIO_new_file(cert_name, "r");
    // tbio = BIO_new_file("signer.pem", "r");


    if (!tbio)
        goto err;

    rcert = PEM_read_bio_X509(tbio, NULL, 0, NULL);

    if (!rcert)
        goto err;

    /* Create recipient STACK and add recipient cert to it */
    recips = sk_X509_new_null();

    if (!recips || !sk_X509_push(recips, rcert))
        goto err;

    /*
     * sk_X509_pop_free will free up recipient STACK and its contents so set
     * rcert to NULL so it isn't freed up twice.
     */
    rcert = NULL;

    /* Open content being encrypted */

    // in = BIO_new_file("encr.txt", "r");
    in = BIO_new_file(input_file, "r");

    if (!in)
        goto err;

    /* encrypt content */
    cms = CMS_encrypt(recips, in, EVP_des_ede3_cbc(), flags);

    if (!cms)
        goto err;

    // out = BIO_new_file("smencr.txt", "w");
    out = BIO_new_file(enc_file, "w");

    if (!out)
        goto err;

    /* Write out S/MIME message */
    if (!SMIME_write_CMS(out, cms, in, flags))
        goto err;

    ret = 0;

 err:

    if (ret) {
        fprintf(stderr, "Error Encrypting Data\n");
        ERR_print_errors_fp(stderr);
    }

    CMS_ContentInfo_free(cms);
    X509_free(rcert);
    sk_X509_pop_free(recips, X509_free);
    BIO_free(in);
    BIO_free(out);
    BIO_free(tbio);
    return ret;
}


int signMessage(char *cert_name, char *input_file, char *signed_file){

    BIO *in = NULL, *out = NULL, *tbio = NULL;
    X509 *scert = NULL;
    EVP_PKEY *skey = NULL;
    CMS_ContentInfo *cms = NULL;
    int ret = 1;

    /*
     * For simple S/MIME signing use CMS_DETACHED. On OpenSSL 1.0.0 only: for
     * streaming detached set CMS_DETACHED|CMS_STREAM for streaming
     * non-detached set CMS_STREAM
     */
    int flags = CMS_DETACHED | CMS_STREAM;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Read in signer certificate and private key */
    // tbio = BIO_new_file("signer.pem", "r");
    tbio = BIO_new_file(cert_name, "r");


    if (!tbio)
        goto err;

    scert = PEM_read_bio_X509(tbio, NULL, 0, NULL);

    BIO_reset(tbio);

    skey = PEM_read_bio_PrivateKey(tbio, NULL, 0, NULL);

    if (!scert || !skey)
        goto err;

    /* Open content being signed */

    // in = BIO_new_file("sign.txt", "r");
    in = BIO_new_file(input_file, "r");

    if (!in)
        goto err;

    /* Sign content */
    cms = CMS_sign(scert, skey, NULL, in, flags);

    if (!cms)
        goto err;

    // out = BIO_new_file("smout.txt", "w");
     out = BIO_new_file(signed_file, "w");
    if (!out)
        goto err;

    if (!(flags & CMS_STREAM))
        BIO_reset(in);

    /* Write out S/MIME message */
    if (!SMIME_write_CMS(out, cms, in, flags))
        goto err;

    ret = 0;

 err:

    if (ret) {
        fprintf(stderr, "Error Signing Data\n");
        ERR_print_errors_fp(stderr);
    }

    CMS_ContentInfo_free(cms);
    X509_free(scert);
    EVP_PKEY_free(skey);
    BIO_free(in);
    BIO_free(out);
    BIO_free(tbio);
    return ret;
}


int main(int argc, char *argv[])
{
    char cert_name[] = "../users/polypose/certificates/certificate.cert.pem";
    char private_key[]      = "polypose.key.pem";
    char signer_cert_name[] = "polypose.signing";
    
    
    // create signing cert : cert + private key
    std::ifstream if_a(cert_name, std::ios_base::binary);
    std::ifstream if_b(private_key, std::ios_base::binary);
    std::ofstream of_c(signer_cert_name, std::ios_base::binary);
    of_c << if_a.rdbuf() << if_b.rdbuf();



    
    char input_file[] = "input.txt";
    char enc_file[]   = "enc_message.txt";
    char signedFile[] = "signed_message.txt";

    encMessage(cert_name, input_file, enc_file);
    
    signMessage(signer_cert_name, enc_file, signedFile); 
    
    
    
    
    return 0 ; 

    cout << "Enter username: ";
    std::string name ;
    cin >> name;
    char usr[name.length()+1];
    strcpy(usr, name.c_str());

    std::string pass = getpass("Enter password: ");


    std::string rcpt_list;
    std::string file_name;
    std::cout << "Enter recipients: \n";
    std::cin >> rcpt_list;
    std::cout << "Enter message file name: \n";
    std::cin >> file_name;
    std::cout << "Please wait";
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


    my::send_http_request(ssl_bio.get(), "GET / HTTP/1.1", "duckduckgo.com", name, pass, rcpt_list, file_name);
    std::string response = my::receive_http_message(ssl_bio.get());
    printf("%s", response.c_str());

    
}