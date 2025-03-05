#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUFFER_SIZE 1024

/*
 * https_client_fixed.c
 *
 * This minimal HTTPS client is adjusted to work with a self-signed TLS server
 * on port 9443. It performs the following steps:
 *   1. Resolves the provided hostname/IP address.
 *   2. Connects to port 9443 (or a user-specified port).
 *   3. Initializes a TLS 1.2+ client context.
 *   4. Skips certificate verification (useful if the server uses a self-signed certificate).
 *   5. Sends a GET request over the encrypted channel.
 *   6. Receives and prints the HTTPS response.
 *
 * USAGE:
 *   cc -o https_client_fixed https_client_fixed.c -lssl -lcrypto
 *   ./https_client_fixed localhost 9443 /
 */

static void init_openssl(void)
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

static void cleanup_openssl(void)
{
    EVP_cleanup();
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <hostname> [port] [path]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Extract command line arguments
    const char *hostname = argv[1];
    int port = 9443;   // Default port for the TLS-enabled server
    const char *path = "/";

    if (argc >= 3) {
        port = atoi(argv[2]);
    }
    if (argc >= 4) {
        path = argv[3];
    }

    // Initialize OpenSSL
    init_openssl();

    // Create an SSL context using the client method
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        fprintf(stderr, "Error: Could not create SSL_CTX\n");
        cleanup_openssl();
        return EXIT_FAILURE;
    }

    /*
     * Skip certificate verification if you're using a self-signed cert.
     * For production, consider removing this line and/or configuring CA trust.
     */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    // Resolve hostname
    struct addrinfo hints, *res, *p;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;       // Allow IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;     // TCP stream socket

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);
    if (getaddrinfo(hostname, port_str, &hints, &res) != 0) {
        perror("getaddrinfo");
        SSL_CTX_free(ctx);
        cleanup_openssl();
        return EXIT_FAILURE;
    }

    // Create and connect the socket
    int sockfd = -1;
    for (p = res; p != NULL; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd < 0) {
            continue;
        }
        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == 0) {
            break;
        }
        close(sockfd);
        sockfd = -1;
    }
    freeaddrinfo(res);

    if (sockfd < 0) {
        fprintf(stderr, "Could not connect to %s:%d\n", hostname, port);
        SSL_CTX_free(ctx);
        cleanup_openssl();
        return EXIT_FAILURE;
    }

    // Create SSL structure and link it to the socket
    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        fprintf(stderr, "SSL_new() failed\n");
        close(sockfd);
        SSL_CTX_free(ctx);
        cleanup_openssl();
        return EXIT_FAILURE;
    }
    SSL_set_fd(ssl, sockfd);

    // Perform TLS handshake
    if (SSL_connect(ssl) <= 0) {
        fprintf(stderr, "TLS handshake failed\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sockfd);
        SSL_CTX_free(ctx);
        cleanup_openssl();
        return EXIT_FAILURE;
    }

    // Prepare and send the HTTP GET request
    char request[BUFFER_SIZE];
    snprintf(request, sizeof(request),
             "GET %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Connection: close\r\n"
             "\r\n",
             path, hostname);

    int sent_bytes = SSL_write(ssl, request, strlen(request));
    if (sent_bytes <= 0) {
        perror("SSL_write");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sockfd);
        SSL_CTX_free(ctx);
        cleanup_openssl();
        return EXIT_FAILURE;
    }

    // Receive and display the response
    char buffer[BUFFER_SIZE];
    int received;
    while ((received = SSL_read(ssl, buffer, BUFFER_SIZE - 1)) > 0) {
        buffer[received] = '\0';
        printf("%s", buffer);
    }
    if (received < 0) {
        fprintf(stderr, "Error: SSL_read() failed\n");
        ERR_print_errors_fp(stderr);
    }

    // Cleanup
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);

    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}
