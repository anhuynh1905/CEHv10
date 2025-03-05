#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#define BUFFER_SIZE 1024

/*
 * http_client.c
 * -------------
 * A minimal HTTP client that:
 * 1. Resolves the provided hostname/IP address.
 * 2. Connects to port 80 (unless another port is specified).
 * 3. Sends a GET request.
 * 4. Receives and prints the response to stdout.
 *
 * Usage:
 *   cc -o http_client http_client.c
 *   ./http_client hostname [port] [path]
 *
 * Example:
 *   ./http_client example.com 80 /
 */

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <hostname> [port] [path]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *hostname = argv[1];
    int port = 80; // default HTTP port
    const char *path = "/"; // default path

    if (argc >= 3) {
        port = atoi(argv[2]);
    }
    if (argc >= 4) {
        path = argv[3];
    }

    // Resolve hostname
    struct addrinfo hints, *res, *p;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;  // Allow IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM; // TCP stream sockets

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    int status = getaddrinfo(hostname, port_str, &hints, &res);
    if (status != 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
        exit(EXIT_FAILURE);
    }

    // Create and connect socket
    int sockfd;
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
    if (sockfd < 0) {
        fprintf(stderr, "Could not connect to %s:%d\n", hostname, port);
        freeaddrinfo(res);
        exit(EXIT_FAILURE);
    }
    freeaddrinfo(res);

    // Build and send HTTP GET request
    char request[BUFFER_SIZE];
    snprintf(request, sizeof(request),
             "GET %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Connection: close\r\n"
             "\r\n",
             path, hostname);

    ssize_t sent_bytes = send(sockfd, request, strlen(request), 0);
    if (sent_bytes < 0) {
        perror("send");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // Read and print the response
    char buffer[BUFFER_SIZE];
    ssize_t received;
    while ((received = recv(sockfd, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[received] = '\0';
        printf("%s", buffer);
    }
    if (received < 0) {
        perror("recv");
    }

    close(sockfd);
    return 0;
}
