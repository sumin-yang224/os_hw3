#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define TRUE 1
#define FALSE 0


typedef enum _error_code{
    ARGUMENT_ERROR,
    SOCKET_ERROR,
    BIND_ERROR,
    LISTEN_ERROR,
    ACCEPT_ERROR,
    CONNECT_ERROR,
    INCORRECT_MSG,
    SEND_ERROR,
    VERIFY_ERROR,
    USER_ERROR
}ERROR_CODE;


void error_handling(int error_type);
int init_server(int *serv_sock, int *clnt_sock, const char* argv[]);
int init_client(int *sock, const char* argv[]);