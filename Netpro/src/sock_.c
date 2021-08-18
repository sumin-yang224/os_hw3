#include "sock_.h"


int init_server(int *serv_sock, int *clnt_sock, const char* argv[]){
    
    struct sockaddr_in serv_addr;
    struct sockaddr_in clnt_addr;
    socklen_t clnt_addr_size;

    *serv_sock = socket(PF_INET, SOCK_STREAM, 0);
    if(*serv_sock == -1)
        error_handling(SOCKET_ERROR);
    
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(atoi(argv[1]));

    if(bind(*serv_sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr))==-1)
        error_handling(BIND_ERROR);
    
    if(listen(*serv_sock, 5)==-1)
        error_handling(LISTEN_ERROR);

    clnt_addr_size = sizeof(clnt_addr);
    *clnt_sock = accept(*serv_sock, (struct sockaddr*)&clnt_addr, &clnt_addr_size);
    
    if(*clnt_sock == -1)
        error_handling(ACCEPT_ERROR);
    
    return TRUE;
    
    
}

int init_client(int *sock, const char* argv[]){
    struct sockaddr_in serv_adr;
    *sock = socket(PF_INET, SOCK_STREAM, 0);
    if(*sock==-1)
        error_handling(SOCKET_ERROR);
    
    memset(&serv_adr, 0, sizeof(serv_adr));
    serv_adr.sin_family=AF_INET;
    serv_adr.sin_addr.s_addr=inet_addr(argv[1]);
    serv_adr.sin_port=htons(atoi(argv[2]));

    if(connect(*sock,(struct sockaddr*)&serv_adr, sizeof(serv_adr))==-1)
        error_handling(CONNECT_ERROR);

    return TRUE;
}
void error_handling(int error_type){
    switch (error_type)
    {
    case ARGUMENT_ERROR:
        printf("Incorrect Argument\n");
        break;
    case SOCKET_ERROR:
        printf("socket() error\n");
        break;
    case BIND_ERROR:
        printf("bind() error\n");
        break;
    case LISTEN_ERROR:
        printf("listen() error\n");
        break;
    case ACCEPT_ERROR:
        printf("accept() error\n");
        break;
    case CONNECT_ERROR:
        printf("connect() error\n");
        break;
    case INCORRECT_MSG:
        printf("Phase 1 :: It's not a reqeust message\n");
        break;
    case SEND_ERROR:
        printf("send() error\n");
        break;
    case VERIFY_ERROR:
        printf("Verification failed.\n");
        break;
    case USER_ERROR:
        printf("User authentication failed.\n");
        break;
    default:
        break;
    }
    exit(1);
}