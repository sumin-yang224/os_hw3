#include "sock_.h"
#include "security.h"
#define BUF_SIZE 1024
#define REQUEST_MSG "I need a token."


void phase1_send_request_message(int *sock, unsigned char *req, int size_req);
int phase2_verification(int *sock, unsigned char *challenge, CERTIFICATE **cert);
int verify_certificate(CERTIFICATE* cert);
void phase3_make_authentication(int *sock, unsigned char *challenge, unsigned char *sym_key1, CERTIFICATE *cert, unsigned char *iv, unsigned char *id);