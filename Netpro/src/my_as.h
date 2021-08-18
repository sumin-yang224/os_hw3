#include "security.h"
#include "sock_.h"
#define NEED_TOKEN_MSG "I need a token."

typedef struct __user_info{
    unsigned char id[ID_SIZE];
    unsigned char pw_hash[SHA256_DIGEST_LENGTH];
    struct __user_info* next;
}USER;

void init_user_info(USER* user);
int create_rsa_key(RSA **rsakey, BIO **out, EVP_PKEY **pkey);
void phase1_send_challenge(int *clnt_sock, unsigned char *challenge, CERTIFICATE **cert);
int phase2_verify_user_and_msg(int *clnt_sock, unsigned char *sym_key1, unsigned char * iv, unsigned char *challenge, unsigned char *id, USER **user);
int authenticate_user(unsigned char* id,unsigned char* pw_hash,USER* user);
int verify_auth_message(unsigned char *recv_challenge, unsigned char *challenge);
int enter_key();