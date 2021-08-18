#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rc4.h>
#include <openssl/rand.h>

#include <stdint.h>
#include <string.h>
#include <malloc.h>
#include <time.h>

#define TRUE 1
#define FALSE 0


#define ID_SIZE 16
#define CHALLENGE_TS_SIZE 16
#define SYM_KEY_SIZE 32
#define HASH_SIZE 32
#define AUTH_MSG_SIZE 64
#define RSA_ENC_SIZE 256

#define BUF_SIZE 1024
#define PUBLIC_KEY_BITS 2056

typedef struct  _certificate
{
    unsigned char name[20];
    unsigned char publickey[512];
    unsigned char sign[RSA_ENC_SIZE];
}CERTIFICATE;

typedef enum _keyType{
    SIZE_16,
    SIZE_32
}KEYTYPE;

void create_symmetric_key(unsigned char *symmetric_key);

int gen_rsa_key(RSA **rsakey, int bits);

void make_auth_msg(unsigned char *id, unsigned char *challenge, unsigned char *sym_key, unsigned char *iv, unsigned char *make_auth_msg);
void make_challenge(unsigned char *challenge);
void make_certificate(CERTIFICATE **cert, RSA *rsa_key_AS, RSA *rsa_key_CA);

void print_auth_msg(unsigned char* auth_msg);
void print_challenge_or_timestamp(unsigned char* challenge_timestamp, int type);
void print_certificate(CERTIFICATE* cert);
void print_encrypted_symmetric_key(unsigned char* sym_key1_encrypted);
void print_iv(unsigned char* iv);
void print_symmetric_key(unsigned char* sym_key1);

void set_info(unsigned char* auth_msg_decrypted, unsigned char* id, unsigned char* pw_hash, unsigned char* recv_challenge);
unsigned char* public_key_to_string(RSA *rsa_public_key);
unsigned char* private_key_to_string(RSA *rsa_private_key);

RSA* rsaFromprivateKey(const char *privateKey);
RSA* rsaFrompublicKey(const char * publicKey);
void use_rc4(unsigned char *base_key,unsigned char *result_key,int key_type);
int enter_key();