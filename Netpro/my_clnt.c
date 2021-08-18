#include "src/my_clnt.h"

RSA *rsaKey_CA_public = NULL;
RSA *rsaKey_CA_private = NULL;

int main(int argc, const char *argv[])
{
    int sock;
    unsigned char msg[BUF_SIZE];
    unsigned char id[ID_SIZE];
    unsigned char challenge[CHALLENGE_TS_SIZE];
    unsigned char sym_key1[SYM_KEY_SIZE], sym_key2[SYM_KEY_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];

    int size_req = sizeof(REQUEST_MSG);
    CERTIFICATE *cert = NULL;

    if(argc !=3)
        error_handling(ARGUMENT_ERROR);
    
    if(init_client(&sock, argv)){
        puts("======================================");
        puts("\tConnected to AS server\t");
        puts("======================================");
    }
    
    phase1_send_request_message(&sock, REQUEST_MSG, size_req);
    phase2_verification(&sock, challenge, &cert);
    phase3_make_authentication(&sock, challenge, sym_key1, cert, iv, id);
    return 0;
}

void phase1_send_request_message(int *sock, unsigned char *req, int size_req){
    puts("Phase 1 :: Request message to AS to get a token.");
    if(enter_key() == 0) error_handling(INCORRECT_MSG);
    write(*sock, req, size_req);
    puts("Phase 1 :: Request message sended.");
    puts("======================================");
}

int phase2_verification(int *sock, unsigned char *challenge, CERTIFICATE **cert){
    // receive challnege and certification
    unsigned char *private_key, *public_key;
    int CA_public_size, CA_private_size;

    read(*sock, &CA_public_size, sizeof(int));
    read(*sock, &CA_private_size, sizeof(int));

    public_key = malloc(sizeof(char) * CA_public_size);
    private_key = malloc(sizeof(char) * CA_private_size);

    read(*sock, public_key, CA_public_size);
    read(*sock, private_key, CA_private_size);

    rsaKey_CA_public = rsaFrompublicKey(public_key);
    rsaKey_CA_private = rsaFromprivateKey(private_key);

    read(*sock,challenge,CHALLENGE_TS_SIZE);
    puts("Phase 2 :: Challenge received.");
    print_challenge_or_timestamp(challenge, 0);
    
    *cert = (CERTIFICATE*)malloc(sizeof(CERTIFICATE));
    recv(*sock, *cert, sizeof(CERTIFICATE), 0);
    puts("Phase 2 :: Certificate received.");
    print_certificate(*cert);

    puts("Phase 2 :: Verify Certificate.");
    
    if(verify_certificate(*cert) != 1){
        error_handling(VERIFY_ERROR);
    }
    puts("Phase 2 :: Authentification Successful.");
    puts("======================================");
}

void phase3_make_authentication(int *sock, unsigned char *challenge, unsigned char *sym_key1, CERTIFICATE *cert, unsigned char *iv, unsigned char *id){

    unsigned char sym_key1_encrypted[RSA_ENC_SIZE];
    unsigned char auth_msg[AUTH_MSG_SIZE];
    unsigned char iv_use[AES_BLOCK_SIZE];

    puts("Phase 3 :: Set IV randomize.");
    RAND_bytes(iv, AES_BLOCK_SIZE);
    memcpy(iv_use,iv,AES_BLOCK_SIZE);

    // k1 generagte
    puts("Phase 3 :: Make symmetric key.");
    create_symmetric_key(sym_key1);

    puts("Phase 3 :: Encrypt symmetric key.");
    RSA_public_encrypt(SYM_KEY_SIZE, sym_key1, sym_key1_encrypted, rsaKey_CA_public, RSA_PKCS1_PADDING);
    print_encrypted_symmetric_key(sym_key1_encrypted);

    // auth msg generate
    make_auth_msg(id, challenge, sym_key1, iv_use, auth_msg);
    puts("Phase 3 :: Make authentication message.");
    print_auth_msg(auth_msg);

    if(enter_key() == 0) error_handling(INCORRECT_MSG);
    
    print_iv(iv);
    write(*sock, iv, AES_BLOCK_SIZE);
    puts("Phase 3 :: IV sended.");

    write(*sock, sym_key1_encrypted, RSA_ENC_SIZE);
    puts("Phase 3 :: Encrypted symmetric key sended.");

    
    write(*sock, auth_msg, AUTH_MSG_SIZE);
    puts("Phase 3 :: Authentication message sended.");
    puts("======================================");
}

int verify_certificate(CERTIFICATE* cert){
    int ret=1;
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned char hash_cmp[SHA256_DIGEST_LENGTH];
    unsigned char *tmp = NULL;

    tmp = malloc(sizeof(char) * (strlen(cert ->name) + strlen(cert -> publickey)));
    
    // "name" || public key(AS)
    strcat(tmp, cert -> name);
    strcat(tmp, cert -> publickey);
    
    SHA256(tmp, strlen(tmp),hash);
    
    int len = RSA_public_decrypt(sizeof(cert -> sign), cert->sign, hash_cmp, rsaKey_CA_public, RSA_PKCS1_PADDING);
   
   
    for(int i=0; i<SHA256_DIGEST_LENGTH; ++i)
        if(hash[i] != hash_cmp[i])
            return FALSE;
    
    return TRUE;
}
