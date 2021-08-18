#include "src/my_as.h"
#define BUF_SIZE 1024

    BIO *out_AS=NULL, *out_CA;
	RSA *rsaKey_AS = NULL, *rsaKey_CA = NULL;
	EVP_PKEY *pkey_AS = NULL, *pkey_CA = NULL;


int main(int argc, const char *argv[])
{
    int server_sock, client_sock;
    unsigned char sym_key1[SYM_KEY_SIZE];
    unsigned char id[ID_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char challenge[CHALLENGE_TS_SIZE];

    CERTIFICATE *cert = NULL;
    USER *user = (USER*)malloc(sizeof(USER));
    // generage rsa key for AS and CA
    if(!create_rsa_key(&rsaKey_AS, &out_AS, &pkey_AS))
	{
		printf("RSA_genkey() error.\n");
		exit(1);
	}

    if(!create_rsa_key(&rsaKey_CA, &out_CA, &pkey_CA)){
        printf("RSA_genkey() error.\n");
		exit(1);
    }

    if(argc !=2)
        error_handling(ARGUMENT_ERROR);

    if(init_server(&server_sock, &client_sock, argv)){
        puts("======================================");
        puts("\tConnected to New Client\t");
        puts("======================================");
    }
    init_user_info(user);
    cert = (CERTIFICATE*)malloc(sizeof(CERTIFICATE));
    phase1_send_challenge(&client_sock, challenge, &cert);
    phase2_verify_user_and_msg(&client_sock, sym_key1, iv, challenge,id, &user);
    return 0;
}

void phase1_send_challenge(int* clnt_sock,unsigned char *challenge, CERTIFICATE **cert){
    unsigned char msg[BUF_SIZE];
    int sign_len, cert_len;
    read(*clnt_sock, msg, sizeof(NEED_TOKEN_MSG));
    if(strcmp(msg, NEED_TOKEN_MSG) != 0){
        close(*clnt_sock);
        error_handling(INCORRECT_MSG);
    }
    puts("Phase 1 :: Request message received.");

    puts("Phase 1 :: Make Challenge.");
    make_challenge(challenge);
    print_challenge_or_timestamp(challenge, 0);

    puts("Phase 1 :: Make Certificate.");
    make_certificate(cert,rsaKey_AS, rsaKey_CA);
    print_certificate(*cert);

    if(enter_key()==0) error_handling(INCORRECT_MSG);

    //   CA rsa key size -> CA public_key_string -> CA private_key_string -> send challenge -> cert
    
    unsigned char *CA_public = public_key_to_string(rsaKey_CA);
    unsigned char *CA_private = private_key_to_string(rsaKey_CA);

    int CA_public_size = strlen(CA_public);
    int CA_private_size = strlen(CA_private);
    
    write(*clnt_sock, &CA_public_size, sizeof(int));
    write(*clnt_sock, &CA_private_size, sizeof(int));

    write(*clnt_sock, CA_public, CA_public_size);
    write(*clnt_sock, CA_private, CA_private_size);
    
    write(*clnt_sock,challenge,CHALLENGE_TS_SIZE);
    if(send(*clnt_sock, *cert, sizeof(CERTIFICATE), 0) == -1)
        error_handling(SEND_ERROR);
    
    free(CA_public);
    free(CA_private);
    
    puts("Phase 1 :: Challenge sended.");
    puts("phase 1 :: Certificate sended.");
    puts("======================================");

}

int phase2_verify_user_and_msg(int *clnt_sock, unsigned char *sym_key1, unsigned char * iv, unsigned char *challenge, unsigned char *id, USER **user){
    unsigned char sym_key1_encrypted[RSA_ENC_SIZE];
    unsigned char auth_msg[AUTH_MSG_SIZE];
    unsigned char auth_msg_decrypted[AUTH_MSG_SIZE];
    unsigned char pw_hash[SHA_DIGEST_LENGTH];
    unsigned char recv_challenge[CHALLENGE_TS_SIZE];
    unsigned char iv_use[AES_BLOCK_SIZE];


    read(*clnt_sock, iv, AES_BLOCK_SIZE);
    puts("Phase 2 :: IV received.");
    print_iv(iv);
    memcpy(iv_use,iv,AES_BLOCK_SIZE);

    read(*clnt_sock, sym_key1_encrypted, RSA_ENC_SIZE);
    puts("Phase 2 :: Encrypted symmetric key received.");
    print_encrypted_symmetric_key(sym_key1_encrypted);

    read(*clnt_sock, auth_msg, AUTH_MSG_SIZE);
    puts("Phase 2 :: Authentication message received.");
    print_auth_msg(auth_msg);

    // decrypt encrypted symmetric key .
    puts("Phase 2 :: Decrypt encrypted symmetric key.");
    RSA_private_decrypt(RSA_ENC_SIZE, sym_key1_encrypted, sym_key1, rsaKey_CA, RSA_PKCS1_PADDING);
    print_symmetric_key(sym_key1);

    // decrypt Authentication message.
    puts("Phase 2 :: Decrypt authentication message.");
    AES_KEY key;
    AES_set_decrypt_key(sym_key1, 256, &key);
    AES_cbc_encrypt(auth_msg, auth_msg_decrypted, AUTH_MSG_SIZE, &key, iv_use, AES_DECRYPT);
    print_auth_msg(auth_msg_decrypted);

    set_info(auth_msg_decrypted, id, pw_hash, recv_challenge);

    puts("Phase 2 :: Verify challenge.");
    if(verify_auth_message(recv_challenge, challenge)==0){
        error_handling(VERIFY_ERROR);
    }

    puts("Phase 2 :: Verification success.");
    puts("Phase 2 :: User authentication start.");

    if(authenticate_user(id,pw_hash,*user)==0){
        error_handling(USER_ERROR);
    }
    puts("Phase 2 :: User authentication success.");
    puts("======================================");
}


void init_user_info(USER* user){

    unsigned char pw[BUF_SIZE];
    strcpy(pw,"1234\n");
    strcpy(user->id,"Alice\n");

    // pw must be hash value.
    SHA256(pw,strlen(pw),user->pw_hash);
    user->next=NULL;
}

int verify_auth_message(unsigned char *recv_challenge, unsigned char *challenge){
    
    for(int i=0; i<CHALLENGE_TS_SIZE; ++i){
        if(recv_challenge[i] != challenge[i])
            return FALSE;
    }
    return TRUE;
}

int authenticate_user(unsigned char* id,unsigned char* pw_hash,USER* user){

    USER *iter = user;
    while(iter!=NULL){
        if(!strcmp(iter->id, id)){
            for(int i=0; i<SHA256_DIGEST_LENGTH;++i)
                if(pw_hash[i] != iter->pw_hash[i]){
                    return FALSE;
                    printf("Phase 2 :: password incorret.\n");
                }
            return TRUE;        
        }
        iter = iter->next;
    }
    printf("Phase 2 :: cannot find user.\n");
    return 0;
}

int create_rsa_key(RSA **rsakey, BIO **out, EVP_PKEY **pkey){
    
    // Generate RSA key pair.
	if(!gen_rsa_key(&(*rsakey), 2048))
	{
		printf("gen_ras_key() error.\n");
		return FALSE;
	}
    // Print RSA key pair.
	*out=BIO_new_fp(stdout, BIO_CLOSE);  // allocate BIO for 'stdout'.
	*pkey=EVP_PKEY_new();
	EVP_PKEY_set1_RSA(*pkey, *rsakey); // convert RSA structure to EVP_PKEY structure for printing key data.
    return TRUE;

}