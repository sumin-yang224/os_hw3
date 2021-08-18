#include "security.h"

void create_symmetric_key(unsigned char *symmetric_key){
    unsigned char rand_key[SYM_KEY_SIZE];
    RAND_bytes(rand_key, sizeof(rand_key));
    use_rc4(rand_key, symmetric_key, SIZE_32);
}

int enter_key(){
    char msg[BUF_SIZE];
    int ret;
    printf("\n");
    while(1){
        puts("Input message(go or Go) to send message.");
        puts("Input message(q or Q) to quit.");
        fgets(msg,BUF_SIZE,stdin);
        if(!strcmp(msg, "q\n") || !strcmp(msg, "Q\n")){
            ret = 0;
            break;
        }
        else if(!strcmp(msg,"go\n") || !strcmp(msg, "Go\n")){
            ret=1;
            break;
        }
        puts("Wrong Input. Try again.");
    }
    printf("\n");
    return ret;
}

int gen_rsa_key(RSA **rsakey, int bits){

    BIGNUM *bne=NULL;

	bne=BN_new();
	if(BN_set_word(bne, RSA_F4)!=1)
		return 0;

	*rsakey=RSA_new();
	if(RSA_generate_key_ex(*rsakey, bits, bne, NULL)!=1)
	{
		BN_free(bne);
		return FALSE;
	}
	return TRUE;
}

void make_auth_msg(unsigned char *id, unsigned char *challenge, unsigned char *sym_key, unsigned char *iv, unsigned char *make_auth_msg){

    unsigned char msg[AUTH_MSG_SIZE];
    unsigned char pw[BUF_SIZE];
    unsigned char pw_hash[SHA256_DIGEST_LENGTH];

    printf("\n");
    while(1){
        printf("Input ID : ");
        fgets(id,ID_SIZE,stdin);
        if(!strcmp(id, "") || strlen(id) > 15){
           printf("ID must be 1-15 size\n");
           continue;
        } 
        break;
    }
    
    int padding = 0;
    padding = ID_SIZE - strlen(id) - 1;

    for(int i=strlen(id); i<ID_SIZE-1; ++i)
        id[i] = '255';
    id[ID_SIZE-1] = padding;    

    while(1){
        printf("Input password : ");
        fgets(pw,BUF_SIZE,stdin);
        if(!strcmp(id, "")){
           printf("pw must be more than 1 character\n");
           continue;
        } 
        break;
    }
    printf("\n");
    
    SHA256(pw, strlen(pw), pw_hash);
    
    for(int i=0; i<ID_SIZE;++i)
        msg[i] = id[i];
    for(int i=ID_SIZE, j=0; i<ID_SIZE+SHA256_DIGEST_LENGTH; ++i, ++j)
        msg[i] = pw_hash[j];
    for(int i=ID_SIZE+SHA256_DIGEST_LENGTH, j=0;i<AUTH_MSG_SIZE;++i, ++j)
        msg[i] = challenge[j];

    printf("Phase 3 :: Make plain text.\n");
    print_auth_msg(msg);

    //encrypt message
    AES_KEY key;
    AES_set_encrypt_key(sym_key ,256,&key);
    AES_cbc_encrypt(msg, make_auth_msg,AUTH_MSG_SIZE,&key,iv,AES_ENCRYPT);
    
}

void make_challenge(unsigned char *challenge){
    unsigned char random_challenge[CHALLENGE_TS_SIZE];
    RAND_bytes(random_challenge, sizeof(random_challenge));
    use_rc4(random_challenge, challenge, SIZE_16);
}

void make_certificate(CERTIFICATE **cert, RSA *rsa_key_AS, RSA *rsa_key_CA){
    
    strcpy((*cert)->name,"Auth Server");
    
    unsigned char tmp[BUF_SIZE];
    unsigned char tmp_enc[4098];

    unsigned char *tmp_public_key = public_key_to_string(rsa_key_AS);
    
    for(int i=0; i<512;++i)
        (*cert) -> publickey[i] = tmp_public_key[i];
    
    int name_size = strlen((*cert) -> name);
    
    int public_key_size = strlen((*cert) -> publickey);

    
    strcat(tmp, (*cert) -> name);
    strcat(tmp, (*cert) -> publickey); // "Auth server" || pu(as)
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(tmp, strlen(tmp), hash); // h("Auth server" || pu(as))
    
    int sign_len = RSA_private_encrypt(sizeof(hash), hash, tmp_enc, rsa_key_CA, RSA_PKCS1_PADDING);
    for(int i=0; i < sign_len; ++i)
        (*cert) -> sign[i] = tmp_enc[i];
}

unsigned char* public_key_to_string(RSA *rsa_public_key){
    BIO *public = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(public,rsa_public_key);
   
    size_t public_len = BIO_pending(public);
    char *pub_key_string = malloc(public_len + 1);

    BIO_read(public, pub_key_string, (int)public_len);
    pub_key_string[public_len] = '\0';

    return pub_key_string;
}

unsigned char* private_key_to_string(RSA *rsa_private_key){
    BIO *private = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(private, rsa_private_key, NULL, NULL, 0, NULL, NULL);

    size_t private_len = BIO_pending(private);
    char *private_key_string = malloc(private_len + 1);

    BIO_read(private, private_key_string, (int)private_len);
    private_key_string[private_len] = '\0';

    return private_key_string;
}

RSA* rsaFrompublicKey(const char * publicKey){
    RSA *rsa = NULL;
    BIO *bio = BIO_new_mem_buf(publicKey, strlen(publicKey));
    PEM_read_bio_RSAPublicKey(bio, &rsa, 0, 0);
    BIO_free_all(bio);

    return rsa;
}

RSA* rsaFromprivateKey(const char *privateKey){
    RSA *rsa = NULL;
    BIO *bio = BIO_new_mem_buf(privateKey, strlen(privateKey));
    PEM_read_bio_RSAPrivateKey(bio, &rsa, 0, 0);
    BIO_free_all(bio);
    return rsa;
}

void print_auth_msg(unsigned char* auth_msg){
    int i,j;
    printf("\nauthentication message : \n\t");
    for(i=0, j=0; i<AUTH_MSG_SIZE;++i,++j, j%=32){
        printf("%02x", auth_msg[i]);
        if(j==31) printf("\n\t");
    }
    printf("\n");
}


void print_challenge_or_timestamp(unsigned char* challenge_timestamp, int type){
    int i;
    if(type==0)printf("\nchallenge : ");
    if(type==1)printf("\ntimestamp : ");
    for(i=0;i<CHALLENGE_TS_SIZE;i++){
        printf("%02x", challenge_timestamp[i]);
    }
    printf("\n\n");
}

void print_certificate(CERTIFICATE* cert){
    int i,j;
    
    printf("\ncertificate : \n");
    printf("\tname : %s\n", cert->name);
    printf("\tpublic key : \n%s\n", cert -> publickey);
    printf("\tsign : \t");
    for(i=0, j=0; i<sizeof(cert->sign);++i,++j, j%=32){
        printf("%02x", cert->sign[i]);
        if(j==31) printf("\n\t\t");
    }
    printf("\n");
}
void print_encrypted_symmetric_key(unsigned char* sym_key1_encrypted){
    int i,j;
    printf("\nEncrypted symmetric key : \n\t");
    for(i=0, j=0;i<RSA_ENC_SIZE; ++i,++j,j%=32){
        printf("%02x", sym_key1_encrypted[i]);
        if(j==31) printf("\n\t");
    }
    printf("\n");
}
void print_iv(unsigned char* iv){
    int i;
    printf("\nIV : ");
    for(i=0; i<AES_BLOCK_SIZE;i++){
        printf("%02x", iv[i]);
    }
    printf("\n\n");
}

void print_symmetric_key(unsigned char* sym_key){
    int i;
    printf("\nSymmetric key : ");
    for(i=0; i<SYM_KEY_SIZE;i++){
        printf("%02x", sym_key[i]);
    }
    printf("\n\n");
}

void set_info(unsigned char* auth_msg_decrypted, unsigned char* id, unsigned char* pw_hash, unsigned char* recv_challenge){

    for(int i=0; i<ID_SIZE;++i){
        id[i] = auth_msg_decrypted[i];
    }

    int padding_len = id[ID_SIZE-1];
    for(int i=ID_SIZE-padding_len-1;i<ID_SIZE;i++){
        id[i]='\0';
    }

    for(int i=ID_SIZE, j=0; i<ID_SIZE+SHA256_DIGEST_LENGTH;++i,++j){
        pw_hash[j] = auth_msg_decrypted[i];
    }
    for(int i=ID_SIZE+SHA256_DIGEST_LENGTH, j=0; i<AUTH_MSG_SIZE;++i,++j){
        recv_challenge[j] = auth_msg_decrypted[i];
    }
}


void use_rc4(unsigned char *base_key ,unsigned char *result_key, int key_type){
    
    RC4_KEY *rc4_key = (RC4_KEY*)malloc(sizeof(RC4_KEY));
    switch(key_type){
        case SIZE_16:
            RC4_set_key(rc4_key, CHALLENGE_TS_SIZE, base_key);
            RC4(rc4_key, CHALLENGE_TS_SIZE, base_key, result_key);
            break;
        case SIZE_32:
            RC4_set_key(rc4_key, SYM_KEY_SIZE, base_key);
            RC4(rc4_key, SYM_KEY_SIZE, base_key, result_key);
            break;
    }
    free(rc4_key);
}