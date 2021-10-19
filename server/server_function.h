#include <sys/shm.h>
#include <sys/stat.h>
#include <signal.h>
#include <stdio.h> 
#include <limits.h> 
#include <string.h> 
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>
#define max_utenti 10 //numero massimo di utenti connessi
#define len_buffer 10000 //dimensione massima dei buffer
#define symkey_size 32 //dimensione della chiave simmetrica
#define iv_size 13
#define tag_len 32

typedef struct
{
    int porta;
    int new_sd;
    char utente[len_buffer];
    char session_key[symkey_size];
    char session_iv[iv_size];
    char session_key_hmac[symkey_size];
}thread_str;

typedef struct {
    int new_sd;
    int sd_comunicazione;
    char session_key_utente1[symkey_size];
    char session_iv_utente1[iv_size];
    char session_key_hmac_utente1[symkey_size];
    char session_key_utente2[symkey_size];
    char session_iv_utente2[iv_size];
    char session_key_hmac_utente2[symkey_size];
    char username_chiamante[len_buffer];
    char username_chiamato[len_buffer];
    pthread_t* thread_invia;
    pthread_t* thread_ricevi;
}parametri_thread_chat;

char nomi_utenti_occupati[max_utenti][len_buffer];

thread_str array_utenti[max_utenti]; //array contentete info sugli utenti(nome e sd)

void invia(char* cmd,int new_sd, int len){
    int ret;//,len; //variabile per gli erorri e per la lunghezza
    uint16_t lmsg; //variabile per contenere la lunghezza del messaggio
    lmsg=htons(len); // trasformo la lunghezza 
    ret=send(new_sd,(void*)&lmsg,sizeof(uint16_t),0); //invio la lunghezza
    if(ret<0){
        perror("Errore in fase di invio della lunghezza: \n");
        exit(-1);
    }
    ret=send(new_sd,(void*)cmd,len,0); //invio il messaggio della lunghezza precedentemente inviata
    if(ret<0){
        perror("Errore in fase di invio del comando: \n");
        exit(-1);
    }
}

void ricevi(char* cmd,int new_sd){
    int ret,len;  //variabile per gli erorri e per la lunghezza
    uint16_t lmsg; //variabile per contenere la lunghezza del messaggio
    ret=recv(new_sd,(void*)&lmsg,sizeof(uint16_t),0); //ricevo la lunghezza
    if(ret<sizeof(uint16_t)){
        //perror("Errore in fase di ricezione della lunghezza: \n");
        exit(-1);
    }
    len=ntohs(lmsg); //trasformo la lunghezza
    ret=recv(new_sd,(void*)cmd,len,0); //ricevo il messaggio della lunghezza arrivata precedentemente
    cmd[len]='\0';
    if(ret<len){
        perror("Errore in fase di ricezione del messaggio: \n");
        exit(-1);
    }
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// FUNZIONI CRITTOGRAFICA 
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//funzione che firma un messaggio con la chiave privata passata
int firmaDigitale(char* msg, EVP_PKEY* privateKey, unsigned char* firma, unsigned int* firma_len) {
    int ret;
    const EVP_MD* hash = EVP_sha256();

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if(ctx == NULL) {
        return 0;
    }

    ret = EVP_SignInit(ctx, hash);
    if(ret == 0) {
        return 0;
    }
    
    ret = EVP_SignUpdate(ctx, msg, strlen(msg));   
    if(ret == 0) {
        return 0;
    }

    ret = EVP_SignFinal(ctx, firma, firma_len, privateKey);
    if(ret == 0) {
        return 0;
    }
    
    EVP_MD_CTX_free(ctx);    
    return 1;
}

//funzione che verifica che un messaggio inviato sia firmato giustamente
int verificaFirma(unsigned char* msg, EVP_PKEY *publicKey, unsigned char* firma, int firma_len) {
    int ret;
    const EVP_MD* hash = EVP_sha256();

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if(ctx == NULL) {
        return 0;
    }
    ret = EVP_VerifyInit(ctx, hash);
    if(ret == 0) {
        return 0;
    }

    ret = EVP_VerifyUpdate(ctx, (unsigned char*)msg, strlen(msg));
    if(ret != 1) {
        return 0;
    }

    ret = EVP_VerifyFinal(ctx, firma, firma_len, publicKey);
    if(ret != 1) {
        return 0;
    }

    EVP_MD_CTX_free(ctx);
    return 1;
}

//funzione utilizzata per autenticare il server
void invia_firma(int new_sd){

    int ret;

    //il server invia il suo certificato
    FILE* cert_file = fopen("server_cert.pem", "r");
    if(!cert_file) { 
        perror("Error: impossibile aprire il file ProjectCA_crl.pem\n"); 
        exit(1); 
    }
    X509* cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
    fclose(cert_file);
    if(!cert){ 
        perror("Error: PEM_read_X509 ha ritornato 0\n"); 
        exit(1); 
    }

    BIO* mbio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(mbio,cert);
    char* cert_buf = NULL;
    long cert_size = BIO_get_mem_data(mbio, &cert_buf);
    uint16_t lmsg = htons(cert_size);
    send(new_sd,(void*)&lmsg,sizeof(uint16_t),0);
    send(new_sd,cert_buf,cert_size,0);

    X509_free(cert);
    BIO_free(mbio);
}

void incremento_iv(char* iv){
    
    for(int i = iv_size-1; i>-1; i--){
        if(iv[i] != 0x7F){
            iv[i] += 0x01;
            break;
        }
        else
            iv[i] = 0x00;
        
        if(i == 0){
            for(int h = 0; h < iv_size; h++)
                iv[h] = 0x00;
        }
        
    }
}

//funzione utilizzata per autenticare il client
void autentica_utente(int new_sd, EVP_PKEY* pubkey){

    int ret;

    //genero il nonce che dovrà tornarmi firmato
    RAND_poll();
    char nonce[100];
    memset(&nonce,0,100);
    ret = RAND_bytes((char*)nonce,100);
    if(ret != 1){
        perror("RAND_bytes ha fallito");
        exit(-1);
    }
    nonce[100]='\0';
    invia(nonce,new_sd,100);

    int len_messaggio;
    uint16_t lmsg;
    ret = recv(new_sd,(void*)&lmsg,sizeof(uint16_t),0);
    if(ret < sizeof(uint16_t)){
        perror("Errore: receive1\n");
        exit(-1);
    }
    len_messaggio = ntohs(lmsg);
    char* messaggio;
    messaggio = (char*)malloc(len_messaggio);
    messaggio[len_messaggio] = '\0';
    ret = recv(new_sd,messaggio,len_messaggio,0);
    if(ret < len_messaggio){
        perror("Errore: receive2\n");
        exit(-1);
    }

    ret = verificaFirma(nonce,pubkey,messaggio,len_messaggio);
    if(ret == 0){
        perror("Errore: verificaFirma\n");
        exit(-1);
    }

    free(messaggio);

}

//funzione usata per scambiare in maniera sicura la chiave simmetrica, l'iv e la chiave per l'HMAC
void perfect_forward_secrecy(int new_sd, char* session_key, char* session_iv, char* session_key_hmac, char* porta_da_inviare, char* username){

    int ret;
    char porta_supporto[len_buffer];
    memcpy(porta_supporto,porta_da_inviare,len_buffer);
    
    //genero il nonce per l'autenticazione e lo invio M1
    RAND_poll();
    char nonce[100];
    memset(&nonce,0,100);
    ret = RAND_bytes((char*)nonce,100);
    if(ret != 1){
        perror("RAND_bytes ha fallito");
        exit(-1);
    }
    nonce[100]='\0';
    invia(nonce,new_sd,100);

    //invio il certificicato M2
    invia_firma(new_sd);
    
    //ricevo R' (il nonce del client) M3
    char nonce_client[100];
    memset(&nonce_client,0,100);
    ricevi(nonce_client,new_sd);

    //prelevo la chiave privata del server
    FILE* chiavePrivata = fopen("server_key.pem", "rb");
    if(chiavePrivata == NULL) {
        perror("Errore: File chiave privata\n");
        exit(-1);
    }

    EVP_PKEY* prvkey;
    prvkey = PEM_read_PrivateKey(chiavePrivata, NULL, NULL, NULL);
    if(prvkey == NULL) {
        perror("Errore: Lettura prvkey\n");
        exit(-1);
    }
    fclose(chiavePrivata);

    //ricevo lo username M4
    int nome_gia_usato = 0;
    char username_supporto[len_buffer];
    //controllo che lo username ricevuto non sia già online
    while(nome_gia_usato==0){
        memset(&username_supporto,0,len_buffer);
        ricevi(username_supporto,new_sd);
        printf("username ricevuto: %s",username_supporto);
        int r;
        nome_gia_usato = 1;
        for(r=0;r<max_utenti;r++){
            if(strcmp(username_supporto,array_utenti[r].utente)==0){
                nome_gia_usato = 0;
                invia("nome occupato",new_sd,14);
                break;
            }
        }
        if(nome_gia_usato==1){   
            invia("nome libero",new_sd,14);
        }
    }
    memcpy(username,username_supporto,len_buffer);
    //prelevo la chiav pubblica dell'utente
    EVP_PKEY* user_pub_key;
    char nome_file[len_buffer+8];
    strncpy(nome_file,username,strlen(username));
    sprintf(nome_file+strlen(username)-1,"_pub.pem");
    FILE* pubkey_file = fopen(nome_file, "r");
    if(!pubkey_file){ 
        perror("Error: errore nell'apertura del file contenente la chiave pubblica dell'utente\n"); 
        exit(1); 
    }
    user_pub_key= PEM_read_PUBKEY(pubkey_file, NULL, NULL, NULL);
    fclose(pubkey_file);
    if(!user_pub_key){ 
        perror("Error: PEM_read_PubKey ha ritornato NULL\n"); 
        exit(1); 
    }

    //ricevo la chiave pubblica temporanea M5
    uint16_t lmsg = 0;
    ret = recv(new_sd,(void*)&lmsg,sizeof(uint16_t),0);
    if(ret < sizeof(uint16_t)){
        perror("Errore: errore nella ricezione\n");
        exit(-1);
    }
    long pubkey_size = ntohs(lmsg);
    unsigned char* pubkey_buf = (unsigned char*)malloc(pubkey_size);
    ret = recv(new_sd,pubkey_buf,pubkey_size,0);
    if(ret < pubkey_size){
        perror("Errore: errore nella ricezione\n");
        exit(-1);
    }

    //creo il messaggio concatenato (R||pubkey_buf||username)
    char buffer[pubkey_size+100+len_buffer];
    memset(&buffer,0,pubkey_size+100+len_buffer);
    strncpy(buffer,nonce,100);
    strncat(buffer,pubkey_buf,pubkey_size);
    strncat(buffer,username,len_buffer);

    //ricevo (R||pubkey_buf||username) firmato M6
    int len_messaggio;
    lmsg = 0;
    ret = recv(new_sd,(void*)&lmsg,sizeof(uint16_t),0);
    if(ret < sizeof(uint16_t)){
        perror("Errore: receive1\n");
        exit(-1);
    }
    len_messaggio = ntohs(lmsg);
    char* messaggio;
    messaggio = (char*)malloc(len_messaggio); 
    messaggio[len_messaggio] = '\0';
    ret = recv(new_sd,messaggio,len_messaggio,0);
    if(ret < len_messaggio){
        perror("Errore: receive2\n");
        exit(-1);
    }

    //verifico che (R||pubkey_buf||username) ricevuto sia firmato correttamente
    ret = verificaFirma(buffer,user_pub_key,messaggio,len_messaggio);
    if(ret == 0){
        perror("Errore: Perfect forward secrecy\n");
        exit(-1);
    }

    //ritrasformo la chiave in EVP_PUBKEY
    RSA* temp_pub_key;
    BIO* mbio = BIO_new(BIO_s_mem());
    BIO_write(mbio,pubkey_buf,pubkey_size);
    temp_pub_key = PEM_read_bio_RSA_PUBKEY(mbio,NULL,NULL,NULL);

    //genero la chiave di simmetrica di sessione e la invio M7
    RAND_poll();
    char symkey[symkey_size + 1]; 
    memset(&symkey,0,symkey_size+1);
    ret = RAND_bytes((char*)symkey,symkey_size); 
    if(ret != 1){
        perror("RAND_bytes ha fallito");
        exit(-1);
    }
    symkey[symkey_size + 1]='\0'; 
    unsigned char* msg_encrypt = malloc(RSA_size(temp_pub_key));
    ret = RSA_public_encrypt(symkey_size+1,symkey,msg_encrypt,temp_pub_key,RSA_PKCS1_PADDING);
    if(ret == -1){
        perror("RSA_public_encrypt ha fallito");
        exit(-1);
    }

    lmsg = htons(RSA_size(temp_pub_key));
    send(new_sd,(void*)&lmsg,sizeof(uint16_t),0);
    send(new_sd,msg_encrypt,RSA_size(temp_pub_key),0);

    
    // setto la variabile che conterrà la chiave di sessione
    memcpy(session_key, symkey, symkey_size + 1);

    //genero iv di sessione e la invio cifarata M8
    RAND_poll();
    char iv [iv_size]; 
    memset(&iv,0,iv_size);
    ret = RAND_bytes((char*)iv,iv_size-1); 
    if(ret != 1){
        perror("RAND_bytes ha fallito");
        exit(-1);
    }
    iv[iv_size]='\0'; 
    unsigned char* iv_encrypt = malloc(RSA_size(temp_pub_key));
    ret = RSA_public_encrypt(iv_size,iv,iv_encrypt,temp_pub_key,RSA_PKCS1_PADDING);
    if(ret == -1){
        perror("RSA_public_encrypt ha fallito");
        exit(-1);
    }

    lmsg = htons(RSA_size(temp_pub_key));
    send(new_sd,(void*)&lmsg,sizeof(uint16_t),0);
    send(new_sd,iv_encrypt,RSA_size(temp_pub_key),0);

    memcpy(session_iv, iv, iv_size);


    // genero chiave per HMAC e la invio firmata cifrata M9
    RAND_poll();
    char symkey_hmac[symkey_size + 1]; 
    memset(&symkey_hmac,0,symkey_size+1);
    ret = RAND_bytes((char*)symkey_hmac,symkey_size); 
    if(ret != 1){
        perror("RAND_bytes ha fallito");
        exit(-1);
    }
    symkey_hmac[symkey_size + 1]='\0';
    unsigned char* msg_encrypt_hmac = malloc(RSA_size(temp_pub_key));

    ret = RSA_public_encrypt(symkey_size+1,symkey_hmac,msg_encrypt_hmac,temp_pub_key,RSA_PKCS1_PADDING);
    if(ret == -1){
        perror("RSA_public_encrypt ha fallito");
        exit(-1);
    }

    lmsg = htons(RSA_size(temp_pub_key));
    send(new_sd,(void*)&lmsg,sizeof(uint16_t),0);
    send(new_sd,msg_encrypt_hmac,RSA_size(temp_pub_key),0);


    // setto la variabile che conterrà la chiave di sessione
    memcpy(session_key_hmac, symkey_hmac, symkey_size + 1);
    
    //invio la porta che il client dovrà usare M10
    invia(porta_supporto,new_sd,len_buffer);

    //invio la firma estesa M11
    char buffer_firma[RSA_size(temp_pub_key)+RSA_size(temp_pub_key)+RSA_size(temp_pub_key)+len_buffer+100];
    memset(&buffer_firma,0,RSA_size(temp_pub_key)+RSA_size(temp_pub_key)+RSA_size(temp_pub_key)+len_buffer+100);
    memcpy(buffer_firma,nonce_client,100);
    memcpy(buffer_firma+100,msg_encrypt,RSA_size(temp_pub_key));
    memcpy(buffer_firma+100+RSA_size(temp_pub_key),iv_encrypt,RSA_size(temp_pub_key));
    memcpy(buffer_firma+100+RSA_size(temp_pub_key)+RSA_size(temp_pub_key),msg_encrypt_hmac,RSA_size(temp_pub_key));
    memcpy(buffer_firma+100+RSA_size(temp_pub_key)+RSA_size(temp_pub_key)+RSA_size(temp_pub_key),porta_da_inviare,len_buffer);

    unsigned char* signature = malloc(EVP_PKEY_size(prvkey));
    unsigned int signature_len;
    ret = firmaDigitale(buffer_firma,prvkey,signature,&signature_len);
    if(ret == 0){
        perror("Errore: firmaDigitale\n");
        exit(-1);
    }

    lmsg = htons(signature_len);
    send(new_sd,(void*)&lmsg,sizeof(uint16_t),0);
    send(new_sd,signature,signature_len,0);




    free(messaggio);
    free(pubkey_buf);
    RSA_free(temp_pub_key);
    free(msg_encrypt);
    free(msg_encrypt_hmac);
    free(iv_encrypt);
    EVP_PKEY_free(prvkey);
    free(signature);
    //free(signature_m8);
    //free(signature_m10);
    //free(signature_porta);
    
    BIO_free(mbio);

}

//funzione di cifratura simmetrica con HMAC
int encrypt(unsigned char *plaintext, int plaintext_len, 
                unsigned char *key,
                unsigned char *iv, int iv_len, 
                unsigned char *ciphertext, 
                unsigned char *tag,char* username,
                unsigned char *key_hmac){

    EVP_CIPHER_CTX *ctx;
    int len=0;
    int ciphertext_len = 0;

    //prelevo l'iv da usare dalla struttra
    int k;
    for(k=0; k<max_utenti;k++){
        if(strcmp(array_utenti[k].utente,username)==0){
            memcpy(iv,array_utenti[k].session_iv,iv_size);
            break;
        }
    }

    if(!(ctx = EVP_CIPHER_CTX_new())){
        perror("Errore: EVP_CIPHER_CTX_new\n");
        exit(-1);
    }
    
    if(1 != EVP_EncryptInit(ctx, EVP_aes_256_gcm(), key, iv)){
        perror("Errore: EVP_EncryptInit\n");
        exit(-1);
    }

    while((ciphertext_len<(plaintext_len-8)) && plaintext_len>8){
        if( 1!= EVP_EncryptUpdate(ctx, ciphertext + ciphertext_len, &len, plaintext + ciphertext_len, 8)){
            perror("Errore: EVP_EncryptUpdate\n");
            exit(-1);
        }
        ciphertext_len += len;
        plaintext_len -= len;
    }
    if(1 != EVP_EncryptUpdate(ctx, ciphertext + ciphertext_len, &len, plaintext + ciphertext_len, plaintext_len)){
        perror("Errore: EVP_EncryptUpdate\n");
        exit(-1);
    }
    ciphertext_len += len;
	
    if(1 != EVP_EncryptFinal(ctx, ciphertext + len, &len)){
        perror("Errore: EVP_EncryptFinal\n");
        exit(-1);
    }
    ciphertext_len += len;
    
    //genero l'HMAC di iv||ciphertext
    HMAC_CTX* ctx_hmac = HMAC_CTX_new();

    unsigned int outlen;
    char messaggio_concatenato[ciphertext_len + iv_size];
    memset(&messaggio_concatenato, 0, ciphertext_len + iv_size);
    strncpy(messaggio_concatenato, iv, iv_size);
    strncat(messaggio_concatenato, ciphertext, ciphertext_len);

    HMAC(EVP_sha256(), key_hmac, 32, messaggio_concatenato, ciphertext_len + iv_size, tag, &outlen);

    //incremento l'IV in modo che per il prossimo messaggio sia diverso e lo scrivo nella struttura
    incremento_iv(iv);
  
    int i;
    for(i=0; i<max_utenti;i++){
        if(strcmp(array_utenti[i].utente,username)==0){
            memset(&array_utenti[i].session_iv,0,iv_size);
            memcpy(array_utenti[i].session_iv,iv,iv_size);
            break;
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    HMAC_CTX_free(ctx_hmac);
    return ciphertext_len;
}


void* symmetric_encryption(char* messaggio, unsigned char* symkey, char* cphr_buf, char* iv_gcm,unsigned char* tag_buf, char* username,unsigned char *key_hmac){ //funzione per cifrare i messaggi utilizzando un meccanismo a chiave simmetrica(AES256)

	int cphr_len = 0;
    int pt_len = len_buffer;
    encrypt(messaggio, pt_len, symkey, iv_gcm, 12, cphr_buf, tag_buf, username, key_hmac);

}

//funzione di decifratura simmetrica con HMAC
int decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext, char* username,unsigned char *key_hmac)
{
    EVP_CIPHER_CTX *ctx;
    int len = 0;
    int plaintext_len = 0;
    int ret;

    //prelvo l'iv da usare dalla struttura
    int k;
    for(k=0; k<max_utenti;k++){
        if(strcmp(array_utenti[k].utente,username)==0){
            memcpy(iv,array_utenti[k].session_iv,iv_size);
            break;
        }
    } 

    //genero il mio HMAC e lo confronto
    HMAC_CTX* ctx_hmac = HMAC_CTX_new();
    unsigned char tag_new[32];
    unsigned int outlen;
    char messaggio_concatenato[ciphertext_len + iv_size];
    memset(&messaggio_concatenato, 0, ciphertext_len + iv_size);
    strncpy(messaggio_concatenato, iv, iv_size);
    strncat(messaggio_concatenato, ciphertext, ciphertext_len);

    HMAC(EVP_sha256(), key_hmac, 32, messaggio_concatenato, ciphertext_len + iv_size, tag_new, &outlen);
    
    if(memcmp(tag,tag_new,32)!=0){
        perror("Error: tag diverso\n");
        exit(1);
    }

    if(!(ctx = EVP_CIPHER_CTX_new())){
        perror("Error: EVP_CIPHER_CTX_new\n");
        exit(1);
    }
    if(!EVP_DecryptInit(ctx, EVP_aes_256_gcm(), key, iv)){
        perror("Error: EVP_DecryptInit\n");
        exit(1);
    }

    while((plaintext_len<(ciphertext_len-8)) && ciphertext_len>8){
        if( 1!= EVP_DecryptUpdate(ctx, plaintext + plaintext_len, &len, ciphertext + plaintext_len, 8)){
            perror("Errore: EVP_EncryptUpdate\n");
            exit(-1);
        }
        plaintext_len += len;
        ciphertext_len -= len;
    }
    if(1 != EVP_DecryptUpdate(ctx, plaintext + plaintext_len, &len, ciphertext + plaintext_len, plaintext_len)){
        perror("Errore: EVP_EncryptUpdate\n");
        exit(-1);
    }
    plaintext_len += len;

    ret = EVP_DecryptFinal(ctx, plaintext + len, &len);
    if(ret < 0){
        perror("Error: EVP_DecryptFinal\n");
        exit(1);
    }

    //incremento l'IV in modo che per il prossimo messaggio sia diverso e lo scrivo nella struttura
    incremento_iv(iv);
    int i;
    for(i=0; i<max_utenti;i++){
        if(strcmp(array_utenti[i].utente,username)==0){
            memset(&array_utenti[i].session_iv,0,iv_size);
            memcpy(array_utenti[i].session_iv,iv,iv_size);
            break;
        }
    }
    EVP_CIPHER_CTX_free(ctx);
    HMAC_CTX_free(ctx_hmac);

    if(ret > 0) {
        plaintext_len += len;
        return plaintext_len;
    }
}

void* symmetric_decryption(char* cphr_buf, char* symkey, char* dec_buf, char* iv_gcm, unsigned char* tag_buf,char* username,char *key_hmac){ //funzione per cifrare i messaggi utilizzando un meccanismo a chiave simmetrica(AES256)

	int cphr_len = 0;
    int ct_len = len_buffer;
    decrypt(cphr_buf, ct_len, tag_buf, symkey, iv_gcm, 12, dec_buf,username, key_hmac);

}



/////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////

//funzione che svuota la lista egli utenti in chat
void inizializza_utenti_occupati(){
    int i;
    for(i=0;i<max_utenti;i++){
        strcpy(nomi_utenti_occupati[i],"");
    }
}

void* client(void* parametri){
    system("cd ../client; ./client > /dev/null 2>&1");
}
void funzione_client(){
    char username[len_buffer]="nessuno";
    pthread_t thread_client;
    pthread_create(&thread_client,NULL,&client,&username);
}

//funzione che svuota la lista degli utenti online
void inizializza_array_utenti(thread_str* array_utenti){
    int i;
    for(i=0;i<max_utenti;i++){
        array_utenti[i].porta=0;
        array_utenti[i].new_sd=0;
        strcpy(array_utenti[i].utente,"");
        memset(array_utenti[i].session_key,0,symkey_size);
        memset(array_utenti[i].session_iv,0,iv_size);
        memset(array_utenti[i].session_key_hmac,0,symkey_size);
    }
}

//thread che gestisce l'invio di messaggi durante la chat
void* thread_function_invia(void* parametri){
    parametri_thread_chat* arg = (parametri_thread_chat*)parametri;
    char session_key[symkey_size];
    memset(&session_key,0,symkey_size);
    memcpy(session_key,arg->session_key_utente1,symkey_size);
    char session_iv[iv_size];
    memset(&session_iv,0,iv_size);
    memcpy(session_iv,arg->session_iv_utente1,iv_size);
    char session_key_hmac[symkey_size];
    memset(&session_key_hmac,0,symkey_size);
    memcpy(session_key_hmac,arg->session_key_hmac_utente1,symkey_size);
    char username[len_buffer];
    memset(&username,0,len_buffer);
    memcpy(username,arg->username_chiamante,len_buffer);
    int new_sd = arg->new_sd;
    int sd_comunicazione = arg->sd_comunicazione;
    pthread_t* thread_ricevi= arg->thread_ricevi;
    int* ritorno_pthread_exit;

    char session_key_hmac_c2[symkey_size];
    memset(&session_key_hmac_c2,0,symkey_size);
    memcpy(session_key_hmac_c2,arg->session_key_hmac_utente2,symkey_size);

    char session_iv_c2[iv_size];
    memset(&session_iv_c2,0,iv_size);
    memcpy(session_iv_c2,arg->session_iv_utente2,iv_size);

    char username_c2[len_buffer];
    memset(&username_c2,0,len_buffer);
    memcpy(username_c2,arg->username_chiamato,len_buffer);

    char session_iv_temp[iv_size];
    memset(&session_iv_temp,0,iv_size);
    memcpy(session_iv_temp,session_iv,iv_size);
    
    while(1){
        char messaggio_chat[len_buffer];
        memset(&messaggio_chat,0,len_buffer);
        char controllo_chiusura[len_buffer];
        memset(&controllo_chiusura,0,len_buffer);
        ricevi(messaggio_chat,new_sd); //ricevo il messaggio dall'utente chiamante

        unsigned char* tag_buf=(unsigned char*)malloc(tag_len);
        invia(messaggio_chat,sd_comunicazione,len_buffer); //invio il messaggio all'utente chiamato
        ricevi(tag_buf,new_sd); //ricevo il tag dall'utente chiamante 
        invia(tag_buf,sd_comunicazione,tag_len); //invio il taga all'utente chiamato

        char* tag_buf_2=(unsigned char*)malloc(tag_len);
        ricevi(tag_buf_2,new_sd);
        unsigned char* tag=(unsigned char*)malloc(tag_len);
        char messaggio_concatenato[len_buffer + iv_size + tag_len];
        memset(&messaggio_concatenato, 0, len_buffer + iv_size + tag_len);
        strncpy(messaggio_concatenato, session_iv_temp, iv_size);
        strncat(messaggio_concatenato, messaggio_chat, len_buffer);
        strncat(messaggio_concatenato, tag_buf, tag_len);
        HMAC(EVP_sha256(), session_key_hmac, 32, messaggio_concatenato, len_buffer + iv_size + tag_len, tag, NULL);

        if(memcmp(tag,tag_buf_2,32)!=0){
            perror("Error: tag diverso\n");
            exit(1);
        }

        incremento_iv(session_iv_temp);

        free(tag_buf_2);
        free(tag);

        memset(&messaggio_concatenato, 0, len_buffer + iv_size + tag_len);
        strncpy(messaggio_concatenato, session_iv_c2, iv_size);
        strncat(messaggio_concatenato, messaggio_chat, len_buffer);
        strncat(messaggio_concatenato, tag_buf, tag_len);
        tag=(unsigned char*)malloc(tag_len);
        HMAC(EVP_sha256(), session_key_hmac_c2, 32, messaggio_concatenato, len_buffer + iv_size + tag_len, tag, NULL);
        invia(tag,sd_comunicazione,tag_len);
       
        incremento_iv(session_iv_c2);

        free(tag_buf);
        free(tag);

        memset(&messaggio_chat,0,len_buffer);
        ricevi(messaggio_chat,new_sd); //ricevo il messaggio dall'utente chiamante per il server
        tag_buf=(unsigned char*)malloc(tag_len);
        ricevi(tag_buf,new_sd); //ricevo il tag dall'utente chiamante per il server
        symmetric_decryption(messaggio_chat,session_key,controllo_chiusura,session_iv,tag_buf,username, session_key_hmac);
        free(tag_buf);
        if(strcmp(controllo_chiusura,"!chiudi_chat\n")==0){
            break;
        }
    }
    pthread_cancel(*thread_ricevi);
    pthread_exit(ritorno_pthread_exit);
}

//thread che gestisce la ricezione di messaggi durante la chat
void* thread_function_ricevi(void* parametri){
    parametri_thread_chat* arg = (parametri_thread_chat*)parametri;
    char session_key[symkey_size];
    memset(&session_key,0,symkey_size);
    memcpy(session_key,arg->session_key_utente2,symkey_size);
    char session_iv[iv_size];
    memset(&session_iv,0,iv_size);
    memcpy(session_iv,arg->session_iv_utente2,iv_size);
    char session_key_hmac[symkey_size];
    memset(&session_key_hmac,0,symkey_size);
    memcpy(session_key_hmac,arg->session_key_hmac_utente2,symkey_size);
    char username[len_buffer];
    memset(&username,0,len_buffer);
    memcpy(username,arg->username_chiamato,len_buffer);
    int new_sd = arg->new_sd;
    int sd_comunicazione = arg->sd_comunicazione;
    pthread_t* thread_invia= arg->thread_invia;
    int* ritorno_pthread_exit;

    char session_key_hmac_c1[symkey_size];
    memset(&session_key_hmac_c1,0,symkey_size);
    memcpy(session_key_hmac_c1,arg->session_key_hmac_utente1,symkey_size);

    char session_iv_c1[iv_size];
    memset(&session_iv_c1,0,iv_size);
    memcpy(session_iv_c1,arg->session_iv_utente1,iv_size);

    char username_c1[len_buffer];
    memset(&username_c1,0,len_buffer);
    memcpy(username_c1,arg->username_chiamante,len_buffer);

    char session_iv_temp[iv_size];
    memset(&session_iv_temp,0,iv_size);
    memcpy(session_iv_temp,session_iv,iv_size);

    while(1){
        char messaggio_chat[len_buffer];
        memset(&messaggio_chat,0,len_buffer);
        char controllo_chiusura[len_buffer];
        memset(&controllo_chiusura,0,len_buffer);
        ricevi(messaggio_chat,sd_comunicazione); //ricevo il messaggio dall'utente chiamato
        invia(messaggio_chat,new_sd,len_buffer); //invio il messaggio all'utente chiamante
        unsigned char *tag_buf;
        tag_buf=(unsigned char*)malloc(tag_len);
        ricevi(tag_buf,sd_comunicazione); //ricevo il tag dall'utente chiamato 
        invia(tag_buf,new_sd,tag_len); //invio il tag all'utente chiamante

        char* tag_buf_2=(unsigned char*)malloc(tag_len);
        ricevi(tag_buf_2,sd_comunicazione);
        unsigned char* tag=(unsigned char*)malloc(tag_len);
        char messaggio_concatenato[len_buffer + iv_size + tag_len];
        memset(&messaggio_concatenato, 0, len_buffer + iv_size + tag_len);
        strncpy(messaggio_concatenato, session_iv_temp, iv_size);
        strncat(messaggio_concatenato, messaggio_chat, len_buffer);
        strncat(messaggio_concatenato, tag_buf, tag_len);
        HMAC(EVP_sha256(), session_key_hmac, 32, messaggio_concatenato, len_buffer + iv_size + tag_len, tag, NULL);
        if(memcmp(tag,tag_buf_2,32)!=0){
            perror("Error: tag diverso\n");
            exit(1);
        }

        incremento_iv(session_iv_temp);
    
        free(tag_buf_2);
        free(tag);


        memset(&messaggio_concatenato, 0, len_buffer + iv_size + tag_len);
        strncpy(messaggio_concatenato, session_iv_c1, iv_size);
        strncat(messaggio_concatenato, messaggio_chat, len_buffer);
        strncat(messaggio_concatenato, tag_buf, tag_len);
        tag=(unsigned char*)malloc(tag_len);
        HMAC(EVP_sha256(), session_key_hmac_c1, 32, messaggio_concatenato, len_buffer + iv_size + tag_len, tag, NULL);
        invia(tag,new_sd,tag_len);
       
        incremento_iv(session_iv_c1);

        free(tag_buf);
        free(tag);


        memset(&messaggio_chat,0,len_buffer);
        ricevi(messaggio_chat,sd_comunicazione); //ricevo il messaggio dall'utente chiamato per il server
        tag_buf=(unsigned char*)malloc(tag_len);
        ricevi(tag_buf,sd_comunicazione); //ricevo il tag dall'utente chiamato per il server
        symmetric_decryption(messaggio_chat,session_key,controllo_chiusura,session_iv,tag_buf,username, session_key_hmac);
        free(tag_buf);
        if(strcmp(controllo_chiusura,"!chiudi_chat\n")==0){
            break;
        }  
    }
    pthread_cancel(*thread_invia);
    pthread_exit(ritorno_pthread_exit);
}

//funzione che elimina l'utente dalla lista degli utenti online
void elimina_utente(char* username, thread_str* array_utenti){
    int i;
    for(i=0;i<max_utenti;i++){
        if(strcmp(array_utenti[i].utente,username)==0){
            array_utenti[i].porta=0;
            array_utenti[i].new_sd=0;
            strcpy(array_utenti[i].utente,"");
            memset(array_utenti[i].session_key,0,symkey_size);
            memset(array_utenti[i].session_iv,0,iv_size);
            memset(array_utenti[i].session_key_hmac,0,symkey_size);
        }
    }
}

//funzione utilizzata per gestire la parte iniziale della chat tra due utenti
//in particolare il "collegamento" tra i due client tramite il server
void gestisci_inizializzazione_chat(char* username, char* utente_chiamante,int new_sd, thread_str* array_utenti, char* session_key, char* session_iv, char* session_key_hmac){

    int ret;
    int i;
    char cmd_cipher[len_buffer];

    //cerco l'utente nel file degli utenti connessi e mi salvo l'indice i
    for(i = 0; i<max_utenti; i++){
        if((strcmp(username,array_utenti[i].utente) == 0)){ 
            break; 
        }
    }

    struct sockaddr_in dest_addr;
    int sd_comunicazione = socket(AF_INET,SOCK_STREAM,0);
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(array_utenti[i].porta);
    inet_pton(AF_INET,"127.0.0.1",&dest_addr.sin_addr); //salvataggio nel formato endian corretto di ip dentro la struct sin_addr
    
    ret = connect(sd_comunicazione, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
    if(ret < 0){
        perror("---- Errore del Client sulla Connect ----\n");
        exit(1);
    }

    int j;
    //aggiungo gli utenti nella lista degli utenti occupati
    for(j=0;j<max_utenti;j++){
        if(strcmp(nomi_utenti_occupati[j],"")==0){
            strcpy(nomi_utenti_occupati[j],username);
            break;
        }
        
    }

    for(j=0;j<max_utenti;j++){
        if(strcmp(nomi_utenti_occupati[j],"")==0){
            strcpy(nomi_utenti_occupati[j],utente_chiamante);
            break;
        }
    }

    //prelevo la session_key e il session_iv dell'utente da contattare
    char session_key_utente2[symkey_size];
    memset(&session_key_utente2,0,symkey_size);
    memcpy(session_key_utente2,array_utenti[i].session_key,symkey_size);
    char session_iv_utente2[iv_size];
    memset(&session_iv_utente2,0,iv_size);
    memcpy(session_iv_utente2,array_utenti[i].session_iv,iv_size);

    char session_key_hmac_utente2[symkey_size];
    memset(&session_key_hmac_utente2,0,symkey_size);
    memcpy(session_key_hmac_utente2,array_utenti[i].session_key_hmac,symkey_size);

    char msg[len_buffer];
    memset(&msg,0,len_buffer);
    memset(&cmd_cipher,0,len_buffer);
    sprintf(msg, "Richiesta comunicazione da: %s\nVuoi accettare?[y,n]\n",utente_chiamante);
    unsigned char *tag_buf;
    tag_buf=(unsigned char*)malloc(tag_len);
    symmetric_encryption(msg,session_key_utente2,cmd_cipher,session_iv_utente2,tag_buf,username, session_key_hmac_utente2);
    
    invia(cmd_cipher,sd_comunicazione,len_buffer);
    invia(tag_buf,sd_comunicazione,tag_len);
    free(tag_buf);
    
    //gestisco la risposta dell'utente, e comunico l'esito al client richiedente
    memset(&msg,0,len_buffer);
    memset(&cmd_cipher,0,len_buffer);
    ricevi(cmd_cipher,sd_comunicazione);
    tag_buf=(unsigned char*)malloc(tag_len);
    ricevi(tag_buf,sd_comunicazione);
    symmetric_decryption(cmd_cipher,session_key_utente2,msg,session_iv_utente2,tag_buf,username,session_key_hmac_utente2);
    free(tag_buf);
    printf("risposta utente contattato: %s\n",msg);
    if(strcmp(msg,"y\n") == 0){ //utente accetta la comunicazione
        memset(&cmd_cipher,0,len_buffer);
        unsigned char *tag_buf;
        tag_buf=(unsigned char*)malloc(tag_len);
        unsigned char esito[len_buffer] = "richiesta accettata\n";
        symmetric_encryption(esito,session_key,cmd_cipher,session_iv,tag_buf,utente_chiamante, session_key_hmac);
        invia(cmd_cipher, new_sd,len_buffer);
        invia(tag_buf,new_sd,tag_len);
        free(tag_buf);


        //leggo la chiave pubblica dell'utente chiamato e la invio all'utente chiamante
        EVP_PKEY* pub_key_utente_chiamato;
        char nome_file_utente_chiamato[len_buffer+8];
        strncpy(nome_file_utente_chiamato,username,strlen(username));
        sprintf(nome_file_utente_chiamato+strlen(username)-1,"_pub.pem");
        FILE* pub_file_utente_chiamato = fopen(nome_file_utente_chiamato, "r");
        if(!pub_file_utente_chiamato){ 
            perror("Error: errore nell'apertura del file contenente la chiave pubblica dell'utente\n"); 
            exit(1); 
        }
        pub_key_utente_chiamato= PEM_read_PUBKEY(pub_file_utente_chiamato, NULL, NULL, NULL);
        fclose(pub_file_utente_chiamato);
        if(!pub_key_utente_chiamato){ 
            perror("Error: PEM_read_PubKey ha ritornato NULL\n"); 
            exit(1); 
        }
        
        BIO* mbio_utente_chiamato = BIO_new(BIO_s_mem());
        PEM_write_bio_PUBKEY(mbio_utente_chiamato,pub_key_utente_chiamato);
        char* pubkey_buf_utente_chiamato = NULL;
        long pubkey_size_utente_chiamato = BIO_get_mem_data(mbio_utente_chiamato, &pubkey_buf_utente_chiamato);
        char cmd_cipher[len_buffer];
        memset(&cmd_cipher,0,len_buffer);
        tag_buf=(unsigned char*)malloc(tag_len);
        symmetric_encryption(pubkey_buf_utente_chiamato,session_key,cmd_cipher,session_iv,tag_buf,utente_chiamante, session_key_hmac);
        invia(cmd_cipher, new_sd,len_buffer);
        invia(tag_buf,new_sd,tag_len);
        free(tag_buf);
        //leggo la chiave pubblica dell'utente che ha iniziato la chat e la invio all'altro

        EVP_PKEY* pub_key_utente_chiamante;
        char nome_file[len_buffer+8];
        strncpy(nome_file,utente_chiamante,strlen(utente_chiamante));
        sprintf(nome_file+strlen(utente_chiamante)-1,"_pub.pem");
        FILE* pub_file_utente_chiamante = fopen(nome_file, "r");
        if(!pub_file_utente_chiamante){ 
            perror("Error: errore nell'apertura del file contenente la chiave pubblica dell'utente\n"); 
            exit(1); 
        }
        pub_key_utente_chiamante= PEM_read_PUBKEY(pub_file_utente_chiamante, NULL, NULL, NULL);
        fclose(pub_file_utente_chiamante);
        if(!pub_key_utente_chiamante){ 
            perror("Error: PEM_read_PubKey ha ritornato NULL\n"); 
            exit(1); 
        }
        BIO* mbio = BIO_new(BIO_s_mem());
        PEM_write_bio_PUBKEY(mbio,pub_key_utente_chiamante);
        char* pubkey_buf = NULL;
        long pubkey_size = BIO_get_mem_data(mbio, &pubkey_buf);
        memset(&cmd_cipher,0,len_buffer);
        tag_buf=(unsigned char*)malloc(tag_len);
        symmetric_encryption(pubkey_buf,session_key_utente2,cmd_cipher,session_iv_utente2,tag_buf,username, session_key_hmac_utente2);
        invia(cmd_cipher, sd_comunicazione,len_buffer);
        invia(tag_buf,sd_comunicazione,tag_len);
        free(tag_buf);
        //il server gestisce lo scambio di messaggi per il perfect forward dei due utenti

        char nonce[100];
        memset(&nonce,0,100);

        //ricevo il nonce dell'utente contattato
        ricevi(nonce,sd_comunicazione);
        tag_buf=(unsigned char*)malloc(tag_len);
        ricevi(tag_buf,sd_comunicazione);
        char* tag=(unsigned char*)malloc(tag_len);
        char messaggio_concatenato[100 + iv_size];
        memset(&messaggio_concatenato, 0, 100 + iv_size);
        strncpy(messaggio_concatenato, session_iv_utente2, iv_size);
        strncat(messaggio_concatenato, nonce, 100);
        HMAC(EVP_sha256(), session_key_hmac_utente2, 32, messaggio_concatenato, 100 + iv_size, tag, NULL);

        if(memcmp(tag,tag_buf,32)!=0){
            perror("Error: tag diverso\n");
            exit(1);
        }

        incremento_iv(session_iv_utente2);
    
        int i;
        for(i=0; i<max_utenti;i++){
            if(strcmp(array_utenti[i].utente,username)==0){
                memset(&array_utenti[i].session_iv,0,iv_size);
                memcpy(array_utenti[i].session_iv,session_iv_utente2,iv_size);
                break;
            }
        }
        free(tag_buf);
        free(tag);

        //invio il nonce all'utente chiamante
        invia(nonce,new_sd,100);

        tag=(unsigned char*)malloc(tag_len);
        memset(&messaggio_concatenato, 0, 100 + iv_size);
        strncpy(messaggio_concatenato, session_iv, iv_size);
        strncat(messaggio_concatenato, nonce, 100);
        HMAC(EVP_sha256(), session_key_hmac, 32, messaggio_concatenato, 100 + iv_size, tag, NULL);
        invia(tag,new_sd,tag_len);
        incremento_iv(session_iv);
    
        for(i=0; i<max_utenti;i++){
            if(strcmp(array_utenti[i].utente,utente_chiamante)==0){
                memset(&array_utenti[i].session_iv,0,iv_size);
                memcpy(array_utenti[i].session_iv,session_iv,iv_size);
                break;
            }
        }
        free(tag);

        //ricevo la chiave pubblica temporanea dall'utente chiamante
        uint16_t lmsg = 0;
        ret = recv(new_sd,(void*)&lmsg,sizeof(uint16_t),0);
        if(ret < sizeof(uint16_t)){
            perror("Errore: errore nella ricezione\n");
            exit(-1);
        }
        int Tpubkey_size = ntohs(lmsg);
        unsigned char* Tpubkey = (unsigned char*)malloc(Tpubkey_size);
        ret = recv(new_sd,Tpubkey,Tpubkey_size,0);
        if(ret < Tpubkey_size){
            perror("Errore: errore nella ricezione\n");
            exit(-1);
        }

        //ricevo nonce e chiave pubblica temporanea firmati dall'utente chiamante
        lmsg = 0;
        ret = recv(new_sd,(void*)&lmsg,sizeof(uint16_t),0);
        if(ret < sizeof(uint16_t)){
            perror("Errore: errore nella ricezione\n");
            exit(-1);
        }
        pubkey_size = ntohs(lmsg);
        pubkey_buf = (unsigned char*)malloc(pubkey_size);
        ret = recv(new_sd,pubkey_buf,pubkey_size,0);
        if(ret < pubkey_size){
            perror("Errore: errore nella ricezione\n");
            exit(-1);
        }
        
        tag_buf=(unsigned char*)malloc(tag_len);
        ricevi(tag_buf,new_sd);

        tag=(unsigned char*)malloc(tag_len);
        char messaggio_concatenato_v2[pubkey_size + iv_size];
        memset(&messaggio_concatenato_v2, 0, pubkey_size + iv_size);
        strncpy(messaggio_concatenato_v2, session_iv, iv_size);
        strncat(messaggio_concatenato_v2, pubkey_buf, pubkey_size);

        //controllo la firma con chive pubblica del chiamante creando il messaggio comcatenato nonce||pubkey_buf
        char buffer[len_buffer];
        memset(&buffer,0,len_buffer);
        strncpy(buffer,nonce,100);
        strncat(buffer,Tpubkey,Tpubkey_size);
        ret = verificaFirma(buffer,pub_key_utente_chiamante,pubkey_buf,pubkey_size);
        if(ret == 0){
            perror("Errore: Perfect forward secrecy\n");
            exit(-1);
        }  

        HMAC(EVP_sha256(), session_key_hmac, 32, messaggio_concatenato_v2, pubkey_size + iv_size, tag, NULL);

        if(memcmp(tag,tag_buf,32)!=0){
            perror("Error: tag diverso\n");
            exit(1);
        }

        incremento_iv(session_iv);
    
        for(i=0; i<max_utenti;i++){
            if(strcmp(array_utenti[i].utente,utente_chiamante)==0){
                memset(&array_utenti[i].session_iv,0,iv_size);
                memcpy(array_utenti[i].session_iv,session_iv,iv_size);
                break;
            }
        }
        free(tag_buf);
        free(tag);

        //invio la chiave pubblica temporanea all'utente contattato
        lmsg = htons(Tpubkey_size);
        send(sd_comunicazione,(void*)&lmsg,sizeof(uint16_t),0);
        send(sd_comunicazione,Tpubkey,Tpubkey_size,0);

        //invio nonce e chiave pubblica temporanea firmati all'utente contattato
        lmsg = htons(pubkey_size);
        send(sd_comunicazione,(void*)&lmsg,sizeof(uint16_t),0);
        send(sd_comunicazione,pubkey_buf,pubkey_size,0);
        
        tag=(unsigned char*)malloc(tag_len);
        memset(&messaggio_concatenato_v2, 0, pubkey_size + iv_size);
        strncpy(messaggio_concatenato_v2, session_iv_utente2, iv_size);
        strncat(messaggio_concatenato_v2, pubkey_buf, pubkey_size);
        HMAC(EVP_sha256(), session_key_hmac_utente2, 32, messaggio_concatenato_v2, pubkey_size + iv_size, tag, NULL);
        invia(tag,sd_comunicazione,tag_len);
        incremento_iv(session_iv_utente2);
    
        for(i=0; i<max_utenti;i++){
            if(strcmp(array_utenti[i].utente,username)==0){
                memset(&array_utenti[i].session_iv,0,iv_size);
                memcpy(array_utenti[i].session_iv,session_iv_utente2,iv_size);
                break;
            }
        }
        free(tag);
        free(pubkey_buf);
        free(Tpubkey);

        //ricevo dall'utente chiamante R'
        lmsg = 0;
        ret = recv(new_sd,(void*)&lmsg,sizeof(uint16_t),0);
        if(ret < sizeof(uint16_t)){
            perror("Errore: errore nella ricezione\n");
            exit(-1);
        }
        pubkey_size = ntohs(lmsg);
        pubkey_buf = (unsigned char*)malloc(pubkey_size);
        ret = recv(new_sd,pubkey_buf,pubkey_size,0);
        if(ret < pubkey_size){
            perror("Errore: errore nella ricezione\n");
            exit(-1);
        }

        tag_buf=(unsigned char*)malloc(tag_len);
        ricevi(tag_buf,new_sd);

        tag=(unsigned char*)malloc(tag_len);
        memset(&messaggio_concatenato, 0, 100 + iv_size);
        strncpy(messaggio_concatenato, session_iv, iv_size);
        strncat(messaggio_concatenato, nonce, 100);
        HMAC(EVP_sha256(), session_key_hmac, 32, messaggio_concatenato, 100 + iv_size, tag, NULL);

        if(memcmp(tag,tag_buf,32)!=0){
            perror("Error: tag diverso\n");
            exit(1);
        }

        incremento_iv(session_iv);
    
        for(i=0; i<max_utenti;i++){
            if(strcmp(array_utenti[i].utente,utente_chiamante)==0){
                memset(&array_utenti[i].session_iv,0,iv_size);
                memcpy(array_utenti[i].session_iv,session_iv,iv_size);
                break;
            }
        }
        free(tag_buf);
        free(tag);

        //invio all'utente chiamato R'
        lmsg = htons(pubkey_size);
        send(sd_comunicazione,(void*)&lmsg,sizeof(uint16_t),0);
        send(sd_comunicazione,pubkey_buf,pubkey_size,0);
        free(pubkey_buf);

        tag=(unsigned char*)malloc(tag_len);
        memset(&messaggio_concatenato, 0, 100 + iv_size);
        strncpy(messaggio_concatenato, session_iv_utente2, iv_size);
        strncat(messaggio_concatenato, nonce, 100);
        HMAC(EVP_sha256(), session_key_hmac_utente2, 32, messaggio_concatenato, 100 + iv_size, tag, NULL);
        invia(tag,sd_comunicazione,tag_len);
        incremento_iv(session_iv_utente2);
    
        for(i=0; i<max_utenti;i++){
            if(strcmp(array_utenti[i].utente,username)==0){
                memset(&array_utenti[i].session_iv,0,iv_size);
                memcpy(array_utenti[i].session_iv,session_iv_utente2,iv_size);
                break;
            }
        }
        free(tag);

        //ricevo dall'utente contattato la chiave di sessione
        lmsg = 0;
        ret = recv(sd_comunicazione,(void*)&lmsg,sizeof(uint16_t),0);
        if(ret < sizeof(uint16_t)){
            perror("Errore: errore nella ricezione\n");
            exit(-1);
        }
        int session_key_size = ntohs(lmsg);
        unsigned char* session_key_buf = (unsigned char*)malloc(session_key_size);
        ret = recv(sd_comunicazione,session_key_buf,session_key_size,0);
        if(ret < session_key_size){
            perror("Errore: errore nella ricezione\n");
            exit(-1);
        }


        //ricevo dall'utente contattato l'iv di sessione
        lmsg = 0;
        ret = recv(sd_comunicazione,(void*)&lmsg,sizeof(uint16_t),0);
        if(ret < sizeof(uint16_t)){
            perror("Errore: errore nella ricezione\n");
            exit(-1);
        }
        int session_iv_size = ntohs(lmsg);
        unsigned char* session_iv_buf = (unsigned char*)malloc(session_iv_size);
        ret = recv(sd_comunicazione,session_iv_buf,session_iv_size,0);
        if(ret < session_iv_size){
            perror("Errore: errore nella ricezione\n");
            exit(-1);
        }


        //ricevo dall'utente contattato la chiave di sessione hmac
        lmsg = 0;
        ret = recv(sd_comunicazione,(void*)&lmsg,sizeof(uint16_t),0);
        if(ret < sizeof(uint16_t)){
            perror("Errore: errore nella ricezione\n");
            exit(-1);
        }
        int session_hmac_size = ntohs(lmsg);
        unsigned char* session_hmac_buf = (unsigned char*)malloc(session_hmac_size);
        ret = recv(sd_comunicazione,session_hmac_buf,session_hmac_size,0);
        if(ret < session_hmac_size){
            perror("Errore: errore nella ricezione\n");
            exit(-1);
        }
        

        //ricevo dall'utente contattato la firma totale con hmac della firma
        lmsg = 0;
        ret = recv(sd_comunicazione,(void*)&lmsg,sizeof(uint16_t),0);
        if(ret < sizeof(uint16_t)){
            perror("Errore: errore nella ricezione\n");
            exit(-1);
        }
        pubkey_size = ntohs(lmsg);
        pubkey_buf = (unsigned char*)malloc(pubkey_size);
        ret = recv(sd_comunicazione,pubkey_buf,pubkey_size,0);
        if(ret < pubkey_size){
            perror("Errore: errore nella ricezione\n");
            exit(-1);
        }

        tag_buf=(unsigned char*)malloc(tag_len);
        ricevi(tag_buf,sd_comunicazione);

        tag=(unsigned char*)malloc(tag_len);
        memset(&messaggio_concatenato_v2, 0, pubkey_size + iv_size);
        strncpy(messaggio_concatenato_v2, session_iv_utente2, iv_size);
        strncat(messaggio_concatenato_v2, pubkey_buf, pubkey_size);

        char buffer_firma[session_hmac_size+session_iv_size+session_key_size+100];
        memset(&buffer_firma,0,session_hmac_size+session_iv_size+session_key_size+100);
        strncpy(buffer_firma,nonce,100);
        strncat(buffer_firma,session_key_buf,session_key_size);
        strncat(buffer_firma,session_iv_buf,session_iv_size);
        strncat(buffer_firma,session_hmac_buf,session_hmac_size);
        verificaFirma(buffer_firma,pub_key_utente_chiamato,pubkey_buf,pubkey_size);
        HMAC(EVP_sha256(), session_key_hmac_utente2, 32, messaggio_concatenato_v2, pubkey_size + iv_size, tag, NULL);
        if(memcmp(tag,tag_buf,32)!=0){
            perror("Error: tag diverso\n");
            exit(1);
        }

        incremento_iv(session_iv_utente2);
    
        for(i=0; i<max_utenti;i++){
            if(strcmp(array_utenti[i].utente,username)==0){
                memset(&array_utenti[i].session_iv,0,iv_size);
                memcpy(array_utenti[i].session_iv,session_iv_utente2,iv_size);
                break;
            }
        }
        free(tag_buf);
        free(tag);

        //invio la chiave di sessione all'utente chiamante
        lmsg = htons(session_key_size);
        send(new_sd,(void*)&lmsg,sizeof(uint16_t),0);
        send(new_sd,session_key_buf,session_key_size,0);

        //invio l'iv di sessione all'utente chiamante
        lmsg = htons(session_iv_size);
        send(new_sd,(void*)&lmsg,sizeof(uint16_t),0);
        send(new_sd,session_iv_buf,session_iv_size,0);

        //invio la chiave di sessione hmac all'utente chiamante
        lmsg = htons(session_hmac_size);
        send(new_sd,(void*)&lmsg,sizeof(uint16_t),0);
        send(new_sd,session_hmac_buf,session_hmac_size,0);

        ////invio all'utente chiamante della firma finale con hmac della firma
        lmsg = htons(pubkey_size);
        send(new_sd,(void*)&lmsg,sizeof(uint16_t),0);
        send(new_sd,pubkey_buf,pubkey_size,0);
        
        tag=(unsigned char*)malloc(tag_len);
        memset(&messaggio_concatenato_v2, 0, pubkey_size + iv_size);
        strncpy(messaggio_concatenato_v2, session_iv, iv_size);
        strncat(messaggio_concatenato_v2, pubkey_buf, pubkey_size);
        HMAC(EVP_sha256(), session_key_hmac, 32, messaggio_concatenato_v2, pubkey_size + iv_size, tag, NULL);
        invia(tag,new_sd,tag_len);
        incremento_iv(session_iv);
    
        for(i=0; i<max_utenti;i++){
            if(strcmp(array_utenti[i].utente,utente_chiamante)==0){
                memset(&array_utenti[i].session_iv,0,iv_size);
                memcpy(array_utenti[i].session_iv,session_iv,iv_size);
                break;
            }
        }
        free(tag);
        free(pubkey_buf);
        free(session_hmac_buf);

        //genero i thread di gestione chat
        pthread_t thread_invia, thread_ricevi;
        parametri_thread_chat parametri;
        parametri.new_sd = new_sd;
        parametri.sd_comunicazione=sd_comunicazione;
        parametri.thread_invia=&thread_invia;
        parametri.thread_ricevi=&thread_ricevi;

        memset(&parametri.session_key_utente1,0,symkey_size);
        memcpy(parametri.session_key_utente1,session_key,symkey_size);
        memset(&parametri.session_key_hmac_utente1,0,symkey_size);
        memcpy(parametri.session_key_hmac_utente1,session_key_hmac,symkey_size);
        memset(&parametri.session_iv_utente1,0,iv_size);
        memcpy(parametri.session_iv_utente1,session_iv,iv_size);
        memset(&parametri.username_chiamante,0,len_buffer);
        memcpy(parametri.username_chiamante,utente_chiamante,len_buffer);

        memset(&parametri.session_key_utente2,0,symkey_size);
        memcpy(parametri.session_key_utente2,session_key_utente2,symkey_size);
        memset(&parametri.session_key_hmac_utente2,0,symkey_size);
        memcpy(parametri.session_key_hmac_utente2,session_key_hmac_utente2,symkey_size);
        memset(&parametri.session_iv_utente2,0,iv_size);
        memcpy(parametri.session_iv_utente2,session_iv_utente2,iv_size);  
        memset(&parametri.username_chiamato,0,len_buffer);
        memcpy(parametri.username_chiamato,username,len_buffer);

        pthread_create(&thread_invia,NULL,&thread_function_invia,&parametri);

        pthread_create(&thread_ricevi,NULL,&thread_function_ricevi,&parametri);

        pthread_join(thread_invia,NULL);
        pthread_join(thread_ricevi,NULL);

        EVP_PKEY_free(pub_key_utente_chiamante);
        EVP_PKEY_free(pub_key_utente_chiamato);
        BIO_free(mbio_utente_chiamato);
        BIO_free(mbio);
        
    }else{ //utente rifiuta la comunicazione
        memset(&cmd_cipher,0,len_buffer);
        unsigned char *tag_buf;
        tag_buf=(unsigned char*)malloc(tag_len);
        unsigned char esito[len_buffer] = "richiesta rifiutata\n";
        symmetric_encryption(esito,session_key,cmd_cipher,session_iv,tag_buf,utente_chiamante, session_key_hmac);
        invia(cmd_cipher, new_sd,len_buffer);
        invia(tag_buf, new_sd,tag_len);
        free(tag_buf);
    }

    //tolgo gli utenti dalla lista degli utenti occupati
    for(j=0;j<max_utenti;j++){
        if(strcmp(nomi_utenti_occupati[j],username)==0){
            strcpy(nomi_utenti_occupati[j],"");
            break;
        }
    }

    for(j=0;j<max_utenti;j++){
        if(strcmp(nomi_utenti_occupati[j],utente_chiamante)==0){
            strcpy(nomi_utenti_occupati[j],"");
            break;
        }
    }

    return;

}

//funzione che gestisce e controlla i comandi ricevuti dal client
int controlla_comando(char* cmd, char* username_utente, int new_sd, thread_str* array_utenti, char* session_key, char* session_iv, char* session_key_hmac){ 
 
    //occorre usare delle variabili di appoggio
    //per spezzare le stringhe date in input al client 
    //al fine di anallizzare il comando correttamente
    int quanteParole = 0;
    char delimiter[2] = " "; //delimitatori sono semplicemente spazi bianchi
    char* token = strtok(cmd, delimiter);
    //per salvare le parole, devo utilizzare un array di strighe 
    char parole[40][len_buffer];
    char cmd_cipher[len_buffer];
 
    int i;
    for(i = 0; i<40; i++) strcpy(parole[i], ""); //devo inizializzarlo
 
    while( token != NULL){ //uso while per salvare le parole nell'array
        strcpy(parole[quanteParole++],token);
        token = strtok(NULL, delimiter);
    }

    if((strcmp(parole[0], "!utenti_online\n") == 0)  && quanteParole < 2){
        int i;
        int k = 0; 
        //due buffer di appoggio per copiare in uno e poi concatenare nell'altro e fare un'unica stampa
        char lista_utenti[len_buffer] = "";
        char appoggio[len_buffer+8] = "";

        for(i =0; i<max_utenti; i++){
            if(strcmp(array_utenti[i].utente,username_utente) == 0 || strcmp(array_utenti[i].utente,"")==0){ //se trovo l'utente che ha fatto la richiesta, ovviamente non lo restituisco
                continue;
            }
            sprintf(appoggio,"utente: %s",array_utenti[i].utente);//aggiungo l'utente
            strcat(lista_utenti,appoggio);//concateno alla lista
            k++;
        }
        if(k==0){
            sprintf(appoggio,"nessun utente");//scrivo che non c'è nessun utente 
            strcat(lista_utenti,appoggio);
        }
        memset(&cmd_cipher,0,len_buffer);
        unsigned char *tag_buf;
        tag_buf=(unsigned char*)malloc(tag_len);
        symmetric_encryption(lista_utenti,session_key,cmd_cipher,session_iv,tag_buf,username_utente, session_key_hmac);
        invia(cmd_cipher, new_sd,len_buffer);
        invia(tag_buf, new_sd,tag_len);
        free(tag_buf);
        return 1;
    } 
    if((strcmp(parole[0], "!esci\n") == 0) && quanteParole < 2){
        //funzione che si occupa della chiusura della connessione con il client
        char richiestachiusura[len_buffer] = "ricevuta disconnessione"; //variabile che conterrà il messaggio da inviare
        memset(&cmd_cipher,0,len_buffer);
        unsigned char *tag_buf;
        tag_buf=(unsigned char*)malloc(tag_len);
        symmetric_encryption(richiestachiusura,session_key,cmd_cipher,session_iv,tag_buf,username_utente, session_key_hmac);
        invia(cmd_cipher, new_sd,len_buffer);
        invia(tag_buf, new_sd,tag_len);
        free(tag_buf);
        elimina_utente(username_utente,array_utenti);
        return 1;
    } 
    if((strcmp(parole[0],"!chat") == 0)  && quanteParole < 3 ){ //da problemi in fase di ritorno verso il client, forse il client si aspetta una invio di ritorno
        int i;
        for(i=0;i<max_utenti;i++){
            if(strcmp(nomi_utenti_occupati[i],parole[1])==0){
                return 0;
            }
        }
        for(i = 0; i<max_utenti; i++){
            if((strcmp(parole[1],array_utenti[i].utente) == 0) && (strcmp(parole[1],username_utente)!=0)){ 
                gestisci_inizializzazione_chat(parole[1],username_utente,new_sd,array_utenti, session_key, session_iv, session_key_hmac);
                return 1;
            }
        }
        return 0;
    }
    return 0;
}
