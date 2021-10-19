#include <stdio.h> 
#include <limits.h> 
#include <string.h> 
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h> 
#include <openssl/hmac.h>
#define len_buffer 10000 //dimensione massima dei buffer
#define symkey_size 32 
#define iv_size 13
#define tag_len 32

void invia(char* cmd,int new_sd,int len){
    int ret; //,len; //variabile per gli erorri e per la lunghezza
    uint16_t lmsg; //variabile per contenere la lunghezza del messaggio
    lmsg=htons(len); // trasformo la lunghezza 
    ret=send(new_sd,(void*)&lmsg,sizeof(uint16_t),0); //invio la lunghezza
    if(ret<sizeof(uint16_t)){
        perror("Errore in fase di invio della lunghezza: \n");
        exit(-1);
    }
    ret=send(new_sd,(void*)cmd,len,0); //invio il messaggio della lunghezza precedentemente inviata
    if(ret<len){
        perror("Errore in fase di invio del comando: \n");
        exit(-1);
    }
}

void ricevi(char* cmd,int new_sd){
    int ret,len;  //variabile per gli erorri e per la lunghezza
    uint16_t lmsg; //variabile per contenere la lunghezza del messaggio
    ret=recv(new_sd,(void*)&lmsg,sizeof(uint16_t),0); //ricevo la lunghezza
    if(ret<sizeof(uint16_t)){
        perror("Errore in fase di ricezione della lunghezza: \n");
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

//funzione per controllare che il comando inserito dal client sia corretto dal punto di vista sintattico
int controlla_comando(char* cmd){ 
 
    //occorre usare delle variabili di appoggio
    //per spezzare le stringhe date in input al client 
    //al fine di anallizzare il comando correttamente
    int quanteParole = 0;
    char delimiter[2] = " "; //delimitatori sono semplicemente spazi bianchi
    char* token = strtok(cmd, delimiter);
    //per salvare le parole, devo utilizzare un array di strighe 
    char parole[40][len_buffer]; //40 sono le massime parole considerate nell'inserimento del comando
 
    int i;
    for(i = 0; i<40; i++) strcpy(parole[i], ""); //devo inizializzarlo
 
    while( token != NULL){ //uso while per salvare le parole nell'array
        strcpy(parole[quanteParole++],token);
        token = strtok(NULL, delimiter);
    }
    if((strcmp(parole[0], "!utenti_online\n") == 0) && quanteParole < 2){
        return 1;
 
    } 
    if((strcmp(parole[0], "!esci\n") == 0) && quanteParole < 2){
        return 1;
 
    } 
    if((strcmp(parole[0],"!chat") == 0) && quanteParole < 3 ){
        return 1;
    }
    return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//FUINZIONI CRITTOGRAFICHE
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

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

//funzione che controlla che un messaggio sia firmato correttamente
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

//funzione che autentica il server
void controlla_firma(int sd, char* server_pubkey){

    int ret;

    //apro file certificato CA
    FILE* cacert_file = fopen("ProjectCA_cert.pem", "r");
    if(!cacert_file){ 
        perror("Error: impossibile aprire il file ProjectCA.pem\n"); 
        exit(1); 
    }
    X509* cacert = PEM_read_X509(cacert_file, NULL, NULL, NULL);
    fclose(cacert_file);
    if(!cacert){ 
        perror("Error: PEM_read_X509 ha ritornato NULL\n"); 
        exit(1); 
    }

    // carico crl 
    FILE* crl_file = fopen("ProjectCA_crl.pem", "r");
    if(!crl_file){ 
        perror("Error: impossibile aprire il file ProjectCA_crl.pem\n"); 
        exit(1); 
    }
    X509_CRL* crl = PEM_read_X509_CRL(crl_file, NULL, NULL, NULL);
    fclose(crl_file);
    if(!crl){ 
        perror("Error: PEM_read_X509_CRL ha ritornato NULL\n"); 
        exit(1); 
    }

    // costruisco uno store con il certificato della CA e il crl
    X509_STORE* store = X509_STORE_new();
    if(!store) { 
        perror("Error: X509_STORE_new ha ritornato NULL\n"); 
        exit(1); 
    }
    ret = X509_STORE_add_cert(store, cacert);
    if(ret != 1) { 
        perror("Error: X509_STORE_add_cert ha ritornato 0\n"); 
        exit(1); 
    }
    ret = X509_STORE_add_crl(store, crl);
    if(ret != 1) { 
        perror("Error: X509_STORE_add_crl ha ritornato 0\n"); 
        exit(1); 
    }
    ret = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
    if(ret != 1) { 
        perror("Error: X509_STORE_set_flags ha ritornato 0\n"); 
        exit(1); 
    }

    //ricevo il certificato dal server e lo controllo
    uint16_t lmsg;
    ret = recv(sd,(void*)&lmsg,sizeof(uint16_t),0);
    if(ret < sizeof(uint16_t)){
        perror("Errore: errore nella ricezione\n");
        exit(-1);
    }
    long pubkey_size = ntohs(lmsg);
    unsigned char* pubkey_buf = (unsigned char*)malloc(pubkey_size);
    ret = recv(sd,pubkey_buf,pubkey_size,0);
    if(ret < pubkey_size){
        perror("Errore: errore nella ricezione\n");
        exit(-1);
    }

    X509* cert;
    BIO* mbio = BIO_new(BIO_s_mem());
    BIO_write(mbio,pubkey_buf,pubkey_size);
    cert = PEM_read_bio_X509(mbio,NULL,NULL,NULL);

    X509_STORE_CTX* certvfy_ctx = X509_STORE_CTX_new();
    if(!certvfy_ctx) { 
        perror("Error: certvfy_ctx ha ritornato NULL\n"); 
        exit(1); 
    }
    ret = X509_STORE_CTX_init(certvfy_ctx, store, cert, NULL);
    if(ret != 1) { 
        perror("Error: X509_STORE_CTX_init ha ritornato 0\n"); 
        exit(1); 
    }
    ret = X509_verify_cert(certvfy_ctx);
    if(ret != 1) { 
        perror("Error: X509_verify_cert ha ritornato 0\n"); 
        exit(1); 
    }

    //prelevo la chiave pubblica del server
    EVP_PKEY* pubkey = X509_get_pubkey(cert);
   

    BIO* mbio_2 = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(mbio_2,pubkey);
    char* pubkey_buf_2 = NULL;
    long pubkey_size_2 = BIO_get_mem_data(mbio_2, &pubkey_buf_2);

    memcpy(server_pubkey,pubkey_buf_2,pubkey_size_2);

    // deallocate data:
    X509_free(cert);
    X509_STORE_free(store);
    X509_STORE_CTX_free(certvfy_ctx);
    EVP_PKEY_free(pubkey);
    free(pubkey_buf);
    free(pubkey_buf_2);
    BIO_free(mbio);
    BIO_free(mbio_2);

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


//funzione che autentica il client
void autenticazione(int sd, EVP_PKEY* prvkey){

    int ret;

    unsigned char* signature = malloc(EVP_PKEY_size(prvkey));
    unsigned int signature_len;

    //ricevo il nonce
    char nonce[100];
    memset(&nonce,0,100);
    ricevi(nonce,sd);

    //firmo il nonce
    ret = firmaDigitale(nonce,prvkey,signature,&signature_len);
    if(ret == 0){
        perror("Errore: firmaDigitale\n");
        exit(-1);
    }

    uint16_t lmsg = htons(signature_len);
    send(sd,(void*)&lmsg,sizeof(uint16_t),0);
    send(sd,signature,signature_len,0);

    free(signature);

}

//funzione per scambiare la chiave di sessione, l'iv e la chiave per l'HMAC
void perfect_forward_secrecy(int sd, char* username, unsigned char* session_key, char* session_iv, char* session_key_hmac, char* chiave_server,char* porta_da_usare){
    
    int ret;
    RSA* temp_priv_key;
    EVP_PKEY* temp_pub_key;

    //ricevo il nonce dal server M1
    char nonce[100];
    memset(&nonce,0,100);
    ricevi(nonce,sd);

    //ricevo il certificato del server e lo controllo M2
    controlla_firma(sd,chiave_server);

    BIO* mbio_supporto = BIO_new(BIO_s_mem());
    EVP_PKEY* pubkey_server = EVP_PKEY_new();
    BIO_write(mbio_supporto,chiave_server,len_buffer);
    pubkey_server = PEM_read_bio_PUBKEY(mbio_supporto,NULL,NULL,NULL);

    //invio R' (il nonce del client) M3
    RAND_poll();
    char nonce_client[100];
    memset(&nonce_client,0,100);
    ret = RAND_bytes((char*)nonce_client,100);
    if(ret != 1){
        perror("RAND_bytes ha fallito");
        exit(-1);
    }
    nonce_client[100]='\0';
    invia(nonce_client,sd,100);


    //client inserisce il proprio username e lo invia al server M4
    int nome_occupato = 0;
    char username_supporto[len_buffer];
    while(nome_occupato==0){
        nome_occupato = 1;
        printf("Inserire il proprio username: \n");
        char messaggio_errore[len_buffer];
        memset(&username_supporto,0,len_buffer);
        memset(&messaggio_errore,0,len_buffer);
        fgets(username_supporto, len_buffer, stdin);
        invia(username_supporto, sd, len_buffer);
        ricevi(messaggio_errore,sd);
        printf("%s\n",messaggio_errore);
        //viene controllato se lo username è già online
        if(strcmp(messaggio_errore,"nome occupato")==0){
            nome_occupato = 0;
        }
    }
    memcpy(username,username_supporto,len_buffer);

    //prelevo la chiave privata
    EVP_PKEY* priv_key;
    char nome_file[len_buffer+9];
    strncpy(nome_file,username,strlen(username));
    sprintf(nome_file+strlen(username)-1,"_priv.pem");
    FILE* privkey_file = fopen(nome_file, "r");
    if(!privkey_file){ 
        perror("Error: errore nell'apertura del file contenente la chiave pubblica dell'utente\n"); 
        exit(1); 
    }
    priv_key= PEM_read_PrivateKey(privkey_file, NULL, NULL, NULL);
    fclose(privkey_file);
    if(!priv_key){ 
        perror("Error: PEM_read_PubKey ha ritornato NULL\n"); 
        exit(1); 
    }


    //creo le chiavi temporanee
    RSA* rsa = NULL;
    BIGNUM* bne = NULL;
    BIO* temp_bio = NULL;
    int bit = 2048;
    unsigned long e = RSA_F4;
    bne = BN_new();
    ret = BN_set_word(bne,e);
    if(ret != 1){
        perror("Error: BN_set_word ha ritornato !=1\n"); 
        exit(1);
    }
    rsa = RSA_new();
    ret = RSA_generate_key_ex(rsa,bit,bne,NULL);
    if(ret != 1){
        perror("Error: RSA_generate_key_ex ha ritornato !=1\n"); 
        exit(1);
    }
    temp_bio = BIO_new(BIO_s_mem());
    ret = PEM_write_bio_RSAPrivateKey(temp_bio,rsa,NULL,NULL,0,NULL,NULL);
    if(ret != 1){
        perror("Error: PEM_write_bio_RSAPrivateKey ha ritornato !=1\n"); 
        exit(1);
    }

    //leggo le chiavi temporanee
    temp_priv_key= PEM_read_bio_RSAPrivateKey(temp_bio, NULL, NULL, NULL);
    if(!temp_priv_key){ 
        perror("Error: PEM_read_RSAPrivateKey ha ritornato NULL\n"); 
        exit(1); 
    }

    EVP_PKEY* chiave_supporto = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(chiave_supporto,rsa);

    BIO* temp_bio_2 = NULL;
    temp_bio_2 = BIO_new(BIO_s_mem());
    ret = PEM_write_bio_PUBKEY(temp_bio_2,chiave_supporto);
    if(ret != 1){
        perror("Error: PEM_write_bio_PUBKEY ha ritornato !=1\n"); 
        exit(1);
    }
    temp_pub_key = PEM_read_bio_PUBKEY(temp_bio_2,NULL,NULL,NULL);
    if(!temp_pub_key){ 
        perror("Error: PEM_read_bio_PUBKEY ha ritornato NULL\n"); 
        exit(1); 
    }

    BIO* mbio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(mbio,temp_pub_key);
    char* pubkey_buf = NULL;
    long pubkey_size = BIO_get_mem_data(mbio, &pubkey_buf);

    //invio la chiave pubblica temporanea M5
    uint16_t lmsg = htons(pubkey_size);
    send(sd,(void*)&lmsg,sizeof(uint16_t),0);
    send(sd,pubkey_buf,pubkey_size,0);
    pubkey_buf[pubkey_size] = '\0';

    char buffer[pubkey_size+100+len_buffer];
    memset(&buffer,0,pubkey_size+100+len_buffer);
    strncpy(buffer,nonce,100);
    strncat(buffer,pubkey_buf,pubkey_size);
    strncat(buffer,username,len_buffer);

    unsigned char* signature = malloc(EVP_PKEY_size(priv_key));
    unsigned int signature_len;

    //firmo il R||Tpubk||username M6
    ret = firmaDigitale(buffer,priv_key,signature,&signature_len);
    if(ret == 0){
        perror("Errore: Perfect forward secrecy\n");
        exit(-1);
    }

    lmsg = htons(signature_len);
    send(sd,(void*)&lmsg,sizeof(uint16_t),0); 
    send(sd,signature,signature_len,0);


    //ricevo la chiave summetrica cifrata e la decifro M7
    lmsg = 0;
    ret = recv(sd,(void*)&lmsg,sizeof(uint16_t),0);
    if(ret < sizeof(uint16_t)){
        perror("Errore: receive1\n");
        exit(-1);
    }
    int len_messaggio_key = ntohs(lmsg);
    char* msg_encrypt;
    msg_encrypt = (char*)malloc(len_messaggio_key);
    msg_encrypt[len_messaggio_key] = '\0';
    ret = recv(sd,msg_encrypt,len_messaggio_key,0);
    if(ret < len_messaggio_key){
        perror("Errore: receive2\n");
        exit(-1);
    }

    unsigned char* msg_decrypt = malloc(symkey_size + 1);

    ret = RSA_private_decrypt(len_messaggio_key,msg_encrypt,msg_decrypt,temp_priv_key,RSA_PKCS1_PADDING);
    if(ret == -1){
        perror("RSA_public_encrypt ha fallito");
        exit(-1);
    }

   
    // setto la variabile che conterrà la chiave di sessione
    memcpy(session_key, msg_decrypt, symkey_size);
    
    //ricevo l'iv cifrato e lo decifro M8
    lmsg = 0;
    ret = recv(sd,(void*)&lmsg,sizeof(uint16_t),0);
    if(ret < sizeof(uint16_t)){
        perror("Errore: receive1\n");
        exit(-1);
    }
    int len_messaggio_iv = ntohs(lmsg);
    char* iv_encrypt;
    iv_encrypt = (char*)malloc(len_messaggio_iv);
    iv_encrypt[len_messaggio_iv] = '\0';
    ret = recv(sd,iv_encrypt,len_messaggio_iv,0);
    if(ret < len_messaggio_iv){
        perror("Errore: receive2\n");
        exit(-1);
    }

    unsigned char* iv_decrypt = malloc(iv_size);

    ret = RSA_private_decrypt(len_messaggio_iv,iv_encrypt,iv_decrypt,temp_priv_key,RSA_PKCS1_PADDING);
    if(ret == -1){
        perror("RSA_public_encrypt ha fallito");
        exit(-1);
    }


    // setto la variabile che conterrà l'iv di sessione
    memcpy(session_iv, iv_decrypt, iv_size);

    //ricevo l'HMAC cifrato e lo decifro M9
    lmsg = 0;
    ret = recv(sd,(void*)&lmsg,sizeof(uint16_t),0);
    if(ret < sizeof(uint16_t)){
        perror("Errore: receive1\n");
        exit(-1);
    }
    int len_messaggio_hmac = ntohs(lmsg);
    char* msg_encrypt_hmac;
    msg_encrypt_hmac = (char*)malloc(len_messaggio_hmac);
    msg_encrypt_hmac[len_messaggio_hmac] = '\0';
    ret = recv(sd,msg_encrypt_hmac,len_messaggio_hmac,0);
    if(ret < len_messaggio_hmac){
        perror("Errore: receive2\n");
        exit(-1);
    }

    unsigned char* msg_decrypt_hmac = malloc(symkey_size + 1);

    ret = RSA_private_decrypt(len_messaggio_hmac,msg_encrypt_hmac,msg_decrypt_hmac,temp_priv_key,RSA_PKCS1_PADDING);
    if(ret == -1){
        perror("RSA_public_encrypt ha fallito");
        exit(-1);
    }


    // setto la variabile che conterrà la chiave di sessione
    memcpy(session_key_hmac, msg_decrypt_hmac, symkey_size);

    //ricevo la porta M10
    ricevi(porta_da_usare,sd);

    //creo il buffer della firma
    char buffer_firma[len_messaggio_key+len_messaggio_iv+len_messaggio_hmac+100+len_buffer];
    memset(&buffer_firma,0,len_messaggio_key+len_messaggio_iv+len_messaggio_hmac+100+len_buffer);
    memcpy(buffer_firma,nonce_client,100);
    memcpy(buffer_firma+100,msg_encrypt,len_messaggio_key);
    memcpy(buffer_firma+100+len_messaggio_key,iv_encrypt,len_messaggio_iv);
    memcpy(buffer_firma+100+len_messaggio_key+len_messaggio_iv,iv_encrypt,len_messaggio_hmac);
    memcpy(buffer_firma+100+len_messaggio_key+len_messaggio_iv+len_messaggio_hmac,porta_da_usare,len_buffer);

    //ricevo la firma di R'||symkey||iv||hmac||porta M11
    lmsg = 0;
    ret = recv(sd,(void*)&lmsg,sizeof(uint16_t),0);
    if(ret < sizeof(uint16_t)){
        perror("Errore: receive1\n");
        exit(-1);
    }
    int len_messaggio = ntohs(lmsg);
    char* signature_finale;
    signature_finale = (char*)malloc(len_messaggio);
    signature_finale[len_messaggio] = '\0';
    ret = recv(sd,signature_finale,len_messaggio,0);
    if(ret < len_messaggio){
        perror("Errore: receive2\n");
        exit(-1);
    }

    ret = verificaFirma(buffer_firma,pubkey_server,signature_finale,len_messaggio);
    if(ret == 0){
            perror("Errore: Perfect forward secrecy\n");
            exit(-1);
    } 


    free(signature);
    free(msg_encrypt);
    free(msg_decrypt);
    free(msg_encrypt_hmac);
    free(msg_decrypt_hmac);
    free(iv_decrypt);
    free(iv_encrypt);
    EVP_PKEY_free(temp_pub_key);
    RSA_free(temp_priv_key);
    EVP_PKEY_free(priv_key);
    free(signature_finale);
    //free(signature_m6);
    //free(signature_m10);
    BIO_free(mbio);
    BIO_free(temp_bio);
    BIO_free(mbio_supporto);
    EVP_PKEY_free(pubkey_server);
    BN_free(bne);
    BIO_free(temp_bio_2);
    EVP_PKEY_free(chiave_supporto);


}

//funzione per scambaire la chiave di sessione, l'iv e la chiave per l'HMAC per il client che subisce la chat
void perfect_forward_secrecy_chat(int new_sd, EVP_PKEY* user_pub_key, char* session_key, char* session_iv,char* username, char* session_key_hmac, char* session_iv_server, char* session_key_hmac_server){

    int ret;

    //genero il nonce da inviare M7
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

    char messaggio_concatenato[100 + iv_size];
    memset(&messaggio_concatenato, 0, 100 + iv_size);
    strncpy(messaggio_concatenato, session_iv_server, iv_size);
    strncat(messaggio_concatenato, nonce, 100);
    char* tag=(unsigned char*)malloc(tag_len);
    HMAC(EVP_sha256(), session_key_hmac_server, 32, messaggio_concatenato, 100 + iv_size, tag, NULL);
    invia(tag,new_sd,tag_len);
    incremento_iv(session_iv_server);

    free(tag);

    //ricevo la chiave pubblica temporanea M11
    uint16_t lmsg;
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

    //creo il messaggio comcatenato nonce||pubkey_buf
    char buffer[len_buffer];
    memset(&buffer,0,len_buffer);
    strncpy(buffer,nonce,100);
    strncat(buffer,pubkey_buf,pubkey_size);

    //ricevo il nonce||pubkey_buf firmata e la controllo M12
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
    
    ret = verificaFirma(buffer,user_pub_key,messaggio,len_messaggio);
    if(ret == 0){
        perror("Errore: Perfect forward secrecy\n");
        exit(-1);
    }
    
    char* tag_buf=(unsigned char*)malloc(tag_len);
    ricevi(tag_buf,new_sd);
    char messaggio_concatenato_v2[len_messaggio + iv_size];
    memset(&messaggio_concatenato_v2, 0, len_messaggio + iv_size);
    strncpy(messaggio_concatenato_v2, session_iv_server, iv_size);
    strncat(messaggio_concatenato_v2, messaggio, len_messaggio);
    tag=(unsigned char*)malloc(tag_len);
    
    HMAC(EVP_sha256(), session_key_hmac_server, 32, messaggio_concatenato_v2, len_messaggio + iv_size, tag, NULL);
    incremento_iv(session_iv_server);
    
    if(memcmp(tag,tag_buf,32)!=0){
        perror("Error: tag diverso\n");
        exit(1);
    }

    free(tag);
    free(tag_buf);

    //ricevi R' (il nonce del client) M14
    char nonce_client[100];
    memset(&nonce_client,0,100);
    ricevi(nonce_client,new_sd);

    tag_buf=(unsigned char*)malloc(tag_len);
    ricevi(tag_buf,new_sd);
    memset(&messaggio_concatenato, 0, 100 + iv_size);
    strncpy(messaggio_concatenato, session_iv_server, iv_size);
    strncat(messaggio_concatenato, nonce, 100);
    tag=(unsigned char*)malloc(tag_len);
    HMAC(EVP_sha256(), session_key_hmac_server, 32, messaggio_concatenato, 100 + iv_size, tag, NULL);
    incremento_iv(session_iv_server);

    if(memcmp(tag,tag_buf,32)!=0){
        perror("Error: tag diverso\n");
        exit(1);
    }

    free(tag);
    free(tag_buf);


    //ritrasformo la chiave in EVP_PUBKEY
    RSA* temp_pub_key;
    BIO* mbio = BIO_new(BIO_s_mem());
    BIO_write(mbio,pubkey_buf,pubkey_size);
    temp_pub_key = PEM_read_bio_RSA_PUBKEY(mbio,NULL,NULL,NULL);

    //genero la chiave simmetrica di sessione e la invio cifrata con la chiave pubblica temporanea M15
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

    //genero l'iv di sessione e la invio cifrata con la chiave pubblica temporanea M16
    RAND_poll();
    char iv[iv_size]; 
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

    //setto la variabile che conterrà l'iv di sessione
    memcpy(session_iv, iv, iv_size);


    // genero la chiave di sessione HMAC e la invio cifrata con la chiave pubblica temporanea M17
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



    //invio la firma completa M18

    char buffer_firma[3*RSA_size(temp_pub_key)+100];
    memset(&buffer_firma,0,RSA_size(temp_pub_key)+100);
    memcpy(buffer_firma,nonce_client,100);
    memcpy(buffer_firma+100,msg_encrypt,RSA_size(temp_pub_key));
    memcpy(buffer_firma+100+RSA_size(temp_pub_key),iv_encrypt,RSA_size(temp_pub_key));
    memcpy(buffer_firma+100+(2*RSA_size(temp_pub_key)),msg_encrypt_hmac,RSA_size(temp_pub_key));


    // ricavo la chiave privata dell'utente
    char nome_file_privkey_mia[len_buffer+9];
    memset(&nome_file_privkey_mia,0,len_buffer+9);
    strncpy(nome_file_privkey_mia,username,strlen(username));
    sprintf(nome_file_privkey_mia+strlen(username)-1,"_priv.pem");
    FILE* chiavePrivata = fopen(nome_file_privkey_mia, "rb");
    if(chiavePrivata == NULL) {
        perror("Errore: File chiave privata\n");
        exit(-1);
    }

    EVP_PKEY* prvkey;
    char password_file[len_buffer];
    memset(&password_file,0,len_buffer);
    strncpy(password_file,username,strlen(username));
    sprintf(password_file+strlen(username)-1,"0");
    prvkey = PEM_read_PrivateKey(chiavePrivata, NULL, NULL, password_file);
    if(prvkey == NULL) {
        perror("Errore: Lettura prvkey\n");
        exit(-1);
    }
    fclose(chiavePrivata);

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


    // tag della firma per il server
    memset(&messaggio_concatenato_v2, 0, signature_len + iv_size);
    strncpy(messaggio_concatenato_v2, session_iv_server, iv_size);
    strncat(messaggio_concatenato_v2, signature, signature_len);
    tag=(unsigned char*)malloc(tag_len);
    HMAC(EVP_sha256(), session_key_hmac_server, 32, messaggio_concatenato_v2, signature_len + iv_size, tag, NULL);
    invia(tag,new_sd,tag_len);
    incremento_iv(session_iv_server);
    free(tag);

    
    free(messaggio);
    free(pubkey_buf);
    RSA_free(temp_pub_key);
    EVP_PKEY_free(prvkey);
    free(msg_encrypt);
    free(msg_encrypt_hmac);
    free(iv_encrypt);
    //free(signature_m8);
    //free(signature_m6);
    //free(signature_m10);

    BIO_free(mbio);
    
}


//funzione per cifrare un messaggio con la chiave simmetrica
int encrypt(unsigned char *plaintext, int plaintext_len, 
                unsigned char *key,
                unsigned char *iv, int iv_len, 
                unsigned char *ciphertext, 
                unsigned char *tag,
                unsigned char* key_hmac){

    EVP_CIPHER_CTX *ctx;
    int len=0;
    int ciphertext_len=0;

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
 
    HMAC_CTX* ctx_hmac = HMAC_CTX_new();

    char messaggio_concatenato[ciphertext_len + iv_size];
    memset(&messaggio_concatenato, 0, ciphertext_len + iv_size);
    strncpy(messaggio_concatenato, iv, iv_size);
    strncat(messaggio_concatenato, ciphertext, ciphertext_len);

    unsigned int outlen;
    HMAC(EVP_sha256(), key_hmac, 32, messaggio_concatenato, ciphertext_len + iv_size, tag, &outlen);
    
    //incremento l'IV in modo che per il prossimo messaggio sia diverso
    incremento_iv(iv);

    EVP_CIPHER_CTX_free(ctx);
    HMAC_CTX_free(ctx_hmac);
    return ciphertext_len;
}


void* symmetric_encryption(char* messaggio, unsigned char* symkey, char* cphr_buf, char* iv_gcm,unsigned char* tag_buf,unsigned char* key_hmac){ //funzione per cifrare i messaggi utilizzando un meccanismo a chiave simmetrica(AES256)

	int cphr_len = 0;
    int pt_len = len_buffer;
    encrypt(messaggio, pt_len, symkey, iv_gcm, 12, cphr_buf, tag_buf, key_hmac);

}

//funzione per decifrare un messaggio con la chiave simmetrica
int decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext,
                unsigned char* key_hmac)
{
    EVP_CIPHER_CTX *ctx;
    int len = 0;
    int plaintext_len = 0;
    int ret;

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

    //incremento l'IV in modo che per il prossimo messaggio sia diverso
    incremento_iv(iv);

    EVP_CIPHER_CTX_free(ctx);
    HMAC_CTX_free(ctx_hmac);
   
    if(ret > 0) {
        plaintext_len += len;
        return plaintext_len;
    } 
}

void* symmetric_decryption( char* cphr_buf, unsigned char* symkey, char* dec_buf, char* iv_gcm, unsigned char* tag_buf,unsigned char* key_hmac){ //funzione per cifrare i messaggi utilizzando un meccanismo a chiave simmetrica(AES256)

	int cphr_len = 0;
    int ct_len = len_buffer;
    decrypt(cphr_buf, ct_len, tag_buf, symkey, iv_gcm, 12, dec_buf, key_hmac);

}

//funzione per scambiare la chiave di sessione, l'iv e la chiave per l'HMAC
void perfect_forward_secrecy_chiamante(int sd, char* username, EVP_PKEY* prvkey, unsigned char* session_key, char* session_iv, EVP_PKEY* pubkey_contatto, char* session_key_hmac, char* session_iv_server,char* session_key_hmac_server){
    
    int ret;
    RSA* temp_priv_key;
    EVP_PKEY* temp_pub_key;

    //ricevo il nonce dal server M8
    char nonce[100];
    memset(&nonce,0,100);
    ricevi(nonce,sd);
    char* tag_buf=(unsigned char*)malloc(tag_len);
    ricevi(tag_buf,sd);
    char messaggio_concatenato[100 + iv_size];
    memset(&messaggio_concatenato, 0, 100 + iv_size);
    strncpy(messaggio_concatenato, session_iv_server, iv_size);
    strncat(messaggio_concatenato, nonce, 100);
    unsigned char* tag=(unsigned char*)malloc(tag_len);
    HMAC(EVP_sha256(), session_key_hmac_server, 32, messaggio_concatenato, 100 + iv_size, tag, NULL);
    incremento_iv(session_iv_server);

    if(memcmp(tag,tag_buf,32)!=0){
        perror("Error: tag diverso\n");
        exit(1);
    }

    free(tag);
    free(tag_buf);


    //creo le chiavi temporanee
    RSA* rsa = NULL;
    BIGNUM* bne = NULL;
    BIO* temp_bio = NULL;
    int bit = 2048;
    unsigned long e = RSA_F4;
    bne = BN_new();
    ret = BN_set_word(bne,e);
    if(ret != 1){
        perror("Error: BN_set_word ha ritornato !=1\n"); 
        exit(1);
    }
    rsa = RSA_new();
    ret = RSA_generate_key_ex(rsa,bit,bne,NULL);
    if(ret != 1){
        perror("Error: RSA_generate_key_ex ha ritornato !=1\n"); 
        exit(1);
    }
    temp_bio = BIO_new(BIO_s_mem());
    ret = PEM_write_bio_RSAPrivateKey(temp_bio,rsa,NULL,NULL,0,NULL,NULL);
    if(ret != 1){
        perror("Error: PEM_write_bio_RSAPrivateKey ha ritornato !=1\n"); 
        exit(1);
    }

    //leggo le chiavi temporanee
    temp_priv_key= PEM_read_bio_RSAPrivateKey(temp_bio, NULL, NULL, NULL);
    if(!temp_priv_key){ 
        perror("Error: PEM_read_RSAPrivateKey ha ritornato NULL\n"); 
        exit(1); 
    }

    EVP_PKEY* chiave_supporto = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(chiave_supporto,rsa);

    BIO* temp_bio_2 = NULL;
    temp_bio_2 = BIO_new(BIO_s_mem());
    ret = PEM_write_bio_PUBKEY(temp_bio_2,chiave_supporto);
    if(ret != 1){
        perror("Error: PEM_write_bio_PUBKEY ha ritornato !=1\n"); 
        exit(1);
    }
    temp_pub_key = PEM_read_bio_PUBKEY(temp_bio_2,NULL,NULL,NULL);
    if(!temp_pub_key){ 
        perror("Error: PEM_read_bio_PUBKEY ha ritornato NULL\n"); 
        exit(1); 
    }

    BIO* mbio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(mbio,temp_pub_key);
    char* pubkey_buf = NULL;
    long pubkey_size = BIO_get_mem_data(mbio, &pubkey_buf);

    //invio la chiave pubblica temporanea M9
    uint16_t lmsg = htons(pubkey_size);
    send(sd,(void*)&lmsg,sizeof(uint16_t),0);
    send(sd,pubkey_buf,pubkey_size,0);
    pubkey_buf[pubkey_size] = '\0';

    char buffer[len_buffer];
    memset(&buffer,0,len_buffer);
    strncpy(buffer,nonce,100);
    strncat(buffer,pubkey_buf,pubkey_size);

    unsigned char* signature = malloc(EVP_PKEY_size(prvkey));
    unsigned int signature_len;

    //firmo la R||Tpubk M10
    ret = firmaDigitale(buffer,prvkey,signature,&signature_len);
    if(ret == 0){
        perror("Errore: Perfect forward secrecy\n");
        exit(-1);
    }

    lmsg = htons(signature_len);
    send(sd,(void*)&lmsg,sizeof(uint16_t),0); 
    send(sd,signature,signature_len,0);

    char messaggio_concatenato_v2[signature_len + iv_size];
    memset(&messaggio_concatenato_v2, 0, signature_len + iv_size);
    strncpy(messaggio_concatenato_v2, session_iv_server, iv_size);
    strncat(messaggio_concatenato_v2, signature, signature_len);
    tag=(unsigned char*)malloc(tag_len);
    HMAC(EVP_sha256(), session_key_hmac_server, 32, messaggio_concatenato_v2, signature_len + iv_size, tag, NULL);
    invia(tag,sd,tag_len);
    incremento_iv(session_iv_server);

    free(tag);

    //invio R' (il nonce del client) M13
    RAND_poll();
    char nonce_client[100];
    memset(&nonce_client,0,100);
    ret = RAND_bytes((char*)nonce_client,100);
    if(ret != 1){
        perror("RAND_bytes ha fallito");
        exit(-1);
    }
    nonce_client[100]='\0';
    invia(nonce_client,sd,100);

    memset(&messaggio_concatenato, 0, 100 + iv_size);
    strncpy(messaggio_concatenato, session_iv_server, iv_size);
    strncat(messaggio_concatenato, nonce, 100);
    tag=(unsigned char*)malloc(tag_len);
    HMAC(EVP_sha256(), session_key_hmac_server, 32, messaggio_concatenato, 100 + iv_size, tag, NULL);
    invia(tag,sd,tag_len);
    incremento_iv(session_iv_server);

    free(tag);

    //ricevo la chiave summetrica cifrata e la decifro M19
    int len_messaggio;
    lmsg = 0;
    ret = recv(sd,(void*)&lmsg,sizeof(uint16_t),0);
    if(ret < sizeof(uint16_t)){
        perror("Errore: receive1\n");
        exit(-1);
    }
    len_messaggio = ntohs(lmsg);
    char* msg_encrypt;
    msg_encrypt = (char*)malloc(len_messaggio);
    msg_encrypt[len_messaggio] = '\0';
    ret = recv(sd,msg_encrypt,len_messaggio,0);
    if(ret < len_messaggio){
        perror("Errore: receive2\n");
        exit(-1);
    }

    unsigned char* msg_decrypt = malloc(symkey_size + 1);

    ret = RSA_private_decrypt(len_messaggio,msg_encrypt,msg_decrypt,temp_priv_key,RSA_PKCS1_PADDING);
    if(ret == -1){
        perror("RSA_public_encrypt ha fallito");
        exit(-1);
    }

   
    // setto la variabile che conterrà la chiave di sessione
    memcpy(session_key, msg_decrypt, symkey_size);
    
    //ricevo l'iv cifrato e lo decifro M20
    lmsg = 0;
    ret = recv(sd,(void*)&lmsg,sizeof(uint16_t),0);
    if(ret < sizeof(uint16_t)){
        perror("Errore: receive1\n");
        exit(-1);
    }
    len_messaggio = ntohs(lmsg);
    char* iv_encrypt;
    iv_encrypt = (char*)malloc(len_messaggio);
    iv_encrypt[len_messaggio] = '\0';
    ret = recv(sd,iv_encrypt,len_messaggio,0);
    if(ret < len_messaggio){
        perror("Errore: receive2\n");
        exit(-1);
    }

    unsigned char* iv_decrypt = malloc(iv_size);

    ret = RSA_private_decrypt(len_messaggio,iv_encrypt,iv_decrypt,temp_priv_key,RSA_PKCS1_PADDING);
    if(ret == -1){
        perror("RSA_public_encrypt ha fallito");
        exit(-1);
    }

    
    // setto la variabile che conterrà l'iv di sessione
    memcpy(session_iv, iv_decrypt, iv_size);

    //ricevo l'HMAC cifrato e lo decifro M21
    len_messaggio = 0;
    lmsg = 0;
    ret = recv(sd,(void*)&lmsg,sizeof(uint16_t),0);
    if(ret < sizeof(uint16_t)){
        perror("Errore: receive1\n");
        exit(-1);
    }
    len_messaggio = ntohs(lmsg);
    char* msg_encrypt_hmac;
    msg_encrypt_hmac = (char*)malloc(len_messaggio);
    msg_encrypt_hmac[len_messaggio] = '\0';
    ret = recv(sd,msg_encrypt_hmac,len_messaggio,0);
    if(ret < len_messaggio){
        perror("Errore: receive2\n");
        exit(-1);
    }

    unsigned char* msg_decrypt_hmac = malloc(symkey_size + 1);

    ret = RSA_private_decrypt(len_messaggio,msg_encrypt_hmac,msg_decrypt_hmac,temp_priv_key,RSA_PKCS1_PADDING);
    if(ret == -1){
        perror("RSA_public_encrypt ha fallito");
        exit(-1);
    }

    
    // setto la variabile che conterrà la chiave di sessione
    memcpy(session_key_hmac, msg_decrypt_hmac, symkey_size);

    //ricevo la firma finale e lo controllo M22
    lmsg = 0;
    ret = recv(sd,(void*)&lmsg,sizeof(uint16_t),0);
    if(ret < sizeof(uint16_t)){
        perror("Errore: receive1\n");
        exit(-1);
    }
    len_messaggio = ntohs(lmsg);
    char* signature_server;
    signature_server = (char*)malloc(len_messaggio);
    signature_server[len_messaggio] = '\0';
    ret = recv(sd,signature_server,len_messaggio,0);
    if(ret < len_messaggio){
        perror("Errore: receive2\n");
        exit(-1);
    }

    char buffer_firma[3*EVP_PKEY_size(temp_pub_key)+100];
    memset(&buffer_firma,0,3*EVP_PKEY_size(temp_pub_key)+100);
    memcpy(buffer_firma,nonce_client,100);
    memcpy(buffer_firma+100,msg_encrypt,EVP_PKEY_size(temp_pub_key));
    memcpy(buffer_firma+100+EVP_PKEY_size(temp_pub_key),iv_encrypt,EVP_PKEY_size(temp_pub_key));
    memcpy(buffer_firma+100+(2*EVP_PKEY_size(temp_pub_key)),msg_encrypt_hmac,EVP_PKEY_size(temp_pub_key));
    verificaFirma(buffer_firma,pubkey_contatto,signature_server,len_messaggio);
    tag_buf=(unsigned char*)malloc(tag_len);
    ricevi(tag_buf,sd);
    memset(&messaggio_concatenato_v2, 0, len_messaggio + iv_size );
    strncpy(messaggio_concatenato_v2, session_iv_server, iv_size  );
    strncat(messaggio_concatenato_v2, signature_server, len_messaggio );
    tag=(unsigned char*)malloc(tag_len);
    
    HMAC(EVP_sha256(), session_key_hmac_server, 32, messaggio_concatenato_v2, len_messaggio + iv_size , tag, NULL);
    incremento_iv(session_iv_server);
    
    if(memcmp(tag,tag_buf,32)!=0){
        perror("Error: tag diverso\n");
        exit(1);
    }

    free(tag);
    free(tag_buf);


    free(signature);
    free(signature_server);
    free(msg_encrypt);
    free(msg_decrypt);
    free(msg_encrypt_hmac);
    free(msg_decrypt_hmac);
    free(iv_decrypt);
    free(iv_encrypt);
    EVP_PKEY_free(temp_pub_key);
    RSA_free(temp_priv_key);
    //free(signature_m8);
    //free(signature_m6);
    //free(signature_m10);
    BIO_free(mbio);
    BIO_free(temp_bio);
    BN_free(bne);
    BIO_free(temp_bio_2);
    EVP_PKEY_free(chiave_supporto);


}
