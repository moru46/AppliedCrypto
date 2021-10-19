#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <signal.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h> 
#include <string.h> 
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <signal.h>
#include "client_function.h"
#include <sys/shm.h>
#include <sys/stat.h>

typedef struct {
    int sd_server;
    char session_key[symkey_size];
    char session_iv[iv_size];
    char session_key_hmac[symkey_size];
    char session_key_server[symkey_size];
    char session_key_hmac_server[symkey_size];
    char username[len_buffer];
    pthread_t* thread_invia;
    pthread_t* thread_ricevi;
}parametri_thread_chat;

pthread_mutex_t semaforo;
pthread_cond_t condizione;
pthread_cond_t condizione_gia_premuto;
int chi_parla = 0;

char session_iv_server[iv_size];

int gia_premuto;

char yes_no[len_buffer];

struct sockaddr_in mittente_addr, my_addr;
int sd_chat;
int len;

//thread utilizzato durante la chat per inviare messaggi
void* thread_function_invia(void* parametri){
    parametri_thread_chat* arg = (parametri_thread_chat*)parametri;

    char session_key[symkey_size];
    memset(&session_key,0,symkey_size);
    memcpy(session_key,arg->session_key,symkey_size);

    char session_iv[iv_size];
    memset(&session_iv,0,iv_size);
    memcpy(session_iv,arg->session_iv,iv_size);

    char session_key_hmac[symkey_size];
    memset(&session_key_hmac,0,symkey_size);
    memcpy(session_key_hmac,arg->session_key_hmac,symkey_size);

    char session_key_server[symkey_size];
    memset(&session_key_server,0,symkey_size);
    memcpy(session_key_server,arg->session_key_server,symkey_size);

    char session_key_hmac_server[symkey_size];
    memset(&session_key_hmac_server,0,symkey_size);
    memcpy(session_key_hmac_server,arg->session_key_hmac_server,symkey_size);

    char session_iv_server_temp[iv_size];
    memset(&session_iv_server_temp,0,iv_size);
    memcpy(session_iv_server_temp,session_iv_server,iv_size);

    int new_sd_chat = arg->sd_server;

    pthread_t* thread_ricevi= arg->thread_ricevi;

    int* ritorno_pthread_exit;
    //vengono periodicamente inviati due messaggi, uno per l'altro client e uno per il server per comunicare se il messaggio inviato è un messaggio di chiusura
    while(1){
        char messaggio_chat[len_buffer];
        memset(&messaggio_chat,0,len_buffer);
        char cmd_cipher[len_buffer];
        memset(&cmd_cipher,0,len_buffer);
        fgets(messaggio_chat, len_buffer, stdin);
        unsigned char *tag_buf;
        tag_buf=(unsigned char*)malloc(tag_len);
        symmetric_encryption(messaggio_chat,session_key,cmd_cipher,session_iv,tag_buf, session_key_hmac);
        invia(cmd_cipher,new_sd_chat,len_buffer);
        invia(tag_buf,new_sd_chat,tag_len);

        char messaggio_concatenato_v2[len_buffer+iv_size+tag_len];
        memset(&messaggio_concatenato_v2, 0, len_buffer + iv_size + tag_len);
        strncpy(messaggio_concatenato_v2, session_iv_server_temp, iv_size);
        strncat(messaggio_concatenato_v2, cmd_cipher, len_buffer);
        strncat(messaggio_concatenato_v2, tag_buf, tag_len);
        unsigned char* tag=(unsigned char*)malloc(tag_len);
        HMAC(EVP_sha256(), session_key_hmac_server, 32, messaggio_concatenato_v2, len_buffer + iv_size + tag_len, tag, NULL);
        invia(tag,new_sd_chat,tag_len);
        incremento_iv(session_iv_server_temp);

        free(tag);
        free(tag_buf);

        if(strcmp(messaggio_chat,"!chiudi_chat\n")==0){
            memset(&cmd_cipher,0,len_buffer);
            unsigned char *tag_buf;
            tag_buf=(unsigned char*)malloc(tag_len);
            symmetric_encryption(messaggio_chat,session_key_server,cmd_cipher,session_iv_server,tag_buf,session_key_hmac_server);
            invia(cmd_cipher,new_sd_chat,len_buffer);
            invia(tag_buf,new_sd_chat,tag_len);
            free(tag_buf);
            break;
        }
        else{
            memset(&cmd_cipher,0,len_buffer);
            memset(&messaggio_chat,0,len_buffer);
            unsigned char esito[len_buffer]="continua chat";
            unsigned char *tag_buf;
            tag_buf=(unsigned char*)malloc(tag_len);
            symmetric_encryption(esito,session_key_server,cmd_cipher,session_iv_server,tag_buf, session_key_hmac_server);
            invia(cmd_cipher,new_sd_chat,len_buffer);
            invia(tag_buf,new_sd_chat,tag_len);
            free(tag_buf);
        }
    }
    pthread_cancel(*thread_ricevi);
    pthread_exit(ritorno_pthread_exit);
}

//thread utilizzato durante la chat per ricevere messaggi
void* thread_function_ricevi(void* parametri){
    parametri_thread_chat* arg = (parametri_thread_chat*)parametri;

    char session_key[symkey_size];
    memset(&session_key,0,symkey_size);
    memcpy(session_key,arg->session_key,symkey_size);

    char session_iv[iv_size];
    memset(&session_iv,0,iv_size);
    memcpy(session_iv,arg->session_iv,iv_size);

    char session_key_hmac[symkey_size];
    memset(&session_key_hmac,0,symkey_size);
    memcpy(session_key_hmac,arg->session_key_hmac,symkey_size);

    char session_key_server[symkey_size];
    memset(&session_key_server,0,symkey_size);
    memcpy(session_key_server,arg->session_key_server,symkey_size);

    char session_key_hmac_server[symkey_size];
    memset(&session_key_hmac_server,0,symkey_size);
    memcpy(session_key_hmac_server,arg->session_key_hmac_server,symkey_size);

    char session_iv_server_temp[iv_size];
    memset(&session_iv_server_temp,0,iv_size);
    memcpy(session_iv_server_temp,session_iv_server,iv_size);

    int new_sd_chat = arg->sd_server;

    pthread_t* thread_invia= arg->thread_invia;

    int* ritorno_pthread_exit;
    while(1){
        char messaggio_chat[len_buffer];
        memset(&messaggio_chat,0,len_buffer);
        char cmd_cipher[len_buffer];
        memset(&cmd_cipher,0,len_buffer);
        ricevi(cmd_cipher,new_sd_chat);
        unsigned char *tag_buf;
        tag_buf=(unsigned char*)malloc(tag_len);
        ricevi(tag_buf,new_sd_chat);
        symmetric_decryption(cmd_cipher,session_key,messaggio_chat,session_iv,tag_buf, session_key_hmac);

        
        char* tag_buf_2=(unsigned char*)malloc(tag_len);
        ricevi(tag_buf_2,new_sd_chat);
        unsigned char* tag=(unsigned char*)malloc(tag_len);
        char messaggio_concatenato[len_buffer + iv_size + tag_len];
        memset(&messaggio_concatenato, 0, len_buffer + iv_size + tag_len);
        strncpy(messaggio_concatenato, session_iv_server_temp, iv_size);
        strncat(messaggio_concatenato, cmd_cipher, len_buffer);
        strncat(messaggio_concatenato, tag_buf, tag_len);
        HMAC(EVP_sha256(), session_key_hmac_server, 32, messaggio_concatenato, len_buffer + iv_size + tag_len, tag, NULL);
        if(memcmp(tag,tag_buf_2,32)!=0){
            perror("Error: tag diverso\n");
            exit(1);
        }

        incremento_iv(session_iv_server_temp);
    
        free(tag_buf_2);
        free(tag);


        free(tag_buf);
        if(strcmp(messaggio_chat,"!chiudi_chat\n")==0){
            printf("messaggio: chiudo la chat, ciao\n");
            break;
        }
        else{
            printf("messaggio: %s\n",messaggio_chat);
        }
    }
    pthread_cancel(*thread_invia);
    pthread_exit(ritorno_pthread_exit);
}

//thread che gestisce le richieste di inizio chat da parte di altri client
void* thread_function_chat(void* parametri){

    parametri_thread_chat* arg = (parametri_thread_chat*)parametri;
    int sd_server = arg->sd_server;
    char session_key[symkey_size];
    memset(&session_key,0,symkey_size);
    memcpy(session_key,arg->session_key,symkey_size);
    char session_key_hmac[symkey_size];
    memset(&session_key_hmac,0,symkey_size);
    memcpy(session_key_hmac,arg->session_key_hmac,symkey_size);

    char username[len_buffer];
    while(1){
        memset(&username,0,len_buffer);
        memcpy(username,arg->username,len_buffer);
        int new_sd_chat = accept(sd_chat, (struct sockaddr*) &mittente_addr, (socklen_t*) &len);
        gia_premuto = 1;
        char risposta[len_buffer] = "n\n";

        //il thread è in attesa di un messaggio dal server per la notifica di una nuova chat
        char messaggio[len_buffer];
        memset(&messaggio,0,len_buffer);
        char cmd_cipher[len_buffer];
        memset(&cmd_cipher,0,len_buffer);

        ricevi(cmd_cipher,new_sd_chat);
        unsigned char *tag_buf;
        tag_buf=(unsigned char*)malloc(tag_len);
        ricevi(tag_buf,new_sd_chat);
        symmetric_decryption(cmd_cipher,session_key,messaggio,session_iv_server,tag_buf, session_key_hmac);
        free(tag_buf);

        pthread_mutex_lock(&semaforo);
        chi_parla = 1;
        pthread_mutex_unlock(&semaforo);
        
        printf("%s\n",messaggio);

        memset(&risposta,0,len_buffer);
        pthread_mutex_lock(&semaforo);
        pthread_cond_wait(&condizione_gia_premuto,&semaforo);
        pthread_mutex_unlock(&semaforo);

        memset(&cmd_cipher,0,len_buffer);
        tag_buf=(unsigned char*)malloc(tag_len);
        symmetric_encryption(yes_no,session_key,cmd_cipher,session_iv_server,tag_buf, session_key_hmac);
        invia(cmd_cipher,new_sd_chat,len_buffer);
        invia(tag_buf,new_sd_chat,tag_len);
        free(tag_buf);

        if(strcmp(yes_no,"n\n") == 0){
            //visto che l'utente ha rifiutato la connessione
            //il controllo ritorna al padre
            pthread_mutex_lock(&semaforo);
            chi_parla = 0; 
            pthread_cond_signal(&condizione);
            pthread_mutex_unlock(&semaforo);
        }
        if(strcmp(yes_no,"y\n") == 0){
            
            //ricevo la chiave pubblica dell'utente con cui chatto per il perfect forward 
            char* buf_pub_key_utente_chiamante;
            buf_pub_key_utente_chiamante = (char*)malloc(len_buffer);
            memset(&cmd_cipher,0,len_buffer);
            ricevi(cmd_cipher,new_sd_chat); 
            
            unsigned char *tag_buf;
            tag_buf=(unsigned char*)malloc(tag_len);
            ricevi(tag_buf,new_sd_chat);
            symmetric_decryption(cmd_cipher,session_key,buf_pub_key_utente_chiamante,session_iv_server,tag_buf, session_key_hmac);
            free(tag_buf);

            //ritrasformo la chiave in EVP_PUBKEY
            EVP_PKEY* pub_key_utente_chimante;
            BIO* mbio = BIO_new(BIO_s_mem());
            BIO_write(mbio,buf_pub_key_utente_chiamante,len_buffer);
            pub_key_utente_chimante = PEM_read_bio_PUBKEY(mbio,NULL,NULL,NULL);

            char session_key_chat[symkey_size];
            memset(&session_key_chat,0,symkey_size);
            char session_iv_chat[iv_size];
            memset(&session_iv_chat,0,iv_size);
            char session_key_hmac_chat[symkey_size];
            memset(&session_key_hmac_chat,0,symkey_size);
            char username_supporto[len_buffer];
            memset(&username_supporto,0,len_buffer);
            memcpy(username_supporto,username,len_buffer);

            //effettuo il perfect forward secrecy con la'ltro client
            perfect_forward_secrecy_chat(new_sd_chat,pub_key_utente_chimante,session_key_chat,session_iv_chat,username_supporto, session_key_hmac_chat,session_iv_server,session_key_hmac);

            printf("chat iniziata\nper uscire dalla chat inserire il comando: !chiudi_chat\n");

            //nel caso la chat inizi vengono generati i due thread per la gestione della chat
            pthread_t thread_invia, thread_ricevi;
            parametri_thread_chat parametri;
            memset(&parametri.session_key,0,symkey_size);
            memcpy(parametri.session_key,session_key_chat,symkey_size);
            memset(&parametri.session_iv,0,iv_size);
            memcpy(parametri.session_iv,session_iv_chat,iv_size);
            memset(&parametri.session_key_hmac,0,symkey_size);
            memcpy(parametri.session_key_hmac,session_key_hmac_chat,symkey_size);
            memset(&parametri.session_key_server,0,symkey_size);
            memcpy(parametri.session_key_server,session_key,symkey_size);
            memset(&parametri.session_key_hmac_server,0,symkey_size);
            memcpy(parametri.session_key_hmac_server,session_key_hmac,symkey_size);
            parametri.sd_server = new_sd_chat;
            parametri.thread_invia=&thread_invia;
            parametri.thread_ricevi=&thread_ricevi;

            pthread_create(&thread_invia,NULL,&thread_function_invia,&parametri);
            pthread_create(&thread_ricevi,NULL,&thread_function_ricevi,&parametri);

            pthread_join(thread_invia,NULL);
            pthread_join(thread_ricevi,NULL);

            pthread_mutex_lock(&semaforo);
            chi_parla = 0; 
            pthread_cond_signal(&condizione);
            pthread_mutex_unlock(&semaforo);

            free(buf_pub_key_utente_chiamante);
            EVP_PKEY_free(pub_key_utente_chimante);
            BIO_free(mbio);
        }   
    }
    gia_premuto = 0;
}

int main(int argc, char* argv[]){

    struct sockaddr_in sv_addr; //var contenente l'addr sel server

    int sd,ret;
    int porta = 4241;
    char* ip = "127.0.0.1";
    int pid;
    char username[len_buffer]; //si suppone che l'username sia un valore contenuto

    sd = socket(AF_INET,SOCK_STREAM,0);
    memset(&sv_addr, 0, sizeof(sv_addr));
    sv_addr.sin_family = AF_INET;
    sv_addr.sin_port = htons(porta);
    inet_pton(AF_INET,ip,&sv_addr.sin_addr); //salvataggio nel formato endian corretto di ip dentro la struct sin_addr
    
    ret = connect(sd, (struct sockaddr*)&sv_addr, sizeof(sv_addr));
    if(ret < 0){
        perror("---- Errore del Client sulla Connect ----\n");
        exit(1);
    }

    char chiave_server[len_buffer];
    memset(&chiave_server,0,len_buffer);

    //porta sulla quale mettersi in ascolto di richieste di chat 
    char porta_da_usare_char[len_buffer]; 
    memset(&porta_da_usare_char,0,len_buffer);


    // chiave di sessione con il client
    unsigned char session_key[symkey_size]; 

    char session_key_hmac[symkey_size]; 
    memset(&session_key_hmac, 0, symkey_size);


    //effetto il perfect forward secrecy e scambio una chiave con il server
    perfect_forward_secrecy(sd,username, session_key, session_iv_server, session_key_hmac, chiave_server, porta_da_usare_char);

    //se il server non ha accettato la connessione, il valore della porta è -1, altrimenti la porta da usare
    int porta_da_usare = atoi(porta_da_usare_char);

    //controllo che il server possa accettare la connessione
    if(porta_da_usare == -1){
        printf("server pieno, riprovare più tardi\n");
        close(sd);
        exit(1);
    }

    sd_chat = socket(AF_INET,SOCK_STREAM,0); //definizione del tipo di socket : tipo TCP,
    memset(&my_addr,0,sizeof(my_addr));
    //inizializzazione della struttura my_addr per index e porta
    my_addr.sin_family = AF_INET; //famiglia dei protocolli ipv4 o TCP
    my_addr.sin_port = htons(porta_da_usare); //little endian / big endian
    my_addr.sin_addr.s_addr = INADDR_ANY; //accetta tutti gli index

    ret = bind(sd_chat,(struct sockaddr*) &my_addr, sizeof(my_addr)); //associazione del canale con il mio index/porta

    ret = listen(sd_chat, 1); //richieste che possono essere in coda contemporaneamente
    if(ret < 0){
        perror("--- Errore Server in fase di Listen ---\n");
        exit(-1);
    }

    len = sizeof(mittente_addr);

    //creo un thread figlio per gestire la ricezione di msg durante la chat con un altro utente
    pthread_t thread_chat;
    parametri_thread_chat parametri;
    parametri.sd_server = sd;
    memset(&parametri.session_key,0,symkey_size);
    memcpy(parametri.session_key,session_key,symkey_size);
    
    memset(&parametri.session_key_hmac,0,symkey_size);
    memcpy(parametri.session_key_hmac,session_key_hmac,symkey_size);
    memset(&parametri.username,0,len_buffer);
    memcpy(parametri.username,username,len_buffer);
    
    pthread_mutex_init(&semaforo,NULL);
    pthread_cond_init(&condizione,NULL);

    pthread_create(&thread_chat,NULL,&thread_function_chat,&parametri);

    printf("\nUtilizza uno fra i seguenti comandi:\n");
    printf("--> !esci (consente di uscire dall'applicazione)\n");
    printf("--> !utenti_online (mostra la lista degli utenti online)\n");
    printf("--> !chat nome_utente (invia una richiesta di comunicazione all'utente \"nome_utente\")\n\n");

    while(1){ //corpo del client nel quale il client manda comandi al server

        //si ferma il thread padre, quando viene ricevuta una richiesta di chat
        //in questo modo il controllo passa al figlio
        //il padre torenrà in funzione dopo che il figlio lo avrà risvegliato
        pthread_mutex_lock(&semaforo);
        while(chi_parla == 1){
            pthread_cond_wait(&condizione,&semaforo);
        }
        pthread_mutex_unlock(&semaforo);

        char cmd[len_buffer]; //cmd per messaggio generico
        char supporto[len_buffer];
        int controllo = 0;
        while(controllo==0){
        	memset(&cmd,0,len_buffer);
            memset(&supporto,0,len_buffer);
	        printf("Comando da inviare:\n");
            pthread_mutex_lock(&semaforo);
            gia_premuto=0;
            pthread_mutex_unlock(&semaforo);
	        fgets(cmd, len_buffer, stdin);
            //se mi è arrivata una richiesta di chat si controlla che l'utente possa inserire solamente y o n e non più un comando
            if(gia_premuto==1){
                while(strcmp(cmd,"y\n")!=0 && strcmp(cmd,"n\n")!=0){
                    printf("devi inserire y o n\n");
                    fgets(cmd, len_buffer, stdin);
                }
                pthread_mutex_lock(&semaforo);
                memcpy(yes_no,cmd,len_buffer);
                pthread_cond_signal(&condizione_gia_premuto);
                while(chi_parla == 1){
                    pthread_cond_wait(&condizione,&semaforo);
                }
                pthread_mutex_unlock(&semaforo);
            }
            else{
                strcpy(supporto,cmd);
                controllo = controlla_comando(supporto);	
                if(controllo==0){
                    printf("Comando non valido \n");
                }
            }
        }

        char cmd_cipher[len_buffer];
        memset(&cmd_cipher,0,len_buffer);
        unsigned char *tag_buf;
        tag_buf=(unsigned char*)malloc(tag_len);
        symmetric_encryption(cmd,session_key,cmd_cipher,session_iv_server,tag_buf, session_key_hmac);

        invia(cmd_cipher, sd,len_buffer);
        invia(tag_buf,sd,tag_len);
        free(tag_buf);
        memset(&supporto,0,len_buffer);
        strcpy(supporto,cmd);
        char* solo_cmd = strtok(supporto," ");
        if(strcmp(solo_cmd,"!esci\n")==0){
            memset(&cmd,0,len_buffer);
            memset(&cmd_cipher,0,len_buffer);
            ricevi(cmd_cipher,sd); //qui ricevo l'esito della richiesta della chat
            unsigned char *tag_buf;
            tag_buf=(unsigned char*)malloc(tag_len);
            ricevi(tag_buf,sd);
            symmetric_decryption(cmd_cipher,session_key,cmd,session_iv_server,tag_buf, session_key_hmac);
            free(tag_buf);
            //attendo che il server comunichi la ricezione della chiusura
            if(strcmp(cmd,"ricevuta disconnessione")==0){
                printf("Chiudo la connessione con il server\n");
                close(sd);
                exit(1);
            }
        }
        if(strcmp(solo_cmd,"!utenti_online\n")==0){
            memset(&cmd,0,len_buffer);
            memset(&cmd_cipher,0,len_buffer);
            ricevi(cmd_cipher,sd); //qui ricevo l'esito della richiesta della chat
            unsigned char *tag_buf;
            tag_buf=(unsigned char*)malloc(tag_len);
            ricevi(tag_buf,sd);
            symmetric_decryption(cmd_cipher,session_key,cmd,session_iv_server,tag_buf,session_key_hmac);
            free(tag_buf);
            printf("%s\n", cmd);
        }
        if(strcmp(solo_cmd,"!chat")==0){
            memset(&cmd,0,len_buffer);
            memset(&cmd_cipher,0,len_buffer);
            ricevi(cmd_cipher,sd); //qui ricevo l'esito della richiesta della chat
            unsigned char *tag_buf;
            tag_buf=(unsigned char*)malloc(tag_len);
            ricevi(tag_buf,sd);
            symmetric_decryption(cmd_cipher,session_key,cmd,session_iv_server,tag_buf, session_key_hmac);
            free(tag_buf);
            printf("risposta del client: %s\n",cmd);
            if(strcmp(cmd, "richiesta accettata\n") == 0){

                char session_key_chat[symkey_size];
                memset(&session_key_chat,0,symkey_size);
                char session_iv_chat[iv_size];
                memset(&session_iv_chat,0,iv_size);
                char session_key_hmac_chat[symkey_size];
                memset(&session_key_hmac_chat,0,symkey_size);

                //ricevo la chiave pubblica dell'utente con il quale voglio chattare
                memset(&cmd,0,len_buffer);
                memset(&cmd_cipher,0,len_buffer);
                ricevi(cmd_cipher,sd); 
                
                unsigned char *tag_buf;
                tag_buf=(unsigned char*)malloc(tag_len);
                ricevi(tag_buf,sd);
                symmetric_decryption(cmd_cipher,session_key,cmd,session_iv_server,tag_buf, session_key_hmac);
                free(tag_buf);

                EVP_PKEY* pubkey_client_contattato;
                BIO* mbio = BIO_new(BIO_s_mem());
                BIO_write(mbio,cmd,len_buffer);
                pubkey_client_contattato = PEM_read_bio_PUBKEY(mbio,NULL,NULL,NULL);

                //prelevo la chiev privata dell'utente
                EVP_PKEY* priv_key;
                char nome_file[len_buffer+9];
                strncpy(nome_file,username,strlen(username));
                sprintf(nome_file+strlen(username)-1,"_priv.pem");
                FILE* privkey_file = fopen(nome_file, "r");
                if(!privkey_file){ 
                    perror("Error: errore nell'apertura del file contenente la chiave pubblica dell'utente\n"); 
                    exit(1); 
                }
                char password_file[len_buffer];
                memset(&password_file,0,len_buffer);
                strncpy(password_file,username,strlen(username));
                sprintf(password_file+strlen(username)-1,"0");
                priv_key= PEM_read_PrivateKey(privkey_file, NULL, NULL, password_file);
                fclose(privkey_file);
                if(!priv_key){ 
                    perror("Error: PEM_read_PubKey ha ritornato NULL\n"); 
                    exit(1); 
                }

                //effettuo il perfect forward secrecy con l'altro client
                perfect_forward_secrecy_chiamante(sd,username,priv_key,session_key_chat,session_iv_chat,pubkey_client_contattato, session_key_hmac_chat,session_iv_server,session_key_hmac);

                EVP_PKEY_free(pubkey_client_contattato);
                EVP_PKEY_free(priv_key);
                BIO_free(mbio);

                printf("L'utente ha accettato la richiesta di comunicazione\n");
                printf("chat iniziata\nper uscire dalla chat inserire il comando: !chiudi_chat\n");

                //creo i thread per la gestione della chat
                pthread_t thread_invia, thread_ricevi;
                parametri_thread_chat parametri;
                memset(&parametri.session_key,0,symkey_size);
                memcpy(parametri.session_key,session_key_chat,symkey_size);
                memset(&parametri.session_iv,0,iv_size);
                memcpy(parametri.session_iv,session_iv_chat,iv_size);
                memset(&parametri.session_key_hmac,0,symkey_size);
                memcpy(parametri.session_key_hmac,session_key_hmac_chat,symkey_size);
                memset(&parametri.session_key_server,0,symkey_size);
                memcpy(parametri.session_key_server,session_key,symkey_size);
                memset(&parametri.session_key_hmac_server,0,symkey_size);
                memcpy(parametri.session_key_hmac_server,session_key_hmac,symkey_size);
                
                parametri.sd_server = sd;
                parametri.thread_invia=&thread_invia;
                parametri.thread_ricevi=&thread_ricevi;

                pthread_create(&thread_invia,NULL,&thread_function_invia,&parametri);
                pthread_create(&thread_ricevi,NULL,&thread_function_ricevi,&parametri);

                pthread_join(thread_invia,NULL);
                pthread_join(thread_ricevi,NULL);
            }else{
                printf("L'utente non è disponibile per la comunicazione\n");
            }
        }
    }

    close(sd);

}
