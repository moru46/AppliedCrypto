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
#include <stdlib.h>
#include <stdio.h> 
#include <limits.h> 
#include <string.h> 
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <pthread.h>
#include "server_function.h"


struct sockaddr_in my_addr, cl_addr;
int sd; //sokcet padre
int pid; //id processo
int len; //lunghezza della struttura cl_addr
int ret; //var per la gestione errori
pthread_t thread;
int porta_ora=3435;

//thread figlio che gestisce uno specifico client
void* thread_function(void* parametri){

    thread_str* str = (thread_str*)parametri;
    int sd_locale = str->new_sd;
    int porta_locale = str->porta;

    //invio la porta sulla quale il client dovrà mettersi in ascolto di richieste di chat
    char porta_da_inviare[len_buffer]; 
    sprintf(porta_da_inviare,"%d",porta_locale);

    char username[len_buffer];

    // chiave di sessione con il client
    char session_key[symkey_size]; 
    memset(&session_key, 0, symkey_size);

    char session_iv[iv_size]; 
    memset(&session_iv, 0, iv_size);

    char session_key_hmac[symkey_size]; 
    memset(&session_key_hmac, 0, symkey_size);

    //effettuo il perfect forward secrecy
    perfect_forward_secrecy(sd_locale, session_key,session_iv, session_key_hmac,porta_da_inviare, username); // scrive in session_key la chiave di sessione

    //scrivo memorizzo la porta assegnata al client
    int j;
    for(j=0;j<max_utenti;j++){
        if(array_utenti[j].porta == porta_locale){
            strcpy(array_utenti[j].utente,username);
            break;
        }
    }

    //salvo i valori del session_key e session_iv nelle informazioni dell'utente nella lista array_utenti
    memcpy(array_utenti[j].session_key,session_key,symkey_size);
    memcpy(array_utenti[j].session_iv,session_iv,iv_size);
    memcpy(array_utenti[j].session_key_hmac,session_key_hmac,symkey_size);

    while(1){ //corpo del figlio nel quale riceve i comandi e li gestisce

        char cmd[len_buffer]; //buffer per il comando ricevuto
        char supporto[len_buffer];
        printf("Attendo comando dal Client!\n");
        memset(&cmd,0,len_buffer);
        memset(&supporto,0,len_buffer);

        char cmd_cipher[len_buffer];
        memset(&cmd_cipher,0,len_buffer);

        ricevi(cmd_cipher,sd_locale);

        unsigned char *tag_buf;
        tag_buf=(unsigned char*)malloc(tag_len);
        ricevi(tag_buf,sd_locale);
        symmetric_decryption(cmd_cipher,session_key,cmd,session_iv,tag_buf,username, session_key_hmac);
        free(tag_buf);

        printf("Comando ricevuto dal client: %s\n", cmd);
        if(controlla_comando(cmd,username,sd_locale,array_utenti,session_key,session_iv, session_key_hmac)==1){
            printf("Comando corretto\n");
            strcpy(supporto,cmd);
            char* solo_cmd= strtok(supporto, " ");
            if(strcmp(solo_cmd,"!esci\n")==0){
                printf("Chiudo la connessione con l'utente %s\n",username);
                pthread_exit(0);
            }
        }else{
            printf("Comando errato\n");
            memset(&cmd_cipher,0,len_buffer);
            unsigned char *tag_buf;
            tag_buf=(unsigned char*)malloc(tag_len);
            unsigned char esito[len_buffer]="Comando ricevuto errato!";
            symmetric_encryption(esito,session_key,cmd_cipher,session_iv,tag_buf,username, session_key_hmac);
            invia(cmd_cipher, sd_locale,len_buffer);
            invia(tag_buf, sd_locale,tag_len);
            free(tag_buf);
        }

    }
    close(sd_locale); //il figlo esce dal ciclo infinito e chiude il suo socket con il client (in realtà non lo fa mai)
    return NULL;

}

int main(int argc, char* argv[]){

   inizializza_array_utenti(array_utenti);
   inizializza_utenti_occupati();

    int porta = 4241; //porta di ascolto
    sd = socket(AF_INET,SOCK_STREAM,0); //definizione del tipo di socket : tipo TCP, 
    memset(&my_addr,0,sizeof(my_addr));
    //inizializzazione della struttura my_addr per index e porta
    my_addr.sin_family = AF_INET; //famiglia dei protocolli ipv4 o TCP
    my_addr.sin_port = htons(porta); //little endian / big endian
    my_addr.sin_addr.s_addr = INADDR_ANY; //accetta tutti gli index
    ret = bind(sd,(struct sockaddr*) &my_addr, sizeof(my_addr)); //associazione del canale con il mio index/porta
    ret = listen(sd, 10); //richieste che possono essere in coda contemporaneamente
    if(ret < 0){
		perror("--- Errore Server in fase di Listen ---\n");
		exit(-1);
	}
    len = sizeof(cl_addr);
    funzione_client();
    //prendo la chiave privata
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

    while(1){
        int i;
        int new_sd = accept(sd, (struct sockaddr*) &cl_addr, (socklen_t*) &len);

        //controllo se il server ha la possibilità di accettare la connessione, in caso negativo manda un messaggio all'utente e chiude
        if(i==(max_utenti-1)){
            invia("-1",new_sd,3);
            close(new_sd);
        }
        else{
            for(i=0;i<max_utenti;i++){
                if(array_utenti[i].porta==0){
                    break;
                }
            }
            array_utenti[i].new_sd = new_sd;
            array_utenti[i].porta=porta_ora;
            porta_ora++;
            if(array_utenti[i].new_sd > 0){

                pthread_create(&thread,NULL,&thread_function,&array_utenti[i]);
            }
       }
    }

    EVP_PKEY_free(prvkey);
    close(sd); //il padre chiude il socket di ascolto sulla listen(non viene mai eseguito)
    return 0;
}
