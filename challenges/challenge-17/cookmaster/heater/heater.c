// filename: main.cpp
#include <string.h>
#include <assert.h>
#include <math.h>
#include <pthread.h>
#include <time.h>
#include <stdbool.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/can.h>
#include <linux/can/raw.h>


#include "openssl/decoder.h"
#include <openssl/core_dispatch.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

struct tempinfo {
  uint16_t temp;
  uint16_t duration;
};

char flag[64];
char interface[] = "vcan0";
int signature_length = 28;
struct tempinfo temp_target = { 22, 0 };
double temp = 22;
EVP_PKEY *pkey = NULL;
EVP_PKEY_CTX *ctx;
const EC_KEY * ec_key;


int init_signature(){
  OSSL_DECODER_CTX *dctx;
  const char *format = "PEM";   /* NULL for any format */
  const char *structure = NULL; /* any structure */
  const char *keytype = "EC";   /* NULL for any key */
  FILE *fp;

  BIO *bio_out;
  bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

  dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, format, structure,
      NULL,
      0,
      NULL, NULL);
  if (dctx == NULL) {
    printf("No decoders\n");
    exit(1);
    /* error: no suitable potential decoders found */
  }
  fp = fopen("pubkey", "r");
  //if (OSSL_DECODER_from_data(dctx, &pub, &publen)) {
  if (OSSL_DECODER_from_fp(dctx, fp)) {
    /* pkey is created with the decoded data from the buffer */
    //printf("Got Key\n");
  } else {
    ERR_print_errors(bio_out);
    /* decoding failure */
    printf("Decoding Error\n");
    exit(1);
  }
  OSSL_DECODER_CTX_free(dctx);

  ctx = EVP_PKEY_CTX_new(pkey, NULL /* no engine */);
  if (!ctx){
    /* Error occurred */
    printf("Error");
  }
  BIO_free(bio_out);
  
  ec_key = EVP_PKEY_get0_EC_KEY(pkey);

}


int signature(unsigned char* message, size_t message_length, unsigned char * sig)
{

  
  int ret;
  unsigned char hash [SHA256_DIGEST_LENGTH];
  SHA256(message, message_length, hash);

  // Create signature and import from packet.
  BN_CTX *bn_ctx = BN_CTX_new();
  BN_CTX_start(bn_ctx);

  BIGNUM *bn_r = BN_CTX_get(bn_ctx);
  BIGNUM *bn_s = BN_CTX_get(bn_ctx);

  BN_bin2bn(sig, 14, bn_r);
  BN_bin2bn(sig+14, 14, bn_s);

  ECDSA_SIG *signature = ECDSA_SIG_new();
  ret = ECDSA_SIG_set0(signature, bn_r, bn_s);

  ret = ECDSA_do_verify(hash, SHA256_DIGEST_LENGTH, signature, ec_key); 

  BN_CTX_end(bn_ctx);
  BN_CTX_free(bn_ctx);
  free(signature);

  if(ret == 1){
    printf("Signature valid\n");
  }

  return ret;
}


int shutdown_signature(){
  EVP_PKEY_free(pkey);
  EVP_PKEY_CTX_free(ctx);
}


float random_float(float min, float max) {
  return ((float)rand() / RAND_MAX) * (max - min) + min;
}


void get_random_double(double* data){
  int rc = RAND_bytes((char *) data, sizeof(double)-2);
  //  *bin = *bin & 0xffffffffffffffffffffff; 

  if(rc != 1) {
    /* RAND_bytes failed */
    unsigned long err = ERR_get_error();
    fprintf(stderr, "Random Error");
    /* `err` is valid    */
  }
}


int send_temperature(){

  int s; 
  struct sockaddr_can addr;
  struct ifreq ifr;
  struct can_frame frame;

  get_random_double(&temp);

  if ((s = socket(PF_CAN, SOCK_RAW, CAN_RAW)) < 0) {
    perror("Socket");
    return 1;
  }

  strcpy(ifr.ifr_name, interface );
  ioctl(s, SIOCGIFINDEX, &ifr);

  memset(&addr, 0, sizeof(addr));
  addr.can_family = AF_CAN;
  addr.can_ifindex = ifr.ifr_ifindex;

  if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("Bind");
    return 1;
  }

  while(1){

    double* temp_ptr = &temp;
    memcpy(frame.data, temp_ptr, sizeof(double));
    bzero(&frame, 8);
    frame.can_id = 0x12;
    frame.len = 8;

    if (write(s, &frame, sizeof(struct can_frame)) != sizeof(struct can_frame)) {
      perror("Write");
      return 1;
    }
    printf("Temperature: %f\n", temp);

    get_random_double(&temp);
    if(temp < temp_target.temp){
      temp += 2;
    }
    else{
      temp -=1;
    }

    if(abs(temp - temp_target.temp) < 3)
    { 
      if(temp_target.duration > 0){
                                   temp_target.duration--;
                                 }
      else{
        temp_target.temp = 22;
      }
    }

    sleep(1);
  }

  if (close(s) < 0) {
    perror("Close");
    return 1;
  }
}


void parse_frame(struct canfd_frame *frame){
  struct tempinfo temp_data; 
  memcpy(&temp_data, frame->data+signature_length, frame->len-signature_length);
  printf("Heating to %d for %d seconds\n", temp_data.temp, temp_data.duration);
  if(temp_data.temp < 200){
    memcpy(&temp_target, frame->data+signature_length, frame->len-signature_length);
  }
}


int can_setup(){

  int s; 
  struct sockaddr_can addr;
  struct ifreq ifr;
  int enable_canfd = 1;
  struct can_filter rfilter[1];

  if ((s = socket(PF_CAN, SOCK_RAW, CAN_RAW)) < 0) {
    perror("Socket");
    return -1;
  }
  /* interface is ok - try to switch the socket into CAN FD mode */
  if (setsockopt(s, SOL_CAN_RAW, CAN_RAW_FD_FRAMES,
        &enable_canfd, sizeof(enable_canfd))){
    printf("error when enabling CAN FD support\n");
    return -1;
  }

  rfilter[0].can_id   = 0x15;
  rfilter[0].can_mask = CAN_SFF_MASK;

  if (setsockopt(s, SOL_CAN_RAW, CAN_RAW_FILTER,
        &rfilter, sizeof(rfilter))){
    printf("error when setting filter\n");
    return -1;
  }

  strcpy(ifr.ifr_name, interface );
  ioctl(s, SIOCGIFINDEX, &ifr);

  memset(&addr, 0, sizeof(addr));
  addr.can_family = AF_CAN;
  addr.can_ifindex = ifr.ifr_ifindex;

  if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("Bind");
    return -1;
  }
  return s;
}


int can_handle(int s){
  struct canfd_frame frame;
  struct tempinfo temp_data; 

  if(s < 0){
    return 1;
  }

  while(1){

    read(s, &frame, sizeof(struct canfd_frame));

    if((frame.len > signature_length) && signature(frame.data + signature_length , frame.len - signature_length, frame.data)){
       parse_frame(&frame);
    }
  }


  if (close(s) < 0) {
    perror("Close");
    return 1;
  }

}

void init_flag(char* flag_buffer){
  FILE *fp;
  fp = fopen("./flag", "r");
  if (fp == NULL) { 
      perror("Could not open flag file.\n"); 
      exit(1); 
  } 
  fgets(flag_buffer, sizeof(flag), fp);
  fclose(fp);
}

int main(){

  int s;

  init_flag(flag);
  init_signature();

  pthread_t temp_sender;
  pthread_create(&temp_sender, NULL, send_temperature, NULL);


  s = can_setup();
  can_handle(s);

  pthread_join(temp_sender, NULL);

  shutdown_signature();

}

