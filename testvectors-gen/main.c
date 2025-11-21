#include <setjmp.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hdrbg.h"

/* Three instances of mldsa-native for all security levels */
#define MLD_CONFIG_FILE "multilevel_config.h"

/* Include level-independent code */
#define MLD_CONFIG_MULTILEVEL_WITH_SHARED 1
/* Keep level-independent headers at the end of monobuild file */
#define MLD_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS
#define MLD_CONFIG_PARAMETER_SET 44
#include "mldsa_native.c"
#undef MLD_CONFIG_MULTILEVEL_WITH_SHARED
#undef MLD_CONFIG_PARAMETER_SET

/* Exclude level-independent code */
#define MLD_CONFIG_MULTILEVEL_NO_SHARED
#define MLD_CONFIG_PARAMETER_SET 65
#include "mldsa_native.c"
/* `#undef` all headers at the and of the monobuild file */
#undef MLD_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS
#undef MLD_CONFIG_PARAMETER_SET

#define MLD_CONFIG_PARAMETER_SET 87
#include "mldsa_native.c"
#undef MLD_CONFIG_PARAMETER_SET

#define MLD_CONFIG_API_CONSTANTS_ONLY
#include <mldsa_native.h>

void randombytes(uint8_t *buf, size_t n){
  memset(buf,0,n);//we want deterministic mode, not hedged mode.
}

void dump_core(uintptr_t addr, uintptr_t size, uintptr_t display_addr){
  printf("@0x%08lx, %lu bytes:\n",display_addr, size);
  uint8_t*r = (uint8_t*)addr;
  while(size){
    printf("%02x ",*r++);
    size--;
  }
  printf("\n");
}

void dump(void*addr, uintptr_t size){
  dump_core((uintptr_t)addr,size,(uintptr_t)addr);
}

static jmp_buf main_exception_ctx;
static jmp_buf*exception_ctx = &main_exception_ctx;
jmp_buf*get_exception_ctx(){
  return exception_ctx;
}
jmp_buf*set_exception_ctx(jmp_buf*new_exception_ctx){
  jmp_buf*old = exception_ctx;
  exception_ctx = new_exception_ctx;
  return old;
}
void throw_exception(uint32_t err_code){
  longjmp(*exception_ctx,err_code);
}
extern uint32_t mldsa_native_repetitions;
#define MLDSA44 1
#define MLDSA65 2
#define MLDSA87 4
int main(int argc, const char*argv[]){
    uint64_t hdrbg_seed = 0;
    size_t message_size = 69;
    unsigned int mldsa44 = 0;
    unsigned int mldsa65 = 0;
    unsigned int mldsa87 = 0;
    unsigned int log_aborts = 1;
    for(int i=1;i<argc;i++){
      const char*seed_str = "--hdrbg-seed=";
      if(0==memcmp(argv[i],seed_str,strlen(seed_str))){
        const char*seed_val_str = argv[i]+strlen(seed_str);
        hdrbg_seed = strtoul(seed_val_str,0,0);
        continue;
      }
      const char*msgsize_str = "--msg-size=";
      if(0==memcmp(argv[i],msgsize_str,strlen(msgsize_str))){
        const char*msgsize_val_str = argv[i]+strlen(msgsize_str);
        char*end;
        message_size = strtoull(msgsize_val_str,&end,0);
        size_t factor=1;
        if(*end=='K' || *end=='k') factor = 1024;
        if(*end=='M' || *end=='m') factor = 1024*1024;
        if(*end=='G' || *end=='g') factor = 1024*1024*1024;
        message_size *= factor;
        continue;
      }
      const char*mldsa44_str = "mldsa44";
      if(0==memcmp(argv[i],mldsa44_str,strlen(mldsa44_str))){
        mldsa44 = 1;
        continue;
      }
      const char*mldsa65_str = "mldsa65";
      if(0==memcmp(argv[i],mldsa65_str,strlen(mldsa65_str))){
        mldsa65 = 1;
        continue;
      }
      const char*mldsa87_str = "mldsa87";
      if(0==memcmp(argv[i],mldsa87_str,strlen(mldsa87_str))){
        mldsa87 = 1;
        continue;
      }
      printf("ERROR unsupported command line argument: '%s'\n",argv[i]);
      abort();
    }
    const uint32_t pset = (mldsa87<<2)|(mldsa65<<1)|mldsa44;
    size_t sksize,pksize,sigsize;
    unsigned int mldsa_pset;
    switch(pset){
      case MLDSA44:
        mldsa_pset=44;
        sksize=MLDSA44_SECRETKEYBYTES;
        pksize=MLDSA44_PUBLICKEYBYTES;
        sigsize=MLDSA44_BYTES;
        break;
      case MLDSA65:
        mldsa_pset=65;
        sksize=MLDSA65_SECRETKEYBYTES;
        pksize=MLDSA65_PUBLICKEYBYTES;
        sigsize=MLDSA65_BYTES;
        break;
      case MLDSA87:
        mldsa_pset=87;
        sksize=MLDSA87_SECRETKEYBYTES;
        pksize=MLDSA87_PUBLICKEYBYTES;
        sigsize=MLDSA87_BYTES;
        break;
      default:
        if(0==pset) printf("ERROR unsupported command line: need exactly one mldsa* argument, none have been found.\n");
        else printf("ERROR unsupported command line: need exactly one mldsa* argument, several have been found.");
        abort();
    }

    uint32_t err_code=0;
    uint8_t*message=0;
    if(0 == (err_code = setjmp(main_exception_ctx))){
        uint8_t entropy[32] = {0};
        const uint8_t nonce[32] = {0};
        dump(&hdrbg_seed,sizeof hdrbg_seed);
        memcpy(entropy,&hdrbg_seed,sizeof hdrbg_seed);
        struct hdrbg_t *drbg = hdrbg_init2(0,entropy,sizeof entropy, nonce, sizeof nonce,0,0);
        if(NULL==drbg) throw_exception(__LINE__);
        uint8_t seed[32];
        hdrbg_fill(drbg,0,seed,sizeof seed);
        dump(seed,sizeof seed);
        //const uint8_t seed[32] = {0xc4, 0x44, 0x46, 0xb2, 0xec, 0x12, 0x9e, 0x35, 0x06, 0x92, 0xe6, 0xb7, 0xde, 0x6e, 0xe9, 0x44, 0xef, 0xfc, 0xa4, 0x1a, 0x55, 0x73, 0x50, 0x54, 0xc5, 0x48, 0x6a, 0x98, 0x52, 0xc9, 0x41, 0xdf};
        uint8_t pk[pksize];
        uint8_t sk[sksize];
        switch(mldsa_pset){
          case 44: if(mldsa44_keypair_internal(pk, sk, seed)){
              throw_exception(__LINE__);
            }
            break;
          case 65: if(mldsa65_keypair_internal(pk, sk, seed)){
              throw_exception(__LINE__);
            }
            break;
          case 87: if(mldsa87_keypair_internal(pk, sk, seed)){
              throw_exception(__LINE__);
            }
            break;
          default:
            throw_exception(__LINE__);
        }
        dump(&sk,sizeof(sk));
        dump(&pk,sizeof(pk));
        const unsigned int ctx_size = 0;
        printf("%u\n",mldsa_pset);
        printf("%u\n",ctx_size);
        printf("%lu\n",message_size);
        message = malloc(message_size);
        if(!message) throw_exception(__LINE__);
        //drbg_get_bytes(&ccore_deterministic_mode_ctx, message,message_size);
        //for(unsigned int i = 0; i < message_size; i++){message[i] = 1+(i%8);}
        memset(message,0,message_size);
        uint8_t sig[sigsize];
        uint32_t sum_z=0;
        uint32_t sum_r=0;
        uint32_t n_aborts_z=0,n_aborts_r=0, n_aborts_t0=0,n_aborts_h=0;
        for(unsigned int i=0;i<1000*1000;i++){
            //if(mldsa87_signature(sig,&sigsize,message, message_size, 0, 0, sk)) throw_exception(__LINE__);
            switch(mldsa_pset){
              case 44: if(mldsa44_signature(sig,&sigsize,message, message_size, 0, 0, sk)){
                  throw_exception(__LINE__);
                }
                break;
              case 65: if(mldsa65_signature(sig,&sigsize,message, message_size, 0, 0, sk)){
                  throw_exception(__LINE__);
                }
                break;
              case 87: if(mldsa87_signature(sig,&sigsize,message, message_size, 0, 0, sk)){
                  throw_exception(__LINE__);
                }
                break;
              default:
                throw_exception(__LINE__);
            }
            //dump(&sig,sizeof(sig));
            //if(mldsa87_verify(sig,sigsize,message, message_size,0,0,pk)) throw_exception(__LINE__);
            //printf("repetitions = %u\n",mldsa_native_repetitions);
            if(log_aborts){
              sum_z += n_aborts_z;
              sum_r += n_aborts_r;
              printf("%2u, %2u, %2u, %2u, %2u, %5u, %5u\n",mldsa_native_repetitions,n_aborts_z,n_aborts_r, n_aborts_t0,n_aborts_h,sum_z,sum_r);
            }else{
              printf("%2u\n",mldsa_native_repetitions);
            }
            hdrbg_fill(drbg,0,message,8);
        }
    } else {
      //exception
      printf("EXCEPTION: %u (0x%x)\n",err_code,err_code);
    } 
    if(message){
      free(message);
    }
    return 0;
}