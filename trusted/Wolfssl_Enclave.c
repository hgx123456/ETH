/* Wolfssl_Enclave.c
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */

#include "Wolfssl_Enclave_t.h"

#include "sgx_trts.h"
#include <sgx_tseal.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/integer.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/ssl.h>
#include <wolfssl/openssl/bn.h>



#define ECC_CURVE_SZ 32 /* SECP256K1 curve size in bytes */
#define ECC_CURVE_ID ECC_SECP256K1



void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

int sprintf(char* buf, const char *fmt, ...)
{
    va_list ap;
    int ret;
    va_start(ap, fmt);
    ret = vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    return ret;
}

static void print_hex(uint8_t* data, int sz)
{
    int i;
    for (i = 0; i < sz; i++) {
        printf("%02X ", data[i]);
        if (i > 0 && ((i+1) % 16) == 0)
            printf("\n");
    }
    printf("\n");
}






int crypto_sha256(const uint8_t *buf, uint32_t len, uint8_t *hash, 
    uint32_t hashSz, uint32_t blkSz)
{
    int ret;
    uint32_t i = 0, chunk;
    wc_Sha256 sha256;
    


    /* Init Sha256 structure */
    ret = wc_InitSha256(&sha256);

    while (i < len) {
        chunk = blkSz;
        if ((chunk + i) > len)
            chunk = len - i;
        /* Perform chunked update */
        ret = wc_Sha256Update(&sha256, (buf + i), chunk);
        if (ret != 0) {
            break;
        }
        i += chunk;
    }

        /* Get final digest result */
        ret = wc_Sha256Final(&sha256, hash);
    return ret;
}


int crypto_ecc_sign(const uint8_t *key, uint32_t keySz,
    const uint8_t *hash, uint32_t hashSz, uint8_t *sig, uint32_t* sigSz,
    int curveSz, int curveId)
{
    int ret;
    mp_int r, s;
    ecc_key ecc;
    WC_RNG rng;

    /* validate arguments */
    if (key == NULL || hash == NULL || sig == NULL || sigSz == NULL ||
        curveSz == 0 || hashSz == 0 || keySz < curveSz || *sigSz < (curveSz*2))
    {
        return BAD_FUNC_ARG;
    }

    /* Initialize signature result */
    memset(sig, 0, curveSz*2);

    /* Setup the RNG */
    ret = wc_InitRng(&rng);
    if (ret < 0) {
        return ret;
    }

    /* Setup the ECC key */
    ret = wc_ecc_init(&ecc);
    if (ret < 0) {
        wc_FreeRng(&rng);
        return ret;
    }

    /* Setup the signature r/s variables */
    ret = mp_init(&r);
    if (ret != MP_OKAY) {
        wc_ecc_free(&ecc);
        wc_FreeRng(&rng);
        return ret;
    }
    ret = mp_init(&s);
    if (ret != MP_OKAY) {
        mp_clear(&r);
        wc_ecc_free(&ecc);
        wc_FreeRng(&rng);
        return ret;
    }

    /* Import private key "k" */
    ret = wc_ecc_import_private_key_ex(
        key, keySz, /* private key "d" */
        NULL, 0,    /* public (optional) */
        &ecc,
        curveId     /* ECC Curve Id */
    );
    
    //WOLFSSL_BIGNUM *RST=NULL;
    //RST=WOLFSSL_BN_new();;

    if (ret == 0) {
        /* Verify ECC Signature */
        ret = wc_ecc_sign_hash_ex(
            hash, hashSz, /* computed hash digest */
            &rng, &ecc,   /* random and key context */
            &r, &s        /* r/s as mp_int */
        );

        /* export r/s */
        mp_to_unsigned_bin(&r, sig);
        mp_to_unsigned_bin(&s, sig + curveSz);
    /*
    const uint8_t secp256k1N[]={
    0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xfe,
    0xba,0xae,0xdc,0xe6,
    0xaf,0x48,0xa0,0x3b,
    0xbf,0xd2,0x5e,0x8c,
    0xd0,0x36,0x41,0x41
    };
    const uint8_t to[]={0x02};
    unsigned int secp256k1HalfN=(unsigned int)secp256k1N/(unsigned int)to;
    */
    }
    
    mp_clear(&r);
    mp_clear(&s);
    wc_ecc_free(&ecc);
    wc_FreeRng(&rng);

    return ret;
}


 int Sha3_3() 
{
    wc_Sha3     sha3;
    int         ret = 0;
    const char* msg = "0x7fc3a6e089b470bbfa6f60bf7534e928ca9a1463";
    word32      msglen = (word32)XSTRLEN(msg);
    
    /*
    const uint8_t msg[] = {
    0x7f,0xc3,0xa6,0xe0,
    0x89,0xb4,0x70,0xbb,
    0xfa,0x6f,0x60,0xbf,
    0x75,0x34,0xe9,0x28,
    0xca,0x9a,0x14,0x63
};
	word32      msglen=20;
    */
    byte        hash[32];
    word32      hashLen = sizeof(hash);


    XMEMSET(hash, 0, sizeof(hash));


    ret = wc_InitSha3_256(&sha3, NULL, 0);
    if (ret != 0) {
        return ret;
    }

    ret = wc_Sha3_256_Update(&sha3, (byte*)msg, msglen);
    ret=wc_Sha3_256_Final(&sha3, hash);
    printf("Hash VALUE:\n");
    print_hex(hash,32);
    return ret;

} /* END wc_Sha3 */

uint32_t a(uint8_t* sealedEccKey,uint8_t* pubKey)
{
    int ret;
    ecc_key key;
    WC_RNG rng;
    //byte der[MAX_DER_SZ];
    //byte buf[MAX_DER_SZ];
    wc_InitRng(&rng);
    wc_ecc_init(&key);
    uint32_t pubQxSz = ECC_CURVE_SZ, pubQySz = ECC_CURVE_SZ;
    ret = wc_ecc_make_key_ex(&rng, ECC_CURVE_SZ, &key, ECC_CURVE_ID);
    if (ret != 0) {
        printf("error %d making ecc key\n", ret);
        //return ret;
    }
    ret=0;
    
    //uint8_t pubKey[ECC_CURVE_SZ*2];
    uint8_t priKey[ECC_CURVE_SZ];
    if (ret == 0) {
        ret = wc_ecc_make_pub(&key, NULL);
    }
    if (ret == 0) {
        ret = wc_ecc_export_public_raw(&key, 
            pubKey, &pubQxSz,               /* public Qx */
            pubKey+ECC_CURVE_SZ, &pubQySz   /* public Qy */
        );
    }    
    //printf("Public Key Qx: %d\n", pubQxSz);
    //print_hex(pubKey, ECC_CURVE_SZ);
    //printf("Public Key Qy: %d\n", pubQySz);
    //print_hex(pubKey+ECC_CURVE_SZ, ECC_CURVE_SZ);
    
    uint32_t priSz= ECC_CURVE_SZ;
    wc_ecc_export_private_only(&key, priKey, &priSz);
    //printf("Private Key : %d\n", priSz);
    //print_hex(priKey,ECC_CURVE_SZ);
    

    //seal priKey
    uint32_t sizeee=sgx_calc_sealed_data_size(0U, sizeof(priKey));
    uint8_t temp_sealed_buf[sizeee];
    sgx_status_t  err = sgx_seal_data(0, NULL, (uint32_t)32,(uint8_t *)priKey,(uint32_t)sizeee,(sgx_sealed_data_t *)temp_sealed_buf);
	if (err == SGX_SUCCESS)
    {
	printf("sealed success\n");
    memcpy(sealedEccKey, temp_sealed_buf, sizeee);
   }
    wc_ecc_free(&key);
    return ret;
}

const unsigned char Num2CharTable[] = "0123456789ABCDEF";
void HexArrayToString(uint8_t *hexarray, int length, uint8_t *string)
{
    int i = 0;
    while(i < length)
    {
        *(string++) = Num2CharTable[(hexarray[i] >> 4) & 0x0f];
        *(string++) = Num2CharTable[hexarray[i] & 0x0f];
        i++;
    }
    *string = 0x0;
}
long int HexArrayToDec(uint8_t *hexarray, int len)
{
    uint8_t dst[50];
    HexArrayToString(hexarray, len, dst);
    int t;
    long sum=0;
    for(int i=0;dst[i];i++){
        if(dst[i]<='9')
            t=dst[i]-'0';
        else
            t=dst[i]-'A'+10;
        sum=sum*16+t;
    }
    return sum;
}

unsigned int my_func(char *pUserInput, unsigned char *pKeyArray)
{
	if (NULL == pUserInput || NULL == pKeyArray)
	{
			return 0;
	}
	
	unsigned int uiKeySize = strlen(pUserInput) / 2;
	int i = 0;
	char cTempor = 0;
	
	while(i < uiKeySize)
	{
		if (*pUserInput >= '0' && *pUserInput <= '9')
		{
			cTempor = *pUserInput - 48;
		}
		else if (*pUserInput >= 'a' && *pUserInput <= 'z') 
		{
			cTempor = 0xa + (*pUserInput - 'a');
		}
		else 
		{
			cTempor = 0xa + (*pUserInput - 'A');
		}
		
		pKeyArray[i] = cTempor;
		pUserInput++;
		
		if (*pUserInput >= '0' && *pUserInput <= '9')
		{
			cTempor = *pUserInput - 48;
		}
		else 
		{
			cTempor = 0xa + (*pUserInput - 'a');
		}

		pKeyArray[i] = (pKeyArray[i] << 4) | cTempor;
		pUserInput++;
		i++;
	}
	
	return uiKeySize;	
}





int ecc_sign(uint8_t* sealedprivKey,uint8_t* kMsg_1,uint8_t* signature)
{
  //const char* kMsg = "2e6447474eeb2bb7a4ee478b4de92c75724c1f285cd750f67867edbd93935e2b";
  /*
  static const uint8_t kMsg[] = {
    0x2e, 0x64, 0x47, 0x47, 0x4e, 0xeb, 0x2b, 0xb7, 
    0xa4, 0xee, 0x47, 0x8b, 0x4d, 0xe9, 0x2c, 0x75, 
    0x72, 0x4c, 0x1f, 0x28, 0x5c, 0xd7, 0x50, 0xf6, 
    0x78, 0x67, 0xed, 0xbd, 0x93, 0x93, 0x5e, 0x2b
};
*/
//const char* kMsg = "11b0fab66c10ecedd23432ed7330e933181b52437eaa3d746de71f520e3aa97e";
/*
static  uint8_t kMsg[] = {
    0x11, 0xb0, 0xfa, 0xb6, 0x6c, 0x10, 0xec, 0xed, 
    0xd2, 0x34, 0x32, 0xed, 0x73, 0x30, 0xe9, 0x33, 
    0x18, 0x1b, 0x52, 0x43, 0x7e, 0xaa, 0x3d, 0x74, 
    0x6d, 0xe7, 0x1f, 0x52, 0x0e, 0x3a, 0xa9, 0x7e
};
*/

/*
static const uint8_t kMsg[]={
0x0f, 0x7c, 0xe2, 0x5d, 0x87, 0xff, 0x36, 0xd4, 
0x12, 0x83, 0x3a, 0xd9, 0x12, 0x54, 0x63, 0xf0, 
0x59, 0x70, 0x10, 0x5b, 0x0f, 0xb6, 0x1d, 0x47, 
0xeb, 0xd6, 0x4f, 0x3b, 0x49, 0x2b, 0x7a, 0x98
};
*/

/*
static const uint8_t kPrivKey[] = {    
    0x82, 0x28, 0xa1, 0xf4, 0xa8, 0x12, 0x39, 0xe1, 
    0xef, 0x7e, 0xcb, 0x03, 0x91, 0x6a, 0xd3, 0x71, 
    0x1c, 0x9d, 0x7a, 0x27, 0x99, 0x85, 0x62, 0x36, 
    0xba, 0x83, 0x22, 0xb7, 0x35, 0xb1, 0x19, 0xf3
};
*/	
	unsigned char kMsg[32];
	my_func(kMsg_1, kMsg);
	printf("msg to sign:\n");
	for(int i=0;i<16;i++){printf("%02X ",kMsg[i]);}
	printf("\n");
	for(int i=16;i<32;i++){printf("%02X ",kMsg[i]);}
	printf("\n");
	//loading priKey to sign message
	uint8_t kPrivKey[ECC_CURVE_SZ];
	uint32_t decrypt_data_len = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealedprivKey);
	//uint32_t decryptedLen = 32;
	sgx_unseal_data((sgx_sealed_data_t*)sealedprivKey, NULL, NULL, (uint8_t*)(&kPrivKey), &decrypt_data_len);
	printf("\nUnseal Private Key : %d\n", sizeof(kPrivKey));
    	print_hex(kPrivKey,sizeof(kPrivKey));


    int ret;
    uint8_t sig[ECC_CURVE_SZ*2];
    uint32_t sigSz = 0;
    uint8_t ss[ECC_CURVE_SZ];

    memset(sig, 0, sizeof(sig));
/*
    ret = crypto_sha256(
        kMsg, sizeof(kMsg), // input message 
        hash, sizeof(hash), // hash digest result 
        32                  // configurable block 
    );
*/

        /* Sign hash using private key */
        /* Note: result of an ECC sign varies for each call even with same 
            private key and hash. This is because a new random public key is 
            used for each operation. */ 
        sigSz = sizeof(sig);



        ret = crypto_ecc_sign(
            kPrivKey, sizeof(kPrivKey), /* private key */
            kMsg, sizeof(kMsg),         /* computed hash digest */
            sig, &sigSz,                /* signature r/s */
            ECC_CURVE_SZ,               /* SECP256K1 curve size in bytes */
            ECC_CURVE_ID                /* curve id */
        );
        


        //printf("Signature %d\n", sigSz);
       // print_hex(sig, sigSz);
	memcpy(signature, sig, sigSz);
	printf("R Value is ===>\n");
	for(int j=0;j<16;j++){printf("%02X ",signature[j]);}
	printf("\n");
	for(int j=16;j<32;j++){printf("%02X ",signature[j]);}
	printf("\n");
	printf("S Value is ===>\n");
	for(int j=32;j<48;j++){printf("%02X ",signature[j]);}
	printf("\n");
	for(int j=48;j<64;j++){printf("%02X ",signature[j]);}
	printf("\n");
	


    return ret;
}

void Hash_256(uint8_t* Msg,uint8_t* hash){

	int ret = crypto_sha256(
        Msg, sizeof(Msg), // input message 
        hash, sizeof(hash), // hash digest result 
        32                  // configurable block 
    );
    //print_hex(hash,32);
    
	
}




#if defined(XMALLOC_USER) || defined(XMALLOC_OVERRIDE)
    #warning verification of heap hint pointers needed when overriding default malloc/free
#endif


/* Max number of WOLFSSL_CTX's */
#ifndef MAX_WOLFSSL_CTX
#define MAX_WOLFSSL_CTX 2
#endif
WOLFSSL_CTX* CTX_TABLE[MAX_WOLFSSL_CTX];

/* Max number of WOLFSSL's */
#ifndef MAX_WOLFSSL
#define MAX_WOLFSSL 2
#endif
WOLFSSL* SSL_TABLE[MAX_WOLFSSL];

/* returns ID assigned on success and -1 on failure
 * @TODO mutex for threaded use cases */
static long AddCTX(WOLFSSL_CTX* ctx)
{
    long i;
    for (i = 0; i < MAX_WOLFSSL_CTX; i++) {
         if (CTX_TABLE[i] == NULL) {
             CTX_TABLE[i] = ctx;
             return i;
         }
    }
    return -1;
}


/* returns ID assigned on success and -1 on failure
 * @TODO mutex for threaded use cases */
static long AddSSL(WOLFSSL* ssl)
{
    long i;
    for (i = 0; i < MAX_WOLFSSL; i++) {
         if (SSL_TABLE[i] == NULL) {
             SSL_TABLE[i] = ssl;
             return i;
         }
    }
    return -1;
}


/* returns the WOLFSSL_CTX pointer on success and NULL on failure */
static WOLFSSL_CTX* GetCTX(long id)
{
    if (id >= MAX_WOLFSSL_CTX || id < 0)
        return NULL;
    return CTX_TABLE[id];
}


/* returns the WOLFSSL pointer on success and NULL on failure */
static WOLFSSL* GetSSL(long id)
{
    if (id >= MAX_WOLFSSL || id < 0)
        return NULL;
    return SSL_TABLE[id];
}


/* Free's and removes the WOLFSSL_CTX associated with 'id' */
static void RemoveCTX(long id)
{
    if (id >= MAX_WOLFSSL_CTX || id < 0)
        return;
    wolfSSL_CTX_free(CTX_TABLE[id]);
    CTX_TABLE[id] = NULL;
}


/* Free's and removes the WOLFSSL associated with 'id' */
static void RemoveSSL(long id)
{
    if (id >= MAX_WOLFSSL || id < 0)
        return;
    wolfSSL_free(SSL_TABLE[id]);
    SSL_TABLE[id] = NULL;
}

#if defined(WOLFSSL_STATIC_MEMORY)
/* check on heap hint when used, aborts if pointer is not in Enclave.
 * In the default case where wolfSSL_Malloc is used the heap hint pointer is not
 * used.*/
static void checkHeapHint(WOLFSSL_CTX* ctx, WOLFSSL* ssl)
{
    WOLFSSL_HEAP_HINT* heap;
    if ((heap = (WOLFSSL_HEAP_HINT*)wolfSSL_CTX_GetHeap(ctx, ssl)) != NULL) {
        if(sgx_is_within_enclave(heap, sizeof(WOLFSSL_HEAP_HINT)) != 1)
            abort();
        if(sgx_is_within_enclave(heap->memory, sizeof(WOLFSSL_HEAP)) != 1)
            abort();
    }
}
#endif /* WOLFSSL_STATIC_MEMORY */


int wc_test(void* args)
{
#ifdef HAVE_WOLFSSL_TEST
	return wolfcrypt_test(args);
#else
    /* wolfSSL test not compiled in! */
    return -1;
#endif /* HAVE_WOLFSSL_TEST */
}

int wc_benchmark_test(void* args)
{

#ifdef HAVE_WOLFSSL_BENCHMARK
    return benchmark_test(args);
#else
    /* wolfSSL benchmark not compiled in! */
    return -1;
#endif /* HAVE_WOLFSSL_BENCHMARK */
}

void enc_wolfSSL_Debugging_ON(void)
{
    wolfSSL_Debugging_ON();
}

void enc_wolfSSL_Debugging_OFF(void)
{
    wolfSSL_Debugging_OFF();
}

int enc_wolfSSL_Init(void)
{
    return wolfSSL_Init();
}


#define WOLFTLSv12_CLIENT 1
#define WOLFTLSv12_SERVER 2

long enc_wolfTLSv1_2_client_method(void)
{
    return WOLFTLSv12_CLIENT;
}

long enc_wolfTLSv1_2_server_method(void)
{
    return WOLFTLSv12_SERVER;
}


/* returns method related to id */
static WOLFSSL_METHOD* GetMethod(long id)
{
    switch (id) {
        case WOLFTLSv12_CLIENT: return wolfTLSv1_2_client_method();
        case WOLFTLSv12_SERVER: return wolfTLSv1_2_server_method();
        default:
            return NULL;
    }
}


long enc_wolfSSL_CTX_new(long method)
{
    WOLFSSL_CTX* ctx;
    long id = -1;

    ctx = wolfSSL_CTX_new(GetMethod(method));
    if (ctx != NULL) {
        id = AddCTX(ctx);
    }
    return id;
}

int enc_wolfSSL_CTX_use_certificate_chain_buffer_format(long id,
        const unsigned char* buf, long sz, int type)
{
    WOLFSSL_CTX* ctx = GetCTX(id);
    if (ctx == NULL) {
        return -1;
    }
    return wolfSSL_CTX_use_certificate_chain_buffer_format(ctx, buf, sz, type);
}

int enc_wolfSSL_CTX_use_certificate_buffer(long id,
        const unsigned char* buf, long sz, int type)
{
    WOLFSSL_CTX* ctx = GetCTX(id);
    if (ctx == NULL) {
        return -1;
    }
    return wolfSSL_CTX_use_certificate_buffer(ctx, buf, sz, type);
}

int enc_wolfSSL_CTX_use_PrivateKey_buffer(long id, const unsigned char* buf,
                                            long sz, int type)
{
    WOLFSSL_CTX* ctx = GetCTX(id);
    if (ctx == NULL) {
        return -1;
    }
    return wolfSSL_CTX_use_PrivateKey_buffer(ctx, buf, sz, type);
}

int enc_wolfSSL_CTX_load_verify_buffer(long id, const unsigned char* in,
                                       long sz, int format)
{
    WOLFSSL_CTX* ctx = GetCTX(id);
    if (ctx == NULL) {
        return -1;
    }
    return wolfSSL_CTX_load_verify_buffer(ctx, in, sz, format);
}


int enc_wolfSSL_CTX_set_cipher_list(long id, const char* list)
{
    WOLFSSL_CTX* ctx = GetCTX(id);
    if (ctx == NULL) {
        return -1;
    }
    return wolfSSL_CTX_set_cipher_list(ctx, list);
}

long enc_wolfSSL_new(long id)
{
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    long ret = -1;

    ctx = GetCTX(id);
    if (ctx == NULL) {
        return -1;
    }
    ssl = wolfSSL_new(ctx);
    if (ssl != NULL) {
        ret = AddSSL(ssl);
    }
    return ret;
}

int enc_wolfSSL_set_fd(long sslId, int fd)
{
    WOLFSSL* ssl = GetSSL(sslId);
    if (ssl == NULL) {
        return -1;
    }
    return wolfSSL_set_fd(ssl, fd);
}

int enc_wolfSSL_connect(long sslId)
{
    WOLFSSL* ssl = GetSSL(sslId);
    if (ssl == NULL) {
        return -1;
    }
    return wolfSSL_connect(ssl);
}

int enc_wolfSSL_write(long sslId, const void* in, int sz)
{
    WOLFSSL* ssl = GetSSL(sslId);
    if (ssl == NULL) {
        return -1;
    }
    return wolfSSL_write(ssl, in, sz);
}

int enc_wolfSSL_get_error(long sslId, int ret)
{
    WOLFSSL* ssl = GetSSL(sslId);
    if (ssl == NULL) {
        return -1;
    }
    return wolfSSL_get_error(ssl, ret);
}

int enc_wolfSSL_read(long sslId, void* data, int sz)
{
    WOLFSSL* ssl = GetSSL(sslId);
    if (ssl == NULL) {
        return -1;
    }
    return wolfSSL_read(ssl, data, sz);
}

void enc_wolfSSL_free(long sslId)
{
    RemoveSSL(sslId);
}

void enc_wolfSSL_CTX_free(long id)
{
    RemoveCTX(id);
}

int enc_wolfSSL_Cleanup(void)
{
    long id;

    /* free up all WOLFSSL's */
    for (id = 0; id < MAX_WOLFSSL; id++)
        RemoveSSL(id);

    /* free up all WOLFSSL_CTX's */
    for (id = 0; id < MAX_WOLFSSL_CTX; id++)
        RemoveCTX(id);
    wolfSSL_Cleanup();
}




double current_time(void)
{
    double curr;
    ocall_current_time(&curr);
    return curr;
}

int LowResTimer(void) /* low_res timer */
{
    int time;
    ocall_low_res_time(&time);
    return time;
}

size_t recv(int sockfd, void *buf, size_t len, int flags)
{
    size_t ret;
    int sgxStatus;
    sgxStatus = ocall_recv(&ret, sockfd, buf, len, flags);
    return ret;
}

size_t send(int sockfd, const void *buf, size_t len, int flags)
{
    size_t ret;
    int sgxStatus;
    sgxStatus = ocall_send(&ret, sockfd, buf, len, flags);
    return ret;
}
