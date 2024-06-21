#ifndef WOLFSSL_ENCLAVE_T_H__
#define WOLFSSL_ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfcrypt/test/test.h"
#include "wolfcrypt/benchmark/benchmark.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

uint32_t a(uint8_t* sealedEccKey, uint8_t* pubKey);
int ecc_sign(uint8_t* sealedprivKey, uint8_t* kMsg, uint8_t* signature);
void Hash_256(uint8_t* Msg, uint8_t* hash);
int Sha3_3(void);
int wc_test(void* args);
int wc_benchmark_test(void* args);
int enc_wolfSSL_Init(void);
void enc_wolfSSL_Debugging_ON(void);
void enc_wolfSSL_Debugging_OFF(void);
long int enc_wolfTLSv1_2_client_method(void);
long int enc_wolfTLSv1_2_server_method(void);
long int enc_wolfSSL_CTX_new(long int method);
int enc_wolfSSL_CTX_use_PrivateKey_buffer(long int ctxId, const unsigned char* buf, long int sz, int type);
int enc_wolfSSL_CTX_load_verify_buffer(long int ctxId, const unsigned char* buf, long int sz, int type);
int enc_wolfSSL_CTX_use_certificate_chain_buffer_format(long int ctxId, const unsigned char* buf, long int sz, int type);
int enc_wolfSSL_CTX_use_certificate_buffer(long int ctxId, const unsigned char* buf, long int sz, int type);
int enc_wolfSSL_CTX_set_cipher_list(long int ctxId, const char* list);
long int enc_wolfSSL_new(long int ctxId);
int enc_wolfSSL_set_fd(long int sslId, int fd);
int enc_wolfSSL_connect(long int sslId);
int enc_wolfSSL_write(long int sslId, const void* in, int sz);
int enc_wolfSSL_get_error(long int sslId, int ret);
int enc_wolfSSL_read(long int sslId, void* out, int sz);
void enc_wolfSSL_free(long int sslId);
void enc_wolfSSL_CTX_free(long int ctxId);
int enc_wolfSSL_Cleanup(void);

sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL ocall_current_time(double* time);
sgx_status_t SGX_CDECL ocall_low_res_time(int* time);
sgx_status_t SGX_CDECL ocall_recv(size_t* retval, int sockfd, void* buf, size_t len, int flags);
sgx_status_t SGX_CDECL ocall_send(size_t* retval, int sockfd, const void* buf, size_t len, int flags);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
