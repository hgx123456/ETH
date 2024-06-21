#ifndef WOLFSSL_ENCLAVE_U_H__
#define WOLFSSL_ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

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

#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
#endif
#ifndef OCALL_CURRENT_TIME_DEFINED__
#define OCALL_CURRENT_TIME_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_current_time, (double* time));
#endif
#ifndef OCALL_LOW_RES_TIME_DEFINED__
#define OCALL_LOW_RES_TIME_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_low_res_time, (int* time));
#endif
#ifndef OCALL_RECV_DEFINED__
#define OCALL_RECV_DEFINED__
size_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_recv, (int sockfd, void* buf, size_t len, int flags));
#endif
#ifndef OCALL_SEND_DEFINED__
#define OCALL_SEND_DEFINED__
size_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_send, (int sockfd, const void* buf, size_t len, int flags));
#endif

sgx_status_t a(sgx_enclave_id_t eid, uint32_t* retval, uint8_t* sealedEccKey, uint8_t* pubKey);
sgx_status_t ecc_sign(sgx_enclave_id_t eid, int* retval, uint8_t* sealedprivKey, uint8_t* kMsg, uint8_t* signature);
sgx_status_t Hash_256(sgx_enclave_id_t eid, uint8_t* Msg, uint8_t* hash);
sgx_status_t Sha3_3(sgx_enclave_id_t eid, int* retval);
sgx_status_t wc_test(sgx_enclave_id_t eid, int* retval, void* args);
sgx_status_t wc_benchmark_test(sgx_enclave_id_t eid, int* retval, void* args);
sgx_status_t enc_wolfSSL_Init(sgx_enclave_id_t eid, int* retval);
sgx_status_t enc_wolfSSL_Debugging_ON(sgx_enclave_id_t eid);
sgx_status_t enc_wolfSSL_Debugging_OFF(sgx_enclave_id_t eid);
sgx_status_t enc_wolfTLSv1_2_client_method(sgx_enclave_id_t eid, long int* retval);
sgx_status_t enc_wolfTLSv1_2_server_method(sgx_enclave_id_t eid, long int* retval);
sgx_status_t enc_wolfSSL_CTX_new(sgx_enclave_id_t eid, long int* retval, long int method);
sgx_status_t enc_wolfSSL_CTX_use_PrivateKey_buffer(sgx_enclave_id_t eid, int* retval, long int ctxId, const unsigned char* buf, long int sz, int type);
sgx_status_t enc_wolfSSL_CTX_load_verify_buffer(sgx_enclave_id_t eid, int* retval, long int ctxId, const unsigned char* buf, long int sz, int type);
sgx_status_t enc_wolfSSL_CTX_use_certificate_chain_buffer_format(sgx_enclave_id_t eid, int* retval, long int ctxId, const unsigned char* buf, long int sz, int type);
sgx_status_t enc_wolfSSL_CTX_use_certificate_buffer(sgx_enclave_id_t eid, int* retval, long int ctxId, const unsigned char* buf, long int sz, int type);
sgx_status_t enc_wolfSSL_CTX_set_cipher_list(sgx_enclave_id_t eid, int* retval, long int ctxId, const char* list);
sgx_status_t enc_wolfSSL_new(sgx_enclave_id_t eid, long int* retval, long int ctxId);
sgx_status_t enc_wolfSSL_set_fd(sgx_enclave_id_t eid, int* retval, long int sslId, int fd);
sgx_status_t enc_wolfSSL_connect(sgx_enclave_id_t eid, int* retval, long int sslId);
sgx_status_t enc_wolfSSL_write(sgx_enclave_id_t eid, int* retval, long int sslId, const void* in, int sz);
sgx_status_t enc_wolfSSL_get_error(sgx_enclave_id_t eid, int* retval, long int sslId, int ret);
sgx_status_t enc_wolfSSL_read(sgx_enclave_id_t eid, int* retval, long int sslId, void* out, int sz);
sgx_status_t enc_wolfSSL_free(sgx_enclave_id_t eid, long int sslId);
sgx_status_t enc_wolfSSL_CTX_free(sgx_enclave_id_t eid, long int ctxId);
sgx_status_t enc_wolfSSL_Cleanup(sgx_enclave_id_t eid, int* retval);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
