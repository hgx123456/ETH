#include "Wolfssl_Enclave_u.h"
#include <errno.h>

typedef struct ms_a_t {
	uint32_t ms_retval;
	uint8_t* ms_sealedEccKey;
	uint8_t* ms_pubKey;
} ms_a_t;

typedef struct ms_ecc_sign_t {
	int ms_retval;
	uint8_t* ms_sealedprivKey;
	uint8_t* ms_kMsg;
	uint8_t* ms_signature;
} ms_ecc_sign_t;

typedef struct ms_Hash_256_t {
	uint8_t* ms_Msg;
	uint8_t* ms_hash;
} ms_Hash_256_t;

typedef struct ms_Sha3_3_t {
	int ms_retval;
} ms_Sha3_3_t;

typedef struct ms_wc_test_t {
	int ms_retval;
	void* ms_args;
} ms_wc_test_t;

typedef struct ms_wc_benchmark_test_t {
	int ms_retval;
	void* ms_args;
} ms_wc_benchmark_test_t;

typedef struct ms_enc_wolfSSL_Init_t {
	int ms_retval;
} ms_enc_wolfSSL_Init_t;

typedef struct ms_enc_wolfTLSv1_2_client_method_t {
	long int ms_retval;
} ms_enc_wolfTLSv1_2_client_method_t;

typedef struct ms_enc_wolfTLSv1_2_server_method_t {
	long int ms_retval;
} ms_enc_wolfTLSv1_2_server_method_t;

typedef struct ms_enc_wolfSSL_CTX_new_t {
	long int ms_retval;
	long int ms_method;
} ms_enc_wolfSSL_CTX_new_t;

typedef struct ms_enc_wolfSSL_CTX_use_PrivateKey_buffer_t {
	int ms_retval;
	long int ms_ctxId;
	const unsigned char* ms_buf;
	long int ms_sz;
	int ms_type;
} ms_enc_wolfSSL_CTX_use_PrivateKey_buffer_t;

typedef struct ms_enc_wolfSSL_CTX_load_verify_buffer_t {
	int ms_retval;
	long int ms_ctxId;
	const unsigned char* ms_buf;
	long int ms_sz;
	int ms_type;
} ms_enc_wolfSSL_CTX_load_verify_buffer_t;

typedef struct ms_enc_wolfSSL_CTX_use_certificate_chain_buffer_format_t {
	int ms_retval;
	long int ms_ctxId;
	const unsigned char* ms_buf;
	long int ms_sz;
	int ms_type;
} ms_enc_wolfSSL_CTX_use_certificate_chain_buffer_format_t;

typedef struct ms_enc_wolfSSL_CTX_use_certificate_buffer_t {
	int ms_retval;
	long int ms_ctxId;
	const unsigned char* ms_buf;
	long int ms_sz;
	int ms_type;
} ms_enc_wolfSSL_CTX_use_certificate_buffer_t;

typedef struct ms_enc_wolfSSL_CTX_set_cipher_list_t {
	int ms_retval;
	long int ms_ctxId;
	const char* ms_list;
	size_t ms_list_len;
} ms_enc_wolfSSL_CTX_set_cipher_list_t;

typedef struct ms_enc_wolfSSL_new_t {
	long int ms_retval;
	long int ms_ctxId;
} ms_enc_wolfSSL_new_t;

typedef struct ms_enc_wolfSSL_set_fd_t {
	int ms_retval;
	long int ms_sslId;
	int ms_fd;
} ms_enc_wolfSSL_set_fd_t;

typedef struct ms_enc_wolfSSL_connect_t {
	int ms_retval;
	long int ms_sslId;
} ms_enc_wolfSSL_connect_t;

typedef struct ms_enc_wolfSSL_write_t {
	int ms_retval;
	long int ms_sslId;
	const void* ms_in;
	int ms_sz;
} ms_enc_wolfSSL_write_t;

typedef struct ms_enc_wolfSSL_get_error_t {
	int ms_retval;
	long int ms_sslId;
	int ms_ret;
} ms_enc_wolfSSL_get_error_t;

typedef struct ms_enc_wolfSSL_read_t {
	int ms_retval;
	long int ms_sslId;
	void* ms_out;
	int ms_sz;
} ms_enc_wolfSSL_read_t;

typedef struct ms_enc_wolfSSL_free_t {
	long int ms_sslId;
} ms_enc_wolfSSL_free_t;

typedef struct ms_enc_wolfSSL_CTX_free_t {
	long int ms_ctxId;
} ms_enc_wolfSSL_CTX_free_t;

typedef struct ms_enc_wolfSSL_Cleanup_t {
	int ms_retval;
} ms_enc_wolfSSL_Cleanup_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_current_time_t {
	double* ms_time;
} ms_ocall_current_time_t;

typedef struct ms_ocall_low_res_time_t {
	int* ms_time;
} ms_ocall_low_res_time_t;

typedef struct ms_ocall_recv_t {
	size_t ms_retval;
	int ocall_errno;
	int ms_sockfd;
	void* ms_buf;
	size_t ms_len;
	int ms_flags;
} ms_ocall_recv_t;

typedef struct ms_ocall_send_t {
	size_t ms_retval;
	int ocall_errno;
	int ms_sockfd;
	const void* ms_buf;
	size_t ms_len;
	int ms_flags;
} ms_ocall_send_t;

static sgx_status_t SGX_CDECL Wolfssl_Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Wolfssl_Enclave_ocall_current_time(void* pms)
{
	ms_ocall_current_time_t* ms = SGX_CAST(ms_ocall_current_time_t*, pms);
	ocall_current_time(ms->ms_time);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Wolfssl_Enclave_ocall_low_res_time(void* pms)
{
	ms_ocall_low_res_time_t* ms = SGX_CAST(ms_ocall_low_res_time_t*, pms);
	ocall_low_res_time(ms->ms_time);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Wolfssl_Enclave_ocall_recv(void* pms)
{
	ms_ocall_recv_t* ms = SGX_CAST(ms_ocall_recv_t*, pms);
	ms->ms_retval = ocall_recv(ms->ms_sockfd, ms->ms_buf, ms->ms_len, ms->ms_flags);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Wolfssl_Enclave_ocall_send(void* pms)
{
	ms_ocall_send_t* ms = SGX_CAST(ms_ocall_send_t*, pms);
	ms->ms_retval = ocall_send(ms->ms_sockfd, ms->ms_buf, ms->ms_len, ms->ms_flags);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[5];
} ocall_table_Wolfssl_Enclave = {
	5,
	{
		(void*)Wolfssl_Enclave_ocall_print_string,
		(void*)Wolfssl_Enclave_ocall_current_time,
		(void*)Wolfssl_Enclave_ocall_low_res_time,
		(void*)Wolfssl_Enclave_ocall_recv,
		(void*)Wolfssl_Enclave_ocall_send,
	}
};
sgx_status_t a(sgx_enclave_id_t eid, uint32_t* retval, uint8_t* sealedEccKey, uint8_t* pubKey)
{
	sgx_status_t status;
	ms_a_t ms;
	ms.ms_sealedEccKey = sealedEccKey;
	ms.ms_pubKey = pubKey;
	status = sgx_ecall(eid, 0, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecc_sign(sgx_enclave_id_t eid, int* retval, uint8_t* sealedprivKey, uint8_t* kMsg, uint8_t* signature)
{
	sgx_status_t status;
	ms_ecc_sign_t ms;
	ms.ms_sealedprivKey = sealedprivKey;
	ms.ms_kMsg = kMsg;
	ms.ms_signature = signature;
	status = sgx_ecall(eid, 1, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t Hash_256(sgx_enclave_id_t eid, uint8_t* Msg, uint8_t* hash)
{
	sgx_status_t status;
	ms_Hash_256_t ms;
	ms.ms_Msg = Msg;
	ms.ms_hash = hash;
	status = sgx_ecall(eid, 2, &ocall_table_Wolfssl_Enclave, &ms);
	return status;
}

sgx_status_t Sha3_3(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_Sha3_3_t ms;
	status = sgx_ecall(eid, 3, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t wc_test(sgx_enclave_id_t eid, int* retval, void* args)
{
	sgx_status_t status;
	ms_wc_test_t ms;
	ms.ms_args = args;
	status = sgx_ecall(eid, 4, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t wc_benchmark_test(sgx_enclave_id_t eid, int* retval, void* args)
{
	sgx_status_t status;
	ms_wc_benchmark_test_t ms;
	ms.ms_args = args;
	status = sgx_ecall(eid, 5, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_Init(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_enc_wolfSSL_Init_t ms;
	status = sgx_ecall(eid, 6, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_Debugging_ON(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 7, &ocall_table_Wolfssl_Enclave, NULL);
	return status;
}

sgx_status_t enc_wolfSSL_Debugging_OFF(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 8, &ocall_table_Wolfssl_Enclave, NULL);
	return status;
}

sgx_status_t enc_wolfTLSv1_2_client_method(sgx_enclave_id_t eid, long int* retval)
{
	sgx_status_t status;
	ms_enc_wolfTLSv1_2_client_method_t ms;
	status = sgx_ecall(eid, 9, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfTLSv1_2_server_method(sgx_enclave_id_t eid, long int* retval)
{
	sgx_status_t status;
	ms_enc_wolfTLSv1_2_server_method_t ms;
	status = sgx_ecall(eid, 10, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_CTX_new(sgx_enclave_id_t eid, long int* retval, long int method)
{
	sgx_status_t status;
	ms_enc_wolfSSL_CTX_new_t ms;
	ms.ms_method = method;
	status = sgx_ecall(eid, 11, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_CTX_use_PrivateKey_buffer(sgx_enclave_id_t eid, int* retval, long int ctxId, const unsigned char* buf, long int sz, int type)
{
	sgx_status_t status;
	ms_enc_wolfSSL_CTX_use_PrivateKey_buffer_t ms;
	ms.ms_ctxId = ctxId;
	ms.ms_buf = buf;
	ms.ms_sz = sz;
	ms.ms_type = type;
	status = sgx_ecall(eid, 12, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_CTX_load_verify_buffer(sgx_enclave_id_t eid, int* retval, long int ctxId, const unsigned char* buf, long int sz, int type)
{
	sgx_status_t status;
	ms_enc_wolfSSL_CTX_load_verify_buffer_t ms;
	ms.ms_ctxId = ctxId;
	ms.ms_buf = buf;
	ms.ms_sz = sz;
	ms.ms_type = type;
	status = sgx_ecall(eid, 13, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_CTX_use_certificate_chain_buffer_format(sgx_enclave_id_t eid, int* retval, long int ctxId, const unsigned char* buf, long int sz, int type)
{
	sgx_status_t status;
	ms_enc_wolfSSL_CTX_use_certificate_chain_buffer_format_t ms;
	ms.ms_ctxId = ctxId;
	ms.ms_buf = buf;
	ms.ms_sz = sz;
	ms.ms_type = type;
	status = sgx_ecall(eid, 14, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_CTX_use_certificate_buffer(sgx_enclave_id_t eid, int* retval, long int ctxId, const unsigned char* buf, long int sz, int type)
{
	sgx_status_t status;
	ms_enc_wolfSSL_CTX_use_certificate_buffer_t ms;
	ms.ms_ctxId = ctxId;
	ms.ms_buf = buf;
	ms.ms_sz = sz;
	ms.ms_type = type;
	status = sgx_ecall(eid, 15, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_CTX_set_cipher_list(sgx_enclave_id_t eid, int* retval, long int ctxId, const char* list)
{
	sgx_status_t status;
	ms_enc_wolfSSL_CTX_set_cipher_list_t ms;
	ms.ms_ctxId = ctxId;
	ms.ms_list = list;
	ms.ms_list_len = list ? strlen(list) + 1 : 0;
	status = sgx_ecall(eid, 16, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_new(sgx_enclave_id_t eid, long int* retval, long int ctxId)
{
	sgx_status_t status;
	ms_enc_wolfSSL_new_t ms;
	ms.ms_ctxId = ctxId;
	status = sgx_ecall(eid, 17, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_set_fd(sgx_enclave_id_t eid, int* retval, long int sslId, int fd)
{
	sgx_status_t status;
	ms_enc_wolfSSL_set_fd_t ms;
	ms.ms_sslId = sslId;
	ms.ms_fd = fd;
	status = sgx_ecall(eid, 18, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_connect(sgx_enclave_id_t eid, int* retval, long int sslId)
{
	sgx_status_t status;
	ms_enc_wolfSSL_connect_t ms;
	ms.ms_sslId = sslId;
	status = sgx_ecall(eid, 19, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_write(sgx_enclave_id_t eid, int* retval, long int sslId, const void* in, int sz)
{
	sgx_status_t status;
	ms_enc_wolfSSL_write_t ms;
	ms.ms_sslId = sslId;
	ms.ms_in = in;
	ms.ms_sz = sz;
	status = sgx_ecall(eid, 20, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_get_error(sgx_enclave_id_t eid, int* retval, long int sslId, int ret)
{
	sgx_status_t status;
	ms_enc_wolfSSL_get_error_t ms;
	ms.ms_sslId = sslId;
	ms.ms_ret = ret;
	status = sgx_ecall(eid, 21, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_read(sgx_enclave_id_t eid, int* retval, long int sslId, void* out, int sz)
{
	sgx_status_t status;
	ms_enc_wolfSSL_read_t ms;
	ms.ms_sslId = sslId;
	ms.ms_out = out;
	ms.ms_sz = sz;
	status = sgx_ecall(eid, 22, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_free(sgx_enclave_id_t eid, long int sslId)
{
	sgx_status_t status;
	ms_enc_wolfSSL_free_t ms;
	ms.ms_sslId = sslId;
	status = sgx_ecall(eid, 23, &ocall_table_Wolfssl_Enclave, &ms);
	return status;
}

sgx_status_t enc_wolfSSL_CTX_free(sgx_enclave_id_t eid, long int ctxId)
{
	sgx_status_t status;
	ms_enc_wolfSSL_CTX_free_t ms;
	ms.ms_ctxId = ctxId;
	status = sgx_ecall(eid, 24, &ocall_table_Wolfssl_Enclave, &ms);
	return status;
}

sgx_status_t enc_wolfSSL_Cleanup(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_enc_wolfSSL_Cleanup_t ms;
	status = sgx_ecall(eid, 25, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

