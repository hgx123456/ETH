#include "Wolfssl_Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_a(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_a_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_a_t* ms = SGX_CAST(ms_a_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_sealedEccKey = ms->ms_sealedEccKey;
	size_t _len_sealedEccKey = 592;
	uint8_t* _in_sealedEccKey = NULL;
	uint8_t* _tmp_pubKey = ms->ms_pubKey;
	size_t _len_pubKey = 64;
	uint8_t* _in_pubKey = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealedEccKey, _len_sealedEccKey);
	CHECK_UNIQUE_POINTER(_tmp_pubKey, _len_pubKey);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealedEccKey != NULL && _len_sealedEccKey != 0) {
		if ( _len_sealedEccKey % sizeof(*_tmp_sealedEccKey) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_sealedEccKey = (uint8_t*)malloc(_len_sealedEccKey)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealedEccKey, 0, _len_sealedEccKey);
	}
	if (_tmp_pubKey != NULL && _len_pubKey != 0) {
		if ( _len_pubKey % sizeof(*_tmp_pubKey) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_pubKey = (uint8_t*)malloc(_len_pubKey)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_pubKey, 0, _len_pubKey);
	}

	ms->ms_retval = a(_in_sealedEccKey, _in_pubKey);
	if (_in_sealedEccKey) {
		if (memcpy_s(_tmp_sealedEccKey, _len_sealedEccKey, _in_sealedEccKey, _len_sealedEccKey)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_pubKey) {
		if (memcpy_s(_tmp_pubKey, _len_pubKey, _in_pubKey, _len_pubKey)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_sealedEccKey) free(_in_sealedEccKey);
	if (_in_pubKey) free(_in_pubKey);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecc_sign(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecc_sign_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecc_sign_t* ms = SGX_CAST(ms_ecc_sign_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_sealedprivKey = ms->ms_sealedprivKey;
	size_t _len_sealedprivKey = 592;
	uint8_t* _in_sealedprivKey = NULL;
	uint8_t* _tmp_kMsg = ms->ms_kMsg;
	size_t _len_kMsg = 64;
	uint8_t* _in_kMsg = NULL;
	uint8_t* _tmp_signature = ms->ms_signature;
	size_t _len_signature = 64;
	uint8_t* _in_signature = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealedprivKey, _len_sealedprivKey);
	CHECK_UNIQUE_POINTER(_tmp_kMsg, _len_kMsg);
	CHECK_UNIQUE_POINTER(_tmp_signature, _len_signature);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealedprivKey != NULL && _len_sealedprivKey != 0) {
		if ( _len_sealedprivKey % sizeof(*_tmp_sealedprivKey) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_sealedprivKey = (uint8_t*)malloc(_len_sealedprivKey);
		if (_in_sealedprivKey == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sealedprivKey, _len_sealedprivKey, _tmp_sealedprivKey, _len_sealedprivKey)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_kMsg != NULL && _len_kMsg != 0) {
		if ( _len_kMsg % sizeof(*_tmp_kMsg) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_kMsg = (uint8_t*)malloc(_len_kMsg);
		if (_in_kMsg == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_kMsg, _len_kMsg, _tmp_kMsg, _len_kMsg)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_signature != NULL && _len_signature != 0) {
		if ( _len_signature % sizeof(*_tmp_signature) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_signature = (uint8_t*)malloc(_len_signature)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_signature, 0, _len_signature);
	}

	ms->ms_retval = ecc_sign(_in_sealedprivKey, _in_kMsg, _in_signature);
	if (_in_signature) {
		if (memcpy_s(_tmp_signature, _len_signature, _in_signature, _len_signature)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_sealedprivKey) free(_in_sealedprivKey);
	if (_in_kMsg) free(_in_kMsg);
	if (_in_signature) free(_in_signature);
	return status;
}

static sgx_status_t SGX_CDECL sgx_Hash_256(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_Hash_256_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_Hash_256_t* ms = SGX_CAST(ms_Hash_256_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_Msg = ms->ms_Msg;
	size_t _len_Msg = 4096;
	uint8_t* _in_Msg = NULL;
	uint8_t* _tmp_hash = ms->ms_hash;
	size_t _len_hash = 64;
	uint8_t* _in_hash = NULL;

	CHECK_UNIQUE_POINTER(_tmp_Msg, _len_Msg);
	CHECK_UNIQUE_POINTER(_tmp_hash, _len_hash);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_Msg != NULL && _len_Msg != 0) {
		if ( _len_Msg % sizeof(*_tmp_Msg) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_Msg = (uint8_t*)malloc(_len_Msg);
		if (_in_Msg == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_Msg, _len_Msg, _tmp_Msg, _len_Msg)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_hash != NULL && _len_hash != 0) {
		if ( _len_hash % sizeof(*_tmp_hash) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_hash = (uint8_t*)malloc(_len_hash)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_hash, 0, _len_hash);
	}

	Hash_256(_in_Msg, _in_hash);
	if (_in_hash) {
		if (memcpy_s(_tmp_hash, _len_hash, _in_hash, _len_hash)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_Msg) free(_in_Msg);
	if (_in_hash) free(_in_hash);
	return status;
}

static sgx_status_t SGX_CDECL sgx_Sha3_3(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_Sha3_3_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_Sha3_3_t* ms = SGX_CAST(ms_Sha3_3_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = Sha3_3();


	return status;
}

static sgx_status_t SGX_CDECL sgx_wc_test(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_wc_test_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_wc_test_t* ms = SGX_CAST(ms_wc_test_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_args = ms->ms_args;



	ms->ms_retval = wc_test(_tmp_args);


	return status;
}

static sgx_status_t SGX_CDECL sgx_wc_benchmark_test(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_wc_benchmark_test_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_wc_benchmark_test_t* ms = SGX_CAST(ms_wc_benchmark_test_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_args = ms->ms_args;



	ms->ms_retval = wc_benchmark_test(_tmp_args);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_Init(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_Init_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_Init_t* ms = SGX_CAST(ms_enc_wolfSSL_Init_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = enc_wolfSSL_Init();


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_Debugging_ON(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	enc_wolfSSL_Debugging_ON();
	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_Debugging_OFF(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	enc_wolfSSL_Debugging_OFF();
	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfTLSv1_2_client_method(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfTLSv1_2_client_method_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfTLSv1_2_client_method_t* ms = SGX_CAST(ms_enc_wolfTLSv1_2_client_method_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = enc_wolfTLSv1_2_client_method();


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfTLSv1_2_server_method(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfTLSv1_2_server_method_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfTLSv1_2_server_method_t* ms = SGX_CAST(ms_enc_wolfTLSv1_2_server_method_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = enc_wolfTLSv1_2_server_method();


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_CTX_new(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_CTX_new_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_CTX_new_t* ms = SGX_CAST(ms_enc_wolfSSL_CTX_new_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = enc_wolfSSL_CTX_new(ms->ms_method);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_CTX_use_PrivateKey_buffer(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_CTX_use_PrivateKey_buffer_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_CTX_use_PrivateKey_buffer_t* ms = SGX_CAST(ms_enc_wolfSSL_CTX_use_PrivateKey_buffer_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const unsigned char* _tmp_buf = ms->ms_buf;
	long int _tmp_sz = ms->ms_sz;
	size_t _len_buf = _tmp_sz;
	unsigned char* _in_buf = NULL;

	CHECK_UNIQUE_POINTER(_tmp_buf, _len_buf);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_buf != NULL && _len_buf != 0) {
		if ( _len_buf % sizeof(*_tmp_buf) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_buf = (unsigned char*)malloc(_len_buf);
		if (_in_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_buf, _len_buf, _tmp_buf, _len_buf)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = enc_wolfSSL_CTX_use_PrivateKey_buffer(ms->ms_ctxId, (const unsigned char*)_in_buf, _tmp_sz, ms->ms_type);

err:
	if (_in_buf) free(_in_buf);
	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_CTX_load_verify_buffer(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_CTX_load_verify_buffer_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_CTX_load_verify_buffer_t* ms = SGX_CAST(ms_enc_wolfSSL_CTX_load_verify_buffer_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const unsigned char* _tmp_buf = ms->ms_buf;
	long int _tmp_sz = ms->ms_sz;
	size_t _len_buf = _tmp_sz;
	unsigned char* _in_buf = NULL;

	CHECK_UNIQUE_POINTER(_tmp_buf, _len_buf);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_buf != NULL && _len_buf != 0) {
		if ( _len_buf % sizeof(*_tmp_buf) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_buf = (unsigned char*)malloc(_len_buf);
		if (_in_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_buf, _len_buf, _tmp_buf, _len_buf)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = enc_wolfSSL_CTX_load_verify_buffer(ms->ms_ctxId, (const unsigned char*)_in_buf, _tmp_sz, ms->ms_type);

err:
	if (_in_buf) free(_in_buf);
	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_CTX_use_certificate_chain_buffer_format(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_CTX_use_certificate_chain_buffer_format_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_CTX_use_certificate_chain_buffer_format_t* ms = SGX_CAST(ms_enc_wolfSSL_CTX_use_certificate_chain_buffer_format_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const unsigned char* _tmp_buf = ms->ms_buf;
	long int _tmp_sz = ms->ms_sz;
	size_t _len_buf = _tmp_sz;
	unsigned char* _in_buf = NULL;

	CHECK_UNIQUE_POINTER(_tmp_buf, _len_buf);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_buf != NULL && _len_buf != 0) {
		if ( _len_buf % sizeof(*_tmp_buf) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_buf = (unsigned char*)malloc(_len_buf);
		if (_in_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_buf, _len_buf, _tmp_buf, _len_buf)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = enc_wolfSSL_CTX_use_certificate_chain_buffer_format(ms->ms_ctxId, (const unsigned char*)_in_buf, _tmp_sz, ms->ms_type);

err:
	if (_in_buf) free(_in_buf);
	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_CTX_use_certificate_buffer(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_CTX_use_certificate_buffer_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_CTX_use_certificate_buffer_t* ms = SGX_CAST(ms_enc_wolfSSL_CTX_use_certificate_buffer_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const unsigned char* _tmp_buf = ms->ms_buf;
	long int _tmp_sz = ms->ms_sz;
	size_t _len_buf = _tmp_sz;
	unsigned char* _in_buf = NULL;

	CHECK_UNIQUE_POINTER(_tmp_buf, _len_buf);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_buf != NULL && _len_buf != 0) {
		if ( _len_buf % sizeof(*_tmp_buf) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_buf = (unsigned char*)malloc(_len_buf);
		if (_in_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_buf, _len_buf, _tmp_buf, _len_buf)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = enc_wolfSSL_CTX_use_certificate_buffer(ms->ms_ctxId, (const unsigned char*)_in_buf, _tmp_sz, ms->ms_type);

err:
	if (_in_buf) free(_in_buf);
	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_CTX_set_cipher_list(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_CTX_set_cipher_list_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_CTX_set_cipher_list_t* ms = SGX_CAST(ms_enc_wolfSSL_CTX_set_cipher_list_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_list = ms->ms_list;
	size_t _len_list = ms->ms_list_len ;
	char* _in_list = NULL;

	CHECK_UNIQUE_POINTER(_tmp_list, _len_list);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_list != NULL && _len_list != 0) {
		_in_list = (char*)malloc(_len_list);
		if (_in_list == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_list, _len_list, _tmp_list, _len_list)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_list[_len_list - 1] = '\0';
		if (_len_list != strlen(_in_list) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ms->ms_retval = enc_wolfSSL_CTX_set_cipher_list(ms->ms_ctxId, (const char*)_in_list);

err:
	if (_in_list) free(_in_list);
	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_new(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_new_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_new_t* ms = SGX_CAST(ms_enc_wolfSSL_new_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = enc_wolfSSL_new(ms->ms_ctxId);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_set_fd(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_set_fd_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_set_fd_t* ms = SGX_CAST(ms_enc_wolfSSL_set_fd_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = enc_wolfSSL_set_fd(ms->ms_sslId, ms->ms_fd);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_connect(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_connect_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_connect_t* ms = SGX_CAST(ms_enc_wolfSSL_connect_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = enc_wolfSSL_connect(ms->ms_sslId);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_write(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_write_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_write_t* ms = SGX_CAST(ms_enc_wolfSSL_write_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const void* _tmp_in = ms->ms_in;
	int _tmp_sz = ms->ms_sz;
	size_t _len_in = _tmp_sz;
	void* _in_in = NULL;

	CHECK_UNIQUE_POINTER(_tmp_in, _len_in);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_in != NULL && _len_in != 0) {
		_in_in = (void*)malloc(_len_in);
		if (_in_in == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_in, _len_in, _tmp_in, _len_in)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = enc_wolfSSL_write(ms->ms_sslId, (const void*)_in_in, _tmp_sz);

err:
	if (_in_in) free(_in_in);
	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_get_error(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_get_error_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_get_error_t* ms = SGX_CAST(ms_enc_wolfSSL_get_error_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = enc_wolfSSL_get_error(ms->ms_sslId, ms->ms_ret);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_read(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_read_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_read_t* ms = SGX_CAST(ms_enc_wolfSSL_read_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_out = ms->ms_out;
	int _tmp_sz = ms->ms_sz;
	size_t _len_out = _tmp_sz;
	void* _in_out = NULL;

	CHECK_UNIQUE_POINTER(_tmp_out, _len_out);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_out != NULL && _len_out != 0) {
		if ((_in_out = (void*)malloc(_len_out)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_out, 0, _len_out);
	}

	ms->ms_retval = enc_wolfSSL_read(ms->ms_sslId, _in_out, _tmp_sz);
	if (_in_out) {
		if (memcpy_s(_tmp_out, _len_out, _in_out, _len_out)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_out) free(_in_out);
	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_free(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_free_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_free_t* ms = SGX_CAST(ms_enc_wolfSSL_free_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	enc_wolfSSL_free(ms->ms_sslId);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_CTX_free(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_CTX_free_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_CTX_free_t* ms = SGX_CAST(ms_enc_wolfSSL_CTX_free_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	enc_wolfSSL_CTX_free(ms->ms_ctxId);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_Cleanup(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_Cleanup_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_Cleanup_t* ms = SGX_CAST(ms_enc_wolfSSL_Cleanup_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = enc_wolfSSL_Cleanup();


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[26];
} g_ecall_table = {
	26,
	{
		{(void*)(uintptr_t)sgx_a, 0, 0},
		{(void*)(uintptr_t)sgx_ecc_sign, 0, 0},
		{(void*)(uintptr_t)sgx_Hash_256, 0, 0},
		{(void*)(uintptr_t)sgx_Sha3_3, 0, 0},
		{(void*)(uintptr_t)sgx_wc_test, 0, 0},
		{(void*)(uintptr_t)sgx_wc_benchmark_test, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_Init, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_Debugging_ON, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_Debugging_OFF, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfTLSv1_2_client_method, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfTLSv1_2_server_method, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_CTX_new, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_CTX_use_PrivateKey_buffer, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_CTX_load_verify_buffer, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_CTX_use_certificate_chain_buffer_format, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_CTX_use_certificate_buffer, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_CTX_set_cipher_list, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_new, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_set_fd, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_connect, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_write, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_get_error, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_read, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_free, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_CTX_free, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_Cleanup, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[5][26];
} g_dyn_entry_table = {
	5,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_print_string_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_current_time(double* time)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_time = sizeof(double);

	ms_ocall_current_time_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_current_time_t);
	void *__tmp = NULL;

	void *__tmp_time = NULL;

	CHECK_ENCLAVE_POINTER(time, _len_time);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (time != NULL) ? _len_time : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_current_time_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_current_time_t));
	ocalloc_size -= sizeof(ms_ocall_current_time_t);

	if (time != NULL) {
		ms->ms_time = (double*)__tmp;
		__tmp_time = __tmp;
		if (_len_time % sizeof(*time) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_time, 0, _len_time);
		__tmp = (void *)((size_t)__tmp + _len_time);
		ocalloc_size -= _len_time;
	} else {
		ms->ms_time = NULL;
	}
	
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (time) {
			if (memcpy_s((void*)time, _len_time, __tmp_time, _len_time)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_low_res_time(int* time)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_time = sizeof(int);

	ms_ocall_low_res_time_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_low_res_time_t);
	void *__tmp = NULL;

	void *__tmp_time = NULL;

	CHECK_ENCLAVE_POINTER(time, _len_time);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (time != NULL) ? _len_time : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_low_res_time_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_low_res_time_t));
	ocalloc_size -= sizeof(ms_ocall_low_res_time_t);

	if (time != NULL) {
		ms->ms_time = (int*)__tmp;
		__tmp_time = __tmp;
		if (_len_time % sizeof(*time) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_time, 0, _len_time);
		__tmp = (void *)((size_t)__tmp + _len_time);
		ocalloc_size -= _len_time;
	} else {
		ms->ms_time = NULL;
	}
	
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (time) {
			if (memcpy_s((void*)time, _len_time, __tmp_time, _len_time)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_recv(size_t* retval, int sockfd, void* buf, size_t len, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = len;

	ms_ocall_recv_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_recv_t);
	void *__tmp = NULL;

	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_recv_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_recv_t));
	ocalloc_size -= sizeof(ms_ocall_recv_t);

	ms->ms_sockfd = sockfd;
	if (buf != NULL) {
		ms->ms_buf = (void*)__tmp;
		__tmp_buf = __tmp;
		memset(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}
	
	ms->ms_len = len;
	ms->ms_flags = flags;
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		errno = ms->ocall_errno;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_send(size_t* retval, int sockfd, const void* buf, size_t len, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = len;

	ms_ocall_send_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_send_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_send_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_send_t));
	ocalloc_size -= sizeof(ms_ocall_send_t);

	ms->ms_sockfd = sockfd;
	if (buf != NULL) {
		ms->ms_buf = (const void*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, buf, _len_buf)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}
	
	ms->ms_len = len;
	ms->ms_flags = flags;
	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		errno = ms->ocall_errno;
	}
	sgx_ocfree();
	return status;
}

