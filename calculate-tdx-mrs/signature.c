#include "signature.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>

#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bn.h>

#include "common.h"
#include "web.h"

static EVP_PKEY* load_raw_ecdsa_p256_pk(const uint8_t* raw_key_64) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM_BLD *param_bld = NULL;
    OSSL_PARAM *params = NULL;

    // prepare the 'uncompressed' format (0x04 prefix + x + y)
    // OpenSSL expects the Octet String format: [0x04][32-byte X][32-byte Y]
    unsigned char encoded_point[65];
    encoded_point[0] = 0x04; 
    memcpy(&encoded_point[1], raw_key_64, 64);

    param_bld = OSSL_PARAM_BLD_new();
    if (!param_bld) return NULL;

    // set the curve and the point data
    OSSL_PARAM_BLD_push_utf8_string(param_bld, OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0);
    OSSL_PARAM_BLD_push_octet_string(param_bld, OSSL_PKEY_PARAM_PUB_KEY, encoded_point, 65);

    params = OSSL_PARAM_BLD_to_param(param_bld);
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);

    // generate the EVP_PKEY object
    if (ctx && params && EVP_PKEY_fromdata_init(ctx) > 0) {
        EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params);
    }

    // Cleanup
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(param_bld);
    EVP_PKEY_CTX_free(ctx);

    return pkey;
}

static int verify_ecdsa_p256_signature(EVP_PKEY *pub_key, const uint8_t *data, size_t data_len, 
								const uint8_t *sig, size_t sig_len) {
    int ret = -1;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    if (!ctx) {
		fprintf(stderr, "[%s] unable to create ctx\n", __func__);
        return -1; // download_data_t allocation error
    }

    // Use the EVP_PKEY_verify series for raw hashes, or EVP_DigestVerify for data
    if ((ret = EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pub_key)) <= 0) {
		fprintf(stderr, "[%s] EVP_DigestVerifyInit failed\n", __func__);
        goto cleanup;
    }
    
	if ((ret = EVP_DigestVerifyUpdate(ctx, data, data_len)) <= 0) {
		fprintf(stderr, "[%s] EVP_DigestVerifyUpdate failed\n", __func__);
        goto cleanup;
    }

    // Returns 1 for success, 0 for invalid signature, < 0 for error
    ret = EVP_DigestVerifyFinal(ctx, sig, sig_len);

cleanup:
    if (ret < 0) {
        ERR_print_errors_fp(stderr);
    }
    EVP_MD_CTX_free(ctx);
    return ret;
}

// input: raw_sig (64 bytes)
// output: der_sig (buffer of at least 72 bytes)
static int signature_ecdsa_p256_convert_raw_to_der(const uint8_t  *raw_sig, uint8_t *der_sig) {
    int der_len = 0;
    
    // create a signature object
    ECDSA_SIG *sig = ECDSA_SIG_new();
    if (!sig) return -1;

    // convert the two 32-byte halves into BIGNUMs
    // BN_bin2bn handles the endianness and leading zeros correctly
    BIGNUM *r = BN_bin2bn(raw_sig, 32, NULL);
    BIGNUM *s = BN_bin2bn(raw_sig + 32, 32, NULL);

    // place them into the signature object (sig now owns the memory for r and s)
    if (!ECDSA_SIG_set0(sig, r, s)) {
        ECDSA_SIG_free(sig);
        BN_free(r);
        BN_free(s);
        return -1;
    }

    // encode the object into the DER buffer
    unsigned char *p = der_sig;
    der_len = i2d_ECDSA_SIG(sig, &p);

    ECDSA_SIG_free(sig);
    return der_len; // This length (usually 70-72) goes into EVP_DigestVerifyFinal
}

int sig_check_quote_v4_signature(quote_v4_t* quote) {
	EVP_PKEY* pk = load_raw_ecdsa_p256_pk(quote->sig_data.ecdsa_attestation_key);

	const uint8_t der_sig_buf_size = 72;
	uint8_t der_sig[der_sig_buf_size];

	ssize_t der_sig_size = signature_ecdsa_p256_convert_raw_to_der(
		(uint8_t*)&quote->sig_data.signature, (uint8_t*)&der_sig);

	if (der_sig_size <= 0) {
		fprintf(stderr, "[%s] converting signature to der format failed: size=%ld\n", __func__, der_sig_size);
		return -1;
	}

	int ret = verify_ecdsa_p256_signature(pk, (uint8_t*)quote, sizeof(quote->header) + sizeof(quote->body),
											der_sig, der_sig_size);

	if (ret < 0) {
		unsigned long err = ERR_get_error();
		char err_buf[256];
		ERR_error_string_n(err, err_buf, sizeof(err_buf));
		fprintf(stderr, "OpenSSL Error: %s\n", err_buf);
	}

	return ret;
}

// This function parses a PEM string into a stack of X509 pointers
static STACK_OF(X509)* parse_pem_chain(const uint8_t* pem_data, const size_t pem_data_size) {
    STACK_OF(X509) *chain = sk_X509_new_null();
    BIO *bio = BIO_new_mem_buf(pem_data, pem_data_size);
    
    X509 *cert = NULL;
    // PEM_read_bio_X509 reads one cert at a time and advances the BIO cursor
    while ((cert = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
        sk_X509_push(chain, cert);
    }

    BIO_free(bio);
    
    // always check if we actually found certificates
    if (sk_X509_num(chain) == 0) {
        sk_X509_free(chain);
        return NULL;
    }
    return chain;
}

static int verify_pck_chain(X509 *target_cert, X509 *intermediate_cert, X509 *root_cert) {
    X509_STORE *store = NULL;
    X509_STORE_CTX *ctx = NULL;
    STACK_OF(X509) *untrusted_stack = NULL;
    int ret = 0;

    // create the store and add the trusted Root
    store = X509_STORE_new();
    X509_STORE_add_cert(store, root_cert);

    // create a stack for intermediate certificates
    untrusted_stack = sk_X509_new_null();
    sk_X509_push(untrusted_stack, intermediate_cert);

    // initialize the verification context
    ctx = X509_STORE_CTX_new();
    if (!X509_STORE_CTX_init(ctx, store, target_cert, untrusted_stack)) {
		fprintf(stderr, "[%s] X509_STORE_CTX_init failed\n", __func__);
        goto cleanup;
    }

    // perform the verification
    // returns 1 for success, 0 for failure, < 0 for internal error
    ret = X509_verify_cert(ctx);

    if (ret < 0) {
        int err = X509_STORE_CTX_get_error(ctx);
        fprintf(stderr, "[%s] Verification failed: %s\n", __func__, X509_verify_cert_error_string(err));
    }

cleanup:
    sk_X509_free(untrusted_stack);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    return ret;
}

int x509_equals(X509 *a, X509 *b) {
    if (!a || !b) return 0;

    unsigned char *buf_a = NULL;
    unsigned char *buf_b = NULL;

    int len_a = i2d_X509(a, &buf_a);
    int len_b = i2d_X509(b, &buf_b);

    if (len_a < 0 || len_b < 0) {
        OPENSSL_free(buf_a);
        OPENSSL_free(buf_b);
        return 0;
    }

    int result = 0;

    if (len_a == len_b && memcmp(buf_a, buf_b, len_a) == 0) {
        result = 1; // equal
    }

    OPENSSL_free(buf_a);
    OPENSSL_free(buf_b);

    return result;
}

int verify_root_ca_cert(X509* report_root_ca_cert) {
	int ret = -1;
	const char* root_ca_url = "https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.pem"; 

	printf("\nFetching root ca cert from: %s\n", root_ca_url);

	X509 *intel_root_ca_cert = NULL;
	int webret = fetch_root_ca_cert_from_intel(root_ca_url, &intel_root_ca_cert);
	if (webret <= 0 || intel_root_ca_cert == NULL) {
		fprintf(stderr, "Failed to fetch Intel Root CA Cert!\n");
		goto cleanup;
	}
	
	if (!x509_equals(report_root_ca_cert, intel_root_ca_cert)) {
		fprintf(stderr, "Intel root ca and report root ca cert do no match!\n");
	} else {
		ret = 1;
	}

	X509_free(intel_root_ca_cert);

cleanup:

	return ret;
}

int sig_check_quote_v4_enclave_report_signature(quote_v4_qe_report_cert_t* qe_report_cert) {
	int ret = -1;

	const uint8_t der_sig_buf_size = 72;
	uint8_t der_sig[der_sig_buf_size];
	
	//
	//	Fetch the QE Authentication Data and QE Certification Data from the QE Report

	quote_v4_qe_auth_data_t* auth_data;
	auth_data = (quote_v4_qe_auth_data_t*)(&qe_report_cert->auth_and_cert_data);

	quote_v4_cert_data_t* cert_data;
	cert_data = (quote_v4_cert_data_t*)
		((uint8_t*)(&qe_report_cert->auth_and_cert_data) + auth_data->size + sizeof(auth_data->size));

	// This is expected in the v4 quote qe report certificate data -> see A.3.12
	assert(cert_data->type == QUOTE_V4_CERT_TYPE_PCK_CERT_CHAIN);

	//
	//	Parse the PCK Certificate Chain from the qe certificate data and verify the chain

	STACK_OF(X509)* chain = parse_pem_chain((uint8_t*)&cert_data->data, cert_data->size);

	// according to the specification, the pem chain consists of (Leaf Cert || Intermediate CA Cert || Root CA Cert)
	if ((ret = sk_X509_num(chain)) != 3) {
		fprintf(stderr, "[%s] size of chain does not equal to 3: %d\n", __func__, ret);
		ret = -1;
		goto cleanup;
	}

	if (verify_pck_chain(sk_X509_value(chain, 0), sk_X509_value(chain, 1), sk_X509_value(chain, 2)) <= 0) {
		printf("PCK cert chain verification failed");
		goto cleanup;
	}

	if (verify_root_ca_cert(sk_X509_value(chain, 2)) <= 0) {
		printf("\t=> Report Root CA Certificate %sinvalid%s.\n", TTY_RED, TTY_WHITE);
		goto cleanup;
	} else {
		printf("\t=> Report Root CA Certificate %svalid%s.\n", TTY_GREEN, TTY_WHITE);
	}
	//
	// Parse the QE Report Signature and convert it to DER format

	ssize_t der_sig_size = signature_ecdsa_p256_convert_raw_to_der(
		(uint8_t*)&qe_report_cert->signature, (uint8_t*)&der_sig);

	if (der_sig_size <= 0) {
		fprintf(stderr, "[%s] converting signature to der format failed: size=%ld\n", __func__, der_sig_size);
		goto cleanup;
	}

	//
	// Extract public key from leaf certificate and use it to verify the signature
	
	EVP_PKEY *pk = X509_get_pubkey(sk_X509_value(chain,0));
	if (!pk) {
		fprintf(stderr, "[%s] failed to get public key from x509 leaf cert\n", __func__);
		goto cleanup;
	}

	ret = verify_ecdsa_p256_signature(pk, (uint8_t*)&qe_report_cert->enclave_report_body,
										sizeof(qe_report_cert->enclave_report_body),
										der_sig, der_sig_size);

cleanup:

	sk_X509_pop_free(chain, X509_free);

	return ret;
}

// see `gen_att_key` in quote_enclave_tdqe.cpp https://github.com/intel/confidential-computing.tee.dcap/blob/e90159735b0467202abd54737486af4d9348a8db/ae/tdqe/quoting_enclave_tdqe.cpp#L775 
int sig_check_attestation_key_hash(quote_v4_signature_data_t* sig, quote_v4_qe_report_cert_t* qe_report_cert) {
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	uint8_t hash[QUOTE_V4_EPB_REPORT_DATA_SIZE];
	unsigned int hash_length = 0;
	
	memset(hash, 0, QUOTE_V4_EPB_REPORT_DATA_SIZE);

	EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);

	EVP_DigestUpdate(ctx, sig->ecdsa_attestation_key, ECDSA_P256_SIG_SIZE);

	// Concat authentication data like https://github.com/intel/confidential-computing.tee.dcap/blob/e90159735b0467202abd54737486af4d9348a8db/QuoteGeneration/quote_wrapper/tdx_quote/td_ql_logic.cpp#L1385-L1388
	const size_t auth_data_size = 0x20;
	uint8_t authentication_data[ /* auth_data_size */ ] =
               {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
                0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};

	EVP_DigestUpdate(ctx, authentication_data, auth_data_size);

	EVP_DigestFinal_ex(ctx, hash, &hash_length);

	assert(hash_length < QUOTE_V4_EPB_REPORT_DATA_SIZE);

	for (size_t i = 0; i < QUOTE_V4_EPB_REPORT_DATA_SIZE; i++) {
		if (hash[i] != qe_report_cert->enclave_report_body.reportdata[i]) return 0;
	}

	return 1;
}
