#include "signature.h"

#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/bn.h>

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
        return -1; // Memory allocation error
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
int signature_ecdsa_p256_convert_raw_to_der(const uint8_t  *raw_sig, uint8_t *der_sig) {
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
