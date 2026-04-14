#include "quote.h"

#include <string.h>
#include <assert.h>

#include "common.h"
#include "signature.h"

quote_t* load_quote_from_file(const char* quote_file_path) {

	quote_t *quote = malloc(sizeof(quote_t));
	if(!quote) {
		printf("Failed to allocate quote.");
		return NULL;
	}

	memset(quote, 0, sizeof(quote_t));

	if (read_file(&quote->raw, &quote->raw_size, quote_file_path)) {
		printf("Failed to open file %s\n", quote_file_path);
		return NULL;
	}

	quote->version = quote->v4->header.version;

	return quote;
}

static void compare_measurements(uint8_t quote_mr[SHA384_DIGEST_SIZE], uint8_t calc_mr[SHA384_DIGEST_SIZE]) {
	char* quote_mr_str = encode_hex(quote_mr, SHA384_DIGEST_SIZE);
	char* calc_mr_str = encode_hex(calc_mr, SHA384_DIGEST_SIZE);

	printf("Quote:%s\nCalc :%s ", quote_mr_str, calc_mr_str);

	if (strcmp(quote_mr_str, calc_mr_str) == 0) {
		printf("(%sMatch%s)\n", TTY_GREEN, TTY_WHITE);
	} else {
		printf("(%sMismatch%s)\n", TTY_RED, TTY_WHITE);
	}

	free(quote_mr_str);
	free(calc_mr_str);
}

void check_quote_measurements(quote_t* quote, uint8_t mrs[MR_LEN][SHA384_DIGEST_LENGTH]) {
	printf("================= MRTD =================\n");
	compare_measurements(quote->v4->body.mrtd_measurement, mrs[INDEX_MRTD]);
	printf("================= RTMR0 ================\n");
	compare_measurements(quote->v4->body.rtmr0_measurement, mrs[INDEX_RTMR0]);
	printf("================= RTMR1 ================\n");
	compare_measurements(quote->v4->body.rtmr1_measurement, mrs[INDEX_RTMR1]);
	printf("================= RTMR2 ================\n");
	compare_measurements(quote->v4->body.rtmr2_measurement, mrs[INDEX_RTMR2]);
	printf("================= RTMR3 ================\n");
	compare_measurements(quote->v4->body.rtmr3_measurement, mrs[INDEX_RTMR3]);
	printf("================= MRSEAM ===============\n");
	compare_measurements(quote->v4->body.mrseam_measurement, mrs[INDEX_MRSEAM]);
}

static int check_quote_v4_qe_identity(quote_v4_qe_report_cert_t *report) {
	int ret = 0;
	char* mrsigner_str = encode_hex(report->enclave_report_body.mrsigner, QUOTE_V4_EPB_MRSIGNER_SIZE);	
	char* isvprodid_str = encode_hex((uint8_t*)&report->enclave_report_body.isv_prodid,
									sizeof(report->enclave_report_body.isv_prodid));
	char* miscselect_str = encode_hex((uint8_t*)&report->enclave_report_body.miscselect,
									sizeof(report->enclave_report_body.miscselect));
	char* attributes_str = encode_hex(report->enclave_report_body.attributes, QUOTE_V4_EPB_ATTRIBUTES_SIZE);
	char* isvsvn_str = encode_hex((uint8_t*)&report->enclave_report_body.isv_svn,
									sizeof(report->enclave_report_body.isv_svn));

	printf("Checking mrsigner: %s ", mrsigner_str);
	printf("(%sinvalid%s)\n", TTY_RED, TTY_WHITE);

	printf("Checking isv-prod-id: %s ", isvprodid_str);
	printf("(%sinvalid%s)\n", TTY_RED, TTY_WHITE);

	printf("Checking miscselect: %s ", miscselect_str);
	printf("(%sinvalid%s)\n", TTY_RED, TTY_WHITE);

	printf("Checking attributes: %s ", attributes_str);
	printf("(%sinvalid%s)\n", TTY_RED, TTY_WHITE);

	printf("Checking isv-svn: %s ", isvsvn_str);
	printf("(%sinvalid%s)\n", TTY_RED, TTY_WHITE);

	free(mrsigner_str);
	free(isvprodid_str);
	free(miscselect_str);
	free(attributes_str);
	free(isvsvn_str);

	return ret;
}

static void check_quote_v4_signature_qe_report_cert(quote_v4_t* quote) {

	quote_v4_qe_report_cert_t* qe_report_cert = (quote_v4_qe_report_cert_t*)(&quote->sig_data.cert_data.data);

	char* body_sig_str = encode_hex(qe_report_cert->signature, ECDSA_P256_SIG_SIZE);

	int ret = sig_check_quote_v4_enclave_report_signature(qe_report_cert);
	printf("\nQE Report Signature: %s ", body_sig_str);
	if (ret == 1) { /* success */
		printf("(%svalid%s)\n\t=>QE Report is authentic\n\n", TTY_GREEN, TTY_WHITE);
	} else if (ret == 0) { /* signature not valid */
		printf("(%sinvalid%s)\n", TTY_RED, TTY_WHITE);
	} else {
		printf("(%sverification failed%s)\n=> Openssl Error: %d\n", TTY_RED, TTY_WHITE, ret);
	}

	char* qe_report_data_str = encode_hex(qe_report_cert->enclave_report_body.reportdata, QUOTE_V4_EPB_REPORT_DATA_SIZE);

	quote_v4_qe_auth_data_t* auth_data = (quote_v4_qe_auth_data_t*)(&qe_report_cert->auth_and_cert_data);
	char* auth_data_str = encode_hex((uint8_t*)auth_data, auth_data->size + sizeof(auth_data->size));

	//printf("QE Authentication Data       : %s\n", auth_data_str);
	printf("QE Report Authentication Data: %s ", qe_report_data_str);

	if (sig_check_attestation_key_hash(&quote->sig_data, qe_report_cert) == 1) { /* valid hash */
		printf("(%svalid%s)\n\t=>(SHA256(Attestation Key || Auth-Data) || 32 time 0x0) valid, therefore the Attestation Key was generated within this QE\n\n", TTY_GREEN, TTY_WHITE);
	} else {
		printf("(%sinvalid%s)\n", TTY_RED, TTY_WHITE);
	}

	printf("Checking QE Identity:\n");
	if (check_quote_v4_qe_identity(qe_report_cert) <= 0) {
		printf("\t=> QE Identity %sinvalid%s\n", TTY_RED, TTY_WHITE);
	} else {
		printf("\t=> QE Identity %svalid%s\n", TTY_GREEN, TTY_WHITE);
	}

	free(body_sig_str);
	free(qe_report_data_str);
	free(auth_data_str);
}

void check_quote_signature(quote_t* quote) {

	// other versions are currently not implemented
	assert(quote->version == 4);

	char* signature_str = encode_hex(quote->v4->sig_data.signature, ECDSA_P256_SIG_SIZE);
	char* attestation_key_str = encode_hex(quote->v4->sig_data.ecdsa_attestation_key, ECDSA_P256_SIG_SIZE);

	printf("\n === Signature Verification ===\n");
	printf("ECDSA Attestation Key: %s\n", attestation_key_str);
	printf("Quote Signature      : %s ", signature_str);

	int ret = sig_check_quote_v4_signature(quote->v4);
	if (ret == 1) { /* success */
		printf("(%svalid%s)\n\t=>Quote Header and Body are signed with the Attestation Key and authentic\n\n", TTY_GREEN, TTY_WHITE);
	} else  if (ret == 0) {	/* signature not valid */
		printf("(%sinvalid%s)\n", TTY_RED, TTY_WHITE);
	} else {
		printf("(%sverification failed%s)\n=> Openssl Error: %d\n", TTY_RED, TTY_WHITE, ret);
	}

	printf("Cert Data Type=%d ", quote->v4->sig_data.cert_data.type);

	switch(quote->v4->sig_data.cert_data.type) {
		case QUOTE_V4_CERT_TYPE_PPID_PLAIN:			/* 1 */
		case QUOTE_V4_CERT_TYPE_PPID_ENC_RSA2048:	/* 2 */
		case QUOTE_V4_CERT_TYPE_PPID_ENC_RSA3072:	/* 3 */
		case QUOTE_V4_CERT_TYPE_PCK_LEAF_PLAIN:		/* 4 */
		case QUOTE_V4_CERT_TYPE_PCK_CERT_CHAIN:		/* 5 */
		case QUOTE_V4_CERT_TYPE_PLAT_MANIFEST:		/* 7 */
			printf("=> abort (currently not implemented)\n");
			break;

		case QUOTE_V4_CERT_TYPE_QE_REPORT_CERT:		/* 6 */
			printf("=> QE Report Certification\n");
			check_quote_v4_signature_qe_report_cert(quote->v4);
			break;

		default:
			printf("=> abort (unkown type)\n");
			break;
	}

	free(signature_str);
	free(attestation_key_str);
}
