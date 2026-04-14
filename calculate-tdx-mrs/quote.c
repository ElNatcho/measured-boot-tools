#include "quote.h"

#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <ctype.h>

#include <cjson/cJSON.h>

#include "common.h"
#include "signature.h"
#include "web.h"

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

static int hexstr_to_bytebuf(const char* hexstr, uint8_t* buf, size_t buf_size) {
	for (size_t i = 0; i < buf_size && *hexstr && *(hexstr + 1); i++) {
		char c1 = *hexstr++;
		char c2 = *hexstr++;

		if (!isxdigit(c1) || !isxdigit(c2)) {
			return 0;
		}

		buf[i]  = (uint8_t)(isdigit(c1) ? c1 - '0' : tolower(c1) - 'a' + 10) << 4;
		buf[i] |= (uint8_t)(isdigit(c2) ? c2 - '0' : tolower(c2) - 'a' + 10);
	}

	return 1;
}

// https://api.portal.trustedservices.intel.com/content/documentation.html#pcs-enclave-identity-v4
static int check_quote_v4_qe_identity(quote_v4_qe_report_cert_t *report) {
	int ret = 1;

	const char* identity_url = "https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity";
	cJSON *root_json = NULL;
	printf("Fetch qe identity from: %s\n", identity_url);
	int webret = fetch_qe_identity_form_intel(identity_url, &root_json);
	if(webret <= 0 || root_json == NULL) {
		fprintf(stderr, "Failed to fetch qe identity from intel!\n");
		return -1;
	}

	cJSON *qe_identity_json = cJSON_GetObjectItem(root_json, "enclaveIdentity");
	if (qe_identity_json == NULL) {
		fprintf(stderr, "Failed to get \"enclaveIdentity\" field from identity json.\n");
		return -1;
	}
	
	char* mrsigner_str = encode_hex(report->enclave_report_body.mrsigner, QUOTE_V4_EPB_MRSIGNER_SIZE);	
	char* isvprodid_str = encode_hex((uint8_t*)&report->enclave_report_body.isv_prodid,
									sizeof(report->enclave_report_body.isv_prodid));
	char* miscselect_str = encode_hex((uint8_t*)&report->enclave_report_body.miscselect,
									sizeof(report->enclave_report_body.miscselect));
	char* attributes_str = encode_hex(report->enclave_report_body.attributes, QUOTE_V4_EPB_ATTRIBUTES_SIZE);
	char* isvsvn_str = encode_hex((uint8_t*)&report->enclave_report_body.isv_svn,
									sizeof(report->enclave_report_body.isv_svn));

	cJSON* mrsigner_json = cJSON_GetObjectItem(qe_identity_json, "mrsigner");
	size_t mrsigner_str_len = QUOTE_V4_EPB_MRSIGNER_SIZE * 2 + 1;
	char lower_id_mrsigner_str[mrsigner_str_len];
	memset(lower_id_mrsigner_str, 0, mrsigner_str_len);
	for (size_t i = 0; i < mrsigner_str_len && i < strlen(mrsigner_json->valuestring); i++) {
		lower_id_mrsigner_str[i] = tolower(mrsigner_json->valuestring[i]);
	}
	printf("Checking mrsigner: %s ", mrsigner_str);
	if (cJSON_IsString(mrsigner_json) && strcmp(lower_id_mrsigner_str, mrsigner_str) == 0) {
		printf("(%svalid%s)\n", TTY_GREEN, TTY_WHITE);
	} else {
		printf("!= %s (%sinvalid%s)\n", lower_id_mrsigner_str, TTY_RED, TTY_WHITE);
		ret = 0;
	}

	cJSON* isvprodid_json = cJSON_GetObjectItem(qe_identity_json, "isvprodid");
	printf("Checking isv-prod-id: %s ", isvprodid_str);
	if (cJSON_IsNumber(isvprodid_json) && isvprodid_json->valueint == report->enclave_report_body.isv_prodid) {
		printf("(%svalid%s)\n", TTY_GREEN, TTY_WHITE);
	} else {
		printf("(%sinvalid%s)\n", TTY_RED, TTY_WHITE);
		ret = 0;
	}

	cJSON* miscselect_json = cJSON_GetObjectItem(qe_identity_json, "miscselect");
	cJSON* miscselect_mask_json = cJSON_GetObjectItem(qe_identity_json, "miscselectMask");
	if (!cJSON_IsString(miscselect_json) || !cJSON_IsString(miscselect_mask_json)) {
		fprintf(stderr, "Failed to retrieve \"miscselect\" and/or \"miscselectMask\" field!\n");
		ret = 0;
	} else {
		printf("Checking miscselect: %s ", miscselect_str);

		uint32_t id_miscselect;
		if (!hexstr_to_bytebuf(miscselect_json->valuestring, (uint8_t*)&id_miscselect, sizeof(id_miscselect))) {
			fprintf(stderr, "Failed to convert \"miscselect\" to valid byte buffer!\n");	
			ret = 0;
			goto skip_miscselect;
		}

		uint32_t id_miscselect_mask;
		if (!hexstr_to_bytebuf(miscselect_mask_json->valuestring, (uint8_t*)&id_miscselect_mask, sizeof(id_miscselect_mask))) {
			fprintf(stderr, "Failed to convert \"miscselect_mask\" to valid byte buffer!\n");
			ret = 0;
			goto skip_miscselect;
		}

		uint32_t miscselect_masked = report->enclave_report_body.miscselect & id_miscselect_mask;
		if (miscselect_masked == id_miscselect) {
			printf("(%svalid%s)\n", TTY_GREEN, TTY_WHITE);
		} else {
			printf("(%sinvalid%s)\n", TTY_RED, TTY_WHITE);
			ret = 0;
		}
	}
skip_miscselect:

	cJSON* attributes_json = cJSON_GetObjectItem(qe_identity_json, "attributes");
	cJSON* attributes_mask_json = cJSON_GetObjectItem(qe_identity_json, "attributesMask");
	if (!cJSON_IsString(attributes_json) || !cJSON_IsString(attributes_mask_json)) {
		fprintf(stderr, "Failed to retrieve \"attributes\" and/or \"attributes_mask\" field!\n");
		ret = 0;
	} else {
		printf("Checking attributes: %s ", attributes_str);

		uint8_t id_attributes[QUOTE_V4_EPB_ATTRIBUTES_SIZE];
		if (!hexstr_to_bytebuf(attributes_json->valuestring, (uint8_t*)&id_attributes, QUOTE_V4_EPB_ATTRIBUTES_SIZE)) {
			fprintf(stderr, "Failed to convert \"attributes\" to valid byte buffer!\n");
			ret = 0;
			goto skip_attributes;
		}

		uint8_t id_attributes_mask[QUOTE_V4_EPB_ATTRIBUTES_SIZE];
		if (!hexstr_to_bytebuf(attributes_mask_json->valuestring, (uint8_t*)&id_attributes_mask, QUOTE_V4_EPB_ATTRIBUTES_SIZE)) {
			fprintf(stderr, "Failed to convert \"attributes_mask\" to valid byte buffer!\n");
			ret = 0;
			goto skip_attributes;
		}

		uint8_t attributes_masked[QUOTE_V4_EPB_ATTRIBUTES_SIZE];
		memset(attributes_masked, 0, QUOTE_V4_EPB_ATTRIBUTES_SIZE);
		for (size_t i = 0; i < QUOTE_V4_EPB_ATTRIBUTES_SIZE; i++) {
			if ((report->enclave_report_body.attributes[i] & id_attributes_mask[i]) != id_attributes[i]) {
				printf("(%sinvalid%s)\n", TTY_RED, TTY_WHITE);
				ret = 0;
				goto skip_attributes;
			}
		}
		printf("(%svalid%s)\n", TTY_GREEN, TTY_WHITE);
	}
skip_attributes:

	printf("Checking isv-svn: %s ", isvsvn_str);

	cJSON* tcblevels_json = cJSON_GetObjectItem(qe_identity_json, "tcbLevels");
	if (!cJSON_IsArray(tcblevels_json)) {
		fprintf(stderr, "Failed to retrieve \"tcbLevels\" field!\n");
		ret = 0;
	} else {
		// iterate over the tcbLevels array
		uint16_t cur_isvsvn = 0;
		cJSON* tcblevel_json = NULL;
		cJSON* tcblevel_iter_json = tcblevels_json->child;
		while(tcblevel_iter_json != NULL) {
			cJSON* tcb_json = cJSON_GetObjectItem(tcblevel_iter_json, "tcb");
			if (!cJSON_IsObject(tcb_json)) {
				fprintf(stderr, "Failed to get \"tcb\" field: %s\n", tcblevel_iter_json->string);
				ret = 0;
			} else {
				cJSON* isvsvn_json = cJSON_GetObjectItem(tcb_json, "isvsvn");
				if (!cJSON_IsNumber(isvsvn_json)) {
					fprintf(stderr, "Failed to get \"isvsvn\": field %s\n", tcb_json->string);
					ret = 0;
				} else {
					if ((uint16_t)isvsvn_json->valueint > cur_isvsvn && (uint16_t)isvsvn_json->valueint <= report->enclave_report_body.isv_svn) {
						tcblevel_json = tcblevel_iter_json;
						cur_isvsvn = (uint16_t)isvsvn_json->valueint;
					}
				}
			}

			tcblevel_iter_json = tcblevel_iter_json->next;
		}

		if (tcblevel_json == NULL) {
			fprintf(stderr, "Failed to find a valid tcb level!\n");
			ret = 0;
			goto skip_isvsvn;
		}

		cJSON* tcbstatus_json = cJSON_GetObjectItem(tcblevel_json, "tcbStatus");
		cJSON* tcbdate_json = cJSON_GetObjectItem(tcblevel_json, "tcbDate");

		if (!cJSON_IsString(tcbstatus_json) || !cJSON_IsString(tcbdate_json)) {
			fprintf(stderr, "Failed to retrieve \"tcbStatus\" and/or \"tcbDate\" field!\n");
			ret = 0;
			goto skip_isvsvn;
		}

		printf("=> date:%s ", tcbdate_json->valuestring);
		if (strcmp(tcbstatus_json->valuestring, "UpToDate") == 0) {
			printf("(%svalid%s)\n", TTY_GREEN, TTY_WHITE);
		} else {
			printf("state:%s (%sinvalid%s)\n", tcbstatus_json->valuestring, TTY_RED, TTY_WHITE);
			ret = 0;
		}
	}
skip_isvsvn:

	cJSON_Delete(root_json);
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
