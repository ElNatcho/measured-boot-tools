
#pragma once

#include <stdint.h>
#include <stddef.h>

#include "eventlog.h"

#define SHA384_DIGEST_SIZE 0x30

#define ECDSA_P256_SIG_SIZE 64


//
//	A.3.1. TD Quote Header
//

#define QUOTE_HDR_QE_VENDOR_ID_SIZE 16
#define QUOTE_HDR_USER_DATA_SIZE 20

typedef struct {
	uint16_t version;
	uint16_t attestation_key_type;
	uint32_t tee_type;
	uint32_t reserved;
	uint8_t qu_vendor_id[QUOTE_HDR_QE_VENDOR_ID_SIZE];
	uint8_t user_data[QUOTE_HDR_USER_DATA_SIZE];
} __attribute__((packed)) quote_header_t;


//
//	A.3.2. TD Quote Body
//

#define QUOTE_V4_TEE_TCB_SVN_SIZE 16
#define QUOTE_V4_MRCONFIG_SIZE 48
#define QUOTE_V4_MROWNER_SIZE 48
#define QUOTE_V4_MROWNERCONFIG_SIZE 48
#define QUOTE_V4_REPORT_DATA_SIZE 64

typedef struct {
	uint8_t tee_tcb_svn[QUOTE_V4_TEE_TCB_SVN_SIZE];
	uint8_t mrseam_measurement[SHA384_DIGEST_SIZE];
	uint8_t mrsignerseam_hash[SHA384_DIGEST_SIZE];
	uint64_t seamattributes;
	uint64_t tdattributes;
	uint64_t xfam;
	uint8_t mrtd_measurement[SHA384_DIGEST_SIZE];
	uint8_t mrconfigid[QUOTE_V4_MRCONFIG_SIZE];
	uint8_t mrowner[QUOTE_V4_MROWNER_SIZE];
	uint8_t mrownerconfig[QUOTE_V4_MROWNERCONFIG_SIZE];
	uint8_t rtmr0_measurement[SHA384_DIGEST_SIZE];
	uint8_t rtmr1_measurement[SHA384_DIGEST_SIZE];
	uint8_t rtmr2_measurement[SHA384_DIGEST_SIZE];
	uint8_t rtmr3_measurement[SHA384_DIGEST_SIZE];
	uint8_t reportdata[QUOTE_V4_REPORT_DATA_SIZE];

} __attribute__((packed)) quote_v4_body_t;

//
//	A.3.10. Enclave Report Body
//

#define QUOTE_V4_EPB_CPU_SVN_SIZE		16
#define QUOTE_V4_EPB_ATTRIBUTES_SIZE	16
#define QUOTE_V4_EPB_MRENCLAVE_SIZE		32
#define QUOTE_V4_EPB_MRSIGNER_SIZE		32
#define QUOTE_V4_EPB_REPORT_DATA_SIZE	64

typedef struct {
	uint8_t cpu_svn[QUOTE_V4_EPB_CPU_SVN_SIZE];
	uint32_t miscselect;
	uint8_t reserved0[28];
	uint8_t attributes[QUOTE_V4_EPB_ATTRIBUTES_SIZE];
	uint8_t mrenclave[QUOTE_V4_EPB_MRENCLAVE_SIZE];
	uint8_t reserved1[32];
	uint8_t mrsigner[QUOTE_V4_EPB_MRSIGNER_SIZE];
	uint8_t reserved2[96];
	uint16_t isv_prodid;
	uint16_t isv_svn;
	uint8_t reserved3[60];
	uint8_t reportdata[QUOTE_V4_EPB_REPORT_DATA_SIZE];
} __attribute__((packed)) quote_v4_enclave_report_body_t;


//
//	A.3.11 QE Report Certificate Data
//

typedef struct {
	quote_v4_enclave_report_body_t enclave_report_body;
	uint8_t signature[ECDSA_P256_SIG_SIZE];
	uint8_t auth_and_cert_data[];
} __attribute__((packed)) quote_v4_qe_report_cert_t;

#define QUOTE_V4_CERT_TYPE_PPID_PLAIN			1
#define QUOTE_V4_CERT_TYPE_PPID_ENC_RSA2048		2
#define QUOTE_V4_CERT_TYPE_PPID_ENC_RSA3072		3
#define QUOTE_V4_CERT_TYPE_PCK_LEAF_PLAIN		4
#define QUOTE_V4_CERT_TYPE_PCK_CERT_CHAIN		5
#define QUOTE_V4_CERT_TYPE_QE_REPORT_CERT		6
#define QUOTE_V4_CERT_TYPE_PLAT_MANIFEST		7


//
//	A.3.7. QE Authentication Data
//

typedef struct {
	uint16_t size;
	uint8_t data[];
} __attribute__((packed)) quote_v4_qe_auth_data_t;


//
//	A.3.9. QE Certificate Data - Version 4
//

typedef struct {
	uint16_t type;
	uint32_t size;
	uint8_t data[];
} __attribute__((packed)) quote_v4_cert_data_t;


//
//	A.3.8. EDSA 256-bit Quote Signature Data Structure - Version 4
//

typedef struct {
	uint8_t signature[ECDSA_P256_SIG_SIZE];
	uint8_t ecdsa_attestation_key[ECDSA_P256_SIG_SIZE];
	quote_v4_cert_data_t cert_data;
} __attribute__((packed)) quote_v4_signature_data_t;


//
//	A.3.12. Full TD Quote in V4
//

typedef struct {
	quote_header_t header;
	quote_v4_body_t body;
	uint32_t sig_data_length;
	quote_v4_signature_data_t sig_data;
} __attribute__((packed)) quote_v4_t;


typedef struct {
	uint32_t version;
	union {
		quote_v4_t *v4;
		uint8_t *raw;
	};

	size_t raw_size;
} quote_t;

quote_t* load_quote_from_file(const char* quote_file_path);
void check_quote_measurements(quote_t* quote, uint8_t mrs[MR_LEN][SHA384_DIGEST_LENGTH]);
void check_quote_signature(quote_t* quote);
