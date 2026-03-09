
#pragma once

#include <stdint.h>
#include <stddef.h>

#include "eventlog.h"

#define SHA384_DIGEST_SIZE 0x30

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

typedef struct {
	quote_header_t header;
	quote_v4_body_t body;
	uint32_t signature_length;
	uint8_t signature_data[];
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
