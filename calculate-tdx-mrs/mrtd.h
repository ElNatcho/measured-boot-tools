#pragma once

#include <stdint.h>
#include <stdio.h>

#include <openssl/sha.h>

// see qemu include/hw/i386/tdvf.h for type definitions
#define TDVF_SECTION_TYPE_BFV		0
#define TDVF_SECTION_TYPE_CFV		1
#define TDVF_SECTION_TYPE_TD_HOB	2
#define TDVF_SECTION_TYPE_TEMP_MEM	3

int
measure_ovmf(uint8_t digest[SHA384_DIGEST_LENGTH], uint8_t *raw_image_file, uint64_t image_size,
                const char *qemu_version);

int
measure_cfv(uint8_t digest[SHA384_DIGEST_LENGTH], uint8_t *raw_image, uint64_t raw_image_size);

typedef struct {
    uint32_t signature;
    uint32_t length;
    uint32_t version;
    uint32_t number_of_section_entry;
} tdx_metadata_descriptor_t;

typedef struct {
    uint32_t data_offset;
    uint32_t raw_data_size;
    uint64_t memory_address;
    uint64_t memory_data_size;
    uint32_t type;
    uint32_t attributes;
} tdx_metadata_section_t;

typedef struct {
	tdx_metadata_descriptor_t descriptor;
	tdx_metadata_section_t* sections;
} tdx_ovmf_metadata_t;

int get_ovmf_metadata(tdx_ovmf_metadata_t* metadata, uint8_t *raw_image, uint64_t raw_image_size);
