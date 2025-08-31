/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include "eventlog.h"
#include <stdint.h> 

#include <openssl/evp.h>
#include <openssl/sha.h>

#include "common.h"
#include "td_hob.h"
#include "rtmrms.h"
#include "mrtd.h"

int rtmr_measure_tdhob(uint32_t mr_index, rtmrcontext_t *context)
{
	int ret = -1;

	if (!context->ovmf_file_path) {
		printf("Failed to open ovmf: no path provided\n");
		return -1;
	}

	uint8_t* ovmf_buf = NULL;
	uint64_t ovmf_size = 0;
	ret = read_file(&ovmf_buf, &ovmf_size, context->ovmf_file_path);
	if (ret) {
		printf("Failed to load %s\n", context->ovmf_file_path);
		return -1;
	}

	uint8_t* td_hob;
	size_t td_hob_size;
	create_td_hob_from_ovmf(&td_hob, &td_hob_size, ovmf_buf, ovmf_size);

	//print_data_ext(td_hob, td_hob_size, "Raw TD HOB:");

    uint8_t hash_td_hob[SHA384_DIGEST_LENGTH];
    hash_buf(EVP_sha384(), hash_td_hob, td_hob, td_hob_size);

	evlog_add(context->evlog, mr_index, "TD Hob", hash_td_hob,
		   "TD Hob passed from host VMM to guest firmware");
	hash_extend(EVP_sha384(), context->mrs[mr_index], hash_td_hob, SHA384_DIGEST_LENGTH);

	return -1;
}

int rtmr_measure_cfv(uint32_t mr_index, rtmrcontext_t *context)
{
	int ret = -1;

	if (!context->ovmf_file_path) {
		printf("Failed to open ovmf: no path provided\n");
		return -1;
	}

	uint8_t *ovmf_buf = NULL;
	uint64_t ovmf_size = 0;
	ret = read_file(&ovmf_buf, &ovmf_size, context->ovmf_file_path);
	if (ret) {
		printf("Failed to load %s\n", context->ovmf_file_path);
		return -1;
	}
	
	uint8_t hash_cfv[SHA384_DIGEST_LENGTH];
	ret = measure_cfv(hash_cfv, ovmf_buf, ovmf_size);
	if (ret) {
		printf("Failed to measure OVMF\n");
	}

	evlog_add(context->evlog, mr_index, "Configuration FV", hash_cfv,
		   "Configuration Firmware Volume");
    
	hash_extend(EVP_sha384(), context->mrs[mr_index], hash_cfv, SHA384_DIGEST_LENGTH);

	return 0;
}
