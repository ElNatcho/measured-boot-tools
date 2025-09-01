/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include "eventlog.h"
#include <stdint.h> 

#include <openssl/evp.h>
#include <openssl/sha.h>

#include "secureboot.h"
#include "common.h"
#include "td_hob.h"
#include "rtmrms.h"
#include "hash.h"
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

int rtmr_measure_qemu_fw_cfg(uint32_t mr_index, rtmrcontext_t *context)
{
	// Measures the configuration handed over by the QEMU firmware configuration (fw_cfg) device. The configuration
	// list is constructed in EDK2 in QemuFwCfgCacheInit.c:ConstructCacheFwCfgList and the measured in
	// QemuFwCfgCacheInit.c:CacheFwCfgInfoWithOptionalMeasurement. However, currently no fw_cfg device is used and
	// only 0x00 0x00 is measured. Therfore, this should suffice for now.
	// (see https://www.qemu.org/docs/master/specs/fw_cfg.html)
	uint8_t fw_cfg_buf[] = { 0x0, 0x0};
	size_t fw_cfg_size = sizeof(fw_cfg_buf);

	uint8_t hash_fw_cfg[SHA384_DIGEST_LENGTH];
	hash_buf(EVP_sha384(), hash_fw_cfg, fw_cfg_buf, fw_cfg_size);

	evlog_add(context->evlog, mr_index, "QEMU FW CFG", hash_fw_cfg,
		   "QEMU Firmware Configuration (fw_cfg) Device. (WARNING: Dummy implementation only"
		   " capable of measuring a non existent fw_cfg device)");

	hash_extend(EVP_sha384(), context->mrs[mr_index], hash_fw_cfg, SHA384_DIGEST_LENGTH);

	return 0;
}

int rtmr_measure_secure_boot_variables(uint32_t mr_index, rtmrcontext_t *context)
{
	// TODO: In general, secure boot variables are stored in the NVRAM. Potentially determine secure
	// boot variables automagically by parsing the NVRAM emulated by Qemu.
	//
	// However, to the best of our knowledge, qemu currently cannot emulate NVRAM, that is usable by
	// EDK2. Thus, falling back on the default values / allowing the user to specify custom values
	// should be sufficient at this point in time.
	return measure_secure_boot_variables(EVP_sha384(), context->mrs[mr_index], mr_index, 
									  context->evlog, context->secure_boot_vars.secure_boot_path,
									  context->secure_boot_vars.pk_path, context->secure_boot_vars.kek_path,
									  context->secure_boot_vars.db_path, context->secure_boot_vars.dbx_path);
}
