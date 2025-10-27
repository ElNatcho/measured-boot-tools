/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <string.h>
#include <stdint.h> 

#include <openssl/evp.h>
#include <openssl/sha.h>

#include "eventlog.h"
#include "secureboot.h"
#include "efi_boot.h"
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

	free(ovmf_buf);

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

	free(ovmf_buf);

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

int rtmr_measure_separator(uint32_t mr_index, rtmrcontext_t *context)
{
	// Measures the EV_SEPARATOR type event (see TCG PC Specific Implementation
	// Specification, Ver. 1.21, Rev. 1.00, Sec. 11.3.1)
	uint8_t separator_buf[] = { 0x0, 0x0, 0x0, 0x0 };
	size_t separator_size = sizeof(separator_buf);

	uint8_t hash_separator[SHA384_DIGEST_LENGTH];
	hash_buf(EVP_sha384(), hash_separator, separator_buf, separator_size);

	evlog_add(context->evlog, mr_index, "Separator", hash_separator,
		   "EV_SEPARATOR type event");

	hash_extend(EVP_sha384(), context->mrs[mr_index], hash_separator, SHA384_DIGEST_LENGTH);

	return 0;
}

int rtmr_measure_acpi_data(uint32_t mr_index, rtmrcontext_t *context) 
{
	(void) mr_index;
	(void) context;
	// Process QemuFwCfgAcpi.c:InstallQemuFwCfgTables

	// Process QemuFwCfgAcpi.c:ProcessCmdAllocate

	/* unused for now since there are functions to measure the acpi tables individually */

	return -1;
}

int rtmr_measure_acpi_table_loader(uint32_t mr_index, rtmrcontext_t *context)
{
	if (!context->acpi.table_loader || context->acpi.table_loader_size <= 0) {
		printf("ACPI table loader not set.\n");
		return -1;
	}

	uint8_t digest[SHA384_DIGEST_LENGTH];
	hash_buf(EVP_sha384(), digest, context->acpi.table_loader, context->acpi.table_loader_size);
	evlog_add(context->evlog, mr_index, "EV_PLATFORM_CONFIG_FLAGS", digest,
		   "ACPI etc/table-loader");
	hash_extend(EVP_sha384(), context->mrs[mr_index], digest, SHA384_DIGEST_LENGTH);

	return 0;
}

int rtmr_measure_acpi_rsdp(uint32_t mr_index, rtmrcontext_t *context)
{
	if (!context->acpi.acpi_rsdp || context->acpi.acpi_rsdp_size <= 0) {
		printf("ACPI rsdp not set.\n");
		return -1;
	}

	uint8_t digest[SHA384_DIGEST_LENGTH];
	hash_buf(EVP_sha384(), digest, context->acpi.acpi_rsdp, context->acpi.acpi_rsdp_size);
	evlog_add(context->evlog, mr_index, "EV_PLATFORM_CONFIG_FLAGS", digest,
		   "ACPI etc/acpi/rsdp");
	hash_extend(EVP_sha384(), context->mrs[mr_index], digest, SHA384_DIGEST_LENGTH);

	return 0;
}

int rtmr_measure_acpi_tables(uint32_t mr_index, rtmrcontext_t *context)
{
	if (!context->acpi.acpi_tables || context->acpi.acpi_tables_size <= 0) {
		printf("ACPI tables not set.\n");
		return -1;
	}

	uint8_t digest[SHA384_DIGEST_LENGTH];
	hash_buf(EVP_sha384(), digest, context->acpi.acpi_tables, context->acpi.acpi_tables_size);
	evlog_add(context->evlog, mr_index, "EV_PLATFORM_CONFIG_FLAGS", digest,
		   "ACPI etc/acpi/tables");
	hash_extend(EVP_sha384(), context->mrs[mr_index], digest, SHA384_DIGEST_LENGTH);

	return 0;
}

int rtmr_measure_smbios_table(uint32_t mr_index, rtmrcontext_t *context)
{
	uint8_t *smbios_table;
	size_t smbios_table_size;
	if (read_file(&smbios_table, &smbios_table_size, context->smbios_table_file_path)) {
		printf("Failed to load smbios table.");
		return -1;
	}

	uint8_t digest[SHA384_DIGEST_LENGTH];
	hash_buf(EVP_sha384(), digest, smbios_table, smbios_table_size);

	evlog_add(context->evlog, mr_index, "EV_EFI_HANDOFF_TABLES", digest,
		   "Smbios table");
	hash_extend(EVP_sha384(), context->mrs[mr_index], digest, SHA384_DIGEST_LENGTH);

	free(smbios_table);

	return 0;
}

int rtmr_measure_efi_boot_vars(uint32_t mr_index, rtmrcontext_t *context)
{
	// Could be used in theory, however, this function omits the first 4 bytes of the measured buffers to compensate for
	// the prepened 4 bytes in the /sys/firmware/efi/efivars/* files.
	//return calculate_efi_boot_vars(EVP_sha384(), context->mrs[mr_index], mr_index, context->evlog,
	//							context->boot_order, context->boot_order_size,
	//							context->bootxxxx_list, context->num_bootxxxx);

	// TODO: split this function into measure_boot_order and measure_bootxxxx

	uint8_t boot_order_digest[SHA384_DIGEST_LENGTH];
	hash_buf(EVP_sha384(), boot_order_digest, (uint8_t*)context->boot_order,
		  context->num_boot_order * sizeof(*context->boot_order));
	evlog_add(context->evlog, mr_index, "EV_EFI_VARIABLE_BOOT", boot_order_digest,
		   "VariableName - BootOrder, VendorGuid - 8BE4DF61-93CA-11D2-AA0D-00E098032B8C");
	hash_extend(EVP_sha384(), context->mrs[mr_index], boot_order_digest, SHA384_DIGEST_LENGTH);

	uint8_t *file_buf = NULL;
	size_t file_size = 0;
	uint8_t file_digest[SHA384_DIGEST_LENGTH];
	for (size_t i = 0; i < context->num_bootxxxx; i++) {
		if (read_file(&file_buf, &file_size, context->bootxxxx_list[i])) {
			printf("Failed to read file %s\n", context->bootxxxx_list[i]);
			return -1;
		}
		hash_buf(EVP_sha384(), file_digest, file_buf, file_size);
		evlog_add(context->evlog, mr_index, "EV_EFI_VARIABLE_BOOT", file_digest,
			"VariableName - Boot####, VendorGuid - 8BE4DF61-93CA-11D2-AA0D-00E098032B8C");
		hash_extend(EVP_sha384(), context->mrs[mr_index], file_digest, SHA384_DIGEST_LENGTH);

		free(file_buf);
	}

	return 0;
}

int rtmr_measure_action(measurement_config_t *config, rtmrcontext_t *context)
{
	if (!config->action_text) {
		printf("No action text configured for measurement.\n");
		return -1;
	}

	size_t max_msg_length = 256;
	char message[max_msg_length];
	snprintf(message, max_msg_length, "%s%s", "Measured Action: ", config->action_text);

	uint8_t digest[SHA384_DIGEST_LENGTH];
	hash_buf(EVP_sha384(), digest, (uint8_t*)config->action_text, strlen(config->action_text));
	evlog_add(context->evlog, config->mr_index, "EV_EFI_ACTION", digest, message);
	hash_extend(EVP_sha384(), context->mrs[config->mr_index], digest, SHA384_DIGEST_LENGTH);

	return 0;
}
