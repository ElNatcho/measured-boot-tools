/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include "eventlog.h"
#include "hash.h"
#include "acpi.h"
#include <stdint.h>

#pragma once

typedef struct {
	const char *secure_boot_path;
	const char *pk_path;
	const char *kek_path;
	const char *db_path;
	const char *dbx_path;
} secureboot_variables_t;

typedef struct {
	uint8_t mrs[MR_LEN][SHA384_DIGEST_LENGTH];

	eventlog_t *evlog;

	const char *ovmf_file_path;

	secureboot_variables_t secure_boot_vars;

	acpi_files_t acpi;

	const char *smbios_table_file_path;

	uint16_t *boot_order;
	size_t num_boot_order;		// TODO: should be identical to num_bootxxxx, maybe combine?
	char **bootxxxx_list;
	size_t num_bootxxxx;

	const char *fwcfg_bootorder_file_path;
	const char *fwcfg_bootmenu_file_path;

	const char *kernel_file_path;
	const char *initrd_file_path;
	const char *cmdline_file_path;

} rtmrcontext_t;

typedef struct {
	uint32_t mr_index;
	char* action_text;
} measurement_config_t;

int rtmr_measure_dummy(uint32_t mr_index, rtmrcontext_t *context);

int rtmr_measure_tdhob(uint32_t mr_index, rtmrcontext_t *context);
int rtmr_measure_cfv(uint32_t mr_index, rtmrcontext_t *context);
int rtmr_measure_qemu_fw_cfg(uint32_t mr_index, rtmrcontext_t *context);
int rtmr_measure_qemu_fw_cfg_boot_menu(uint32_t mr_index, rtmrcontext_t *context);
int rtmr_measure_qemu_fw_cfg_boot_order(uint32_t mr_index, rtmrcontext_t *context);
int rtmr_measure_secure_boot_variables(uint32_t mr_index, rtmrcontext_t *context);
int rtmr_measure_separator(uint32_t mr_index, rtmrcontext_t *context);
int rtmr_measure_acpi_data(uint32_t mr_index, rtmrcontext_t *context);
int rtmr_measure_acpi_table_loader(uint32_t mr_index, rtmrcontext_t *context);
int rtmr_measure_acpi_rsdp(uint32_t mr_index, rtmrcontext_t *context);
int rtmr_measure_acpi_tables(uint32_t mr_index, rtmrcontext_t *context);
int rtmr_measure_smbios_table(uint32_t mr_index, rtmrcontext_t *context);
int rtmr_measure_efi_boot_vars(uint32_t mr_index, rtmrcontext_t *context);
int rtmr_measure_action(measurement_config_t *config, rtmrcontext_t *context);
int rtmr_measure_pe_kernel_image(measurement_config_t *config, rtmrcontext_t *context);
int rtmr_measure_initrd_image(measurement_config_t *config, rtmrcontext_t *context);
int rtmr_measure_cmdline(measurement_config_t *config, rtmrcontext_t *context);
