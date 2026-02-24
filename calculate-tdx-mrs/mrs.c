/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/stat.h>
#include <dirent.h>
#include <libgen.h>
#include <unistd.h>
#include <libgen.h>
#include <wchar.h>
#include <uchar.h>

#include <openssl/pkcs7.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "ProcessorBind.h"
#include "Base.h"
#include "UefiBaseType.h"
#include "PeImage.h"
#include "PeCoffLib.h"
#include "PiFirmwareVolume.h"
#include "PiHob.h"
#include "MeasureBootPeCoff.h"
#include "SecMain.h"
#include "ImageAuthentication.h"
#include "UefiTcgPlatform.h"

#include "common.h"
#include "hash.h"
#include "kernel_config.h"
#include "eventlog.h"
#include "td_hob.h"
#include "mrtd.h"
#include "efi_boot.h"
#include "secureboot.h"
#include "mrs.h"
#include "rtmrms.h"

extern EFI_GUID gEfiImageSecurityDatabaseGuid;

/**
 * Calculates the measurement register for the TDX SEAM module (MRSEAM)
 *
 * The MRTD contains the digest of the TDX-module as measured by the SEAM loader
 *
 */
int
calculate_mrseam(uint8_t *mr, eventlog_t *evlog, const char *tdx_module)
{
    memset(mr, 0x0, SHA384_DIGEST_LENGTH);

    uint8_t hash_mrseam[SHA384_DIGEST_LENGTH];
    int ret = hash_file(EVP_sha384(), hash_mrseam, tdx_module);
    if (ret) {
        printf("Failed to measure the TDX-module\n");
        return -1;
    }

    evlog_add(evlog, INDEX_MRSEAM, "TDX-Module", hash_mrseam, "SEAMLDR Measurement: TDX-Module");
    memcpy(mr, hash_mrseam, SHA384_DIGEST_LENGTH);

    return 0;
}

/**
 * Calculates the TDX Build-Time Measurement Register (MRTD)
 *
 * The MRTD contains the digest of the OVMF as hashed by the Intel TDX module.
 *
 */
int
calculate_mrtd(uint8_t *mr, eventlog_t *evlog, const char *ovmf_file, const char *qemu_version)
{
    int ret = -1;

    DEBUG("Calculating MRTD...\n");

    memset(mr, 0x0, SHA384_DIGEST_LENGTH);

    uint8_t *ovmf_buf = NULL;
    uint64_t ovmf_size = 0;
    ret = read_file(&ovmf_buf, &ovmf_size, ovmf_file);
    if (ret) {
        goto out;
    }

    uint8_t hash_mrtd[SHA384_DIGEST_LENGTH];
    ret = measure_ovmf(hash_mrtd, ovmf_buf, ovmf_size, qemu_version);
    if (ret) {
        printf("Failed to measure ovmf\n");
        goto out;
    }

    evlog_add(evlog, INDEX_MRTD, "OVMF", hash_mrtd,
              "TDX Module Measurement: Initial TD contents (OVMF)");
    memcpy(mr, hash_mrtd, SHA384_DIGEST_LENGTH);

    ret = 0;

out:
    if (ovmf_buf)
        free(ovmf_buf);

    return ret;
}

/**
 * Calculates RTMR0
 *
 * RTMR0 contains the following artifacts:
 * - EFI TD handoff block
 * - EFI Configuration FV
 * - EFI Secure Boot variables
 * - QEMU FW Cfg Files as passed to OVMF
 * - EFI Boot variables
 */
int
calculate_rtmr0(uint8_t *mr, eventlog_t *evlog, const char *ovmf_file,
                acpi_files_t *cfg, const char *ovmf_version,
                uint16_t *boot_order, size_t len_boot_order, char **bootxxxx, size_t num_bootxxxx,
                const char *secure_boot, const char *pk, const char *kek, const char *db, const char *dbx)
{
    int ret = -1;
    long len = 0;

    DEBUG("Calculating RTMR0...\n");

    memset(mr, 0x0, SHA384_DIGEST_LENGTH);

    // Measure EFI TD Handoff Block:
    // UEFI Platform Initialization Specification, Vol. 3, Chapter 5 5 HOB Code Definitions
    len = get_td_hob_size();
    uint8_t td_hob[len];
    ret = create_td_hob(td_hob, len);
    if (ret) {
        return -1;
    }
    uint8_t hash_td_hob[SHA384_DIGEST_LENGTH];
    hash_buf(EVP_sha384(), hash_td_hob, td_hob, len);
    evlog_add(evlog, INDEX_RTMR0, "TD Hob", hash_td_hob,
              "TD Hob passed from host VMM to guest firmware");
    hash_extend(EVP_sha384(), mr, hash_td_hob, SHA384_DIGEST_LENGTH);

    // Configuration Firmware Volume (CFV)
    uint8_t *ovmf_buf = NULL;
    uint64_t ovmf_size = 0;
    if (ovmf_file) {
        ret = read_file(&ovmf_buf, &ovmf_size, ovmf_file);
        if (ret) {
            printf("Failed to load %s\n", ovmf_file);
            goto out;
        }
        uint8_t hash_cfv[SHA384_DIGEST_LENGTH];
        ret = measure_cfv(hash_cfv, ovmf_buf, ovmf_size);
        if (ret) {
            printf("Failed to measure ovmf\n");
            goto out;
        }
        evlog_add(evlog, INDEX_RTMR0, "Configuration FV", hash_cfv, "Configuration Firmware Volume");
        hash_extend(EVP_sha384(), mr, hash_cfv, SHA384_DIGEST_LENGTH);
    }

    // Measure UEFI Secure Boot Variables: SecureBoot, PK, KEK, db, dbx
    ret = measure_secure_boot_variables(EVP_sha384(), mr, INDEX_RTMR0, evlog, secure_boot, pk, kek, db, dbx);
    if (ret) {
        printf("Failed to measure secure boot variables\n");
        goto out;
    }

    // EV_SEPARATOR
    uint8_t *ev_separator = OPENSSL_hexstr2buf("00000000", NULL);
    if (!ev_separator) {
        printf("Failed to allocate memory for ev separator\n");
        goto out;
    }
    uint8_t hash_ev_separator[SHA384_DIGEST_LENGTH];
    hash_buf(EVP_sha384(), hash_ev_separator, ev_separator, 4);
    evlog_add(evlog, INDEX_RTMR0, "EV_SEPARATOR", hash_ev_separator, "HASH(00000000)");
    hash_extend(EVP_sha384(), mr, hash_ev_separator, SHA384_DIGEST_LENGTH);

    // EV_PLATFORM_CONFIG_FLAGS: ACPI tables
    ret = calculate_acpi_tables(EVP_sha384(), mr, INDEX_RTMR0, evlog, cfg);
    if (ret) {
        printf("failed to calculate acpi tables\n");
        goto out;
    }

    // EV_EFI_VARIABLE_BOOT boot variables
    ret = calculate_efi_boot_vars(EVP_sha384(), mr, INDEX_RTMR0, evlog, boot_order, len_boot_order, bootxxxx, num_bootxxxx);
    if (ret) {
        printf("Failed to calculate EFI boot variables\n");
        goto out;
    }

    // Terminating EV_SEPARATOR is extended only in edk2-stable202408.01
    if (!strcmp(ovmf_version, "edk2-stable202408.01")) {
        // EV_SEPARATOR
        hash_buf(EVP_sha384(), hash_ev_separator, ev_separator, 4);
        evlog_add(evlog, INDEX_RTMR0, "EV_SEPARATOR", hash_ev_separator, "HASH(00000000)");
        hash_extend(EVP_sha384(), mr, hash_ev_separator, SHA384_DIGEST_LENGTH);
    }

    ret = 0;

out:
    if (ovmf_buf)
        free(ovmf_buf);
    if (ev_separator)
        OPENSSL_free(ev_separator);

    return ret;
}

/**
 * Calculate RTMR0 Extended Version
 *
 *
 */
int calculate_rtmr0_ext(uint8_t *mr, eventlog_t *evlog, const char *ovmf_file_path, acpi_files_t *acpi_files,
						const char *secure_boot_path, const char *pk_path, const char *kek_path,
						const char *db_path, const char *dbx_path, const char *smbios_table_file,
						const char *kernel_file_path, const char *initrd_file_path, const char *cmdline_file_path,
						uint16_t *boot_order, size_t len_boot_order, char **bootxxxx, size_t num_bootxxxx,
						const char* fwcfg_bootorder_file_path, const char* fwcfg_bootmenu_file_path)
{
	int ret = 0;

	rtmrcontext_t context = {
		.evlog			  = evlog,
		.ovmf_file_path	  = ovmf_file_path,
		.secure_boot_vars = {
			.secure_boot_path = secure_boot_path,
			.pk_path		  = pk_path,
			.kek_path		  = kek_path,
			.db_path		  = db_path,
			.dbx_path		  = dbx_path
		},
		.acpi = *acpi_files,
		.smbios_table_file_path = smbios_table_file,
		.boot_order = boot_order,
		.num_boot_order= len_boot_order,
		.bootxxxx_list = bootxxxx,
		.num_bootxxxx = num_bootxxxx,
		.kernel_file_path = kernel_file_path,
		.initrd_file_path = initrd_file_path,
		.cmdline_file_path = cmdline_file_path,
		.fwcfg_bootmenu_file_path = fwcfg_bootmenu_file_path,
		.fwcfg_bootorder_file_path = fwcfg_bootorder_file_path
	};

	measurement_config_t config;

	// Measure system configuration table / TD HOB (1. EV_EFI_HANDOFF_TABLES2) and firmware blob (2. EV_EFI_PLATFORM_FIRMWARE_BLOB2)

	rtmr_measure_tdhob(&config, &context);

	rtmr_measure_cfv(&config, &context);

	// Measure ?? (3. EV_PLATFORM_CONFIG_FLAGS)

	//rtmr_measure_qemu_fw_cfg(&config, &context);
	rtmr_measure_qemu_fw_cfg_boot_menu(&config, &context);
	rtmr_measure_qemu_fw_cfg_boot_order(&config, &context);

	// Measure EFI secure boot variables (4.,5.,6.,7.,8. EV_EFI_VARIABLE_DRIVER_CONFIG)

	rtmr_measure_secure_boot_variables(&config, &context);

	// Measure separator (9. EV_SEPARATOR)

	rtmr_measure_separator(&config, &context);

	// Measure ACPI DATA(?) (10.,11.,12. EV_PLATFORM_CONFIG_FLAGS)
	// TODO: Currently, the acpi tables are generated dynamically by qemu. The API for generation
	// appears to be only internally available to QEMU. Thus, for now, the tables need to be dumped
	// manually via the `acpidump` utility.

	rtmr_measure_acpi_table_loader(&config, &context);
	rtmr_measure_acpi_rsdp(&config, &context);
	rtmr_measure_acpi_tables(&config, &context);

	// Measure Smbios Table (13. EV_EFI_HANDOFF_TABLES)
	// TODO: Same situation as with the ACPI tables. The smbios table can be dumped with `dmidecode`.


	config.mr_index = 1;
	rtmr_measure_pe_kernel_image(&config, &context);
	
	rtmr_measure_smbios_table(&config, &context);

	// Measure EFI boot variables (14.,15.,16.,17.,18.,19.,20.,21. EFI_VARIABLE_BOOT)

	rtmr_measure_efi_boot_vars(&config, &context);

	config.mr_index = 1;
	config.action_text = "Calling EFI Application from Boot Option";
	rtmr_measure_action(&config, &context);

	rtmr_measure_separator(&config, &context);

	rtmr_measure_cmdline(&config, &context);

	rtmr_measure_initrd_image(&config, &context);

	config.action_text = "Exit Boot Services Invocation";
	rtmr_measure_action(&config, &context);

	config.action_text = "Exit Boot Services Returned with Success";
	rtmr_measure_action(&config, &context);

	// Measure SBat Level (??) (28. EV_EFI_VARIABLE_AUTHORITY)	

	memcpy(mr, context.mrs[INDEX_RTMR0], SHA384_DIGEST_LENGTH);

	return ret;
}

/**
 * Calculates RTMR1
 *
 * RTMR1 contains the Linux kernel PE/COFF image measurement as well as some boot strings.
 *
 */
int
calculate_rtmr1(uint8_t *mr, eventlog_t *evlog, const char *kernel_file, const char *config_file,
                const char *dump_kernel_path, const char *ovmf_version)
{
    int ret = -1;

    DEBUG("Calculating RTMR1...\n");

    memset(mr, 0x0, SHA384_DIGEST_LENGTH);

    // Measure kernel
    uint8_t hash_kernel[SHA384_DIGEST_LENGTH] = { 0 };
    uint8_t *kernel_buf = NULL;
    uint64_t kernel_size = 0;

    ret = LoadPeImage(&kernel_buf, &kernel_size, kernel_file);
    if (ret != 0) {
        goto out;
    }

    if (config_file) {
        // Load configuration variables
        config_t config = { 0 };
        if (config_file) {
            ret = config_load(&config, config_file);
            if (ret != 0) {
                printf("Failed to load configuration\n");
                goto out;
            }
        }

        ret = config_prepare_kernel_pecoff(kernel_buf, kernel_size, &config);
        if (ret != 0) {
            printf("Failed to prepare kernel PE/COFF image\n");
            goto out;
        }
    }

    EFI_STATUS status = MeasurePeImage(EVP_sha384(), hash_kernel, kernel_buf, kernel_size);
    if (EFI_ERROR(status)) {
        printf("printf: Failed to measure PE Image: %llx\n", status);
        goto out;
    }
    evlog_add(evlog, INDEX_RTMR1, basename((char *)kernel_file), hash_kernel,
              "Linux Kernel PE/COFF Image");

    hash_extend(EVP_sha384(), mr, hash_kernel, SHA384_DIGEST_LENGTH);

    if (dump_kernel_path) {
        if (write_file(kernel_buf, kernel_size, dump_kernel_path)) {
            printf("Failed to write kernel to %s\n", dump_kernel_path);
            goto out;
        }
        DEBUG("Wrote PEIFV to %s\n", dump_kernel_path);
    }

    // TCG PCClient Firmware Spec:
    // https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClient_PFP_r1p05_v23_pub.pdf 10.4.4
    char *action_data0 = EFI_CALLING_EFI_APPLICATION;
    uint8_t hash_efi_action0[SHA384_DIGEST_LENGTH];
    hash_buf(EVP_sha384(), hash_efi_action0, (uint8_t *)action_data0, strlen(action_data0));
    evlog_add(evlog, INDEX_RTMR1, "EV_EFI_ACTION", hash_efi_action0, action_data0);
    hash_extend(EVP_sha384(), mr, hash_efi_action0, SHA384_DIGEST_LENGTH);

    // Terminating EV_SEPARATOR is extended only in newer versions
    uint8_t *ev_separator = NULL;
    if (strcmp(ovmf_version, "edk2-stable202408.01")) {
        ev_separator = OPENSSL_hexstr2buf("00000000", NULL);
        if (!ev_separator) {
            printf("Failed to allocate memory for ev separator\n");
            goto out;
        }
        uint8_t hash_ev_separator[SHA384_DIGEST_LENGTH];
        hash_buf(EVP_sha384(), hash_ev_separator, ev_separator, 4);
        evlog_add(evlog, INDEX_RTMR1, "EV_SEPARATOR", hash_ev_separator, "HASH(00000000)");
        hash_extend(EVP_sha384(), mr, hash_ev_separator, SHA384_DIGEST_LENGTH);
    }

    char *action_data1 = EFI_EXIT_BOOT_SERVICES_INVOCATION;
    uint8_t hash_efi_action1[SHA384_DIGEST_LENGTH];
    hash_buf(EVP_sha384(), hash_efi_action1, (uint8_t *)action_data1, strlen(action_data1));
    evlog_add(evlog, INDEX_RTMR1, "EV_EFI_ACTION", hash_efi_action1, action_data1);
    hash_extend(EVP_sha384(), mr, hash_efi_action1, SHA384_DIGEST_LENGTH);

    char *action_data2 = EFI_EXIT_BOOT_SERVICES_SUCCEEDED;
    uint8_t hash_efi_action2[SHA384_DIGEST_LENGTH];
    hash_buf(EVP_sha384(), hash_efi_action2, (uint8_t *)action_data2, strlen(action_data2));
    evlog_add(evlog, INDEX_RTMR1, "EV_EFI_ACTION", hash_efi_action2, action_data2);
    hash_extend(EVP_sha384(), mr, hash_efi_action2, SHA384_DIGEST_LENGTH);

    ret = 0;

out:
    if (kernel_buf)
        OPENSSL_free(kernel_buf);
    if (ev_separator)
        OPENSSL_free(ev_separator);

    return ret;
}

/**
 * Calculates RTMR2
 *
 * RTMR2 contains the Linux kernel command line.
 *
 */
int
calculate_rtmr2(uint8_t *mr, eventlog_t *evlog, const char *cmdline_file, size_t trailing_zeros)
{
    int ret = -1;

    DEBUG("Calculating RTMR2...\n");

    memset(mr, 0x0, SHA384_DIGEST_LENGTH);

    // EV_EVENT_TAG kernel commandline (OVMF uses CHAR16)
    DEBUG("Reading cmdline from: %s\n", cmdline_file);

    uint8_t *cmdline_buf;
    size_t cmdline_size = 0;
    ret = read_file(&cmdline_buf, &cmdline_size, cmdline_file);
    if (ret) {
        return -1;
    }
    DEBUG("cmdline size: %ld\n", cmdline_size);

    size_t cmdline_len = 0;
    char16_t *wcmdline =
        convert_to_char16((const char *)cmdline_buf, cmdline_size, &cmdline_len, trailing_zeros);
    if (!wcmdline) {
        printf("Failed to convert to wide character string\n");
        goto out;
    }

    uint8_t hash_ev_event_tag[SHA384_DIGEST_LENGTH];
    hash_buf(EVP_sha384(), hash_ev_event_tag, (uint8_t *)wcmdline, cmdline_len);
    evlog_add(evlog, INDEX_RTMR2, "EV_EVENT_TAG", hash_ev_event_tag, cmdline_file);

    hash_extend(EVP_sha384(), mr, hash_ev_event_tag, SHA384_DIGEST_LENGTH);

    ret = 0;

out:
    if (cmdline_buf) {
        free(cmdline_buf);
    }
    if (wcmdline) {
        free(wcmdline);
    }

    return ret;
}

/**
 * Calculates RTMR3
 *
 * RTMR3 is currently empty.
 *
 */
int
calculate_rtmr3(uint8_t *mr, eventlog_t *evlog)
{
    (void)evlog;

    int ret = -1;

    DEBUG("Calculating RTMR3...\n");

    memset(mr, 0x0, SHA384_DIGEST_LENGTH);

    ret = 0;

    return ret;
}
