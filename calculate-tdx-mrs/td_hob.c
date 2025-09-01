/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

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
#include "td_hob.h"
#include "mrtd.h"

#define RESOURCE_DESCRIPTOR_LEN 9

size_t
get_td_hob_size()
{
    return sizeof(EFI_HOB_HANDOFF_INFO_TABLE) +
           sizeof(EFI_HOB_RESOURCE_DESCRIPTOR) * RESOURCE_DESCRIPTOR_LEN;
}

int
create_td_hob(uint8_t *dest, size_t dest_len)
{
    // Create TD handoff block
    size_t len = get_td_hob_size();
    if (dest_len < len) {
        printf("Failed to create TD HOB: provided buffer too small\n");
        return -1;
    }

    EFI_HOB_HANDOFF_INFO_TABLE tbl = { .Header = { .HobType = EFI_HOB_TYPE_HANDOFF,
                                                   .HobLength = sizeof(EFI_HOB_HANDOFF_INFO_TABLE),
                                                   .Reserved = 0x0 },
                                       .Version = EFI_HOB_HANDOFF_TABLE_VERSION,
                                       .BootMode = BOOT_WITH_FULL_CONFIGURATION,
                                       .EfiMemoryTop = 0x0,
                                       .EfiMemoryBottom = 0x0,
                                       .EfiFreeMemoryTop = 0x0,
                                       .EfiFreeMemoryBottom = 0x0,
                                       .EfiEndOfHobList = 0x8091f0 };

    memcpy(dest, (uint8_t *)&tbl, sizeof(EFI_HOB_HANDOFF_INFO_TABLE));

    size_t hob_offset = sizeof(EFI_HOB_HANDOFF_INFO_TABLE);

    // Sizes: OvmfPkg/OvmfPkgX64.fdf
    // Build/OvmfX64/RELEASE_GCC5/X64/OvmfPkg/ResetVector/ResetVector/DEBUG/Autogen.h
    // Build/OvmfX64/DEBUG_GCC5/X64/OvmfPkg/Sec/SecMain/DEBUG/AutoGen.h
    // Build/OvmfX64/RELEASE_GCC5/X64/OvmfPkg/PlatformPei/PlatformPei/DEBUG/PlatformPei.debug
    size_t physical_start[RESOURCE_DESCRIPTOR_LEN] = {
        0x0,         // Size: 0x800000       ?? Reserved BIOS Legacy
        0x800000,    // Size: 0x6000         _PCD_VALUE_PcdOvmfSecPageTablesBase
        0x806000,    // Size: 0x3000         _PCD_VALUE_PcdOvmfLockBoxStorageBase
        0x809000,    // Size: 0x2000         _PCD_VALUE_PcdOvmfSecGhcbBase
        0x80b000,    // Size: 0x2000         _PCD_VALUE_PcdOvmfWorkAreaBase
        0x80d000,    // Size: 0x4000         _PCD_VALUE_PcdOvmfSnpSecretsBase
        0x811000,    // Size: 0xF000         _PCD_VALUE_PcdOvmfSecPeiTempRamBase
        0x820000,    // Size: 0x7F7E0000     _PCD_VALUE_PcdOvmfPeiMemFvBase
        0x100000000, // Size: 0x80000000     ?? PCI MMIO
    };

    size_t resource_length[RESOURCE_DESCRIPTOR_LEN] = {
        0x800000, // Base: 0x0            ??
        0x6000, // Base: 0x800000       _PCD_VALUE_PcdOvmfSecPageTablesBase         _PCD_VALUE_PcdOvmfSecPageTablesSize
        0x3000, // Base: 0x806000       _PCD_VALUE_PcdOvmfLockBoxStorageBase        _PCD_VALUE_PcdOvmfLockBoxStorageSize (0x1000) + _PCD_VALUE_PcdGuidedExtractHandlerTableSize (0x1000) + _PCD_VALUE_PcdOvmfSecGhcbPageTableSize (0x1000)
        0x2000, // Base: 0x809000       _PCD_VALUE_PcdOvmfSecGhcbBase               _PCD_VALUE_PcdOvmfSecGhcbSize
        0x2000, // Base: 0x80b000       _PCD_VALUE_PcdOvmfWorkAreaBase              _PCD_VALUE_PcdOvmfWorkAreaSize (0x1000) + _PCD_VALUE_PcdOvmfCpuidSize (0x1000)
        0x4000, // Base: 0x80d000       _PCD_VALUE_PcdOvmfSnpSecretsBase            _PCD_VALUE_PcdOvmfSnpSecretsSize (0x1000) + _PCD_VALUE_PcdOvmfCpuidSize (0x1000) + _PCD_VALUE_PcdOvmfSecSvsmCaaSize (0x1000) + _PCD_VALUE_PcdOvmfSecApicPageTableSize (0x1000)
        0xF000, // Base: 0x811000       _PCD_VALUE_PcdOvmfSecPeiTempRamBase         _PCD_VALUE_PcdOvmfSecPeiTempRamSize
        0x7F7E0000, // Base: 0x820000       _PCD_VALUE_PcdOvmfPeiMemFvBase              ?? _PCD_VALUE_PcdOvmfPeiMemFvSize (0xE0000) + _PCD_VALUE_PcdOvmfDxeMemFvSize (0xE80000)
        0x80000000, // Base: 0x100000000    ??
    };

    EFI_RESOURCE_TYPE resource_type[RESOURCE_DESCRIPTOR_LEN] = {
        EFI_RESOURCE_MEMORY_UNACCEPTED, EFI_RESOURCE_SYSTEM_MEMORY,
        EFI_RESOURCE_MEMORY_UNACCEPTED, EFI_RESOURCE_SYSTEM_MEMORY,
        EFI_RESOURCE_SYSTEM_MEMORY,     EFI_RESOURCE_MEMORY_UNACCEPTED,
        EFI_RESOURCE_SYSTEM_MEMORY,     EFI_RESOURCE_MEMORY_UNACCEPTED,
        EFI_RESOURCE_MEMORY_UNACCEPTED
    };

    for (size_t i = 0; i < RESOURCE_DESCRIPTOR_LEN; i++) {
        EFI_HOB_RESOURCE_DESCRIPTOR rd = {
            .Header = { .HobType = EFI_HOB_TYPE_RESOURCE_DESCRIPTOR,
                        .HobLength = sizeof(EFI_HOB_RESOURCE_DESCRIPTOR),
                        .Reserved = 0x0 },
            .Owner = { .Data1 = 0x0, .Data2 = 0x0, .Data3 = 0x0, .Data4 = { 0x0 } },
            .ResourceType = resource_type[i],
            .ResourceAttribute = EFI_RESOURCE_ATTRIBUTE_PRESENT |
                                 EFI_RESOURCE_ATTRIBUTE_INITIALIZED | EFI_RESOURCE_ATTRIBUTE_TESTED,
            .PhysicalStart = physical_start[i],
            .ResourceLength = resource_length[i]
        };

        memcpy(dest + hob_offset, (uint8_t *)&rd, sizeof(EFI_HOB_RESOURCE_DESCRIPTOR));
        hob_offset += sizeof(EFI_HOB_RESOURCE_DESCRIPTOR);
    }
    print_td_hob(dest, len);

    return 0;
}

/*	see hw/i386/tdvf-hob.h in the qemu source
 */

#define EFI_RESOURCE_ATTRIBUTE_TDVF_PRIVATE     \
    (EFI_RESOURCE_ATTRIBUTE_PRESENT |           \
     EFI_RESOURCE_ATTRIBUTE_INITIALIZED |       \
     EFI_RESOURCE_ATTRIBUTE_TESTED)

#define EFI_RESOURCE_ATTRIBUTE_TDVF_UNACCEPTED  \
    (EFI_RESOURCE_ATTRIBUTE_PRESENT |           \
     EFI_RESOURCE_ATTRIBUTE_INITIALIZED |       \
     EFI_RESOURCE_ATTRIBUTE_TESTED)

#define EFI_RESOURCE_ATTRIBUTE_TDVF_MMIO        \
    (EFI_RESOURCE_ATTRIBUTE_PRESENT     |       \
     EFI_RESOURCE_ATTRIBUTE_INITIALIZED |       \
     EFI_RESOURCE_ATTRIBUTE_UNCACHEABLE)


/*	see target/i386/kvm/tdx.h for TdxRamType and TdxRamEntry definitions
 *	TODO: specifiy exact qemu source / put qemu in thirdparty library folder
 */

enum TdxRamType {
	TDX_RAM_UNACCEPTED,
	TDX_RAM_ADDED,
};

typedef struct {
	uint64_t address;
	uint64_t length;
	enum TdxRamType type;
}	TdxRamEntry;

// see tdx.c:tdx_add_ram_entry
static int
tdx_add_ram_entry(TdxRamEntry** ram_entries, size_t* nr_ram_entries, uint64_t address, uint64_t length,
				  enum TdxRamType type) {
	*ram_entries = realloc(*ram_entries, (*nr_ram_entries + 1) * sizeof(TdxRamEntry));
	if(!ram_entries) {
		printf("realloc failed\n");
		return -1;
	}
	(*ram_entries)[*nr_ram_entries].address = address;
	(*ram_entries)[*nr_ram_entries].length = length;
	(*ram_entries)[*nr_ram_entries].type = type;
	*nr_ram_entries = *nr_ram_entries + 1;

	return 0;
}

static int
tdx_ram_entry_compare(const void *lhs_, const void* rhs_)
{
    const TdxRamEntry *lhs = lhs_;
    const TdxRamEntry *rhs = rhs_;

    if (lhs->address == rhs->address) {
        return 0;
    }
    if (lhs->address > rhs->address) {
        return 1;
    }
    return -1;
}

int
create_td_hob_from_ovmf(uint8_t** dest, size_t* dest_len, uint8_t* raw_ovmf_image, uint64_t raw_ovmf_image_size) {
	// Build the ram entries array according to the qemu source. See tdx.c:tdx_finalize_vm, tdx_accept_ram_range,
	// tdx_add_ram_entry

	// Build the ram entries array from the e820 entries

	// TODO: parameterize this via the command line arguments
	// Prepare the ram_entries array like in tdx.c:tdx_init_ram_entries
	// This contains the initial memory added to the vm (the -m parameter of qemu).
	TdxRamEntry e820_ram_entries[] = {
		{ .address = 0x0, .length = 0x80000000, .type = TDX_RAM_UNACCEPTED }
	};

	size_t nr_ram_entries = sizeof(e820_ram_entries) / sizeof(TdxRamEntry);
	TdxRamEntry* ram_entries = malloc(sizeof(e820_ram_entries));
	if (!ram_entries) {
		printf("malloc failed!\n");
		return -1;
	}
	memcpy(ram_entries, e820_ram_entries, sizeof(e820_ram_entries));

	// Fetch the ovmf section table from the file to add emulate the loop in tdx.c:tdx_finalize_vm
	tdx_ovmf_metadata_t ovmf_metadata = { .sections = NULL };
	if (get_ovmf_metadata(&ovmf_metadata, raw_ovmf_image, raw_ovmf_image_size)) {
		printf("failed to get ovmf metadata\n");
		return -1;
	}

	// Add specific ovmf sections to the ram entries array
	ssize_t td_hob_index = -1;
	for (size_t i = 0; i < ovmf_metadata.descriptor.number_of_section_entry; i++) {
		/*printf("[%ld] data_offset=%08x raw_data_size=%08x memory_address=%016lx length=%016lx type=%08x attribute=%08x\n", i,
					ovmf_metadata.sections[i].data_offset,
					ovmf_metadata.sections[i].raw_data_size,
					ovmf_metadata.sections[i].memory_address,
					ovmf_metadata.sections[i].memory_data_size,
					ovmf_metadata.sections[i].type,
					ovmf_metadata.sections[i].attributes);*/

		if (ovmf_metadata.sections[i].type == TDVF_SECTION_TYPE_TD_HOB) {
			td_hob_index = i;
		}

		if (ovmf_metadata.sections[i].type == TDVF_SECTION_TYPE_TD_HOB ||
			ovmf_metadata.sections[i].type == TDVF_SECTION_TYPE_TEMP_MEM) {
			// see tdx.c:tdx_accept_ram_range
			TdxRamEntry* entry;
			uint64_t head_start, tail_start, head_length, tail_length;
			uint64_t tmp_address, tmp_length;
			uint64_t address = ovmf_metadata.sections[i].memory_address;
			uint64_t length = ovmf_metadata.sections[i].memory_data_size;
			uint32_t j;

			for (j = 0; j < nr_ram_entries; j++) {
				entry = &ram_entries[j];

				if (address + length <= entry->address ||
					entry->address + entry->length <= address) {
					continue;
				}

				// TODO: omit EINVAL checks for now because the VM cannot start if these checks are not correct

				break;
			}

			if (j == nr_ram_entries) {
				// In tdx.c:tdx_accept_ram_range the function is aborted with -1 at this point.
				// However, no special handling is done and the outer TdxFirmwareEntry loop is not aborted.
				continue;
			}

			tmp_address = entry->address;
		    tmp_length = entry->length;

		    entry->address = address;
		    entry->length = length;
		    entry->type = TDX_RAM_ADDED;

		    head_length = address - tmp_address;
		    if (head_length > 0) {
				head_start = tmp_address;
		        tdx_add_ram_entry(&ram_entries, &nr_ram_entries, head_start, head_length, TDX_RAM_UNACCEPTED);
		    }

		    tail_start = address + length;
		    if (tail_start < tmp_address + tmp_length) {
		        tail_length = tmp_address + tmp_length - tail_start;
				tdx_add_ram_entry(&ram_entries, &nr_ram_entries, tail_start, tail_length, TDX_RAM_UNACCEPTED);
		    }
		}
	}

	if (td_hob_index == -1) {
		printf("failed to find TD_HOB section\n");
		return -1;
	}

	qsort(ram_entries, nr_ram_entries, sizeof(TdxRamEntry), &tdx_ram_entry_compare);

	/*printf("nr_ram_entries=%ld\n", nr_ram_entries);
	for (size_t i = 0; i < nr_ram_entries; i++) {
		printf("[%ld] address=%016lx length=%016lx type=%d\n", i, ram_entries[i].address,
					ram_entries[i].length, ram_entries[i].type);
	}*/

	// Create TD handoff block

	size_t hob_len = sizeof(EFI_HOB_HANDOFF_INFO_TABLE) + nr_ram_entries * sizeof(EFI_HOB_RESOURCE_DESCRIPTOR);
	uint8_t* hob = malloc(hob_len);
	if (!hob) {
		printf("malloc failed\n");
		return -1;
	}

    EFI_HOB_HANDOFF_INFO_TABLE tbl = { .Header = { .HobType = EFI_HOB_TYPE_HANDOFF,
                                                   .HobLength = sizeof(EFI_HOB_HANDOFF_INFO_TABLE),
                                                   .Reserved = 0x0 },
                                       .Version = EFI_HOB_HANDOFF_TABLE_VERSION,
                                       .BootMode = BOOT_WITH_FULL_CONFIGURATION,
                                       .EfiMemoryTop = 0x0,
                                       .EfiMemoryBottom = 0x0,
                                       .EfiFreeMemoryTop = 0x0,
                                       .EfiFreeMemoryBottom = 0x0,
                                       .EfiEndOfHobList = 0x0 };	/* initialize later */

	size_t hob_offset = sizeof(EFI_HOB_HANDOFF_INFO_TABLE);

    for (size_t i = 0; i < nr_ram_entries; i++) {
        EFI_HOB_RESOURCE_DESCRIPTOR rd = {
            .Header = { .HobType = EFI_HOB_TYPE_RESOURCE_DESCRIPTOR,
                        .HobLength = sizeof(EFI_HOB_RESOURCE_DESCRIPTOR),
                        .Reserved = 0x0 },
            .Owner = { .Data1 = 0x0, .Data2 = 0x0, .Data3 = 0x0, .Data4 = { 0x0 } },
            .ResourceType = (ram_entries[i].type == TDX_RAM_UNACCEPTED ?
								EFI_RESOURCE_MEMORY_UNACCEPTED : EFI_RESOURCE_SYSTEM_MEMORY),
            .ResourceAttribute = (ram_entries[i].type == TDX_RAM_UNACCEPTED ?
									EFI_RESOURCE_ATTRIBUTE_TDVF_UNACCEPTED : EFI_RESOURCE_ATTRIBUTE_TDVF_PRIVATE) ,
            .PhysicalStart = ram_entries[i].address,
            .ResourceLength = ram_entries[i].length
        };

        memcpy(hob + hob_offset, (uint8_t *)&rd, sizeof(EFI_HOB_RESOURCE_DESCRIPTOR));
        hob_offset += sizeof(EFI_HOB_RESOURCE_DESCRIPTOR);
    }

	// align the hob_offset up (see tdvf_align in tdvf-hob.c:tdvf_get_area)
	if (hob_offset & 0xf) {
		hob_offset = (hob_offset & ~0xf) + 0x10;
	}

	tbl.EfiEndOfHobList = ovmf_metadata.sections[td_hob_index].memory_address + hob_offset; 

	memcpy(hob, &tbl, sizeof(EFI_HOB_HANDOFF_INFO_TABLE));

	*dest_len = hob_len;
	*dest = hob;

	print_td_hob(*dest, *dest_len);

    return 0;

}

void
print_td_hob(uint8_t *data, size_t len)
{
    DEBUG("Printing EFI handoff tables\n");
    size_t offset = 0;
    while (offset < len) {
        EFI_HOB_GENERIC_HEADER *hdr = (EFI_HOB_GENERIC_HEADER *)((uint8_t *)data + offset);
        switch (hdr->HobType) {
        case EFI_HOB_TYPE_HANDOFF:
            EFI_HOB_HANDOFF_INFO_TABLE *hob =
                (EFI_HOB_HANDOFF_INFO_TABLE *)((uint8_t *)data + offset);
            DEBUG("EFI_HOB_HANDOFF_INFO_TABLE:\n");
            DEBUG("\tHobType: %d\n", hob->Header.HobType);
            DEBUG("\tHobLength: %d\n", hob->Header.HobLength);
            DEBUG("\tVersion: %d\n", hob->Version);
            DEBUG("\tBoot Mode: %d\n", hob->BootMode);
            DEBUG("\tEfiMemoryTop: 0x%llx\n", hob->EfiMemoryTop);
            DEBUG("\tEfiMemoryBottom: 0x%llx\n", hob->EfiMemoryBottom);
            DEBUG("\tEfiFreeMemoryTop: 0x%llx\n", hob->EfiFreeMemoryTop);
            DEBUG("\tEfiFreememoryBottom: 0x%llx\n", hob->EfiFreeMemoryBottom);
            DEBUG("\tEfiEndOfHobList: 0x%llx\n", hob->EfiEndOfHobList);
            break;

        case EFI_HOB_TYPE_RESOURCE_DESCRIPTOR:
            EFI_HOB_RESOURCE_DESCRIPTOR *rd =
                (EFI_HOB_RESOURCE_DESCRIPTOR *)((uint8_t *)data + offset);
            DEBUG("EFI_HOB_RESOURCE_DESCRIPTOR:\n");
            DEBUG("\tHobType: %d\n", hob->Header.HobType);
            DEBUG("\tHobLength: %d\n", hob->Header.HobLength);
            DEBUG("\tGUID: %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x\n", rd->Owner.Data1,
                  rd->Owner.Data2, rd->Owner.Data3, rd->Owner.Data4[0], rd->Owner.Data4[1],
                  rd->Owner.Data4[2], rd->Owner.Data4[3], rd->Owner.Data4[4], rd->Owner.Data4[5],
                  rd->Owner.Data4[6], rd->Owner.Data4[7]);
            DEBUG("\tResourceType: %x\n", rd->ResourceType);
            DEBUG("\tResourceAttribute: %x\n", rd->ResourceAttribute);
            DEBUG("\tPhysicalStart: %llx\n", rd->PhysicalStart);
            DEBUG("\tResourceLength: %llx\n", rd->ResourceLength);
            break;
        }

        offset += hdr->HobLength;
    }
}
