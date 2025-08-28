/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include "eventlog.h"
#include "hash.h"

#pragma once

typedef struct {
	uint8_t mrs[MR_LEN][SHA384_DIGEST_LENGTH];

	eventlog_t *evlog;

	const char *ovmf_file_path;
} rtmrcontext_t;

int rtmr_measure_tdhob(uint32_t mr_index, rtmrcontext_t *context);
int rtmr_measure_cfv(uint32_t mr_index, rtmrcontext_t *context);
