/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include "eventlog.h"

#pragma once

typedef struct {
	eventlog_t *evlog;

	const char *ovmf_file_path;
} rtmrcontext_t;

int rtmr_measure_tdhob(rtmrcontext_t *context);
int rtmr_measure_cfv(rtmrcontext_t *context);
