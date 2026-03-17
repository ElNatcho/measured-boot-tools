
#pragma once

#include <stdint.h>

#include "quote.h"

int sig_check_quote_v4_signature(quote_v4_t* quote);
int sig_check_quote_v4_enclave_report_signature(quote_v4_qe_report_cert_t* qe_report_cert);
int sig_check_attestation_key_hash(quote_v4_signature_data_t* sig, quote_v4_qe_report_cert_t* qe_report_cert);
