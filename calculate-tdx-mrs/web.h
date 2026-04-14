
#pragma once

#include <openssl/x509.h>
#include <cjson/cJSON.h>

int fetch_root_ca_cert_from_intel(const char* url, X509** cert);
int fetch_qe_identity_form_intel(const char* url, cJSON** root);
