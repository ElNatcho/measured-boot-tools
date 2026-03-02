#include "quote.h"

#include <string.h>

#include "common.h"

static char *
encode_hex(const uint8_t *bin, int length)
{
    size_t len = length * 2 + 1;
    char *hex = calloc(len, 1);
    for (int i = 0; i < length; ++i) {
        // snprintf writes a '0' byte
        snprintf(hex + i * 2, 3, "%.2x", bin[i]);
    }
    return hex;
}

quote_t* load_quote_from_file(const char* quote_file_path) {

	quote_t *quote = malloc(sizeof(quote_t));
	if(!quote) {
		printf("Failed to allocate quote.");
		return NULL;
	}

	memset(quote, 0, sizeof(quote_t));

	if (read_file(&quote->raw, &quote->raw_size, quote_file_path)) {
		printf("Failed to open file %s\n", quote_file_path);
		return NULL;
	}

	quote->version = quote->v4->header.version;

	return quote;
}

static void compare_measurements(uint8_t quote_mr[SHA384_DIGEST_SIZE], uint8_t calc_mr[SHA384_DIGEST_SIZE]) {
	char* quote_mr_str = encode_hex(quote_mr, SHA384_DIGEST_SIZE);
	char* calc_mr_str = encode_hex(calc_mr, SHA384_DIGEST_SIZE);

	printf("Quote:%s\nCalc :%s", quote_mr_str, calc_mr_str);

	if (strcmp(quote_mr_str, calc_mr_str) == 0) {
		printf("(\x1B[32mMatch\x1B[37m)\n");
	} else {
		printf("(\x1B[31mMismatch\x1B[37m)\n");
	}

	free(quote_mr_str);
	free(calc_mr_str);
}

void check_quote(quote_t* quote, uint8_t mrs[MR_LEN][SHA384_DIGEST_LENGTH]) {
	printf("================= MRTD =================\n");
	compare_measurements(quote->v4->body.mrtd_measurement, mrs[INDEX_MRTD]);
	printf("================= RTMR0 ================\n");
	compare_measurements(quote->v4->body.rtmr0_measurement, mrs[INDEX_RTMR0]);
	printf("================= RTMR1 ================\n");
	compare_measurements(quote->v4->body.rtmr1_measurement, mrs[INDEX_RTMR1]);
	printf("================= RTMR2 ================\n");
	compare_measurements(quote->v4->body.rtmr2_measurement, mrs[INDEX_RTMR2]);
	printf("================= RTMR3 ================\n");
	compare_measurements(quote->v4->body.rtmr3_measurement, mrs[INDEX_RTMR3]);
	printf("================= MRSEAM ===============\n");
	compare_measurements(quote->v4->body.mrseam_measurement, mrs[INDEX_MRSEAM]);
}
