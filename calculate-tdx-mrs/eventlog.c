/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <assert.h>
#include <openssl/sha.h>

#include "eventlog.h"
#include "common.h"
#include "hash.h"

const char *
index_to_mr(uint32_t index)
{
    switch (index) {
    case INDEX_MRTD:
        return "MRTD";
    case INDEX_RTMR0:
        return "RTMR0";
    case INDEX_RTMR1:
        return "RTMR1";
    case INDEX_RTMR2:
        return "RTMR2";
    case INDEX_RTMR3:
        return "RTMR3";
    case INDEX_MRSEAM:
        return "MRSEAM";
    default:
        return "unknown";
    }
}

int load_compare_digest_list(eventlog_t *evlog, const char *path)
{
	int ret = -1;

	char *file_buf = NULL;
	size_t file_size;
	ret = read_file((uint8_t**)&file_buf, &file_size, path);
	if (ret) {
		printf("Failed to read file: %s\n", path);
		return -1;
	}

	// For now, digests are stored as hex ascii strings in a file. One digest is stored per line.
	char (*digests)[SHA384_DIGEST_LENGTH * 2 + 1] = NULL;
	size_t digests_count = 0;
	size_t digest_size = 0;
	size_t digest_start_i = 0;
	size_t i = 0;
	for (i = 0; i < file_size; i++) {
		if (isxdigit(file_buf[i])) {
			continue;
		} else if (file_buf[i] == '\r') {
			// prevent multiple sequential \r (or in the middle of digests)
			if (i < file_size && file_buf[i + 1] != '\n') {
				printf("Unexpected character '%c' at position %ld\n", file_buf[i], i);
				return -1;
			}
			continue;
		} else if (i > 0 && (file_buf[i] == '\n' || i + 1 == file_size /* entry before EOF without nl */)) {
			// ignore \r in size calculation 
			digest_size = (file_buf[i - 1] == '\r' ? i - 1 : i) - digest_start_i;
			// Currently, only sha384 is used, thus we only expect this hash size (* 2 since we are dealing with
			// ascii hex and not raw bytes)
			if (digest_size != SHA384_DIGEST_LENGTH * 2) {
				printf("Unexpected digest length %ld at position %ld\n", digest_size, digest_start_i);
				continue;	// recoverable - laod the rest
			}

			digests = realloc(digests, (digests_count + 1) * sizeof(digests[0]));
			if (!digests) {
				printf("realloc failed\n");
				return -1;
			}

			memcpy(&digests[digests_count], file_buf + digest_start_i, SHA384_DIGEST_LENGTH * 2);
			digests[digests_count][SHA384_DIGEST_LENGTH * 2] = '\0'; // terminate the copied hash with \0

			digests_count += 1;
			digest_start_i = i + 1;
		} else {
			printf("Unexpected character '%c' at position %ld\n", file_buf[i], i);
			return -1;
		}
	}

	/*for (size_t i = 0; i < digests_count; i++) {
		printf("[Digest:%ld] %s\n", i, digests[i]);
	}*/

	evlog->compare_digest_list = digests;
	evlog->compare_digest_list_count = digests_count;

	return 0;
}

int
evlog_add(eventlog_t *evlog, uint32_t index, const char *name, uint8_t *hash, const char *desc)
{
    int ret;
    char *hashstr = encode_hex(hash, SHA384_DIGEST_LENGTH);
    if (!hashstr) {
        printf("Failed to allocate memory\n");
        return -1;
    }

    char s[1024] = { 0 };
    if (evlog->format == FORMAT_JSON) {
        ret = snprintf(s, sizeof(s),
                       "{"
                       "\n\t\"type\":\"TDX Reference Value\","
                       "\n\t\"subtype\":\"%s\","
                       "\n\t\"index\":%d,"
                       "\n\t\"sha384\":\"%s\","
                       "\n\t\"description\":\"%s: %s\""
                       "\n},\n",
                       name, index, hashstr, index_to_mr(index), desc);
    } else if (evlog->format == FORMAT_TEXT) {
		if (evlog->compare_digest_list) {

			char *cmphashstr;
			char *matchstr;
			char *colorstr;

			assert(evlog->compare_digest_list_count >= evlog->compare_digest_list_offset);

			if (index == INDEX_MRTD || evlog->compare_digest_list_count == evlog->compare_digest_list_offset) {
				cmphashstr = "n/a";
				matchstr = "";
			} else {
				cmphashstr = evlog->compare_digest_list[evlog->compare_digest_list_offset];

				// TODO: color mode disable
				if (strcmp(cmphashstr, hashstr) == 0) {
					matchstr = "Match";
					colorstr = TTY_GREEN;
				} else {
					matchstr = "Mismatch";
					colorstr = TTY_RED;
				}

				evlog->compare_digest_list_offset += 1;
			}

			ret = snprintf(s, sizeof(s),
						  "subtype: %s"
						  "\n\tindex: %d"
						  "\n\tsha384    : %s"
						  "\n\tcmp-sha384: %s (%s%s%s)"
	                      "\n\tdescription: %s: %s\n",
			              name, index, hashstr, cmphashstr, colorstr, matchstr, TTY_WHITE, index_to_mr(index), desc);
		} else {
		    ret = snprintf(s, sizeof(s),
						   "subtype: %s"
					       "\n\tindex: %d"
				           "\n\tsha384: %s"
	                       "\n\tdescription: %s: %s\n",
			               name, index, hashstr, index_to_mr(index), desc);
		}
    }
    if (!ret) {
        printf("Failed to print eventlog\n");
        ret = -1;
        goto out;
    }

    if (!evlog->log[index]) {
        size_t size = strlen(s) + 1;
        evlog->log[index] = (char *)malloc(size);
        if (!evlog->log[index]) {
            printf("Failed to allocate memory\n");
            ret = -1;
            goto out;
        }
        strncpy(evlog->log[index], s, size);
    } else {
        size_t size = strlen(evlog->log[index]) + strlen(s) + 1;
        evlog->log[index] = (char *)realloc(evlog->log[index], size);
        if (!evlog->log[index]) {
            printf("Failed to allocate memory\n");
            ret = -1;
            goto out;
        }
        strncat(evlog->log[index], s, strlen(s) + 1);
    }

out:
    free(hashstr);
    return ret;
}
