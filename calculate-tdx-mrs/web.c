#include "web.h"

#include <openssl/evp.h>
#include <openssl/pem.h>

#include <curl/curl.h>

typedef struct {
    char *data;
    size_t size;
} download_data_t;

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t real_size = size * nmemb;
    download_data_t *mem = (download_data_t*)userp;

    char *ptr = realloc(mem->data, mem->size + real_size + 1);
    if (!ptr) {
        fprintf(stderr, "Not enough memory\n");
        return 0; // abort transfer
    }

    mem->data = ptr;
    memcpy(&(mem->data[mem->size]), contents, real_size);
    mem->size += real_size;
    mem->data[mem->size] = '\0'; // null-terminate (useful for text)

    return real_size;
}

static int download_to_memory(const char *url, download_data_t *out) {
    CURL *curl;
    CURLcode res;

    out->data = malloc(1);  // will grow as needed
    out->size = 0;

    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "curl init failed\n");
        return 0;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, out);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        fprintf(stderr, "Download failed: %s\n", curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        free(out->data);
        return 0;
    }

    curl_easy_cleanup(curl);
    return 1;
}

int fetch_root_ca_cert_from_intel(const char* url, X509** cert) {
	download_data_t download_cert;

	if (!download_to_memory(url, &download_cert)) {
		fprintf(stderr, "Download from %s failed!\n", url);
		return 0;
	}

	BIO *bio = BIO_new_mem_buf(download_cert.data, download_cert.size);

	*cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	if (!*cert) {
		fprintf(stderr, "Unable to parse intel root ca cert:\n");
		for(size_t i = 0; i < download_cert.size; i++) {
			fprintf(stderr, "%02x", download_cert.data[i]);
		}
		fprintf(stderr, "\n");
		return 0;
	}

	BIO_free(bio);
	free(download_cert.data);
	
	return 1;
}

int fetch_qe_identity_form_intel(const char* url, cJSON** root) {
	download_data_t download_json;

	if(!download_to_memory(url, &download_json)) {
		fprintf(stderr, "Download from %s failed!\n", url);
		return 0;
	}

	// see write_callback, download_json.data is 0-terminated
	*root = cJSON_Parse(download_json.data);

	return 1;
}
