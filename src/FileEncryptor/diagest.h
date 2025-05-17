#pragma once
#pragma warning(disable:4996)
#include <openssl/evp.h>
#include "handle.h"
#include <openssl/sha.h>
bool generate_file_sha256_digest(const char* filename, unsigned char* md_value,
    unsigned int* md_len, unsigned long bytes_to_hash);

bool generate_sha256_digest(const unsigned char* data, size_t data_len, unsigned char* md_value, unsigned int* md_len);
