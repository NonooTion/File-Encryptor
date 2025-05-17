#pragma once
#pragma warning(disable:4996)
#include <openssl/evp.h>
#include "handle.h"
#include <iostream>
#include <openssl/pem.h>
bool sign_digest(const unsigned char* digest, unsigned int digest_len, const char* priv_key_file,
    unsigned char* signature, unsigned int* sig_len);
bool verify_sign(const unsigned char* digest, unsigned int digest_len,
    const char* pub_key_file, const unsigned char* signature, unsigned int sig_len);
