#pragma once
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include "handle.h"
#pragma warning(disable:4996)
void derive_key(const char* password, unsigned char* key, int key_len);

void derive_iv(const char* password, unsigned char* iv, int iv_len);


// ±£´æ¹«Ô¿ºÍË½Ô¿
void generate_keys();