#pragma once
#define OPENSSL_Applink  // 这必须在其他包含之前定义

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "handle.h"
#include "diagest.h"
#include "derive.h"
#include "print.h"
#include "sig.h"
#pragma warning(disable:4996)
enum class Mode {
    ECB,
    CBC,
    CFB,
    OFB
};

enum class Algo {
    AES,
    DES
};
void encrypt(const char* infile, const char* password, const char* outfile,
    const char* pub_key_file, const char* priv_key_file, Mode mode,Algo algo);

void decrypt(const char* infile, const char* outfile,
    const char* pub_key_file, const char* priv_key_file, Mode mode,Algo algo);

