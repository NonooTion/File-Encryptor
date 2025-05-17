#include "sig.h"
bool sign_digest(const unsigned char* digest, unsigned int digest_len, const char* priv_key_file,
    unsigned char* signature, unsigned int* sig_len) {
    EVP_PKEY* priv_key = nullptr;
    BIO* priv_bio = BIO_new_file(priv_key_file, "r");
    if (!priv_bio) {
        std::cerr << "Could not open private key file!" << std::endl;
        return false;
    }

    priv_key = PEM_read_bio_PrivateKey(priv_bio, NULL, NULL, NULL);
    BIO_free(priv_bio);
    if (!priv_key) {
        std::cerr << "Failed to read private key!" << std::endl;
        return false;
    }

    EVP_MD_CTX* sig_ctx = EVP_MD_CTX_new();
    if (!sig_ctx) {
        EVP_PKEY_free(priv_key);
        handleErrors();
        return false;
    }

    // 初始化签名上下文
    if (EVP_SignInit(sig_ctx, EVP_sha256()) != 1) {
        EVP_MD_CTX_free(sig_ctx);
        EVP_PKEY_free(priv_key);
        handleErrors();
        return false;
    }

    // 更新签名
    if (EVP_SignUpdate(sig_ctx, digest, digest_len) != 1) {
        EVP_MD_CTX_free(sig_ctx);
        EVP_PKEY_free(priv_key);
        handleErrors();
        return false;
    }

    // 完成签名
    *sig_len = EVP_MAX_MD_SIZE;
    if (EVP_SignFinal(sig_ctx, signature, sig_len, priv_key) != 1) {
        EVP_MD_CTX_free(sig_ctx);
        EVP_PKEY_free(priv_key);
        handleErrors();
        return false;
    }

    // 释放资源
    EVP_MD_CTX_free(sig_ctx);
    EVP_PKEY_free(priv_key);
    return true;
}

bool verify_sign(const unsigned char* digest, unsigned int digest_len,
    const char* pub_key_file, const unsigned char* signature, unsigned int sig_len) {
    EVP_PKEY* pub_key = nullptr;
    BIO* pub_bio = BIO_new_file(pub_key_file, "r");
    if (!pub_bio) {
        std::cerr << "Could not open public key file!" << std::endl;
        return false;
    }

    pub_key = PEM_read_bio_PUBKEY(pub_bio, NULL, NULL, NULL);
    BIO_free(pub_bio);
    if (!pub_key) {
        std::cerr << "Failed to read public key!" << std::endl;
        return false;
    }

    EVP_MD_CTX* verify_ctx = EVP_MD_CTX_new();
    if (!verify_ctx) {
        EVP_PKEY_free(pub_key);
        handleErrors();
        return false;
    }

    // 初始化验证上下文
    if (EVP_VerifyInit(verify_ctx, EVP_sha256()) != 1) {
        EVP_MD_CTX_free(verify_ctx);
        EVP_PKEY_free(pub_key);
        handleErrors();
        return false;
    }

    // 更新验证
    if (EVP_VerifyUpdate(verify_ctx, digest, digest_len) != 1) {
        EVP_MD_CTX_free(verify_ctx);
        EVP_PKEY_free(pub_key);
        handleErrors();
        return false;
    }

    // 完成验证
    int result = EVP_VerifyFinal(verify_ctx, signature, sig_len, pub_key);

    // 释放资源
    EVP_MD_CTX_free(verify_ctx);
    EVP_PKEY_free(pub_key);

    return result == 1; // 返回 true 代表验证成功
}