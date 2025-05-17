#include "derive.h"
#include "handle.h"
void derive_key(const char* password, unsigned char* key, int key_len) {
    // 使用 PBKDF2 派生密钥
    unsigned char* salt = (unsigned char*)"key derive salt";
    int salt_len = strlen((char*)salt);
    if (PKCS5_PBKDF2_HMAC_SHA1(password, strlen(password), salt, salt_len, 10000, key_len, key) != 1) {
        handleErrors();
    }
}

void derive_iv(const char* password, unsigned char* iv, int iv_len) {
    // 使用 PBKDF2 派生初始向量
    unsigned char* salt = (unsigned char*)"iv derive salt";
    int salt_len = strlen((char*)salt);
    if (PKCS5_PBKDF2_HMAC_SHA1(password, strlen(password), salt, salt_len, 10000, iv_len, iv) != 1) {
        handleErrors();
    }
}

// 生成公钥和私钥文件
void generate_keys() {
    // 创建 RSA 对象
    RSA* rsa = RSA_new();
    BIGNUM* bn = BN_new();
    // 设置公钥指数
    if (!BN_set_word(bn, RSA_F4)) {
        handleErrors();
    }
    // 生成 RSA 密钥
    if (RSA_generate_key_ex(rsa, 2048, bn, NULL) != 1) {
        handleErrors();
    }
    // 创建 EVP_PKEY 对象并关联 RSA 密钥
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
        handleErrors();
    }
    // 使用 BIO 保存公钥
    BIO* pub_bio = BIO_new_file("public.pem", "wb");
    if (!pub_bio) {
        std::cerr << "无法打开公钥文件" << std::endl;
        EVP_PKEY_free(pkey);
        BN_free(bn);
        return;
    }
    // 写入公钥
    if (PEM_write_bio_PUBKEY(pub_bio, pkey) == 0) {
        std::cerr << "公钥保存失败" << std::endl;
        BIO_free(pub_bio);
        EVP_PKEY_free(pkey);
        BN_free(bn);
        return;
    }
    BIO_free(pub_bio);
    // 使用 BIO 保存私钥
    BIO* priv_bio = BIO_new_file("private.pem", "wb");
    if (!priv_bio) {
        std::cerr << "无法打开私钥文件" << std::endl;
        EVP_PKEY_free(pkey);
        BN_free(bn);
        return;
    }
    // 写入私钥
    if (PEM_write_bio_PrivateKey(priv_bio, pkey, NULL, NULL, 0, NULL, NULL) == 0) {
        std::cerr << "私钥保存失败" << std::endl;
        BIO_free(priv_bio);
        EVP_PKEY_free(pkey);
        BN_free(bn);
        return;
    }
    BIO_free(priv_bio);
    // 释放资源
    EVP_PKEY_free(pkey);
    BN_free(bn);
    std::cout << "密钥生成成功，保存为 public.pem 与 private.pem." << std::endl;
}