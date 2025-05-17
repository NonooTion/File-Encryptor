#include "derive.h"
#include "handle.h"
void derive_key(const char* password, unsigned char* key, int key_len) {
    // ʹ�� PBKDF2 ������Կ
    unsigned char* salt = (unsigned char*)"key derive salt";
    int salt_len = strlen((char*)salt);
    if (PKCS5_PBKDF2_HMAC_SHA1(password, strlen(password), salt, salt_len, 10000, key_len, key) != 1) {
        handleErrors();
    }
}

void derive_iv(const char* password, unsigned char* iv, int iv_len) {
    // ʹ�� PBKDF2 ������ʼ����
    unsigned char* salt = (unsigned char*)"iv derive salt";
    int salt_len = strlen((char*)salt);
    if (PKCS5_PBKDF2_HMAC_SHA1(password, strlen(password), salt, salt_len, 10000, iv_len, iv) != 1) {
        handleErrors();
    }
}

// ���ɹ�Կ��˽Կ�ļ�
void generate_keys() {
    // ���� RSA ����
    RSA* rsa = RSA_new();
    BIGNUM* bn = BN_new();
    // ���ù�Կָ��
    if (!BN_set_word(bn, RSA_F4)) {
        handleErrors();
    }
    // ���� RSA ��Կ
    if (RSA_generate_key_ex(rsa, 2048, bn, NULL) != 1) {
        handleErrors();
    }
    // ���� EVP_PKEY ���󲢹��� RSA ��Կ
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
        handleErrors();
    }
    // ʹ�� BIO ���湫Կ
    BIO* pub_bio = BIO_new_file("public.pem", "wb");
    if (!pub_bio) {
        std::cerr << "�޷��򿪹�Կ�ļ�" << std::endl;
        EVP_PKEY_free(pkey);
        BN_free(bn);
        return;
    }
    // д�빫Կ
    if (PEM_write_bio_PUBKEY(pub_bio, pkey) == 0) {
        std::cerr << "��Կ����ʧ��" << std::endl;
        BIO_free(pub_bio);
        EVP_PKEY_free(pkey);
        BN_free(bn);
        return;
    }
    BIO_free(pub_bio);
    // ʹ�� BIO ����˽Կ
    BIO* priv_bio = BIO_new_file("private.pem", "wb");
    if (!priv_bio) {
        std::cerr << "�޷���˽Կ�ļ�" << std::endl;
        EVP_PKEY_free(pkey);
        BN_free(bn);
        return;
    }
    // д��˽Կ
    if (PEM_write_bio_PrivateKey(priv_bio, pkey, NULL, NULL, 0, NULL, NULL) == 0) {
        std::cerr << "˽Կ����ʧ��" << std::endl;
        BIO_free(priv_bio);
        EVP_PKEY_free(pkey);
        BN_free(bn);
        return;
    }
    BIO_free(priv_bio);
    // �ͷ���Դ
    EVP_PKEY_free(pkey);
    BN_free(bn);
    std::cout << "��Կ���ɳɹ�������Ϊ public.pem �� private.pem." << std::endl;
}