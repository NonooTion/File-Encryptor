#pragma once
#include "diagest.h"

bool generate_file_sha256_digest(const char* filename, unsigned char* md_value,
    unsigned int* md_len, unsigned long bytes_to_hash) {
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        handleErrors();
        return false;
    }

    // ��ʼ�� SHA-256 ժҪ������
    if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(md_ctx);
        handleErrors();
        return false;
    }

    // ���ļ�
    FILE* file = fopen(filename, "rb");
    if (!file) {
        std::cerr << "Could not open file: " << filename << std::endl;
        EVP_MD_CTX_free(md_ctx);
        return false;
    }

    // ��ȡָ���ֽ���������ժҪ
    unsigned char buffer[4096];
    size_t bytes_read;
    unsigned long total_bytes_read = 0;

    while (total_bytes_read < bytes_to_hash) {
        bytes_read = fread(buffer, 1, sizeof(buffer), file);
        if (bytes_read == 0) {
            break; // ���û�и������ݣ����˳�ѭ��
        }

        // ����ʵ����Ҫ������ֽ���
        size_t bytes_to_process = bytes_to_hash - total_bytes_read;
        if (bytes_read > bytes_to_process) {
            bytes_read = bytes_to_process; // ���ƶ�ȡ���ֽ���
        }

        EVP_DigestUpdate(md_ctx, buffer, bytes_read);
        total_bytes_read += bytes_read;
    }

    // ���ժҪ����
    if (EVP_DigestFinal_ex(md_ctx, md_value, md_len) != 1) {
        EVP_MD_CTX_free(md_ctx);
        fclose(file);
        handleErrors();
        return false;
    }

    // �ͷ������ĺ͹ر��ļ�
    EVP_MD_CTX_free(md_ctx);
    fclose(file);
    return true;
}

bool generate_sha256_digest(const unsigned char* data, size_t data_len, unsigned char* md_value, unsigned int* md_len) {
    if (!data || !md_value || !md_len) {
        std::cerr << "Invalid input to generate SHA256 digest." << std::endl;
        return false;
    }

    // ���� SHA-256 ժҪ
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data, data_len);
    SHA256_Final(md_value, &sha256);

    // ����ժҪ����
    *md_len = SHA256_DIGEST_LENGTH;
    return true;
}