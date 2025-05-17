#include "cipher.h"

bool rsa_encrypt_key(const unsigned char* key, size_t key_len, const char* pub_key_file,
    unsigned char** encrypted_key, size_t* enc_key_len) {
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

    // 创建 RSA 上下文
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pub_key, NULL);
    if (!ctx) {
        EVP_PKEY_free(pub_key);
        handleErrors();
        return false;
    }

    //// 初始化加密
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pub_key);
        handleErrors();
        return false;
    }
    if (EVP_PKEY_encrypt(ctx, NULL, enc_key_len, key, key_len) <= 0) {
        fprintf(stderr, "Unable to determine buffer length for encryption\n");
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    // 计算加密后的密钥长度
    if (EVP_PKEY_encrypt(ctx, NULL, enc_key_len, key, key_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pub_key);
        handleErrors();
        return false;
    }
    // 分配内存并执行加密
    
    *encrypted_key = (unsigned char*)OPENSSL_malloc(*enc_key_len);
    if (*encrypted_key == nullptr) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pub_key);
        std::cerr << "Memory allocation failed!" << std::endl;
        return false;
    }

    // 再次调用 EVP_PKEY_encrypt 来执行实际加密
    if (EVP_PKEY_encrypt(ctx, *encrypted_key, enc_key_len, key, key_len) <= 0) {
        free(*encrypted_key); // 释放内存
        EVP_PKEY_CTX_free(ctx);
       EVP_PKEY_free(pub_key);
        handleErrors();
        return false; 
    }
    // 释放资源
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pub_key);
    return true;
}

bool rsa_decrypt_key(const unsigned char* encrypted_key, size_t enc_key_len,
    const char* priv_key_file, unsigned char** decrypted_key, size_t* dec_key_len) {
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

    // 创建 RSA 上下文
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv_key, NULL);
    if (!ctx) {
        EVP_PKEY_free(priv_key);
        handleErrors();
        return false;
    }

    // 初始化解密
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(priv_key);
        handleErrors();
        return false;
    }

    // 计算解密后的密钥长度
    if (EVP_PKEY_decrypt(ctx, NULL, dec_key_len, encrypted_key, enc_key_len) <= 0) {
        fprintf(stderr, "Unable to determine buffer length for decryption\n");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(priv_key);
        handleErrors();
        return false;
    }

    // 分配内存以存放解密后的密钥
    *decrypted_key = (unsigned char*)OPENSSL_malloc(*dec_key_len);
    if (*decrypted_key == nullptr) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(priv_key);
        std::cerr << "Memory allocation failed!" << std::endl;
        return false;
    }

    // 执行实际解密
    if (EVP_PKEY_decrypt(ctx, *decrypted_key, dec_key_len, encrypted_key, enc_key_len) <= 0) {
        free(*decrypted_key); // 释放内存
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(priv_key);
        handleErrors();
        return false;
    }

    // 释放资源
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(priv_key);
    return true;
}

void encrypt(const char* infile, const char* password, const char* outfile,
    const char* pub_key_file, const char* priv_key_file, Mode mode,Algo algo) {
    const size_t BUF_SIZE = 64 * 1024;

    size_t BLOCK_SIZE;
    const EVP_CIPHER* cipher = nullptr;
    switch (algo) {
    case Algo::DES :
        BLOCK_SIZE = 8;
        switch (mode) {
        case Mode::ECB: cipher = EVP_des_ecb(); break;
        case Mode::CBC: cipher = EVP_des_cbc(); break;
        case Mode::CFB: cipher = EVP_des_cfb64(); break;
        case Mode::OFB: cipher = EVP_des_ofb(); break;
        }
        break;
    case Algo::AES:
        BLOCK_SIZE = 16;
        switch (mode) {
        case Mode::ECB: cipher = EVP_aes_128_ecb(); break;
        case Mode::CBC: cipher = EVP_aes_128_cbc(); break;
        case Mode::CFB: cipher = EVP_aes_128_cfb(); break;
        case Mode::OFB: cipher = EVP_aes_128_ofb(); break;
        }
        break;
    }
    unsigned char* in_buf = (unsigned char*)malloc(BUF_SIZE + BLOCK_SIZE);
    unsigned char* out_buf = (unsigned char*)malloc(BUF_SIZE + BLOCK_SIZE);
    unsigned char* key = (unsigned char*)malloc(BLOCK_SIZE);
    unsigned char* iv = (unsigned char*)malloc(BLOCK_SIZE);

    derive_key(password, key, BLOCK_SIZE);
    derive_iv(password, iv, BLOCK_SIZE);

    EVP_CIPHER_CTX* cipher_ctx = EVP_CIPHER_CTX_new();
    if (!cipher_ctx) handleErrors();


    // 初始化加密
    if (EVP_EncryptInit_ex(cipher_ctx, cipher, NULL, key, iv) != 1) {
        handleErrors();
    }

    FILE* input_file = fopen(infile, "rb");
    if (!input_file) {
        std::cerr << "Could not open input file" << "\n";
        free(in_buf);
        free(out_buf);
        free(key);
        free(iv);
        EVP_CIPHER_CTX_free(cipher_ctx);
        return;
    }
    //获取输入文件的总字节数
    fseek(input_file, 0, SEEK_END);
    size_t totol_input_bytes = ftell(input_file);
    fseek(input_file, 0, SEEK_SET);

    //对明文生成消息摘要
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    if (generate_file_sha256_digest(infile, md_value, &md_len, totol_input_bytes))
        printf("消息摘要生成成功!\n");

    //使用私钥对消息摘要进行签名
    unsigned char sig[256];
    unsigned int sig_len = sizeof(sig);
    if (sign_digest(md_value, md_len, priv_key_file, sig, &sig_len))
        printf("签名生成成功!\n");

    //使用公钥加密对称密钥
    unsigned char* enc_key = nullptr;
    size_t enc_key_len;
    if (rsa_encrypt_key(key, BLOCK_SIZE, pub_key_file, &enc_key, &enc_key_len))
        printf("对称密钥加密成功!\n");


    FILE* output_file = fopen(outfile, "wb"); // 打开输出文件
    fwrite(iv, 1, BLOCK_SIZE, output_file);       // 写入 IV
    fwrite(&enc_key_len, sizeof(size_t), 1, output_file); // 写入加密密钥的长度
    fwrite(enc_key, 1, enc_key_len, output_file); // 写入加密的对称密钥
    fwrite(sig, 1, sig_len, output_file);          // 写入签名
    printf("IV、密钥长度、密钥、签名写入成功!\n");
    //加密输入文件并输出密文
    //加密文件
    if (!output_file) {
        std::cerr << "Could not open output file!" << std::endl;
        free(in_buf);
        free(out_buf);
        free(key);
        free(iv);
        EVP_CIPHER_CTX_free(cipher_ctx);
        fclose(input_file);
        return;
    }

    // 加密文件内容
    while (size_t in_nbytes = fread(in_buf, 1, BUF_SIZE, input_file)) {
        int out_nbytes = 0;
        EVP_EncryptUpdate(cipher_ctx, out_buf, &out_nbytes, in_buf, in_nbytes);
        fwrite(out_buf, 1, out_nbytes, output_file);
    }

    int out_nbytes = 0;
    if (EVP_EncryptFinal_ex(cipher_ctx, out_buf, &out_nbytes) != 1) {
        handleErrors();
    }
    fwrite(out_buf, 1, out_nbytes, output_file);

    // 释放加密上下文
    EVP_CIPHER_CTX_free(cipher_ctx);
    fclose(input_file);
    fclose(output_file);
    std::cout << "加密成功,文件存放在: " << outfile << std::endl;

    fclose(output_file);
    //清理
    free(in_buf);
    free(out_buf);
    free(key);
    free(iv);
}

void decrypt(const char* infile, const char* outfile, const char* pub_key_file, const char* priv_key_file, Mode mode,Algo algo) {
    size_t BLOCK_SIZE;
    const EVP_CIPHER* cipher = nullptr;
    switch (algo) {
    case Algo::DES:
        BLOCK_SIZE = 8;
        switch (mode) {
        case Mode::ECB: cipher = EVP_des_ecb(); break;
        case Mode::CBC: cipher = EVP_des_cbc(); break;
        case Mode::CFB: cipher = EVP_des_cfb64(); break;
        case Mode::OFB: cipher = EVP_des_ofb(); break;
        }
        break;
    case Algo::AES:
        BLOCK_SIZE = 16;
        switch (mode) {
        case Mode::ECB: cipher = EVP_aes_128_ecb(); break;
        case Mode::CBC: cipher = EVP_aes_128_cbc(); break;
        case Mode::CFB: cipher = EVP_aes_128_cfb(); break;
        case Mode::OFB: cipher = EVP_aes_128_ofb(); break;
        }
        break;
    }
    unsigned char* iv = (unsigned char*)malloc(BLOCK_SIZE);
    unsigned char* enc_key = nullptr;
    size_t enc_key_len;

    // 打开输入文件
    FILE* input_file = fopen(infile, "rb");
    if (!input_file) {
        std::cerr << "Could not open input file" << "\n";
        free(iv);
        return;
    }

    // 读取 IV
    fread(iv, 1, BLOCK_SIZE, input_file);

    // 读取加密的对称密钥的长度
    fread(&enc_key_len, sizeof(size_t), 1, input_file);

    // 读取加密的对称密钥
    enc_key = (unsigned char*)malloc(enc_key_len);
    fread(enc_key, 1, enc_key_len, input_file);

    // 读取签名
    unsigned char sig[256];
    fread(sig, 1, sizeof(sig), input_file);

    // 获取密文的长度
    fseek(input_file, 0, SEEK_END);
    size_t file_size = ftell(input_file);
    size_t cipher_len = file_size - BLOCK_SIZE - sizeof(size_t) - enc_key_len - sizeof(sig);
    fseek(input_file, BLOCK_SIZE + sizeof(size_t) + enc_key_len + sizeof(sig), SEEK_SET);

    // 读取密文
    unsigned char* in_buf = (unsigned char*)malloc(cipher_len);
    fread(in_buf, 1, cipher_len, input_file);
    fclose(input_file);

    // 使用私钥解密对称密钥
    unsigned char* decrypted_key = nullptr;
    size_t decrypted_key_len;
    if (!rsa_decrypt_key(enc_key, enc_key_len, priv_key_file, &decrypted_key, &decrypted_key_len)) {
        std::cerr << "Failed to decrypt symmetric key." << std::endl;
        free(iv);
        free(enc_key);
        free(in_buf);
        return;
    }

    // 使用解密后的对称密钥解密密文
    EVP_CIPHER_CTX* cipher_ctx = EVP_CIPHER_CTX_new();

    // 初始化解密
    if (EVP_DecryptInit_ex(cipher_ctx, cipher, NULL, decrypted_key, iv) != 1) {
        handleErrors();
    }

    // 解密文件内容
    unsigned char* out_buf = (unsigned char*)malloc(cipher_len + BLOCK_SIZE);
    int out_nbytes = 0;
    EVP_DecryptUpdate(cipher_ctx, out_buf, &out_nbytes, in_buf, cipher_len);

    // 处理解密后的数据
    int final_nbytes = 0;
    if (EVP_DecryptFinal_ex(cipher_ctx, out_buf + out_nbytes, &final_nbytes) != 1) {
        handleErrors();
    }
    out_nbytes += final_nbytes;

    // 释放解密上下文
    EVP_CIPHER_CTX_free(cipher_ctx);
    free(in_buf);

    // 生成解密后的消息摘要
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    if (!generate_sha256_digest(out_buf, out_nbytes, md_value, &md_len)) {
        std::cerr << "Failed to generate hash from decrypted content." << std::endl;
        free(out_buf);
        return;
    }

    // 使用公钥验证签名
    if (!verify_sign(md_value, md_len, pub_key_file, sig, sizeof(sig))) {
        std::cerr << "Signature verification failed!" << std::endl;
        free(out_buf);
        return;
    }
    std::cout << "签名验证通过!\n" << std::endl;

    // 将解密后的明文写入输出文件
    FILE* output_file = fopen(outfile, "wb");
    if (!output_file) {
        std::cerr << "Could not open output file!" << std::endl;
        free(out_buf);
        return;
    }
    fwrite(out_buf, 1, out_nbytes, output_file);

    // 释放资源
    fclose(output_file);
    free(out_buf);
    free(iv);

    std::cout << "解密成功,文件存放在: " << outfile << std::endl;
}
