#include "cipher.h"
#include "derive.h"
#include <filesystem>
#pragma warning(disable:4996)
void initialize_providers() {
    if (!OSSL_PROVIDER_load(NULL, "legacy")) {
        fprintf(stderr, "Failed to load legacy provider.\n");
        handleErrors();
    }
    if (!OSSL_PROVIDER_load(NULL, "default")) {
        fprintf(stderr, "Failed to load legacy provider.\n");
        handleErrors();
    }
}

Mode get_mode(const char* mode_str) {
    if (strcmp(mode_str, "ECB") == 0) return Mode::ECB;
    if (strcmp(mode_str, "CBC") == 0) return Mode::CBC;
    if (strcmp(mode_str, "CFB") == 0) return Mode::CFB;
    if (strcmp(mode_str, "OFB") == 0) return Mode::OFB;
    throw std::invalid_argument("Unknown mode");
}

Algo get_algo(const char* algo_str)
{
    if (strcmp(algo_str, "AES") == 0) return Algo::AES;
    if (strcmp(algo_str, "DES") == 0) return Algo::DES;
  
    throw std::invalid_argument("Unknown algo");
}


int main(int argc, char* argv[]) {
    initialize_providers();
    if (argc < 2) {
        std::cerr << "Usage: ./FileEncryptor <command> [options]" << std::endl;
        std::cerr << "\tcommand: keygen(生成对称密钥pem文件)" << std::endl;
        std::cerr << "\tcommand: encrypt(加密文件)" << std::endl;
        std::cerr << "\tcommand: decrypt(解密文件)" << std::endl;
        return 1;
    }

    const char* command = argv[1];

    if (strcmp(command, "keygen") == 0) {
        generate_keys();
    }
    else if (strcmp(command, "encrypt") == 0) {
        if (argc < 9) { // 更新参数数量检查
            std::cerr << "Usage: ./FileEncryptor encrypt <algorithm> <mode> <password> <input_file> <output_file> <pub_key_file> <priv_key_file>" << std::endl;
            return 1;
        }

        Algo algorithm = get_algo(argv[2]); // AES 或 DES
        Mode mode = get_mode(argv[3]); // ECB, CBC, CFB, OFB
        char* password = argv[4]; // 输入的口令
        char* input_file = argv[5]; // 输入文件
        char* output_file = argv[6]; // 输出文件
        char* pub_key_file = argv[7]; // 公钥文件
        char* priv_key_file = argv[8]; // 私钥文件
         // 调用加密函数
        encrypt(input_file, password, output_file, pub_key_file, priv_key_file, mode, algorithm);
    }
    else if (strcmp(command, "decrypt") == 0) {
        if (argc < 7) { // 更新参数数量检查
            std::cerr << "Usage: ./FileEncryptor decrypt <algorithm> <mode> <input_file> <output_file> <pub_key_file> <priv_key_file>" << std::endl;
            return 1;
        }

        Algo algorithm = get_algo(argv[2]); // AES 或 DES
        Mode mode = get_mode(argv[3]); // 获取解密模式
        char* input_file = argv[4]; // 输入文件
        char* output_file = argv[5]; // 输出文件
        char* pub_key_file = argv[6]; // 公钥文件
        char* priv_key_file = argv[7]; // 私钥文件
       // 调用解密函数
       decrypt(input_file, output_file, pub_key_file, priv_key_file, mode, algorithm);
       
    }
    else {
        std::cerr << "Invalid command." << std::endl;
    }
    return 0;
}
  