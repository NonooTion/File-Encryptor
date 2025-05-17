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
        std::cerr << "\tcommand: keygen(���ɶԳ���Կpem�ļ�)" << std::endl;
        std::cerr << "\tcommand: encrypt(�����ļ�)" << std::endl;
        std::cerr << "\tcommand: decrypt(�����ļ�)" << std::endl;
        return 1;
    }

    const char* command = argv[1];

    if (strcmp(command, "keygen") == 0) {
        generate_keys();
    }
    else if (strcmp(command, "encrypt") == 0) {
        if (argc < 9) { // ���²����������
            std::cerr << "Usage: ./FileEncryptor encrypt <algorithm> <mode> <password> <input_file> <output_file> <pub_key_file> <priv_key_file>" << std::endl;
            return 1;
        }

        Algo algorithm = get_algo(argv[2]); // AES �� DES
        Mode mode = get_mode(argv[3]); // ECB, CBC, CFB, OFB
        char* password = argv[4]; // ����Ŀ���
        char* input_file = argv[5]; // �����ļ�
        char* output_file = argv[6]; // ����ļ�
        char* pub_key_file = argv[7]; // ��Կ�ļ�
        char* priv_key_file = argv[8]; // ˽Կ�ļ�
         // ���ü��ܺ���
        encrypt(input_file, password, output_file, pub_key_file, priv_key_file, mode, algorithm);
    }
    else if (strcmp(command, "decrypt") == 0) {
        if (argc < 7) { // ���²����������
            std::cerr << "Usage: ./FileEncryptor decrypt <algorithm> <mode> <input_file> <output_file> <pub_key_file> <priv_key_file>" << std::endl;
            return 1;
        }

        Algo algorithm = get_algo(argv[2]); // AES �� DES
        Mode mode = get_mode(argv[3]); // ��ȡ����ģʽ
        char* input_file = argv[4]; // �����ļ�
        char* output_file = argv[5]; // ����ļ�
        char* pub_key_file = argv[6]; // ��Կ�ļ�
        char* priv_key_file = argv[7]; // ˽Կ�ļ�
       // ���ý��ܺ���
       decrypt(input_file, output_file, pub_key_file, priv_key_file, mode, algorithm);
       
    }
    else {
        std::cerr << "Invalid command." << std::endl;
    }
    return 0;
}
  