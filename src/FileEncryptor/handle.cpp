#include "handle.h"

void handleErrors()
{
    unsigned long err_code;

    // ��ȡ�������
    while ((err_code = ERR_get_error()) != 0) {
        // ���������ת��Ϊ�ɶ��ַ���
        char* err_msg = ERR_error_string(err_code, nullptr);
        std::cerr << "Error: " << err_msg << std::endl;
    }
   abort();
}