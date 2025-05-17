#include "handle.h"

void handleErrors()
{
    unsigned long err_code;

    // 获取错误代码
    while ((err_code = ERR_get_error()) != 0) {
        // 将错误代码转换为可读字符串
        char* err_msg = ERR_error_string(err_code, nullptr);
        std::cerr << "Error: " << err_msg << std::endl;
    }
   abort();
}