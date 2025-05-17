# File-Encryptor

基于OpenSSL库的文件加密系统

## 项目简介

File-Encryptor 是一个基于 OpenSSL 的文件加密与解密工具，支持 AES 和 DES 算法，支持多种分组模式（ECB、CBC、CFB、OFB），并集成了基于 RSA 的密钥管理、数字签名和 SHA-256 摘要校验，保障文件的机密性与完整性。

## 功能特性

- **对称加密/解密**：支持 AES、DES 算法，支持 ECB、CBC、CFB、OFB 模式。
- **密钥派生**：基于 PBKDF2 从密码派生密钥和 IV，提升安全性。
- **非对称密钥管理**：自动生成 RSA 公私钥（2048位），用于加密对称密钥和数字签名。
- **数字签名与校验**：对文件摘要进行签名，解密时自动校验签名，防止篡改。
- **SHA-256 摘要**：对文件内容生成 SHA-256 摘要，确保完整性。

## 依赖环境

- OpenSSL 开发库（已包含在 `include/openssl` 和 `lib` 目录下）
- C++17 或以上编译器

## 编译方法

1. 确保已安装 C++ 编译器（如 MSVC、g++）。
2. 配置 OpenSSL 头文件和库路径（如已包含在本项目中可直接编译）。
3. 进入 `src/FileEncryptor` 目录，使用 IDE 或命令行编译 `FileEncryptor.sln` 或 `FileEncryptor.vcxproj`。

## 使用方法

### 1. 生成密钥对

```bash
./FileEncryptor keygen
```
将在当前目录生成 `public.pem` 和 `private.pem`。

### 2. 文件加密

```bash
./FileEncryptor encrypt <algorithm> <mode> <password> <input_file> <output_file> <pub_key_file> <priv_key_file>
```
- `<algorithm>`: `AES` 或 `DES`
- `<mode>`: `ECB`、`CBC`、`CFB`、`OFB`
- `<password>`: 用于派生对称密钥的密码
- `<input_file>`: 待加密文件
- `<output_file>`: 输出加密文件
- `<pub_key_file>`: 公钥文件（如 `public.pem`）
- `<priv_key_file>`: 私钥文件（如 `private.pem`）

### 3. 文件解密

```bash
./FileEncryptor decrypt <algorithm> <mode> <input_file> <output_file> <pub_key_file> <priv_key_file>
```
参数同上。

## 典型流程

1. 先运行 `keygen` 生成密钥对。
2. 用 `encrypt` 命令加密文件，输出加密文件。
3. 用 `decrypt` 命令解密文件，自动校验签名和完整性。

## 安全说明

- 密钥和 IV 通过 PBKDF2 从用户密码派生，防止弱口令攻击。
- 对称密钥通过 RSA 公钥加密，只有私钥持有者可解密。
- 文件摘要采用 SHA-256，签名采用 RSA，确保数据未被篡改。

## 目录结构

- `src/`：源码目录
- `lib/`：OpenSSL 静态库
- `include/openssl/`：OpenSSL 头文件
- `bin/`：可执行文件输出目录

## License

本项目仅供学习与研究使用，禁止用于非法用途。
