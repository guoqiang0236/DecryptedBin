#pragma once
#include <string>
#include "aes.h"
#include "modes.h"
#include "osrng.h"
#include "crc.h"

class FileEncryptor
{
public:
    static const char ENCRYPTION_HEADER[];
    static const int HEADER_SIZE = 12;
    static const int KEY_SIZE = 16;
    static const int CRC_SIZE = 4;

    FileEncryptor();
    ~FileEncryptor();

    bool EncryptFile(const char* filename);
    std::string DecryptFile(const char* filename);

    bool EncryptFileWithCRCFile(const char* binFile, const char* crcFile);
    std::string DecryptFileWithCRCFile(const char* binFile, const char* crcFile);
    bool EncryptFileWithCRCFile(const char* binFile, const char* crcFile, const char* outFile);
    std::string DecryptFileWithCRCFile(const char* encryptedFile, const char* crcFile, const char* originalName);

    uint32_t CalculateCRC32(const std::string& data);
    bool VerifyCRC32(const std::string& data, uint32_t expectedCRC);

    bool SaveCRC32ToFile(const char* crcFile, uint32_t crc32);
    uint32_t LoadCRC32FromFile(const char* crcFile);

    std::string ReadBinaryFile(const char* filename);
    bool WriteBinaryFile(const char* filename, const std::string& data);

private:
    void Encrypt(std::string& str, const std::string& key, const byte* iv);
    void Decrypt(std::string& str, const std::string& key, const byte* iv);

    std::string GenerateKeyFromFilename(const char* filename);
    void GenerateRandomIV(byte* iv);

    bool IsEncryptedFile(FILE* fp);
    std::string ReadFileContent(FILE* fp);
    bool WriteEncryptedFile(const char* filename, const byte* iv,
        const std::string& encryptedText, uint32_t crc32);
};

bool EncryptFile2(const char* ifn);
std::string DecryptFile2(const char* ifn);