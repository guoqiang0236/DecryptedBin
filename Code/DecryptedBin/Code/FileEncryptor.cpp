#include "FileEncryptor.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>

#pragma comment(lib, "cryptlib.lib")

const char FileEncryptor::ENCRYPTION_HEADER[] = "<!!!ENC!!!>";

FileEncryptor::FileEncryptor()
{
}

FileEncryptor::~FileEncryptor()
{
}

uint32_t FileEncryptor::CalculateCRC32(const std::string& data)
{
    CryptoPP::CRC32 crc;
    crc.Update((const byte*)data.c_str(), data.length());

    uint32_t result;
    crc.Final((byte*)&result);
    return result;
}

bool FileEncryptor::VerifyCRC32(const std::string& data, uint32_t expectedCRC)
{
    uint32_t actualCRC = CalculateCRC32(data);
    return actualCRC == expectedCRC;
}

void FileEncryptor::Encrypt(std::string& str, const std::string& key, const byte* iv)
{
    CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption cfbEncryption(
        (byte*)key.c_str(),
        CryptoPP::AES::DEFAULT_KEYLENGTH,
        iv
    );

    cfbEncryption.ProcessData(
        (byte*)&str[0],
        (byte*)&str[0],
        str.length()
    );
}

void FileEncryptor::Decrypt(std::string& str, const std::string& key, const byte* iv)
{
    CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption cfbDecryption(
        (byte*)key.c_str(),
        CryptoPP::AES::DEFAULT_KEYLENGTH,
        iv
    );

    cfbDecryption.ProcessData(
        (byte*)&str[0],
        (byte*)&str[0],
        str.length()
    );
}

bool FileEncryptor::EncryptFile(const char* filename)
{
    if (!filename)
        return false;

    std::string key = GenerateKeyFromFilename(filename);

    byte iv[CryptoPP::AES::BLOCKSIZE];
    GenerateRandomIV(iv);

    std::ifstream ifs(filename, std::ios::binary);
    if (!ifs.is_open())
        return false;

    ifs.seekg(0, std::ios::end);
    std::streamsize fileSize = ifs.tellg();
    ifs.seekg(0, std::ios::beg);

    std::string text;
    text.resize(static_cast<size_t>(fileSize));
    ifs.read(&text[0], fileSize);
    ifs.close();

    uint32_t crc32 = CalculateCRC32(text);

    Encrypt(text, key, iv);

    return WriteEncryptedFile(filename, iv, text, crc32);
}

std::string FileEncryptor::DecryptFile(const char* filename)
{
    if (!filename)
        return "ERR";

    byte iv[CryptoPP::AES::BLOCKSIZE];
    uint32_t storedCRC = 0;
    std::string text;

    std::string key = GenerateKeyFromFilename(filename);

    FILE* ifp = nullptr;
    if (fopen_s(&ifp, filename, "rb") != 0 || !ifp)
        return "ERR";

    if (!IsEncryptedFile(ifp))
    {
        std::cout << "Not an encrypted file!" << std::endl;
        rewind(ifp);
        text = ReadFileContent(ifp);
        fclose(ifp);

        EncryptFile(filename);
        return text;
    }

    fread(iv, sizeof(byte), CryptoPP::AES::BLOCKSIZE, ifp);
    fread(&storedCRC, sizeof(uint32_t), 1, ifp);

    text = ReadFileContent(ifp);
    fclose(ifp);

    Decrypt(text, key, iv);

    if (!VerifyCRC32(text, storedCRC))
    {
        std::cout << "CRC32 verification failed! Data may be corrupted." << std::endl;
        return "ERR_CRC";
    }

    return text;
}

bool FileEncryptor::SaveCRC32ToFile(const char* crcFile, uint32_t crc32)
{
    FILE* fp = nullptr;
    if (fopen_s(&fp, crcFile, "w") != 0 || !fp)
        return false;

    fprintf(fp, "CRC32: 0x%08X\n", crc32);
    fclose(fp);
    return true;
}

uint32_t FileEncryptor::LoadCRC32FromFile(const char* crcFile)
{
    FILE* fp = nullptr;
    if (fopen_s(&fp, crcFile, "r") != 0 || !fp)
        return 0;

    uint32_t crc32 = 0;
    fscanf_s(fp, "CRC32: 0x%X", &crc32);
    fclose(fp);
    return crc32;
}

bool FileEncryptor::EncryptFileWithCRCFile(const char* binFile, const char* crcFile)
{
    if (!binFile || !crcFile)
        return false;

    std::string key = GenerateKeyFromFilename(binFile);
    byte iv[CryptoPP::AES::BLOCKSIZE];
    GenerateRandomIV(iv);

    std::ifstream ifs(binFile, std::ios::binary);
    if (!ifs.is_open())
        return false;

    ifs.seekg(0, std::ios::end);
    std::streamsize fileSize = ifs.tellg();
    ifs.seekg(0, std::ios::beg);

    std::string text;
    text.resize(static_cast<size_t>(fileSize));
    ifs.read(&text[0], fileSize);
    ifs.close();

    uint32_t crc32 = CalculateCRC32(text);

    if (!SaveCRC32ToFile(crcFile, crc32))
        return false;

    Encrypt(text, key, iv);

    return WriteEncryptedFile(binFile, iv, text, crc32);
}

std::string FileEncryptor::DecryptFileWithCRCFile(const char* binFile, const char* crcFile)
{
    if (!binFile || !crcFile)
        return "ERR";

    uint32_t expectedCRC = LoadCRC32FromFile(crcFile);
    if (expectedCRC == 0)
    {
        std::cout << "Failed to load CRC32 from file: " << crcFile << std::endl;
        return "ERR";
    }

    std::string decrypted = DecryptFile(binFile);
    if (decrypted == "ERR" || decrypted == "ERR_CRC")
        return decrypted;

    uint32_t actualCRC = CalculateCRC32(decrypted);
    if (actualCRC != expectedCRC)
    {
        std::cout << "CRC32 mismatch with external CRC file!" << std::endl;
        std::cout << "Expected: 0x" << std::hex << expectedCRC << std::endl;
        std::cout << "Actual: 0x" << actualCRC << std::dec << std::endl;
        return "ERR_CRC_FILE";
    }

    return decrypted;
}

bool FileEncryptor::EncryptFileWithCRCFile(const char* binFile, const char* crcFile, const char* outFile)
{
    if (!binFile || !crcFile || !outFile)
        return false;

    std::string key = GenerateKeyFromFilename(binFile);
    byte iv[CryptoPP::AES::BLOCKSIZE];
    GenerateRandomIV(iv);

    std::ifstream ifs(binFile, std::ios::binary);
    if (!ifs.is_open())
        return false;

    ifs.seekg(0, std::ios::end);
    std::streamsize fileSize = ifs.tellg();
    ifs.seekg(0, std::ios::beg);

    std::string text;
    text.resize(static_cast<size_t>(fileSize));
    ifs.read(&text[0], fileSize);
    ifs.close();

    uint32_t crc32 = CalculateCRC32(text);

    if (!SaveCRC32ToFile(crcFile, crc32))
        return false;

    Encrypt(text, key, iv);

    return WriteEncryptedFile(outFile, iv, text, crc32);
}

std::string FileEncryptor::DecryptFileWithCRCFile(const char* encryptedFile, const char* crcFile, const char* originalName)
{
    if (!encryptedFile || !crcFile || !originalName)
        return "ERR";

    uint32_t expectedCRC = LoadCRC32FromFile(crcFile);
    if (expectedCRC == 0)
    {
        std::cout << "Failed to load CRC32 from file: " << crcFile << std::endl;
        return "ERR";
    }

    byte iv[CryptoPP::AES::BLOCKSIZE];
    uint32_t storedCRC = 0;
    std::string text;

    std::string key = GenerateKeyFromFilename(originalName);

    FILE* ifp = nullptr;
    if (fopen_s(&ifp, encryptedFile, "rb") != 0 || !ifp)
        return "ERR";

    if (!IsEncryptedFile(ifp))
    {
        std::cout << "Not an encrypted file!" << std::endl;
        fclose(ifp);
        return "ERR";
    }

    fread(iv, sizeof(byte), CryptoPP::AES::BLOCKSIZE, ifp);
    fread(&storedCRC, sizeof(uint32_t), 1, ifp);

    text = ReadFileContent(ifp);
    fclose(ifp);

    Decrypt(text, key, iv);

    if (!VerifyCRC32(text, storedCRC))
    {
        std::cout << "CRC32 verification failed! Data may be corrupted." << std::endl;
        return "ERR_CRC";
    }

    uint32_t actualCRC = CalculateCRC32(text);
    if (actualCRC != expectedCRC)
    {
        std::cout << "CRC32 mismatch with external CRC file!" << std::endl;
        std::cout << "Expected: 0x" << std::hex << expectedCRC << std::endl;
        std::cout << "Actual: 0x" << actualCRC << std::dec << std::endl;
        return "ERR_CRC_FILE";
    }

    return text;
}
std::string FileEncryptor::GenerateKeyFromFilename(const char* filename)
{
    std::string fullPath = filename;
    size_t pos = fullPath.find_last_of("\\/");
    std::string filenameOnly = (pos != std::string::npos) ?
        fullPath.substr(pos + 1) : fullPath;

    std::ostringstream oss;
    if (filenameOnly.length() > KEY_SIZE)
        filenameOnly = filenameOnly.substr(filenameOnly.length() - KEY_SIZE, KEY_SIZE);

    oss << std::setw(KEY_SIZE) << std::setfill('0') << filenameOnly;
    return oss.str();
}

void FileEncryptor::GenerateRandomIV(byte* iv)
{
    CryptoPP::AutoSeededRandomPool rnd;
    rnd.GenerateBlock(iv, CryptoPP::AES::BLOCKSIZE);
}

bool FileEncryptor::IsEncryptedFile(FILE* fp)
{
    char header[HEADER_SIZE + 1] = { 0 };
    size_t bytesRead = fread(header, sizeof(char), HEADER_SIZE, fp);

    if (bytesRead != HEADER_SIZE)
        return false;

    header[HEADER_SIZE] = '\0';
    return strcmp(header, ENCRYPTION_HEADER) == 0;
}

std::string FileEncryptor::ReadFileContent(FILE* fp)
{
    long currentPos = ftell(fp);

    fseek(fp, 0, SEEK_END);
    long fileSize = ftell(fp);

    long dataSize = fileSize - currentPos;

    fseek(fp, currentPos, SEEK_SET);

    std::string text;
    text.resize(dataSize);
    fread(&text[0], sizeof(char), dataSize, fp);

    return text;
}

bool FileEncryptor::WriteEncryptedFile(const char* filename, const byte* iv,
    const std::string& encryptedText, uint32_t crc32)
{
    FILE* ofp = nullptr;
    if (fopen_s(&ofp, filename, "wb") != 0 || !ofp)
        return false;

    fwrite(ENCRYPTION_HEADER, sizeof(char), HEADER_SIZE, ofp);
    fwrite(iv, sizeof(byte), CryptoPP::AES::BLOCKSIZE, ofp);
    fwrite(&crc32, sizeof(uint32_t), 1, ofp);
    fwrite(encryptedText.c_str(), sizeof(char), encryptedText.length(), ofp);

    fclose(ofp);
    return true;
}

bool EncryptFile2(const char* ifn)
{
    FileEncryptor encryptor;
    return encryptor.EncryptFile(ifn);
}

std::string DecryptFile2(const char* ifn)
{
    FileEncryptor encryptor;
    return encryptor.DecryptFile(ifn);
}

std::string FileEncryptor::ReadBinaryFile(const char* filename)
{
    std::ifstream ifs(filename, std::ios::binary);
    if (!ifs.is_open())
        return "";

    ifs.seekg(0, std::ios::end);
    std::streamsize fileSize = ifs.tellg();
    ifs.seekg(0, std::ios::beg);

    std::string data;
    data.resize(static_cast<size_t>(fileSize));
    ifs.read(&data[0], fileSize);
    ifs.close();

    return data;
}

bool FileEncryptor::WriteBinaryFile(const char* filename, const std::string& data)
{
    std::ofstream ofs(filename, std::ios::binary);
    if (!ofs.is_open())
        return false;

    ofs.write(data.c_str(), data.length());
    ofs.close();
    return true;
}