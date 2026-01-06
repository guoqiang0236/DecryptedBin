#include <iostream>
#include <string>
#include <iomanip>
#include <Windows.h>
#include "FileEncryptor.h"

//int main()
//{
//
//    std::cout << "========== Firmware Encryption/Decryption Comparison Tool ==========" << std::endl << std::endl;
//
//    const char* originalFile = "ControlPanel_DL_v1.2.bin";
//    const char* encryptedFile = "ControlPanel_DL_v1.2_encrypted.bin";
//    const char* decryptedFile = "ControlPanel_DL_v1.2_decrypted.bin";
//    const char* crcFile = "ControlPanel_DL_v1.2_crc32.txt";
//
//    FileEncryptor encryptor;
//    std::string originalData;
//    std::string encryptedData;
//    std::string decryptedData;
//
//    originalData = encryptor.ReadBinaryFile(originalFile);
//    if (originalData.empty())
//    {
//        std::cout << "[Error] Failed to read original file: " << originalFile << std::endl;
//        system("pause");
//        return 1;
//    }
//
//    uint32_t originalCRC = encryptor.CalculateCRC32(originalData);
//    std::cout << "[1] Read Original Firmware ✓" << std::endl;
//    std::cout << "    File: " << originalFile << std::endl;
//    std::cout << "    Size: " << originalData.length() << " bytes" << std::endl;
//    std::cout << "    CRC32: 0x" << std::hex << std::uppercase
//        << std::setw(8) << std::setfill('0') << originalCRC << std::dec << std::endl;
//    std::cout << std::endl;
//
//    if (encryptor.EncryptFileWithCRCFile(originalFile, crcFile, encryptedFile))
//    {
//        encryptedData = encryptor.ReadBinaryFile(encryptedFile);
//
//        std::cout << "[2] Encrypt Firmware ✓" << std::endl;
//
//        uint32_t encryptedCRC = encryptor.CalculateCRC32(encryptedData);
//
//        std::cout << "    File: " << encryptedFile << std::endl;
//        std::cout << "    Size: " << encryptedData.length() << " bytes" << std::endl;
//        std::cout << "    CRC32: 0x" << std::hex << std::uppercase
//            << std::setw(8) << std::setfill('0') << encryptedCRC << std::dec << std::endl;
//
//        uint32_t savedCRC = encryptor.LoadCRC32FromFile(crcFile);
//        std::cout << "    CRC32 saved to txt: 0x" << std::hex << std::uppercase
//            << std::setw(8) << std::setfill('0') << savedCRC << std::dec << std::endl;
//    }
//    else
//    {
//        std::cout << "[2] Encryption Failed ✗" << std::endl;
//        system("pause");
//        return 1;
//    }
//    std::cout << std::endl;
//
//    decryptedData = encryptor.DecryptFileWithCRCFile(encryptedFile, crcFile, originalFile);
//    if (decryptedData != "ERR" && decryptedData != "ERR_CRC" && decryptedData != "ERR_CRC_FILE")
//    {
//        encryptor.WriteBinaryFile(decryptedFile, decryptedData);
//
//        std::cout << "[3] Decrypt Firmware ✓" << std::endl;
//
//        uint32_t decryptedCRC = encryptor.CalculateCRC32(decryptedData);
//        std::cout << "    File: " << decryptedFile << std::endl;
//        std::cout << "    Size: " << decryptedData.length() << " bytes" << std::endl;
//        std::cout << "    CRC32: 0x" << std::hex << std::uppercase
//            << std::setw(8) << std::setfill('0') << decryptedCRC << std::dec << std::endl;
//    }
//    else
//    {
//        std::cout << "[3] Decryption Failed: " << decryptedData << std::endl;
//        system("pause");
//        return 1;
//    }
//    std::cout << std::endl;
//
//    std::cout << "==================== Comparison Result ====================" << std::endl;
//    std::cout << "Original File CRC32: 0x" << std::hex << std::uppercase
//        << std::setw(8) << std::setfill('0') << originalCRC << std::dec << std::endl;
//
//    uint32_t decryptedCRC = encryptor.CalculateCRC32(decryptedData);
//    std::cout << "Decrypted File CRC32: 0x" << std::hex << std::uppercase
//        << std::setw(8) << std::setfill('0') << decryptedCRC << std::dec << std::endl;
//
//    if (originalCRC == decryptedCRC)
//    {
//        std::cout << "\n✓ Verification Passed! Original and decrypted files match perfectly" << std::endl;
//    }
//    else
//    {
//        std::cout << "\n✗ Verification Failed! Files do not match" << std::endl;
//    }
//
//    std::cout << "\nOriginal Size: " << originalData.length() << " bytes" << std::endl;
//    std::cout << "Encrypted Size: " << encryptedData.length() << " bytes (added "
//        << (encryptedData.length() - originalData.length()) << " bytes)" << std::endl;
//    std::cout << "Decrypted Size: " << decryptedData.length() << " bytes" << std::endl;
//
//    std::cout << "\nGenerated Files:" << std::endl;
//    std::cout << "  1. " << encryptedFile << " (Encrypted Firmware)" << std::endl;
//    std::cout << "  2. " << decryptedFile << " (Decrypted Firmware)" << std::endl;
//    std::cout << "  3. " << crcFile << " (CRC32 Checksum)" << std::endl;
//    std::cout << "===========================================================" << std::endl;
//
//    system("pause");
//    return 0;
//}


int main(int argc, char* argv[])
{
    std::cout << "========== Firmware Decryption Tool ==========" << std::endl << std::endl;

    const char* encryptedFile = nullptr;
    const char* crcFile = nullptr;
    const char* outputFile = nullptr;
    const char* originalName = nullptr;

    if (argc >= 3)
    {
        encryptedFile = argv[1];
        crcFile = argv[2];

        if (argc >= 4)
            outputFile = argv[3];
        else
            outputFile = "decrypted_output.bin";

        if (argc >= 5)
            originalName = argv[4];
        else
            originalName = encryptedFile;
    }
    else
    {
        std::cout << "Usage: " << argv[0] << " <encrypted_file> <CRC32_file> [output_file] [original_filename]" << std::endl;
        std::cout << std::endl;
        std::cout << "Examples:" << std::endl;
        std::cout << "  " << argv[0] << " firmware.bin firmware_crc32.txt" << std::endl;
        std::cout << "  " << argv[0] << " firmware.bin firmware_crc32.txt output.bin" << std::endl;
        std::cout << "  " << argv[0] << " firmware.bin firmware_crc32.txt output.bin original.bin" << std::endl;
        system("pause");
        return 1;
    }

    FileEncryptor encryptor;

    std::cout << "[1] Checking encrypted file..." << std::endl;
    std::string encryptedData = encryptor.ReadBinaryFile(encryptedFile);
    if (encryptedData.empty())
    {
        std::cout << "    ✗ Failed to read encrypted file: " << encryptedFile << std::endl;
        system("pause");
        return 1;
    }
    std::cout << "    ✓ Encrypted file: " << encryptedFile << std::endl;
    std::cout << "    Size: " << encryptedData.length() << " bytes" << std::endl;
    std::cout << std::endl;

    std::cout << "[2] Checking CRC32 file..." << std::endl;
    uint32_t expectedCRC = encryptor.LoadCRC32FromFile(crcFile);
    if (expectedCRC == 0)
    {
        std::cout << "    ✗ Failed to read CRC32 file: " << crcFile << std::endl;
        system("pause");
        return 1;
    }
    std::cout << "    ✓ CRC32 file: " << crcFile << std::endl;
    std::cout << "    Expected CRC32: 0x" << std::hex << std::uppercase
        << std::setw(8) << std::setfill('0') << expectedCRC << std::dec << std::endl;
    std::cout << std::endl;

    std::cout << "[3] Starting decryption..." << std::endl;
    std::string decryptedData = encryptor.DecryptFileWithCRCFile(encryptedFile, crcFile, originalName);

    if (decryptedData == "ERR" || decryptedData == "ERR_CRC" || decryptedData == "ERR_CRC_FILE")
    {
        std::cout << "    ✗ Decryption failed: " << decryptedData << std::endl;
        system("pause");
        return 1;
    }

    if (!encryptor.WriteBinaryFile(outputFile, decryptedData))
    {
        std::cout << "    ✗ Failed to write decrypted file" << std::endl;
        system("pause");
        return 1;
    }

    uint32_t actualCRC = encryptor.CalculateCRC32(decryptedData);
    std::cout << "    ✓ Decryption successful" << std::endl;
    std::cout << "    Output file: " << outputFile << std::endl;
    std::cout << "    Size: " << decryptedData.length() << " bytes" << std::endl;
    std::cout << "    Actual CRC32: 0x" << std::hex << std::uppercase
        << std::setw(8) << std::setfill('0') << actualCRC << std::dec << std::endl;
    std::cout << std::endl;

    //std::cout << "==================== Verification Result ====================" << std::endl;
    if (expectedCRC == actualCRC)
    {
        std::cout << "CRC32 verification passed" << std::endl;
        //std::cout << "Firmware integrity verified successfully" << std::endl;
        //std::cout << "Safe to update firmware" << std::endl;
    }
    else
    {
        std::cout << "CRC32 verification failed" << std::endl;
        //std::cout << "Firmware may be corrupted" << std::endl;
        //std::cout << "Do not update firmware" << std::endl;
    }
    //std::cout << "=============================================================" << std::endl;

    return 0;
}