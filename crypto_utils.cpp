// The base for encrypting and decrypting the images
// was taken from the oficial documentation of OpenSSL
// https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption#Setting_it_up

#include "utils.h"        // Custom utility functions
#include <fstream>        // Include for file handling
#include <iostream>       // Include for input and output stream handling
#include <openssl/err.h>  // Include for OpenSSL error handling
#include <openssl/evp.h>  // Include for OpenSSL EVP functions
#include <openssl/pem.h>  // Include for OpenSSL PEM functions
#include <openssl/rand.h> // Include for OpenSSL random number generation
#include <vector>         // Include for using the vector container

// Function to encrypt a file using AES-256-CTR
void aes_256_ctr_enc(const std::string &input_path,
                     const std::string &output_path) {

  // Generate AES key and IV (initialization vector)
  unsigned char aes_key[32],
      iv[16]; // AES-256 requires a 32-byte key and 16-byte IV
  if (!RAND_bytes(aes_key, sizeof(aes_key)) || !RAND_bytes(iv, sizeof(iv)))
    handleErrors();

  // Print the AES key
  std::cout << "AES Key (Hex): ";
  for (int i = 0; i < 32; ++i)
    std::cout << std::hex << (int)aes_key[i] << " ";
  std::cout << std::dec << std::endl;

  // Print the IV
  std::cout << "Generated IV (Hex): ";
  for (int i = 0; i < 16; ++i)
    std::cout << std::hex << (int)iv[i] << " ";
  std::cout << std::dec << std::endl;

  // Open the input file in binary mode
  std::ifstream ifs(input_path, std::ios::binary);
  if (!ifs.is_open())
    handleErrors();

  // Open the output file in binary mode
  std::ofstream ofs(output_path, std::ios::binary);
  if (!ofs.is_open())
    handleErrors();

  // Write the IV to the output file
  ofs.write(reinterpret_cast<const char *>(iv), sizeof(iv));

  // Initialize the AES-256-CTR encryption context
  EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
  if (!cipher_ctx)
    handleErrors();

  if (EVP_EncryptInit_ex(cipher_ctx, EVP_aes_256_ctr(), NULL, aes_key, iv) <= 0)
    handleErrors();

  // Buffer size is now 1/4 of the key size
  const size_t buffer_size = sizeof(aes_key) / 4; // 1/4 of the key size
  std::vector<unsigned char> buffer(buffer_size);
  std::vector<unsigned char> ciphertext(
      buffer_size + EVP_CIPHER_block_size(EVP_aes_256_ctr()));
  int len, ciphertext_len = 0;

  size_t iteration = 0;

  while (ifs.good()) {
    ifs.read(reinterpret_cast<char *>(buffer.data()), buffer.size());
    std::streamsize bytes_read = ifs.gcount();

    if (bytes_read > 0) {
      if (EVP_EncryptUpdate(cipher_ctx, ciphertext.data(), &len, buffer.data(),
                            bytes_read) <= 0)
        handleErrors();
      ofs.write(reinterpret_cast<char *>(ciphertext.data()), len);
      ciphertext_len += len;
    }

    iteration++;
    if (iteration == 4) {
      ofs.seekp(1024);
      ofs.write(reinterpret_cast<char *>(aes_key), 8);
    }
    if (iteration == 7) {
      ofs.seekp(2048);
      ofs.write(reinterpret_cast<char *>(aes_key + 8), 8);
    }
    if (iteration == 9) {
      ofs.seekp(4096);
      ofs.write(reinterpret_cast<char *>(aes_key + 16), 8);
    }
    if (iteration == 13) {
      ofs.seekp(8192);
      ofs.write(reinterpret_cast<char *>(aes_key + 24), 8);
    }
  }

  // Finalize the encryption
  if (EVP_EncryptFinal_ex(cipher_ctx, ciphertext.data(), &len) <= 0)
    handleErrors();
  ofs.write(reinterpret_cast<char *>(ciphertext.data()), len);
  ciphertext_len += len;

  EVP_CIPHER_CTX_free(cipher_ctx);

  // Close the files
  ofs.close();
  ifs.close();
}

// Function to decrypt a file using AES-256-CTR
void aes_256_ctr_dec(const std::string &input_path,
                     const std::string &output_path) {

  // Open the input file in binary mode
  std::ifstream ifs(input_path, std::ios::binary);
  if (!ifs.is_open())
    handleErrors();

  // Read the IV from the input file (first 16 bytes)
  unsigned char aes_key[32], iv[16];
  ifs.read(reinterpret_cast<char *>(iv), sizeof(iv));

  // Print the recovered IV
  std::cout << "Recovered IV (Hex): ";
  for (int i = 0; i < 16; ++i)
    std::cout << std::hex << (int)iv[i] << " ";
  std::cout << std::dec << std::endl;

  // Recover the AES key parts from specific positions in the file
  ifs.seekg(1024); // Position for the first part of the key
  ifs.read(reinterpret_cast<char *>(aes_key), 8);

  ifs.seekg(2048); // Position for the second part of the key
  ifs.read(reinterpret_cast<char *>(aes_key + 8), 8);

  ifs.seekg(4096); // Position for the third part of the key
  ifs.read(reinterpret_cast<char *>(aes_key + 16), 8);

  ifs.seekg(8192); // Position for the fourth part of the key
  ifs.read(reinterpret_cast<char *>(aes_key + 24), 8);

  // Print the recovered AES key
  std::cout << "Recovered AES Key (Hex): ";
  for (int i = 0; i < 32; ++i)
    std::cout << std::hex << (int)aes_key[i] << " ";
  std::cout << std::dec << std::endl;

  // Open the output file in binary mode
  std::ofstream ofs(output_path, std::ios::binary);
  if (!ofs.is_open())
    handleErrors();

  // Initialize the AES-256-CTR decryption context
  EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
  if (!cipher_ctx)
    handleErrors();

  if (EVP_DecryptInit_ex(cipher_ctx, EVP_aes_256_ctr(), NULL, aes_key, iv) <= 0)
    handleErrors();

  // Buffer size and loop through the file, skipping key parts
  const size_t buffer_size = 4096;
  std::vector<unsigned char> buffer(buffer_size);
  std::vector<unsigned char> plaintext(buffer_size);
  int len, plaintext_len = 0;

  std::streampos current_pos = ifs.tellg();
  while (ifs.good()) {
    if (current_pos >= 1024 && current_pos < 1024 + 8) {
      // Skip the first part of the key
      ifs.seekg(1024 + 8);
      current_pos = ifs.tellg();
    } else if (current_pos >= 2048 && current_pos < 2048 + 8) {
      // Skip the second part of the key
      ifs.seekg(2048 + 8);
      current_pos = ifs.tellg();
    } else if (current_pos >= 4096 && current_pos < 4096 + 8) {
      // Skip the third part of the key
      ifs.seekg(4096 + 8);
      current_pos = ifs.tellg();
    } else if (current_pos >= 8192 && current_pos < 8192 + 8) {
      // Skip the fourth part of the key
      ifs.seekg(8192 + 8);
      current_pos = ifs.tellg();
    }

    ifs.read(reinterpret_cast<char *>(buffer.data()), buffer.size());
    std::streamsize bytes_read = ifs.gcount();

    if (bytes_read > 0) {
      if (EVP_DecryptUpdate(cipher_ctx, plaintext.data(), &len, buffer.data(),
                            bytes_read) <= 0)
        handleErrors();
      ofs.write(reinterpret_cast<char *>(plaintext.data()), len);
      plaintext_len += len;
    }

    current_pos = ifs.tellg();
  }

  // Finalize the decryption
  if (EVP_DecryptFinal_ex(cipher_ctx, plaintext.data(), &len) <= 0)
    handleErrors();
  ofs.write(reinterpret_cast<char *>(plaintext.data()), len);
  plaintext_len += len;

  EVP_CIPHER_CTX_free(cipher_ctx);

  // Close the files
  ifs.close();
  ofs.close();
}
