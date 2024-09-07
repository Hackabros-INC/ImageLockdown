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

  // Open the input file in binary mode
  std::ifstream ifs(input_path, std::ios::binary);
  if (!ifs.is_open())
    handleErrors();

  // Open the output file in binary mode
  std::ofstream ofs(output_path, std::ios::binary);
  if (!ofs.is_open())
    handleErrors();

  // Write the AES key and IV to the output file
  ofs.write(reinterpret_cast<char *>(aes_key), sizeof(aes_key));
  ofs.write(reinterpret_cast<char *>(iv), sizeof(iv));

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

  // Read the AES key and IV from the input file
  unsigned char aes_key[32], iv[16];
  ifs.read(reinterpret_cast<char *>(aes_key), sizeof(aes_key));
  ifs.read(reinterpret_cast<char *>(iv), sizeof(iv));

  if (!ifs.good())
    handleErrors();

  // Calculate the size of the encrypted data
  ifs.seekg(0, std::ios::end);
  std::streampos end = ifs.tellg();
  std::streamoff data_len = end - static_cast<std::streamoff>(sizeof(aes_key)) -
                            static_cast<std::streamoff>(sizeof(iv));

  // Return to the start of the encrypted data
  ifs.seekg(sizeof(aes_key) + sizeof(iv), std::ios::beg);

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

  // Buffer size is now 1/4 of the key size
  const size_t buffer_size = sizeof(aes_key) / 4; // 1/4 of the key size
  std::vector<unsigned char> buffer(buffer_size);
  std::vector<unsigned char> plaintext(buffer_size);
  int len, plaintext_len = 0;

  while (data_len > 0) {
    size_t chunk_size = std::min(buffer_size, static_cast<size_t>(data_len));
    ifs.read(reinterpret_cast<char *>(buffer.data()), chunk_size);
    std::streamsize bytes_read = ifs.gcount();
    data_len -= bytes_read;

    if (bytes_read > 0) {
      if (EVP_DecryptUpdate(cipher_ctx, plaintext.data(), &len, buffer.data(),
                            bytes_read) <= 0)
        handleErrors();
      ofs.write(reinterpret_cast<char *>(plaintext.data()), len);
      plaintext_len += len;
    }
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
