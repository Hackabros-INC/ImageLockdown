#include "utils.h" // Custom utility functions
#include <cstring>
#include <fstream>        // Include for file handling
#include <iostream>       // Include for input and output stream handling
#include <openssl/err.h>  // Include for OpenSSL error handling
#include <openssl/evp.h>  // Include for OpenSSL EVP functions
#include <openssl/pem.h>  // Include for OpenSSL PEM functions
#include <openssl/rand.h> // Include for OpenSSL random number generation
#include <vector>         // Include for using the vector container

// Function to encrypt a file using AES-256 in CTR mode
void aes_256_ctr_enc(const std::string &input_path,
                     const std::string &output_path) {
  // Generate AES key and initialization vector (IV)
  unsigned char aes_key[32], iv[16];
  if (!RAND_bytes(aes_key, sizeof(aes_key)) || !RAND_bytes(iv, sizeof(iv)))
    handleErrors(); // Generate random key and IV, handle errors if failed

  // Reorganize parts of the key for custom encryption logic
  unsigned char reorganized_key[32];
  std::memcpy(reorganized_key, aes_key + 16,
              8); // Move third part to the first position
  std::memcpy(reorganized_key + 8, aes_key,
              8); // Move first part to the second position
  std::memcpy(reorganized_key + 16, aes_key + 24,
              8); // Move fourth part to the third position
  std::memcpy(reorganized_key + 24, aes_key + 8,
              8); // Move second part to the fourth position

  // Open input file to read, handle errors if file can't be opened
  std::ifstream ifs(input_path, std::ios::binary);
  if (!ifs.is_open())
    handleErrors();

  // Open output file to write, handle errors if file can't be opened
  std::ofstream ofs(output_path, std::ios::binary);
  if (!ofs.is_open())
    handleErrors();

  // Write reorganized key and IV to output file
  ofs.write(reinterpret_cast<char *>(reorganized_key), sizeof(reorganized_key));
  ofs.write(reinterpret_cast<char *>(iv), sizeof(iv));

  // Initialize encryption context
  EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
  if (!cipher_ctx)
    handleErrors();

  // Set up the encryption operation with AES-256 in CTR mode
  if (EVP_EncryptInit_ex(cipher_ctx, EVP_aes_256_ctr(), NULL, aes_key, iv) <= 0)
    handleErrors();

  // Encrypt the input file in chunks
  std::vector<unsigned char> buffer(1024); // Buffer for reading input
  std::vector<unsigned char> ciphertext(
      buffer.size() +
      EVP_CIPHER_block_size(EVP_aes_256_ctr())); // Buffer for encrypted data
  int len, ciphertext_len = 0;

  // Read input file, encrypt, and write to output file in chunks
  while (ifs.good()) {
    ifs.read(reinterpret_cast<char *>(buffer.data()), buffer.size());
    std::streamsize bytes_read = ifs.gcount();
    if (bytes_read > 0) {
      if (EVP_EncryptUpdate(cipher_ctx, ciphertext.data(), &len, buffer.data(),
                            bytes_read) <= 0)
        handleErrors();
      ofs.write(reinterpret_cast<char *>(ciphertext.data()),
                len); // Write encrypted data
      ciphertext_len += len;
    }
  }

  // Finalize the encryption process
  if (EVP_EncryptFinal_ex(cipher_ctx, ciphertext.data(), &len) <= 0)
    handleErrors();
  ofs.write(reinterpret_cast<char *>(ciphertext.data()),
            len); // Write any remaining encrypted data
  ciphertext_len += len;

  // Clean up and close the files and context
  EVP_CIPHER_CTX_free(cipher_ctx);
  ofs.close();
  ifs.close();
}

// Function to decrypt a file encrypted with AES-256 in CTR mode
void aes_256_ctr_dec(const std::string &input_path,
                     const std::string &output_path) {
  // Open input file to read the encrypted data
  std::ifstream ifs(input_path, std::ios::binary);
  if (!ifs.is_open())
    handleErrors();

  // Read reorganized key and IV from the encrypted file
  unsigned char reorganized_key[32], iv[16];
  ifs.read(reinterpret_cast<char *>(reorganized_key), sizeof(reorganized_key));
  ifs.read(reinterpret_cast<char *>(iv), sizeof(iv));

  // Reorganize key parts back to their original positions
  unsigned char aes_key[32];
  std::memcpy(aes_key, reorganized_key + 8,
              8); // Restore second part (originally the first)
  std::memcpy(aes_key + 8, reorganized_key + 24,
              8); // Restore fourth part (originally the second)
  std::memcpy(aes_key + 16, reorganized_key,
              8); // Restore first part (originally the third)
  std::memcpy(aes_key + 24, reorganized_key + 16,
              8); // Restore third part (originally the fourth)

  // Open output file to write decrypted data
  std::ofstream ofs(output_path, std::ios::binary);
  if (!ofs.is_open())
    handleErrors();

  // Initialize decryption context
  EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
  if (!cipher_ctx)
    handleErrors();

  // Set up decryption with AES-256 in CTR mode
  if (EVP_DecryptInit_ex(cipher_ctx, EVP_aes_256_ctr(), NULL, aes_key, iv) <= 0)
    handleErrors();

  // Decrypt the file in chunks
  std::vector<unsigned char> buffer(1024); // Buffer for encrypted data
  std::vector<unsigned char> plaintext(
      buffer.size()); // Buffer for decrypted data
  int len, plaintext_len = 0;

  // Read encrypted file, decrypt, and write plaintext to output file in chunks
  while (ifs.good()) {
    ifs.read(reinterpret_cast<char *>(buffer.data()), buffer.size());
    std::streamsize bytes_read = ifs.gcount();
    if (bytes_read > 0) {
      if (EVP_DecryptUpdate(cipher_ctx, plaintext.data(), &len, buffer.data(),
                            bytes_read) <= 0)
        handleErrors();
      ofs.write(reinterpret_cast<char *>(plaintext.data()),
                len); // Write decrypted data
      plaintext_len += len;
    }
  }

  // Finalize the decryption process
  if (EVP_DecryptFinal_ex(cipher_ctx, plaintext.data(), &len) <= 0)
    handleErrors();
  ofs.write(reinterpret_cast<char *>(plaintext.data()),
            len); // Write remaining decrypted data
  plaintext_len += len;

  // Clean up and close the files and context
  EVP_CIPHER_CTX_free(cipher_ctx);
  ifs.close();
  ofs.close();
}
