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

  // Ensure RSA keys are available, generating them if necessary
  check_and_generate_keys("private_key.pem", "public_key.pem");

  // Generate AES key and IV (initialization vector)
  unsigned char aes_key[32],
      iv[16]; // AES-256 requires a 32-byte key and 16-byte IV
  if (!RAND_bytes(aes_key, sizeof(aes_key)) || !RAND_bytes(iv, sizeof(iv)))
    handleErrors();

  // Load the public RSA key
  EVP_PKEY *public_key = load_key("public_key.pem", false);

  // Encrypt the AES key using the RSA public key
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(public_key, NULL);
  if (!ctx)
    handleErrors();

  EVP_PKEY_free(public_key);

  if (EVP_PKEY_encrypt_init(ctx) <= 0)
    handleErrors();

  size_t outlen;
  if (EVP_PKEY_encrypt(ctx, NULL, &outlen, aes_key, sizeof(aes_key)) <= 0)
    handleErrors();

  std::vector<unsigned char> encrypted_key(outlen);
  if (EVP_PKEY_encrypt(ctx, encrypted_key.data(), &outlen, aes_key,
                       sizeof(aes_key)) <= 0)
    handleErrors();

  encrypted_key.resize(outlen);
  EVP_PKEY_CTX_free(ctx);

  // Open the input file in binary mode
  std::ifstream ifs(input_path, std::ios::binary);
  if (!ifs.is_open())
    handleErrors();

  // Open the output file in binary mode
  std::ofstream ofs(output_path, std::ios::binary);
  if (!ofs.is_open())
    handleErrors();

  // Write the encrypted AES key, its length, and the IV to the output file
  size_t encrypted_key_len = encrypted_key.size();
  ofs.write(reinterpret_cast<char *>(&encrypted_key_len),
            sizeof(encrypted_key_len));
  ofs.write(reinterpret_cast<char *>(encrypted_key.data()),
            encrypted_key.size());
  ofs.write(reinterpret_cast<char *>(iv), sizeof(iv));

  // Initialize the AES-256-CTR encryption context
  EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
  if (!cipher_ctx)
    handleErrors();

  if (EVP_EncryptInit_ex(cipher_ctx, EVP_aes_256_ctr(), NULL, aes_key, iv) <= 0)
    handleErrors();

  // Buffer for reading the file in chunks
  const size_t buffer_size = 1024 * 1024; // 1 MB buffer
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

  // Ensure RSA keys are available, generating them if necessary
  check_and_generate_keys("private_key.pem", "public_key.pem");

  // Open the input file in binary mode
  std::ifstream ifs(input_path, std::ios::binary);
  if (!ifs.is_open())
    handleErrors();

  // Read the length of the encrypted AES key
  size_t encrypted_key_len;
  ifs.read(reinterpret_cast<char *>(&encrypted_key_len),
           sizeof(encrypted_key_len));
  if (!ifs.good())
    handleErrors();

  // Read the encrypted AES key and IV
  std::vector<unsigned char> encrypted_key(encrypted_key_len);
  std::vector<unsigned char> iv(16);

  ifs.read(reinterpret_cast<char *>(encrypted_key.data()),
           encrypted_key.size());
  if (ifs.gcount() != static_cast<std::streamsize>(encrypted_key.size()))
    handleErrors();

  ifs.read(reinterpret_cast<char *>(iv.data()), iv.size());
  if (ifs.gcount() != static_cast<std::streamsize>(iv.size()))
    handleErrors();

  // Calculate the size of the encrypted data
  ifs.seekg(0, std::ios::end);
  std::streampos end = ifs.tellg();
  std::streamoff data_len =
      end - static_cast<std::streamoff>(sizeof(encrypted_key_len)) -
      static_cast<std::streamoff>(encrypted_key.size()) -
      static_cast<std::streamoff>(iv.size());

  // Return to the start of the encrypted data
  ifs.seekg(sizeof(encrypted_key_len) + encrypted_key.size() + iv.size(),
            std::ios::beg);

  // Open the output file in binary mode
  std::ofstream ofs(output_path, std::ios::binary);
  if (!ofs.is_open())
    handleErrors();

  // Load the private RSA key
  EVP_PKEY *private_key = load_key("private_key.pem", true);
  if (!private_key)
    handleErrors();

  // Decrypt the AES key using the RSA private key
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(private_key, NULL);
  if (!ctx)
    handleErrors();

  EVP_PKEY_free(private_key);

  if (EVP_PKEY_decrypt_init(ctx) <= 0)
    handleErrors();

  size_t outlen;
  if (EVP_PKEY_decrypt(ctx, NULL, &outlen, encrypted_key.data(),
                       encrypted_key.size()) <= 0)
    handleErrors();

  std::vector<unsigned char> aes_key(outlen);
  if (EVP_PKEY_decrypt(ctx, aes_key.data(), &outlen, encrypted_key.data(),
                       encrypted_key.size()) <= 0)
    handleErrors();

  aes_key.resize(outlen);
  EVP_PKEY_CTX_free(ctx);

  // Initialize the AES-256-CTR decryption context
  EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
  if (!cipher_ctx)
    handleErrors();

  if (EVP_DecryptInit_ex(cipher_ctx, EVP_aes_256_ctr(), NULL, aes_key.data(),
                         iv.data()) <= 0)
    handleErrors();

  // Buffer for reading the file in chunks
  const size_t buffer_size = 1024 * 1024; // 1 MB buffer
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
