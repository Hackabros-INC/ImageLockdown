#include "utils.h"
#include <fstream>
#include <iostream>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <vector>

void encrypt(const std::string &input_path, const std::string &output_path) {
  std::cout << "input_path=" << input_path << std::endl;
  std::cout << "output_path=" << output_path << std::endl;

  // Generate AES key and IV
  unsigned char aes_key[32], iv[12];
  if (!RAND_bytes(aes_key, sizeof(aes_key)) || !RAND_bytes(iv, sizeof(iv)))
    handleErrors();

  // Load public key
  EVP_PKEY *public_key = load_key("public_key.pem", false);

  // Encrypt AES key with RSA public key
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

  // Read input file in chunks
  std::ifstream ifs(input_path, std::ios::binary);
  if (!ifs.is_open())
    handleErrors();

  // Open output file
  std::ofstream ofs(output_path, std::ios::binary);
  if (!ofs.is_open())
    handleErrors();

  // Write the encrypted key and IV to the output file
  ofs.write((char *)encrypted_key.data(), encrypted_key.size());
  ofs.write((char *)iv, sizeof(iv));

  // Encrypt data with AES-256-GCM
  EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
  if (!cipher_ctx)
    handleErrors();

  if (EVP_EncryptInit_ex(cipher_ctx, EVP_aes_256_gcm(), NULL, aes_key, iv) <= 0)
    handleErrors();

  const size_t buffer_size = 1024 * 1024; // 1 MB buffer
  std::vector<unsigned char> buffer(buffer_size);
  std::vector<unsigned char> ciphertext(buffer_size +
                                        16); // Add space for GCM tag
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

  if (EVP_EncryptFinal_ex(cipher_ctx, ciphertext.data(), &len) <= 0)
    handleErrors();
  ofs.write(reinterpret_cast<char *>(ciphertext.data()), len);
  ciphertext_len += len;

  // Get the GCM tag
  std::vector<unsigned char> tag(16);
  if (EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) <=
      0)
    handleErrors();

  EVP_CIPHER_CTX_free(cipher_ctx);

  // Write the tag to the output file
  ofs.write(reinterpret_cast<char *>(tag.data()), tag.size());
  ofs.close();
  ifs.close();

  std::cout << "Encrypted image" << std::endl;
}

void decrypt(const std::string &input_path, const std::string &output_path) {
  std::cout << "input_path=" << input_path << std::endl;
  std::cout << "output_path=" << output_path << std::endl;

  // Read input file
  std::ifstream ifs(input_path, std::ios::binary);
  std::vector<unsigned char> encrypted_key(256); // RSA 2048 bit key size
  std::vector<unsigned char> iv(12);
  std::vector<unsigned char> tag(16);

  ifs.read((char *)encrypted_key.data(), encrypted_key.size());
  ifs.read((char *)iv.data(), iv.size());

  ifs.seekg(0, std::ios::end);
  std::streampos end = ifs.tellg();
  std::streamoff data_len = end -
                            static_cast<std::streamoff>(encrypted_key.size()) -
                            static_cast<std::streamoff>(iv.size()) -
                            static_cast<std::streamoff>(tag.size());

  ifs.seekg(encrypted_key.size() + iv.size(), std::ios::beg);
  std::vector<unsigned char> ciphertext(data_len);
  ifs.read((char *)ciphertext.data(), ciphertext.size());
  ifs.read((char *)tag.data(), tag.size());
  ifs.close();

  // Load private key
  EVP_PKEY *private_key = load_key("private_key.pem", true);

  // Decrypt AES key with RSA private key
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

  // Decrypt data with AES-256-GCM
  EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
  if (!cipher_ctx)
    handleErrors();

  if (EVP_DecryptInit_ex(cipher_ctx, EVP_aes_256_gcm(), NULL, aes_key.data(),
                         iv.data()) <= 0)
    handleErrors();

  std::vector<unsigned char> plaintext(ciphertext.size());
  int len;

  if (EVP_DecryptUpdate(cipher_ctx, plaintext.data(), &len, ciphertext.data(),
                        ciphertext.size()) <= 0)
    handleErrors();

  int plaintext_len = len;

  if (EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data()) <=
      0)
    handleErrors();

  if (EVP_DecryptFinal_ex(cipher_ctx, plaintext.data() + len, &len) <= 0)
    handleErrors();

  plaintext_len += len;
  EVP_CIPHER_CTX_free(cipher_ctx);

  // Write to output file
  std::ofstream ofs(output_path, std::ios::binary);
  ofs.write((char *)plaintext.data(), plaintext_len);
  ofs.close();

  std::cout << "Decrypted image" << std::endl;
}
