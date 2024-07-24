#include <fstream>
#include <iostream>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <vector>

void handleErrors() {
  ERR_print_errors_fp(stderr);
  abort();
}

void encrypt(const std::string &input_path, const std::string &output_path,
             EVP_PKEY *public_key) {
  // Generate AES key and IV
  unsigned char aes_key[32], iv[12];
  if (!RAND_bytes(aes_key, sizeof(aes_key)) || !RAND_bytes(iv, sizeof(iv)))
    handleErrors();

  // Encrypt AES key with RSA public key
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(public_key, NULL);
  if (!ctx)
    handleErrors();

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

  // Read input file
  std::ifstream ifs(input_path, std::ios::binary);
  std::vector<unsigned char> input_data((std::istreambuf_iterator<char>(ifs)),
                                        std::istreambuf_iterator<char>());
  ifs.close();

  // Encrypt data with AES-256-GCM
  EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
  if (!cipher_ctx)
    handleErrors();

  if (EVP_EncryptInit_ex(cipher_ctx, EVP_aes_256_gcm(), NULL, aes_key, iv) <= 0)
    handleErrors();

  std::vector<unsigned char> ciphertext(input_data.size() +
                                        16); // Add space for GCM tag
  int len;

  if (EVP_EncryptUpdate(cipher_ctx, ciphertext.data(), &len, input_data.data(),
                        input_data.size()) <= 0)
    handleErrors();

  int ciphertext_len = len;

  if (EVP_EncryptFinal_ex(cipher_ctx, ciphertext.data() + len, &len) <= 0)
    handleErrors();

  ciphertext_len += len;

  // Get the GCM tag
  std::vector<unsigned char> tag(16);
  if (EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) <=
      0)
    handleErrors();

  EVP_CIPHER_CTX_free(cipher_ctx);

  // Write to output file
  std::ofstream ofs(output_path, std::ios::binary);
  ofs.write((char *)encrypted_key.data(), encrypted_key.size());
  ofs.write((char *)iv, sizeof(iv));
  ofs.write((char *)ciphertext.data(), ciphertext_len);
  ofs.write((char *)tag.data(), tag.size());
  ofs.close();
}
