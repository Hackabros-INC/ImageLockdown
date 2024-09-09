// The base for encrypting and decrypting the images
// was taken from the oficial documentation of OpenSSL
// https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption#Setting_it_up

#include "utils.h" // Custom utility functions
#include <cstring>
#include <fstream>        // Include for file handling
#include <iostream>       // Include for input and output stream handling
#include <openssl/err.h>  // Include for OpenSSL error handling
#include <openssl/evp.h>  // Include for OpenSSL EVP functions
#include <openssl/pem.h>  // Include for OpenSSL PEM functions
#include <openssl/rand.h> // Include for OpenSSL random number generation
#include <vector>         // Include for using the vector container

void aes_256_ctr_enc(const std::string &input_path,
                     const std::string &output_path) {
  // Generar la llave AES y el IV
  unsigned char aes_key[32], iv[16];
  if (!RAND_bytes(aes_key, sizeof(aes_key)) || !RAND_bytes(iv, sizeof(iv)))
    handleErrors();

  // Reorganizar las partes de la llave
  unsigned char reorganized_key[32];
  std::memcpy(reorganized_key, aes_key + 16,
              8); // Tercera parte a la primera posición
  std::memcpy(reorganized_key + 8, aes_key,
              8); // Primera parte a la segunda posición
  std::memcpy(reorganized_key + 16, aes_key + 24,
              8); // Cuarta parte a la tercera posición
  std::memcpy(reorganized_key + 24, aes_key + 8,
              8); // Segunda parte a la cuarta posición

  // Abrir los archivos de entrada y salida
  std::ifstream ifs(input_path, std::ios::binary);
  if (!ifs.is_open())
    handleErrors();
  std::ofstream ofs(output_path, std::ios::binary);
  if (!ofs.is_open())
    handleErrors();

  // Escribir la llave reorganizada y el IV en el archivo de salida
  ofs.write(reinterpret_cast<char *>(reorganized_key), sizeof(reorganized_key));
  ofs.write(reinterpret_cast<char *>(iv), sizeof(iv));

  // Inicializar el contexto de encriptación
  EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
  if (!cipher_ctx)
    handleErrors();
  if (EVP_EncryptInit_ex(cipher_ctx, EVP_aes_256_ctr(), NULL, aes_key, iv) <= 0)
    handleErrors();

  // Encriptar el archivo
  std::vector<unsigned char> buffer(1024);
  std::vector<unsigned char> ciphertext(
      buffer.size() + EVP_CIPHER_block_size(EVP_aes_256_ctr()));
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

  // Finalizar la encriptación
  if (EVP_EncryptFinal_ex(cipher_ctx, ciphertext.data(), &len) <= 0)
    handleErrors();
  ofs.write(reinterpret_cast<char *>(ciphertext.data()), len);
  ciphertext_len += len;

  EVP_CIPHER_CTX_free(cipher_ctx);
  ofs.close();
  ifs.close();
}

void aes_256_ctr_dec(const std::string &input_path,
                     const std::string &output_path) {
  // Abrir el archivo de entrada
  std::ifstream ifs(input_path, std::ios::binary);
  if (!ifs.is_open())
    handleErrors();

  // Leer la llave reorganizada y el IV del archivo de entrada
  unsigned char reorganized_key[32], iv[16];
  ifs.read(reinterpret_cast<char *>(reorganized_key), sizeof(reorganized_key));
  ifs.read(reinterpret_cast<char *>(iv), sizeof(iv));

  // Reorganizar las partes de la llave para obtener la original
  unsigned char aes_key[32];
  std::memcpy(aes_key, reorganized_key + 8,
              8); // Segunda parte (originalmente la primera)
  std::memcpy(aes_key + 8, reorganized_key + 24,
              8); // Cuarta parte (originalmente la segunda)
  std::memcpy(aes_key + 16, reorganized_key,
              8); // Primera parte (originalmente la tercera)
  std::memcpy(aes_key + 24, reorganized_key + 16,
              8); // Tercera parte (originalmente la cuarta)

  // Abrir el archivo de salida
  std::ofstream ofs(output_path, std::ios::binary);
  if (!ofs.is_open())
    handleErrors();

  // Inicializar el contexto de desencriptación
  EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
  if (!cipher_ctx)
    handleErrors();
  if (EVP_DecryptInit_ex(cipher_ctx, EVP_aes_256_ctr(), NULL, aes_key, iv) <= 0)
    handleErrors();

  // Desencriptar el archivo
  std::vector<unsigned char> buffer(1024);
  std::vector<unsigned char> plaintext(buffer.size());
  int len, plaintext_len = 0;

  while (ifs.good()) {
    ifs.read(reinterpret_cast<char *>(buffer.data()), buffer.size());
    std::streamsize bytes_read = ifs.gcount();
    if (bytes_read > 0) {
      if (EVP_DecryptUpdate(cipher_ctx, plaintext.data(), &len, buffer.data(),
                            bytes_read) <= 0)
        handleErrors();
      ofs.write(reinterpret_cast<char *>(plaintext.data()), len);
      plaintext_len += len;
    }
  }

  // Finalizar la desencriptación
  if (EVP_DecryptFinal_ex(cipher_ctx, plaintext.data(), &len) <= 0)
    handleErrors();
  ofs.write(reinterpret_cast<char *>(plaintext.data()), len);
  plaintext_len += len;

  EVP_CIPHER_CTX_free(cipher_ctx);
  ifs.close();
  ofs.close();
}
