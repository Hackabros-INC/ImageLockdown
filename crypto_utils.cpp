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

void aes_256_gcm_enc(const std::string &input_path,
                     const std::string &output_path) {
  // Generar clave AES y IV
  unsigned char aes_key[32], iv[12];
  if (!RAND_bytes(aes_key, sizeof(aes_key)) || !RAND_bytes(iv, sizeof(iv)))
    handleErrors();

  // Leer archivo de entrada en fragmentos
  std::ifstream ifs(input_path, std::ios::binary);
  if (!ifs.is_open())
    handleErrors();

  // Abrir archivo de salida
  std::ofstream ofs(output_path, std::ios::binary);
  if (!ofs.is_open())
    handleErrors();

  // Escribir IV y clave AES en el archivo de salida
  ofs.write((char *)iv, sizeof(iv));
  ofs.write((char *)aes_key, sizeof(aes_key));

  // Encriptar datos con AES-256-GCM
  EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
  if (!cipher_ctx)
    handleErrors();

  if (EVP_EncryptInit_ex(cipher_ctx, EVP_aes_256_gcm(), NULL, aes_key, iv) <= 0)
    handleErrors();

  const size_t buffer_size = 1024 * 1024; // Búfer de 1 MB
  std::vector<unsigned char> buffer(buffer_size);
  std::vector<unsigned char> ciphertext(
      buffer_size + 16); // Espacio adicional para el tag GCM
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

  // Obtener y escribir el tag GCM
  std::vector<unsigned char> tag(16);
  if (EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) <=
      0)
    handleErrors();

  EVP_CIPHER_CTX_free(cipher_ctx);

  ofs.write(reinterpret_cast<char *>(tag.data()), tag.size());
  ofs.close();
  ifs.close();
}

void aes_256_gcm_dec(const std::string &input_path,
                     const std::string &output_path) {
  // Abrir archivo de entrada en modo binario
  std::ifstream ifs(input_path, std::ios::binary);
  if (!ifs.is_open())
    handleErrors();

  // Leer IV y clave AES desde el archivo
  std::vector<unsigned char> iv(12);
  unsigned char aes_key[32];

  ifs.read((char *)iv.data(), iv.size());
  if (ifs.gcount() != static_cast<std::streamsize>(iv.size()))
    handleErrors();

  ifs.read((char *)aes_key, sizeof(aes_key));
  if (ifs.gcount() != static_cast<std::streamsize>(sizeof(aes_key)))
    handleErrors();

  // Calcular el tamaño de los datos encriptados
  ifs.seekg(0, std::ios::end);
  std::streampos end = ifs.tellg();
  std::streamoff data_len = end - static_cast<std::streamoff>(iv.size()) -
                            static_cast<std::streamoff>(sizeof(aes_key)) - 16;

  // Leer el tag GCM al final del archivo
  std::vector<unsigned char> tag(16);
  ifs.seekg(-16, std::ios::end);
  ifs.read((char *)tag.data(), tag.size());
  if (ifs.gcount() != static_cast<std::streamsize>(tag.size()))
    handleErrors();

  // Volver al inicio de los datos encriptados
  ifs.seekg(iv.size() + sizeof(aes_key), std::ios::beg);

  // Abrir archivo de salida en modo binario
  std::ofstream ofs(output_path, std::ios::binary);
  if (!ofs.is_open())
    handleErrors();

  // Desencriptar datos con AES-256-GCM
  EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
  if (!cipher_ctx)
    handleErrors();

  if (EVP_DecryptInit_ex(cipher_ctx, EVP_aes_256_gcm(), NULL, aes_key,
                         iv.data()) <= 0)
    handleErrors();

  if (EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_TAG, tag.size(),
                          tag.data()) <= 0)
    handleErrors();

  const size_t buffer_size = 1024 * 1024; // Tamaño del búfer de 1 MB
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

  if (EVP_DecryptFinal_ex(cipher_ctx, plaintext.data(), &len) <= 0)
    handleErrors();
  ofs.write(reinterpret_cast<char *>(plaintext.data()), len);
  plaintext_len += len;

  EVP_CIPHER_CTX_free(cipher_ctx);
  ifs.close();
  ofs.close();
}
