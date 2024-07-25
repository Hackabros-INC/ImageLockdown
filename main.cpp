#include "crypto_utils.h"
#include "utils.h"
#include <cstdlib>
#include <iostream>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <string>

int main(int argc, char *argv[]) {
  // Template
  // if (argc != 4) {
  //   std::cerr << "Uso: " << argv[0] << " <operation> <input_path>
  //   <output_path>"
  //             << std::endl;
  //   return 1;
  // }

  // std::string operation = argv[1];
  // std::string input_path = argv[2];
  // std::string output_path = argv[3];

  // if (operation == "encrypt") {
  //   encrypt(input_path, output_path);
  // } else if (operation == "decrypt") {
  //   decrypt(input_path, output_path);
  // } else {
  //   std::cerr << "Operación no válida: " << operation << std::endl;
  //   return 1;
  // }

  // Initialize OpenSSL
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();

  // Generate RSA key pair
  EVP_PKEY *key = generate_key();
  save_key(key, "private_key.pem", "public_key.pem");

  // Encrypt the file
  encrypt("0.119 GB.TIF", "encrypted.TIF");

  // Decrypt the file
  decrypt("encrypted.TIF", "decrypted.TIF");

  // Clean up
  EVP_PKEY_free(key);
  EVP_cleanup();
  ERR_free_strings();

  return 0;
}
