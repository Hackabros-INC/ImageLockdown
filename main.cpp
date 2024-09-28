#include "crypto_utils.h"
#include <cstdlib>
#include <iostream>
#include <string>

void encrypt(const std::string &mode, const std::string &input_path,
             const std::string &output_path);
void decrypt(const std::string &mode, const std::string &input_path,
             const std::string &output_path);

int main(int argc, char *argv[]) {
  if (argc != 5) {
    std::cerr << "Uso: " << argv[0] << " <operation> <input_path> <output_path>"
              << std::endl;
    return 1;
  }

  std::string mode = argv[1];
  std::string operation = argv[2];
  std::string input_path = argv[3];
  std::string output_path = argv[4];

  if (operation == "encrypt") {
    encrypt(mode, input_path, output_path);
  } else if (operation == "decrypt") {
    decrypt(mode, input_path, output_path);
  } else {
    std::cerr << "Operación no válida: " << operation << std::endl;
    return 1;
  }

  return 0;
}

void encrypt(const std::string &mode, const std::string &input_path,
             const std::string &output_path) {
  std::cout << "input_path=" << input_path << std::endl;
  std::cout << "output_path=" << output_path << std::endl;

  if (mode == "0") {
    aes_256_ctr_enc(input_path, output_path);
  } else if (mode == "1") {
    aes_256_gcm_enc(input_path, output_path);
  }

  std::cout << "Encrypted image" << std::endl;
}

void decrypt(const std::string &mode, const std::string &input_path,
             const std::string &output_path) {
  std::cout << "input_path=" << input_path << std::endl;
  std::cout << "output_path=" << output_path << std::endl;

  if (mode == "0") {
    aes_256_ctr_dec(input_path, output_path);
  } else if (mode == "1") {
    aes_256_gcm_dec(input_path, output_path);
  }

  std::cout << "Decrypted image" << std::endl;
}
