#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <string>

void handleErrors();

EVP_PKEY *generate_key();
void save_key(EVP_PKEY *pkey, const std::string &priv_filename,
              const std::string &pub_filename);
EVP_PKEY *load_key(const std::string &filename, bool is_private);

bool file_exists(const std::string &filename);
void check_and_generate_keys(const std::string &private_key_path,
                             const std::string &public_key_path);
