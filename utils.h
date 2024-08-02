#include <openssl/err.h>  // Include for OpenSSL error handling
#include <openssl/evp.h>  // Include for OpenSSL EVP functions
#include <openssl/pem.h>  // Include for OpenSSL PEM functions
#include <openssl/rand.h> // Include for OpenSSL random number generation
#include <string>         // Include for string handling

void handleErrors();

EVP_PKEY *generate_key();
void save_key(EVP_PKEY *pkey, const std::string &priv_filename,
              const std::string &pub_filename);
EVP_PKEY *load_key(const std::string &filename, bool is_private);

bool file_exists(const std::string &filename);
void check_and_generate_keys(const std::string &private_key_path,
                             const std::string &public_key_path);
