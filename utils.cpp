#include <fstream>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <string>

void handleErrors() {
  ERR_print_errors_fp(stderr);
  abort();
}

EVP_PKEY *generate_key() {
  EVP_PKEY_CTX *ctx;
  EVP_PKEY *pkey = NULL;

  ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
  if (!ctx)
    handleErrors();

  if (EVP_PKEY_keygen_init(ctx) <= 0)
    handleErrors();

  if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0)
    handleErrors();

  if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
    handleErrors();

  EVP_PKEY_CTX_free(ctx);

  return pkey;
}

void save_key(EVP_PKEY *pkey, const std::string &priv_filename,
              const std::string &pub_filename) {
  FILE *priv_key_file = fopen(priv_filename.c_str(), "wb");
  PEM_write_PrivateKey(priv_key_file, pkey, NULL, NULL, 0, NULL, NULL);
  fclose(priv_key_file);

  FILE *pub_key_file = fopen(pub_filename.c_str(), "wb");
  PEM_write_PUBKEY(pub_key_file, pkey);
  fclose(pub_key_file);
}

EVP_PKEY *load_key(const std::string &filename, bool is_private) {
  FILE *key_file = fopen(filename.c_str(), "rb");
  EVP_PKEY *pkey = NULL;

  if (is_private)
    pkey = PEM_read_PrivateKey(key_file, NULL, NULL, NULL);
  else
    pkey = PEM_read_PUBKEY(key_file, NULL, NULL, NULL);

  fclose(key_file);
  return pkey;
}

bool file_exists(const std::string &filename) {
  std::ifstream file(filename);
  return file.good();
}

void check_and_generate_keys(const std::string &private_key_path,
                             const std::string &public_key_path) {
  if (!(file_exists(private_key_path) && file_exists(public_key_path))) {
    // Generar y guardar el par de llaves RSA
    EVP_PKEY *key = generate_key();
    save_key(key, private_key_path.c_str(), public_key_path.c_str());

    // Liberar recursos
    EVP_PKEY_free(key);
  }
}
