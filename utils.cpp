#include <fstream>        // Include for file handling
#include <openssl/err.h>  // Include for OpenSSL error handling
#include <openssl/evp.h>  // Include for OpenSSL EVP functions
#include <openssl/pem.h>  // Include for OpenSSL PEM functions
#include <openssl/rand.h> // Include for OpenSSL random number generation
#include <string>         // Include for string handling

// Function to handle OpenSSL errors
void handleErrors() {
  ERR_print_errors_fp(stderr); // Print OpenSSL errors to standard error
  abort();                     // Abort the program
}

// Function to generate an RSA key
EVP_PKEY *generate_key() {
  EVP_PKEY_CTX *ctx;     // Context for key generation
  EVP_PKEY *pkey = NULL; // Pointer to hold the generated key

  // Create a context for RSA key generation
  ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
  if (!ctx)
    handleErrors(); // Handle error if context creation fails

  // Initialize the key generation context
  if (EVP_PKEY_keygen_init(ctx) <= 0)
    handleErrors(); // Handle error if initialization fails

  // Set the RSA key length to 2048 bits
  if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0)
    handleErrors(); // Handle error if setting key length fails

  // Generate the RSA key
  if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
    handleErrors(); // Handle error if key generation fails

  EVP_PKEY_CTX_free(ctx); // Free the context

  return pkey; // Return the generated key
}

// Function to save the RSA key to files
void save_key(EVP_PKEY *pkey, const std::string &priv_filename,
              const std::string &pub_filename) {
  // Open file to write the private key
  FILE *priv_key_file = fopen(priv_filename.c_str(), "wb");
  // Write the private key in PEM format
  PEM_write_PrivateKey(priv_key_file, pkey, NULL, NULL, 0, NULL, NULL);
  fclose(priv_key_file); // Close the private key file

  // Open file to write the public key
  FILE *pub_key_file = fopen(pub_filename.c_str(), "wb");
  // Write the public key in PEM format
  PEM_write_PUBKEY(pub_key_file, pkey);
  fclose(pub_key_file); // Close the public key file
}

// Function to load an RSA key from a file
EVP_PKEY *load_key(const std::string &filename, bool is_private) {
  // Open the key file for reading
  FILE *key_file = fopen(filename.c_str(), "rb");
  EVP_PKEY *pkey = NULL; // Pointer to hold the loaded key

  // Load the key based on whether it is private or public
  if (is_private)
    pkey = PEM_read_PrivateKey(key_file, NULL, NULL, NULL);
  else
    pkey = PEM_read_PUBKEY(key_file, NULL, NULL, NULL);

  fclose(key_file); // Close the key file
  return pkey;      // Return the loaded key
}

// Function to check if a file exists
bool file_exists(const std::string &filename) {
  std::ifstream file(filename); // Open the file
  return file.good(); // Return true if the file exists, false otherwise
}

// Function to check if key files exist and generate them if not
void check_and_generate_keys(const std::string &private_key_path,
                             const std::string &public_key_path) {
  // Check if both the private and public key files exist
  if (!(file_exists(private_key_path) && file_exists(public_key_path))) {
    // Generate and save the RSA key pair
    EVP_PKEY *key = generate_key();
    save_key(key, private_key_path.c_str(), public_key_path.c_str());

    // Free the key resources
    EVP_PKEY_free(key);
  }
}
