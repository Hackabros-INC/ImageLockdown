#include <string> // Include for string handling

void aes_256_ctr_enc(const std::string &input_path,
                     const std::string &output_path);
void aes_256_ctr_dec(const std::string &input_path,
                     const std::string &output_path);
void aes_256_gcm_enc(const std::string &input_path,
                     const std::string &output_path);
void aes_256_gcm_dec(const std::string &input_path,
                     const std::string &output_path);
