int aes_gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                    unsigned char *aad, int aad_len,
                    unsigned char *tag,
                    unsigned char *key,
                    unsigned char *iv, int iv_len,
                    unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    /* Create and initialize the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        return -1;

    /* Initialize the decryption operation. */
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        return -1;

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        return -1;

    /* Initialize key and IV */
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        return -1;

    /* Provide any AAD data. This can be called zero or more times as required */
    if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
        return -1;

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        return -1;
    plaintext_len = len;
