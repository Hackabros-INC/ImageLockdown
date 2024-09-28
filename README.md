# ImageLockdown

ImageLockdown is a C++ program that encrypts and decrypts image files using the AES-256 algorithm from the OpenSSL library. The program now supports two modes of operation: CTR (Counter) and GCM (Galois/Counter Mode).

## Usage

```bash
./main <mode> <enc/dec> <input_path> <output_path>
```

- `<mode>`: Set the encryption/decryption mode.
  - `0` for AES-256-CTR.
  - `1` for AES-256-GCM.
- `<enc/dec>`: Choose whether to encrypt (`enc`) or decrypt (`dec`) the file.
- `<input_path>`: Path to the input file (the image to be encrypted or the encrypted file to be decrypted).
- `<output_path>`: Path where the output file will be saved (either the encrypted file or the decrypted image).

### Example

1. **Encrypt an image in CTR mode**:
    ```bash
    ./main 0 enc image.jpg encrypted_image.bin
    ```

2. **Decrypt an image in CTR mode**:
    ```bash
    ./main 0 dec encrypted_image.bin decrypted_image.jpg
    ```

3. **Encrypt an image in GCM mode**:
    ```bash
    ./main 1 enc image.jpg encrypted_image.bin
    ```

4. **Decrypt an image in GCM mode**:
    ```bash
    ./main 1 dec encrypted_image.bin decrypted_image.jpg
    ```

## Prerequisites

- OpenSSL library installed
- C++17 or later

## Compilation

You can compile the program using `g++` or any other compatible compiler. Here's an example using `g++`:

```bash
g++ -o main main.cpp -lssl -lcrypto
```

Ensure that OpenSSL is properly installed on your system.
